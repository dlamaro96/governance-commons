// SPDX-License-Identifier: Apache-2.0
// Private inactive canonical facts. Parsing and hashing never grant access.
import { AUTHORITY_ADMISSION_LIMITS } from '../../authority/src/admission.ts';
import { decisionFailure, decisionHash, decisionShapes, validateRegistry } from '../../authority/src/decision-schema.ts';
import type { AuthorityDecisionRegistry } from '../../authority/src/decision-types.ts';
import type { Counter, Digest, Parsed, UUID, Version } from '../../authority/src/types.ts';
import type { AuthorityHumanClosure } from '../../authority-storage/src/contracts.ts';
import { parseAuthorityHumanClosure } from '../../authority-storage/src/loader.ts';
import { admitted, array, counter, digest, equal, fail, foundationScalars, literal, nullable, shape, uuid, version, type Validator } from '../../authority-storage/src/shape.ts';

export type HumanAssetContext = {
  readonly formatVersion: 1;
  readonly kind: 'inactive-human-asset-context';
  readonly contentAuthority: false;
  readonly closure: AuthorityHumanClosure;
  readonly registry: AuthorityDecisionRegistry;
  readonly asset: {
    readonly tenantId: UUID;
    readonly id: UUID;
    readonly version: Version;
    readonly status: 'active' | 'unavailable' | 'retired';
    readonly visibility: 'tenant' | 'restricted';
    readonly allowedIdentities: readonly UUID[];
  };
  readonly placement: null | {
    readonly version: Version;
    readonly domainId: UUID | null;
    readonly recordedAssetVersion: Version;
    readonly recordedDomainVersion: Version | null;
  };
  /** Direct domain first, then ancestors; the final entry is the root. */
  readonly domainPath: readonly {
    readonly id: UUID;
    readonly version: Version;
    readonly parentId: UUID | null;
    readonly typeId: UUID;
    readonly typeVersion: Version;
    readonly status: 'active' | 'retired';
  }[];
  readonly domainEpoch: Counter;
  readonly unavailableFacts: readonly ['classification', 'approved-tags', 'purpose', 'environment'];
  readonly contextDigest: Digest;
};

const zero = '0'.repeat(64) as Digest;
const pass: Validator = value => value;
const domainEpoch: Validator = (value, path) => value === '0' ? value : counter(value, path);
const domain = shape({id: uuid, version, parentId: nullable(uuid), typeId: uuid, typeVersion: version, status: literal('active', 'retired')});
const domainPath: Validator = (value, path) => {
  if (!Array.isArray(value)) fail('Expected domain ancestry array.', 'type');
  if (value.length > AUTHORITY_ADMISSION_LIMITS.domainPathEntries) fail('Domain ancestry exceeds the authority profile.', 'limit');
  // This is a path, not a set. Preserve nearest-first order exactly.
  return Object.freeze(value.map((entry, index) => domain(entry, `${path}/${index}`)));
};
const unavailableFacts: Validator = value => {
  equal(value, ['classification', 'approved-tags', 'purpose', 'environment'], 'Unavailable fact markers differ.');
  return Object.freeze(['classification', 'approved-tags', 'purpose', 'environment'] as const);
};
const envelope = shape({
  formatVersion: literal(1), kind: literal('inactive-human-asset-context'), contentAuthority: literal(false),
  closure: pass, registry: pass,
  asset: shape({tenantId: uuid, id: uuid, version, status: literal('active', 'unavailable', 'retired'), visibility: literal('tenant', 'restricted'), allowedIdentities: array(uuid, value => value as string, 4096)}),
  placement: nullable(shape({version, domainId: nullable(uuid), recordedAssetVersion: version, recordedDomainVersion: nullable(version)})),
  domainPath, domainEpoch, unavailableFacts, contextDigest: digest,
});

/** Admit the entire envelope before reflection, with one shared 8 MiB/node/depth
 * profile. A detached DTO is evidence only: no security revision or missing fact
 * is invented, and no authorization evaluator is invoked here. */
export function parseHumanAssetContext(value: unknown): Parsed<HumanAssetContext> {
  try {
    const admittedEnvelope = admitted(value);
    const out = envelope(admittedEnvelope.data, '') as HumanAssetContext;
    const registry = decisionShapes.registry(out.registry, '/registry') as AuthorityDecisionRegistry;
    validateRegistry(registry);
    foundationScalars(registry);
    equal(out.registry, registry, 'Context registry must use distinct canonical ordering.');
    const parsedClosure = parseAuthorityHumanClosure(out.closure, registry);
    if (!parsedClosure.ok) return parsedClosure;
    const context: HumanAssetContext = Object.freeze({...out, registry, closure: parsedClosure.value});
    foundationScalars(context);
    const {asset, placement, domainPath: path, closure} = context;
    equal([closure.session.tenantId, closure.snapshot.tenantId], [asset.tenantId, asset.tenantId], 'Asset and closure tenant differ.');
    equal(closure.selectors, [{action: 'asset:metadata.read', resource: {tenantId: asset.tenantId, kind: 'asset', id: asset.id}, revision: asset.version, field: null}], 'Closure must select only this current asset metadata revision.');
    if (placement !== null && placement.recordedAssetVersion > asset.version) fail('Recorded placement asset version exceeds the current asset.', 'version');
    if (placement === null || placement.domainId === null) {
      if (path.length !== 0) fail('Unplaced asset cannot have domain ancestry.');
      if (placement !== null && placement.recordedDomainVersion !== null) fail('Unplaced record cannot pin a domain version.');
    } else {
      if (!path.length || path[0]!.id !== placement.domainId) fail('Domain ancestry must start at the placed domain.');
      if (placement.recordedDomainVersion === null || placement.recordedDomainVersion > path[0]!.version) fail('Recorded placement domain version exceeds the current domain or is missing.', 'version');
    }
    const seen = new Set<UUID>();
    for (let index = 0; index < path.length; index++) {
      const entry = path[index]!;
      if (seen.has(entry.id)) fail('Domain ancestry repeats a domain.', 'duplicate');
      seen.add(entry.id);
      if (entry.parentId !== (path[index + 1]?.id ?? null)) fail('Domain ancestry is disconnected or its root has a parent.');
    }
    // SQL011 advances this epoch on every domain and placement row write.
    if (context.domainEpoch === '0' && (placement !== null || path.length !== 0)) fail('Written placement or ancestry requires a positive domain epoch.');
    equal(context.contextDigest, decisionHash({...context, contextDigest: zero}), 'Asset context digest differs.');
    return {ok: true, value: context};
  } catch (error) {
    return decisionFailure(error);
  }
}
