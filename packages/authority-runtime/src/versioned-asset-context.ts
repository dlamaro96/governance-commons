// SPDX-License-Identifier: Apache-2.0
import {decisionFailure, decisionHash} from '../../authority/src/decision-schema.ts';
import type {Counter, Digest, Parsed} from '../../authority/src/types.ts';
import {admitted, counter, digest, equal, literal, shape} from '../../authority-storage/src/shape.ts';
import {parseHumanAssetContext, type HumanAssetContext} from './asset-context.ts';

/** SQL033 provenance for the canonical heads read in the same snapshot. A
 * detached result never authorizes a subsequent read or write. Classification
 * facts are still unavailable; this counter is not their producer. */
export type VersionedHumanAssetContext = {
  readonly formatVersion: 1;
  readonly kind: 'inactive-versioned-asset-context';
  readonly contentAuthority: false;
  readonly context: HumanAssetContext;
  readonly securityRevision: Counter;
  readonly contextDigest: Digest;
};
const zero = '0'.repeat(64) as Digest;
const envelope = shape({formatVersion: literal(1), kind: literal('inactive-versioned-asset-context'),
  contentAuthority: literal(false), context: value => value, securityRevision: counter, contextDigest: digest});

export function parseVersionedHumanAssetContext(value: unknown): Parsed<VersionedHumanAssetContext> {
  try {
    // One physical budget for the whole wrapper, before nested traversal. The
    // inner parser cannot reset the accepted envelope's byte/node/depth budget.
    const out = envelope(admitted(value).data, '') as VersionedHumanAssetContext;
    const context = parseHumanAssetContext(out.context);
    if (!context.ok) return context;
    const result = Object.freeze({...out, context: context.value});
    equal(out.context, context.value, 'Versioned context must retain its canonical inner envelope.');
    equal(result.contextDigest, decisionHash({...result, contextDigest: zero}), 'Versioned asset context digest differs.');
    return {ok: true, value: result};
  } catch (error) {
    return decisionFailure(error);
  }
}
