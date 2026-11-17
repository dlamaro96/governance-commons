// SPDX-License-Identifier: Apache-2.0
/** PRIVATE CONTRACT SKETCH ONLY. No parser, persistence, route or runtime is implemented here.
 * Root adoption and a new forward migration are required; no migration number is allocated.
 * Existing reference-code-list v1 bundles/hashes and SQL022/023 remain unchanged. */
import type {
  Instant, UUID, Hash, Labels, WorkflowPin, Result, Download,
} from './reference-data-contracts.ts';

export const STRUCTURE_LIMITS = Object.freeze({
  endpointCodes: 256, hierarchyEdges: 256, crosswalkMappings: 256,
  temporalBoundaryPoints: 514, hierarchyDepth: 256,
  code: 128, label: 240, description: 2048, methodDetails: 512,
  transformationNotes: 2048, confidenceBasis: 1024,
  assignments: 64, pageDefault: 25, pageMaximum: 100, cursor: 1024, search: 200,
  releaseBytes: 245760, payloadBytes: 262144, envelopeBytes: 327680,
  responseBytes: 1048576, downloadBytes: 8388608,
  nodes: 20000, depth: 16, properties: 128, array: 256,
  totalUtf16: 327680, stringUtf16: 8192,
  version: 2147483647, expectedVersion: 2147483646,
  commandDeadlineMs: 30000, statementDeadlineMs: 15000, lockDeadlineMs: 2000,
} as const);

/** Nonzero canonical lowercase UUID; positive 32-bit version; lowercase SHA256. */
export interface ReferenceReleasePin {
  readonly setId: UUID;
  readonly version: number;
  readonly publicationHash: Hash;
}
export interface Interval {
  /** null starts at the structure release's canonical effectiveFrom. */
  readonly validFrom: Instant | null;
  /** null ends at the structure release's declared validUntil, or infinity. */
  readonly validUntil: Instant | null;
}
export type Activation = {readonly kind:'on-publication'} | {readonly kind:'at';readonly at:Instant};
export interface CommonDefinition {
  readonly formatVersion: 1;
  readonly labels: Labels;
  readonly ownerId: UUID;
  readonly status: 'active' | 'deprecated';
  readonly activation: Activation;
  readonly validUntil: Instant | null;
}
export interface HierarchyEdge extends Interval {
  readonly parentCode: string;
  readonly childCode: string;
}
export interface HierarchyDefinition extends CommonDefinition {
  readonly kind: 'reference-hierarchy';
  readonly reference: ReferenceReleasePin;
  readonly multiParent: 'forbid' | 'allow';
  /** Complete replacement, 0..256. Empty explicitly removes all relationships. */
  readonly edges: readonly HierarchyEdge[];
}
/** Declared provenance only. Neither notes nor a described rule are executable. */
export type MappingMethod = 'steward-asserted' | 'source-reported' | 'rule-described';
export type MappingConfidence =
  | {readonly kind:'not-assessed'}
  | {readonly kind:'declared';readonly basisPoints:number;readonly basis:string};
export interface CrosswalkMapping extends Interval {
  readonly sourceCode: string;
  readonly targetCode: string;
  readonly relation: 'equivalent' | 'source-broader' | 'source-narrower' | 'related';
  readonly method: MappingMethod;
  readonly methodDetails: string;
  readonly transformationNotes: string;
  /** 0..10000 is an authored assessment, never a computed probability. */
  readonly confidence: MappingConfidence;
}
export interface CrosswalkDefinition extends CommonDefinition {
  readonly kind: 'reference-crosswalk';
  readonly source: ReferenceReleasePin;
  readonly target: ReferenceReleasePin;
  readonly cardinality: 'many-to-many';
  /** Reject any intersecting intervals for one ordered code pair, even identical rows.
   * Different target/source pairs are intentional many-to-many mappings, not collisions.
   * No exception/waiver path is in this increment. */
  readonly overlapPolicy: 'reject-overlapping-pair';
  readonly mappings: readonly CrosswalkMapping[];
}
export type StructureDefinition = HierarchyDefinition | CrosswalkDefinition;
/** These endpoint set identities and kind are fixed for the lifetime of structureId.
 * Pinned release versions may change only through another complete reviewed release. */
export type StructureIdentity =
  | {readonly kind:'reference-hierarchy';readonly referenceSetId:UUID}
  | {readonly kind:'reference-crosswalk';readonly sourceSetId:UUID;readonly targetSetId:UUID};

export interface StructureProposal {
  readonly id: UUID;
  readonly structureId: UUID;
  readonly expectedVersion: number;
  readonly release: StructureDefinition;
  readonly workflow: WorkflowPin;
  readonly assignments: Readonly<Record<string,UUID>>;
  readonly expiresAt: Instant;
}
export interface StructureApprovalPayload {
  readonly formatVersion: 1;
  readonly kind: 'reference-structure-publication';
  readonly structureId: UUID;
  readonly expectedVersion: number;
  readonly release: StructureDefinition;
}
export interface StructureProposalDigestPreimage {
  readonly id: UUID;
  readonly binding: 'reference.structure.publish';
  readonly payload: StructureApprovalPayload;
  readonly workflow: WorkflowPin;
  readonly assignments: Readonly<Record<string,UUID>>;
  readonly expiresAt: Instant;
}
export interface PublicationCoordinates {
  readonly structureId: UUID;
  readonly version: number;
  readonly publishedAt: Instant;
  readonly effectiveFrom: Instant;
}
/** activation disappears at publication; all other approved normalized fields remain. */
export type PublishedStructure = PublicationCoordinates & (
  | Omit<HierarchyDefinition,'activation'>
  | Omit<CrosswalkDefinition,'activation'>
);
export interface StructurePublicationResult extends PublicationCoordinates {
  readonly binding: 'reference.structure.publish';
  readonly publicationHash: Hash;
}
export interface StructureReleaseView {
  readonly release: PublishedStructure;
  readonly publicationHash: Hash;
}
export interface StructureProposalReceipt {readonly instance:{readonly id:UUID}}
export interface StructureAuthoringContext extends StructureReleaseView {
  readonly identity: StructureIdentity;
  readonly latestPublishedVersion: number;
  /** Audience is intentionally absent: current endpoint visibility is authoritative. */
  readonly audiencePolicy: 'intersection-of-current-endpoint-audiences';
}
export interface StructureReleaseSummary extends PublicationCoordinates {
  readonly identity: StructureIdentity;
  readonly labels: Labels;
  readonly ownerId: UUID;
  readonly status: 'active' | 'deprecated';
  readonly validUntil: Instant | null;
  readonly publicationHash: Hash;
  readonly entryCount: number;
}
export interface StructurePage<T> {readonly items:readonly T[];readonly nextCursor:string|null}
export interface StructurePageQuery {readonly limit?:number;readonly cursor?:string}
export interface StructureListQuery extends StructurePageQuery {
  readonly q?: string;
  readonly kind?: StructureIdentity['kind'];
  readonly setId?: UUID;
}
export interface StructureEffectiveQuery extends StructurePageQuery {readonly asOf?:Instant}
export interface SelectedStructure {
  readonly asOf: Instant;
  readonly version: number;
  readonly publicationHash: Hash;
  readonly effectiveFrom: Instant;
  readonly effectiveUntil: Instant | null;
}
export interface EndpointGap {
  readonly endpoint: 'reference' | 'source' | 'target';
  readonly reason: 'NOT_EFFECTIVE' | 'EXPIRED' | 'DEPRECATED' | 'PIN_SUPERSEDED';
}
export type UnavailableStructureSelection =
  | {readonly phase:'NOT_EFFECTIVE';readonly asOf:Instant;readonly version:null;readonly publicationHash:null;
     readonly effectiveFrom:null;readonly effectiveUntil:null;readonly gaps:readonly []}
  | (SelectedStructure & {readonly phase:'EXPIRED'|'DEPRECATED';readonly gaps:readonly []})
  | (SelectedStructure & {readonly phase:'ENDPOINT_PIN_NOT_EFFECTIVE';readonly gaps:readonly EndpointGap[]});
/** structure describes the selected release whenever selection.version exists.
 * Only NOT_EFFECTIVE uses the latest currently authorized summary; no effective rows exist then.
 * Authoring-context is always the latest published head. */
export type EffectiveStructureView =
  | {readonly structure:StructureReleaseSummary;readonly selection:UnavailableStructureSelection;
     readonly items:readonly [];readonly nextCursor:null}
  | {readonly structure:StructureReleaseSummary;
     readonly selection:SelectedStructure & {readonly phase:'EFFECTIVE';readonly gaps:readonly []};
     readonly kind:'reference-hierarchy';readonly reference:ReferenceReleasePin;readonly multiParent:'forbid'|'allow';
     readonly items:readonly HierarchyEdge[];readonly nextCursor:string|null}
  | {readonly structure:StructureReleaseSummary;
     readonly selection:SelectedStructure & {readonly phase:'EFFECTIVE';readonly gaps:readonly []};
     readonly kind:'reference-crosswalk';readonly source:ReferenceReleasePin;readonly target:ReferenceReleasePin;
     readonly cardinality:'many-to-many';readonly overlapPolicy:'reject-overlapping-pair';
     readonly items:readonly CrosswalkMapping[];readonly nextCursor:string|null};

/** Proposed pure-module seams, not implementations. Validation gets authorized complete
 * endpoint bundles and known successor boundaries from the service, never caller claims. */
export interface EndpointValidationContext {
  readonly pin: ReferenceReleasePin;
  readonly releaseStatus: 'active'|'deprecated';
  readonly publishedAt: Instant;
  readonly effectiveFrom: Instant;
  readonly declaredValidUntil: Instant|null;
  readonly nextKnownEffectiveFrom: Instant|null;
  readonly codes: readonly {readonly code:string;readonly status:'active'|'deprecated';
    readonly validFrom:Instant|null;readonly validUntil:Instant|null}[];
}
export interface StructurePublicationContext {
  readonly payload: StructureApprovalPayload;
  readonly publishedAt: Instant;
  readonly previous: PublishedStructure|null;
  readonly endpoints: readonly EndpointValidationContext[];
}
export interface ProposedPureModule {
  parseProposal(input:unknown,requesterId:unknown):Result<StructureProposal>;
  parseApprovalPayload(input:unknown):Result<StructureApprovalPayload>;
  proposalDigest(input:unknown,requesterId:unknown):Result<Hash>;
  publish(context:StructurePublicationContext):Result<PublishedStructure>;
  parsePublishedBundle(input:unknown):Result<PublishedStructure>;
  publicationHash(input:unknown):Result<Hash>;
  serializeBundle(input:unknown,format:'json'|'csv'):Result<Download>;
  parsePublicationResult(input:unknown):Result<StructurePublicationResult>;
}

/** RFC4180 CRLF, UTF8 without BOM; exactly one release metadata row even for zero entries.
 * Later rows repeat schema/kind/id/version/hash and fill only their applicable entry fields;
 * all non-applicable fields are empty. JSON cells are canonical and must round-trip losslessly. */
export const STRUCTURE_CSV_COLUMNS = Object.freeze([
  'recordType','schemaVersion','structureKind','structureId','version','publicationHash',
  'labelsJson','ownerId','status','publishedAt','effectiveFrom','validUntil',
  'referencePinJson','sourcePinJson','targetPinJson','multiParent','cardinality','overlapPolicy',
  'parentCode','childCode','sourceCode','targetCode','entryValidFrom','entryValidUntil',
  'relation','method','methodDetails','transformationNotes','confidenceJson',
] as const);
export type StructureCSVRecordType = 'release'|'hierarchy-edge'|'crosswalk-mapping';

export const ROUTES = Object.freeze([
  'GET /api/v1/reference-data/structures?q=&kind=&setId=&limit=&cursor=',
  'GET /api/v1/reference-data/structures/:id/effective?asOf=&limit=&cursor=',
  'GET /api/v1/reference-data/structures/:id/releases?limit=&cursor=',
  'GET /api/v1/reference-data/structures/:id/releases/:version',
  'GET /api/v1/reference-data/structures/:id/authoring-context',
  'GET /api/v1/reference-data/structures/:id/releases/:version/download?format=json|csv',
  'POST /api/v1/reference-data/structure-proposals',
] as const);
