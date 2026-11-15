# Constrained relations implementation contract

Status: **PLANNED — NOT IMPLEMENTED OR QUALIFIED.** This is the next bounded increment after complete authored-type migrations. It advances MOD-001/002/004, CORE-002/006/007, SYS-DATA-001–005 and SYS-SEC-002/003; it does not complete those requirements, AT-MOD-01, E2E-06 or M2. The full specification and canonical requirement register remain authoritative. Optional activation does not remove any later required implementation.

SQL001–007 and existing authored asset/model/plan formats remain unchanged once applied. SQL008 is a new migration, subject to root review and isolated upgrade qualification before core application. Do not modify application source or runtime while the preceding increment's qualification is frozen.

## Authored relation types

Use a distinct strict JSON format, separate from the existing attribute-model and asset-type formats. Every field below is required; reject unknown fields, duplicate JSON keys, coercion, unsafe identifiers, malformed Unicode, invalid UUIDs and executable expressions. Versions are positive PostgreSQL integers and publication advances by exactly one. Logical keys retain the existing safe64 grammar; the server assigns a separate immutable relation-type UUID.

```ts
interface RelationEndpointRule {
  typeId: string;                  // Existing immutable authored asset-type UUID.
  includeDescendants: boolean;
}
interface RelationTypeDefinition {
  formatVersion: 1;
  id: string;
  version: number;
  label: string;
  inverseLabel: string;
  direction: 'directed' | 'undirected';
  sourceTypes: readonly RelationEndpointRule[];
  targetTypes: readonly RelationEndpointRule[];
  sourceStates: readonly string[] | null;
  targetStates: readonly string[] | null;
  cardinality: {
    outgoing: { min: 0; max: number | null };
    incoming: { min: 0; max: number | null };
  };
  allowSelf: boolean;
  cycles: 'allow' | 'acyclic';
  attributes: Readonly<Record<string, AttributeDefinition>>;
  requiredOwner: boolean;
  lifecycle: LifecycleDefinition;
}
```

Labels contain 1–120 characters. Each endpoint list contains 1–32 unique type UUIDs, sorted canonically. A rule matches the endpoint's own immutable type UUID at any version; `includeDescendants` also matches ancestry from that asset's **actual pinned** authored definition. Never infer ancestry from current heads or from the source-native `assets.type` label. Attribute-only/untyped assets cannot satisfy an endpoint rule. All endpoint type identities must exist in the same tenant. Record exact asset/model revisions in previews and relation revisions even though endpoint eligibility uses nominal type identity.

State allowlists are null, meaning any valid state in the endpoint's pinned lifecycle, or 1–32 unique safe state identifiers, sorted canonically. Definition parsing validates their grammar; publication does not pretend current nominal type heads enumerate every state of every allowed historical pin or future descendant. A non-null list is an additional restriction; it never makes an invalid pinned state legal. Do not infer future descendant lifecycle states from an ancestor's current head. Relation-owned attributes use the existing complete typed grammar and validator. Relation-owned lifecycle uses the existing lifecycle grammar, independently of either endpoint's lifecycle.

Undirected types require equal canonical source/target rules, state allowlists and cardinality. Canonicalize endpoints into ascending UUID order before uniqueness, serialization and hashing; incoming/outgoing queries both include an undirected edge. Self-edges count once toward each directed degree, or once toward undirected degree. `acyclic` requires `allowSelf:false`. Cycles are allowed by default and may be prohibited per relation type only; the whole business graph is never forced into a DAG.

This increment implements **structural 0..N and 0..unbounded cardinality**. Finite maxima are integers 1–1,000; null means no declared maximum, not unlimited execution. Reject positive minima with `RELATION_MINIMUM_UNSUPPORTED`; do not silently substitute zero. Required participation must later have persistent bindings covering eligible assets with zero edges. Counting only endpoints that already have edges is not minimum-cardinality implementation.

## Canonical relations, uniqueness and time

A relation has an immutable opaque UUID, tenant, immutable logical relation-type UUID and endpoint UUIDs, exact relation-type version, typed attributes, owner, lifecycle state, optimistic version, validity interval, visibility, asserted provenance and immutable revisions. Changes to endpoints or type identity require a distinct edge; they are not ordinary PATCH fields. New edges use the current relation-type version. Existing edges keep their version pins.

One non-tombstoned edge may exist per `(tenant, relationTypeId, canonicalSourceId, canonicalTargetId)`, independent of the pinned type version. Different logical types may connect the same assets. Retry keys do not replace this database uniqueness rule. DELETE is a tombstone with a new immutable revision; there is no hard-delete or resurrection API in this increment. Reassertion after a tombstone creates a new UUID under the current type version and preserves the prior history.

All non-tombstoned edges count toward structural degree and cycle validation across versions of the same logical relation type, regardless of relation lifecycle or validity dates. Every surviving incident edge's pinned limits must remain satisfied. An undirected acyclic type forms a forest; a directed acyclic type forbids a directed return path. Budget exhaustion cannot be interpreted as proof of acyclicity. A type's cycle policy cannot change with live edges without an explicit future relation migration.

`validFrom` and `validTo` are nullable canonical UTC timestamps with millisecond precision. Both null means unbounded validity; otherwise use the half-open interval `[validFrom, validTo)` and require `validFrom < validTo` when both exist. The parser rejects invalid calendar values/precision and does not round. Business validity does not rewrite transaction history or exempt an edge from structural constraints. Lists without `validAt` include every non-tombstoned edge, including future/expired edges. Graph traversal freezes `validAt` to the request's UTC instant when omitted and returns that resolved instant for later pages. Validity filters apply before graph expansion. Historical transaction-time graph reconstruction, simultaneous-validity cardinality and multiple disjoint validity episodes are required follow-on work; `validAt` alone is not an as-of-history claim.

Only `origin:'asserted'` is implemented here. The server records the manual identity source, actor, tenant, assertion time and ingestion time; clients cannot supply another actor or label data as imported/derived. Authority identifies a manual assertion; it does not claim certification or an implemented conflict-resolution ranking. Preserve explicit unknown source-observation/run/confidence/precedence fields rather than inventing external evidence. Imported claims, derived rules and authority/conflict resolution remain required later.

## Stable views and API payloads

All paths below have `/api/v1` prefix. In type views and `/relation-types/:id` paths, `id` is the logical key; `relationTypeId` is the separate immutable UUID. Relation `:id` paths use edge UUIDs. A version view retains current-head metadata in the summary fields and the requested immutable definition in `definition`; relation labels always come from the relation's pinned definition. UUIDs use the existing contract; timestamps use the canonical representation above; SHA256 values are lowercase 64-hex. Use the existing authenticated server session, CSRF, Problem Details, correlation IDs and rate-limit behavior. Never accept a tenant ID as authority.

```ts
interface RelationTypeSummary {
  id: string; relationTypeId: string; currentVersion: number;
  label: string; createdAt: string; createdBy: string;
}
interface RelationTypeView extends RelationTypeSummary {
  version: number; definition: RelationTypeDefinition; definitionHash: string;
  versionCreatedAt: string; versionCreatedBy: string;
}
interface RelationEndpointView {
  assetId: string; name: string; assetVersion: number;
  typeId: string | null; modelId: string | null;
  modelVersion: number | null; state: string | null;
}
interface RelationView {
  id: string; relationTypeId: string; relationTypeKey: string;
  relationTypeVersion: number; version: number;
  source: RelationEndpointView; target: RelationEndpointView;
  direction: 'directed' | 'undirected'; label: string; inverseLabel: string;
  attributes: AttributeValues; ownerId: string | null; state: string;
  validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
  status: 'active' | 'tombstoned';
  provenance: { origin: 'asserted'; source: { kind: 'manual'; identityId: string };
    authority: 'manual-assertion'; precedence: null; actorId: string; assertedAt: string;
    ingestedAt: string; sourceObservedAt: null; sourceVersion: null;
    sourceRunId: null; confidence: null };
  createdAt: string; createdBy: string; updatedAt: string; updatedBy: string;
}
interface RelationCreate {
  relationTypeId: string; relationTypeVersion: number;
  sourceAssetId: string; sourceAssetVersion: number;
  targetAssetId: string; targetAssetVersion: number;
  attributes: unknown; ownerId: string | null;
  validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
}
interface RelationEdit {
  sourceAssetVersion: number; targetAssetVersion: number;
  attributes: unknown; ownerId: string | null;
  validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
}
interface RelationTypePreview {
  relationTypeId: string; id: string; currentVersion: number; proposedVersion: number;
  coverage: 'complete-tenant-relation-type-bindings'; relationCount: number;
  changes: readonly { code: string; path: string; requiresMigration: boolean }[];
  relations: readonly { relationId: string; relationVersion: number;
    currentIssues: readonly ValidationIssue[]; proposedIssues: readonly ValidationIssue[] }[];
  requiresExplicitMigration: boolean; compatibleWithProvidedRelations: boolean;
  pinsPreserved: true; previewDigest: string;
}
```

`RelationEndpointView` permits null type fields for a visible untyped graph root with no eligible relations. Actual relation endpoints always have valid non-null authored type/model pins and lifecycle states. An attribute-only graph root may retain its attribute model fields while `typeId` and `state` remain null.

`RelationEdit` is a complete editable-fields replacement, preventing omitted fields from being confused with null. State changes use the separate transition route. Creation chooses the pinned type's initial state; clients cannot skip its transition graph. Explicit non-null owner replacements require an active identity and active membership even when ownership is optional. Required ownership is checked against current activity on every relation mutation. Visibility lists have at most 100 unique same-tenant memberships; tenant visibility requires an empty list, restricted visibility requires a nonempty list. Create/edit must leave the actor able to read the resulting edge, so a mutation cannot serialize a newly inaccessible response. Normalized membership references enforce tenant identity integrity. Visibility and ownership never grant access to either endpoint.

| Method and path | Body/query and response | Preconditions |
|---|---|---|
| POST `/relation-types/validate` | `{text}` → `{definition}` | Fresh models read/write; strict file parse only |
| GET `/relation-types` | `q,limit,cursor` → `{items:RelationTypeSummary[],nextCursor}` | Fresh models read |
| POST `/relation-types` | `{definition}` → 201 `{type:RelationTypeView}` | Initial version 1; models read/write; Idempotency-Key |
| GET `/relation-types/:id` | → `{type:RelationTypeView}` at current head | Models read |
| GET `/relation-types/:id/versions/:version` | → `{type:RelationTypeView}` at immutable pin | Models read |
| GET `/relation-types/:id/versions` | `limit,cursor` → `{items:{version,definitionHash,createdAt,createdBy}[],nextCursor}` in version ascending order | Models read |
| POST `/relation-types/:id/previews` | `{definition}` → `{preview:RelationTypePreview}` | If-Match=head; models read/write and catalog read |
| POST `/relation-types/:id/versions` | `{definition,previewDigest}` → 201 `{type:RelationTypeView}` | Same permissions, If-Match, Idempotency-Key, fresh complete preview |
| POST `/relations` | `RelationCreate` → 201 `{relation:RelationView}` | Catalog read/write and models read; Idempotency-Key; exact endpoint and type versions |
| GET `/relations/:id` | → `{relation:RelationView}` | Catalog/models read; current edge and both-endpoint access |
| PATCH `/relations/:id` | `RelationEdit` → `{relation:RelationView}` | Same write permissions; If-Match=edge version; Idempotency-Key |
| POST `/relations/:id/transitions` | `{state,sourceAssetVersion,targetAssetVersion}` → `{relation:RelationView}` | Same write permissions, If-Match, Idempotency-Key; pinned legal transition |
| DELETE `/relations/:id` | No body → `{relation:RelationView}` with tombstoned status | Same write permissions, If-Match, Idempotency-Key; preserve history |
| GET `/relations/:id/revisions` | `limit,cursor` → `{items:RelationRevisionView[],nextCursor}` | Catalog/models/audit read; reauthorize current edge and original endpoints |
| GET `/assets/:id/relations` | `direction,relationTypeId,validAt,limit,cursor` → `{items:RelationView[],nextCursor,graphRevision}` | Catalog/models read; root and every returned edge/endpoints visible |
| GET `/assets/:id/graph` | `direction,relationTypeId,validAt,depth,limit,cursor` → graph page below | Same read permissions and per-hop authorization |

`RelationRevisionView` is `{relationId,version,snapshot:RelationView,recordedAt,recordedBy}`. Its endpoint snapshot remains the revision's recorded values, but access is checked against current endpoint/edge authorization before returning it. There is no revision rewrite or user-selected execution identity. Cached mutation responses must be reauthorized against their original recorded edge/endpoints, including tombstoned results, before serialization.

Missing/inaccessible edge or endpoint uses the same 404 unavailable response. Current role denial is 403. Stale optimistic versions, graph cursors or digests are 409. Missing preconditions are 428. Invalid constraints are 422 with bounded authorized issues; complete hidden scope is generic 403 without hidden identifiers or counts. Oversized profiles fail explicitly before partial writes. Lock timeout/deadlock/statement timeout maps to 503 with rollback and retry guidance. Structured codes include `RELATION_INVALID`, `RELATION_DUPLICATE`, `RELATION_CARDINALITY`, `RELATION_CYCLE`, `RELATION_SCOPE_UNAVAILABLE`, `RELATION_PROFILE_LIMIT`, `RELATION_MIGRATION_REQUIRED` and `RELATION_GRAPH_STALE`.

## Persistence, publication and atomicity

SQL008 adds relation-type heads/immutable versions, normalized endpoint-type references, canonical edges, immutable revisions, normalized visibility membership references, and one tenant graph-revision row. Its counter is an internal PostgreSQL bigint, read and hashed without numeric rounding; it is never a public revision number. Every tenant table has forced RLS and tenant-scoped unique/FK identities, including source/target assets, owner/allowed memberships, type versions and revision parents. Runtime roles cannot own/bypass tables; no runtime history UPDATE/DELETE/TRUNCATE. Database constraints enforce paired identities, interval ordering, exact version references, canonical undirected endpoints, live uniqueness and immutable parent-derived reference membership. Deferred checks cannot be satisfied by a fabricated nested trigger. Direct SQL invariant and concurrency probes are required; service-only happy paths do not qualify the storage boundary.

Application locks follow the established order: idempotency → tenant ledger → model scope → relevant type heads → all affected assets ascending UUID → relations ascending UUID → identities ascending UUID → memberships ascending UUID. Acquire actor/owner activity locks where necessary using the reviewed narrowly scoped principal-lock mechanism, followed by fresh authorization. Apply bounded lock/statement budgets before the first wait. Direct storage guards must not introduce a conflicting lock order. Root and storage worker agree the actual SQL serialization mechanism before implementation; cardinality/cycle checks cannot rely on an unprotected count-before-insert.

Relation create/edit/transition/tombstone commits canonical state, its immutable revision, normalized references, audit, outbox, graph revision and idempotency success atomically. No connector or external service execution occurs in a request handler. Late failures roll back every affected write; separate failed-attempt audit stores sanitized codes only.

Mutation/publication validation closures are bounded to 1,000 live edges, 2,000 distinct asset records, 512 KiB of canonical projected validation data and at most 100 returned issues; all bounds apply before writes. A complete proposed asset set also retains the existing asset-migration cohort bounds. Exceeding any bound yields `RELATION_PROFILE_LIMIT` with no partial success. Hidden-scope refusal precedes exposing counts or limit details.

Type preview loads the complete bounded directly bound live-edge cohort, verifies both endpoints and all pinned policies, and refuses inaccessible scope before returning counts. Bind its digest to tenant/type identity, head, definition, relation revisions, endpoint revisions/pins/states, visibility and relevant current owner activity. Compatible publication preserves edge pins. Labels and optional attribute additions can be compatible after full validation; endpoint/direction/cardinality/cycle/ownership/lifecycle changes or destructive attribute changes with live edges require explicit relation migration and are blocked in this increment. Do not implement migration as an unreviewed repin. With no live edges, the next validated definition may change these policies; tombstoned historical edges remain immutable and cannot be resurrected under obsolete rules.

Degree/cycle validation uses the complete bounded logical-type cohort, not only currently visible or currently effective edges. If the actor cannot access the necessary scope, fail generically before showing constraints dependent on hidden edges. This restriction is an explicit development-profile limitation, not implicit authority to inspect private relations.

## Existing asset mutation hooks and source preservation

Add a shared application guard accepting a **complete proposed endpoint set**, for example `validateRelationsForEndpointChanges(tx, principal, proposedEndpoints)`, where each proposal includes asset UUID, expected current revision, proposed model ID/version, proposed pinned lifecycle state and resolved authored policy. All proposals are immutable validated data, not callbacks or executable rules.

Single assignment and ordinary asset lifecycle transitions pass a singleton set. Complete authored-type migration passes the entire proposed cohort **before writes**, so validation resolves both ends from the same proposed set when both change. An unchanged opposite endpoint comes from current canonical storage under the transaction's locks. Never validate bulk migration by sequentially mixing one new endpoint with another endpoint's old state. Reuse the same guard for any future ingress changing bindings/state. Expand and lock the entire affected endpoint union in deterministic order before relation locks; do not append lower UUID asset locks after a singleton was already locked. Respect complete-scope bounds and refuse hidden required validation.

If a proposed endpoint breaks an incident pinned relation rule, return `RELATION_MIGRATION_REQUIRED` and leave every asset/type/relation/journal unchanged. There is no automatic edge delete, endpoint substitution, state repair or relation repin. Endpoint source status such as `unavailable` is evidence of scan availability, not a governed lifecycle transition and not proof that a steward's relation ceased to exist.

Mandatory source behavior: ordinary complete scans, source rename, zero-result scans, failed/partial scans and permission reduction must preserve asserted relations and their revisions. Never reinterpret `parent_external_id` as an asserted relation or emit imported provenance for it without an implemented importer. A source adapter cannot rewrite curated relation ownership, attributes or validity. Future confirmed purge/deletion must use an explicit retention-aware relation policy; no CASCADE deleting governed edges/history.

Mandatory audit behavior: `visibleAudit` currently allows non-`asset.*` events as tenant-visible. Add relation-aware filtering before emitting any `relation.*` event or exposing its before/after metadata. Relation history and audit require current edge and both-endpoint access, including original endpoints for tombstoned records. Type-level events contain definition hashes/version references only; keep edge IDs, endpoint names, counts, plan literals and values in separately authorized relation history. Source preservation and audit privacy are acceptance gates, not follow-up polish.

## Authorized graph and pagination

Definition inventory uses literal bounded search `q` of at most 64 characters, limit 1–100 (default 25), and deterministic logical-key ascending order. Relation lists/revisions and graph pages use limit 1–100 (default 25) and edge UUID ascending/revision ascending respectively. Query integer spellings are canonical base-10 positive integers; reject duplicate query keys, unknown keys and out-of-range values rather than clamping. Canonical cursor filters include explicit defaults and distinguish an absent list `validAt` from a graph's resolved instant. Graph direction is `in|out|both`, default both; depth is 1–6, default 1. `relationTypeId` is one optional UUID filter. Unknown filters/sorts are rejected. All pagination uses the existing signed, purpose-separated, at-most 1,024-byte cursor. Bind tenant, actor, resource root, filter, resolved validity instant, page size, sort and last key; no cursor is an authorization grant.

```ts
interface RelationGraphPage {
  rootAssetId: string;
  direction: 'in' | 'out' | 'both'; depth: number; validAt: string;
  graphRevision: string;           // Opaque 43-character base64url HMAC-SHA256 fence.
  nodes: readonly RelationEndpointView[];
  edges: readonly RelationView[];
  nextCursor: string | null;
}
```

Traverse only authorized nodes and edges at **every** expansion step. Hidden intermediary nodes cannot bridge visible nodes; do not expose hidden-node placeholders, blocked-path markers, degree counts, tooltips or layout gaps. Validity and type filters apply before expansion. Depth is shortest reachable hop distance; returned edges are those considered from an authorized frontier at distance below depth, in the requested direction. Deduplicate canonical edge IDs and use visited-node state, not exponential enumeration of paths. Cycles cannot cause repeated expansion.

Materialize no more than 1,000 authorized nodes/5,000 authorized edges/512 KiB projected graph data per traversal, within a fixed transaction timeout. Apply authorization before limits/counts; unrelated hidden scope must not change page metadata. A response contains at most 100 edges and only the authorized root plus their distinct endpoints, sorted by UUID. Pagination orders the deterministic selected edge set by UUID; node repetition between pages is permitted and callers merge by ID/version. No unfiltered total is returned. `nextCursor` reflects only remaining authorized selected edges. Exceeded traversal bounds fail with `RELATION_PROFILE_LIMIT`, never a falsely complete or silently truncated graph; clients can reduce depth/filter or expand another visible node.

The public `graphRevision` is a fixed-length, unpadded base64url HMAC-SHA256 token under a server-held key with a distinct graph-fence domain separator. Hash a canonical tuple of format version, query purpose (`asset-relations` or `asset-graph`), authenticated tenant and actor, root asset UUID, normalized query/filter context and the exact internal counter. The normalized context includes direction, applicable depth, relation-type filter, resolved/absent validity instant, page size and sort, but excludes the changing page-position key. Signed cursor payloads store this opaque token only. Never expose the raw counter or its deltas in responses, decoded cursor payloads, errors or public audit metadata; signing a base64 payload does not hide its contents. Token values are not counts, sortable revisions or authorization grants.

The first implementation may recompute the bounded authorized traversal per page under the tenant ledger, rather than serialize a frontier into a large token or create an external graph store. After acquiring the required locks and fresh authorization, read a coherent canonical snapshot, recompute the context-bound HMAC from the current internal counter and compare it to the cursor's opaque fence in constant time before returning data. No multi-request promise of an unchanged graph without that fence. Current node metadata comes from the authoritative assets; no stale search projection may authorize graph access.

The internal graph counter increments transactionally on edge creation, editable-field/state/visibility/validity changes and tombstones; also on endpoint binding, lifecycle state, visibility and allowed-identity changes. Because `RelationEndpointView` includes name and assetVersion, **any asset revision change** (including ownership/description/source refresh) increments that tenant counter for this conservative profile. Relation-type head/definition publication increments it too. Use a database-backed mechanism covering direct authorized storage mutations, not only one HTTP route; batch increments may coalesce, but no relevant change can leave the fence unchanged. A changed opaque fence returns 409 `RELATION_GRAPH_STALE` without identifying an object or revealing a mutation count. Conservative invalidation can follow unrelated canonical changes; it means only that the prior pagination snapshot must be restarted, and must not be presented as an edge count or evidence that a particular hidden object exists or changed. The same opaque-fence mechanism binds paginated asset-relation lists whose views include endpoint metadata. Immutable revision-list pages still reauthorize current access on every call.

Identity, role and membership revocations may not bump the graph revision. Independently reauthorize the actor and every returned edge/endpoint on every request, including cursor pages and cached mutation replays. A matching revision/cursor never revives revoked access. Do not claim graph revision alone is a permission epoch.

## Pure contracts, UI and ownership

The pure module uses the existing `ValidationResult<T>`/`ValidationIssue` shape. Proposed exports: `parseRelationTypeDefinition(unknown)`, `parseRelationTypeFile(string)`, `validateRelationTypeUpgrade(current, proposed, providedRelations)`, `validateRelationCandidate(definition, sourcePolicy, targetPolicy, input, completeTypedAdjacency)`, and a bounded deterministic traversal helper over already authorized input. All limits and collection completeness must be explicit in input contracts; pure helpers do not authorize, query databases, accept tenant headers as proof or claim complete tenancy from caller-supplied arrays. Root freezes the precise TypeScript signatures and shared HTTP view module before workers edit.

Web routes are `/relation-types`, `/relation-types/new/definition`, `/relation-types/:id`, `/relation-types/:id/edit`, `/relations/:id`, and asset `?tab=relations`. The creation route keeps logical key `new` usable as an ordinary detail key. Provide visual definition editing, duplicate-safe file import/export, complete preview/confirmation, immutable type and relation histories, owner/state/validity editing, stale recovery, tenant/permission states, an accessible relation table and bounded graph expansion. Show asserted provenance and exact pins; do not label this technical lineage. Preserve existing English/Arabic RTL, keyboard, light/dark and responsive behavior. No disabled button may stand in for a required implemented capability.

- Root owns final shared SQL/API/domain contracts, application services, endpoint-mutation/audit/source integration, integration review, records, CI and Git. Root reviews and integrates every shared change.
- Pure worker owns new relation validation/traversal modules and their unit tests only, against agreed signatures.
- Web worker owns relation authoring/detail/graph UI, route inventory and browser acceptance tests; coordinate shared Asset page hooks with root.
- Storage worker owns SQL008 drafting and isolated SQL/concurrency tests under explicit root delegation and review; do not apply to core independently or edit prior migrations.
- Workers are not alone in the checkout. Preserve others' edits, agree interfaces first, and keep current application-source freeze until root opens the increment.

## Acceptance gates and evidence boundaries

1. Strict visual/file/REST definition and relation attributes round-trip, including exact decimals; duplicate keys, missing required values, invalid calendars, unknown fields and unsupported positive minima fail clearly.
2. Nominal endpoint and actual pinned-descendant matching work; foreign tenant/type/member references, wrong types, removed ancestry, invalid pinned/allowed endpoint states, illegal relation transitions and inactive required owners fail.
3. Database uniqueness rejects duplicate and reversed-undirected live edges across type versions. Two concurrent writes at max 1 leave exactly one committed edge. Different relation types remain independent.
4. Allowed cycles execute successfully. Acyclic/self violations and concurrent opposing edges fail without partial writes. Undirected cycle checks enforce a forest. All graph budgets terminate deterministically.
5. Single assignment and a mixed-pin bulk type migration validate complete proposed endpoint sets. Rejected changes preserve all head/definition/asset/edge pins, values, revisions, audit, outbox and idempotency results. Compatible publication preserves old edge pins.
6. Real late-failure injection after relation/revision/normalized-reference writes proves rollback. Identical retry creates one result; changed idempotency input conflicts. Replays recheck original edge/endpoints after access revocation.
7. Deliberately unique hidden node/edge names and hidden bridges never enter graph nodes, edges, counts, cursors, tooltips, layouts, revision history or audit. Test both same-tenant restrictions and identical-name foreign tenants, restricted edges between visible endpoints, and revocation between pages.
8. Signed cursor tampering, actor/tenant/filter/depth/validity/page-size mismatch and relevant canonical changes fail. Verify endpoint name/version/owner changes invalidate pages and membership revocation denies independently of revision changes. Decode public cursors and inspect responses/errors/audit to prove the internal counter/deltas are absent; opaque fences have fixed length and differ across actor/root/query-purpose contexts. Unrelated canonical changes may produce only the same generic stale response, without object identifiers or mutation counts.
9. Actual source rename/rescan, failed/partial/zero scans and permission reduction preserve asserted edges and curator values. Source status changes do not silently erase relationships.
10. Isolated actual PostgreSQL 007→008 upgrade preserves old models/assets/receipts, replays checksums safely, enforces runtime/RLS/privilege/FK/immutability boundaries and handles invalid writes/concurrency. Test real API and browser create→inspect→edit/transition→history→graph→tenant denial, accessible table fallback, keyboard, scoped axe, Arabic, both themes and 390/768/1024/1440 widths. Inspect actual rendered screenshots.

Evidence records must identify exact revision/images/tool versions, commands, executed cases, failures and limits. Authored tests, fixtures, screenshots from another revision and static review are not executed qualification. Full AT-MOD-01 also requires all ingresses and broader model behavior; do not mark it complete from these gates.

## Required adjacent work remains open

Positive minimum cardinality and required participation bindings; complete explicit relation migration/repair/restore; relation-type inheritance and scoped overrides; domain/attribute/responsibility types and full ownership rules; imported/derived relation claims, bounded rules, provenance precedence and conflict resolution; valid-time cardinality and transaction-time/as-of graph comparison; relation-based authorization grants and field sensitivity; full bulk/import/workflow/form/MCP invariants; semantic models; OpenLineage/native/custom lineage, evidence/SQL transformations, impact analysis and exports; scalable graph execution beyond this profile; glossary approval and effective-dated reference flows; and all remaining M3–M10 requirements. These are mandatory programme work, not optional features or capabilities satisfied by asserted graph screens.
