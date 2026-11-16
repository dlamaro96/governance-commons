# Business domains, type pins and asset placement — implementation contract

Current status, 2026-11-16: **IMPLEMENTED SCOPED DOMAIN INCREMENT; LOCAL SQL, SEED AND API VERIFIED.** The actual154-case API and targeted three-journey browser gates pass on their recorded source; full19-browser qualification also passes on its separately recorded source. See `STATE.md` and the exact reports under `docs/verification/business-domains-*.json`. Scoped authority, full model/acceptance stories, hosted qualification and release remain open.

Original adoption checkpoint (2026-11-15): **CONTRACT ADOPTED; implementation and execution had not begun.** The lead reviewed and adopted the six engineering decisions below in ADR0009. This is the next bounded increment after required relation participation and migration. The interfaces define implementation obligations, not evidence of working endpoints, migrations or capabilities. Contract adoption changes no requirement, milestone, verification or release status. File ownership must be assigned before parallel source changes.

Read `STATE.md`, `PLAN.md`, `../product/BUILD_SPEC.md` and the canonical `../product/requirements.yaml`. Preserve every applied migration and historical definition, snapshot, receipt and evidence record. SQL001–011 are now applied and immutable. SQL011 passed its isolated storage/concurrency gate before core application; the exact checksum and execution evidence are recorded separately. Any database correction requires a new forward migration; no earlier SQL file may change. Never edit a previously applied SQL file to implement this contract.

## Governing requirements and bounded outcome

The full governing text remains authoritative. The following mapping describes contributions, not whole-row completion:

| Requirement | Contribution of this increment | Required work that remains |
| --- | --- | --- |
| CORE-001 | Immutable tenant-scoped business-domain identity; create/rename preserves asset identity and audit continuity. | Other canonical organizational and identity entities remain required. A business domain never becomes a security tenant. |
| CORE-002/006/007/009 | Tenant-safe references, current authorization, immutable domain/placement history, atomic audit/outbox, optimistic versions and safe retries; transaction time remains distinct from source observation. | Full cross-interface, cross-store, temporal and evidence qualification remains open. |
| MOD-001/002/003 | Versioned domain types, exact inheritance pins, typed fields, required owner, lifecycle, visual/declarative editing, complete bounded preview and explicit migration. | Reusable attribute-definition identities, scoped overrides, typed search/sort/catalog export and all required bulk/workflow/MCP ingress remain required. |
| CAT-004 | A source scan preserves curator-managed domain placement. | Full field-claim provenance, configurable merge policy and conflict reconciliation remain required. |
| SYS-DATA-001.01–.05; SYS-DATA-002 | Canonical domains, type definitions, hierarchy and bounded traversal; separate immutable domain/placement revisions; explicit compatibility and recovery. | Full organizational model, attribute constraints/index management and other governed model kinds remain required. |
| SYS-DATA-004; SYS-API-001.01–.03 | Canonical writes, journals and event versions; strict versioned APIs, idempotency, bounded pagination and schemas. | Full projection operations, generated clients and all module APIs remain required. |
| SYS-SEC-002.01–.03; SYS-SEC-003 | PostgreSQL is the scope source of truth; current tenant/action checks; an explicit versioned scope descriptor for later authority; forced tenant RLS and no hidden counts. | Scoped grants, responsibility authority, typed policy AST, explicit denies/inheritance and PostgreSQL/OpenSearch/reference-evaluator equivalence are the next security increment. Placement alone implements none of those grants. |
| SPEC-076/077/083/085/086/109/111/115/116 | A foundation for domain-scoped owner/steward work, domain context and identity/scope/model APIs with stable IDs and immutable history. | Multiple editable roles and enforceable domain responsibilities remain required before an owner-approval claim. |
| UX-10/36/38/39; E2E-06; AT-MOD-01 | Working domain-type editor, domain administration, history and bounded migration workbench with real API/browser evidence. | These broad screens/stories remain incomplete, including all-ingress validation and full import/export. |
| SPEC-151; CAT-006; UX-09; E2E-05 | Supplies the scope foundation for M2 glossary/stewardship. | Multilingual terms, approval, linked discovery and responsibility enforcement remain required. |
| REF-001–006; UX-21; E2E-13; AT-REF-01 | Supplies a domain foundation for governed reference publication. | Actual effective-dated values, crosswalks, approvals, scheduled activation, imports/exports/webhooks and real DQ integration remain required. |

The bounded user outcome is: an administrator defines a domain type, creates a business domain, assigns an existing scanned asset, renames and moves the domain without replacing the asset, inspects the real history, and previews/executes a compatible or explicit domain-type upgrade. Invalid pins, attributes, lifecycle changes, cycles, stale edits and unauthorized/foreign resources fail through the same application services.

Implementation of this outcome does not close M2, MOD-001/002, SYS-SEC-002, E2E-05/06, AT-MOD-01 or release qualification. Optional activation of a later module never makes its required implementation optional. The canonical register's dependency rows are engineering ordering, not an alternative to the complete source clauses.

## Identity, placement and historical compatibility decisions

1. A domain is a first-class resource in the authenticated tenant, with an opaque immutable UUID. Its name is display data, not an identifier. Domain names need not be unique; disambiguation uses the authorized breadcrumb and UUID. A domain has one nullable parent and one exact domain-type pin. Domain hierarchy and type inheritance are separate graphs.
2. Domain-type heads have immutable UUIDs and immutable tenant-unique safe keys. Their versions and authored definitions are append-only. Domain types never occupy `governance_models`, `asset_type_versions` or relation-type tables. Kind checking prevents a same-UUID or same-key asset/relation type from becoming a domain parent. Reuse pure typed-value logic, not asset persistence adapters.
3. A domain has `status: active|retired` for administrative availability and a separate `state` from its exact pinned business lifecycle. Ordinary lifecycle changes follow the pinned transition graph. A root may have no parent; a new/moved/restored active domain requires an active parent. Moving a domain moves its subtree logically without changing descendant parent IDs or asset IDs. Cycles and depth overflow are rejected over the complete resulting hierarchy.
4. An asset has zero or one current primary business domain in this increment. Additional collections or multi-domain assignments are a separate design, not an inferred capability. Placement has its own optimistic version and immutable revision stream. Placement is curated metadata; scanner observations, missing-source handling, asset-type migration and relation repair preserve it.
5. **Placement is an additive subresource.** Do not add fields to the existing `assetView` snapshot or change the existing `GraphAssetTuple`/typed-migration tuple. SQL007 checks typed tuples against real immutable asset revisions; SQL009's graph revision guard additionally checks the exact full production `assetView` shape. A UI convenience field must not invalidate those historical/protected formats. New placement reads use their own DTO/endpoint. Existing asset version and source identity do not change merely because placement changes.
6. Consequently, an asset's future authorization state is the composite of its existing asset version, placement version, current domain ancestry and scope fence. An asset version alone cannot fence a placement or ancestor move. No new authorization, approval, cache, export or mutation path may silently treat it as sufficient. Activation of scoped authority requires integrating this composite into every affected current and historical read, preview, execution and replay path.
7. Existing assets receive no invented placement history. Before first assignment the canonical absence of a placement row is exposed as `version:0`, `domainId:null`, and null recording metadata. Version zero is explicitly an unrecorded initial state, never a fabricated revision. First assignment creates version1. Unassignment later creates the next real revision with `domainId:null`; rows and history are never deleted. Unassigning the absent/already-unassigned state is a no-change error.
8. Every recorded placement revision references the actual existing asset revision observed during that mutation, and the actual target domain revision when assigned. Rename/move does not rewrite that reference. Current reads resolve the current domain; historical reads present the recorded reference as such. A missing required actual asset/domain revision is a storage-integrity error, never permission to synthesize history.
9. Retiring a domain requires no current placements and no active child domains. Historical placements/revisions and retired children remain. Retirement does not cascade, move assets or erase history. Restoration requires a valid current type pin, legal state/attributes/owner and active parent. Retired domains allow explicit type migration and restoration; other ordinary edits require restoration first.
10. Documentation ownership does not grant access. `ownerId` is an active tenant member when newly selected; required ownership is enforced by the pinned type. No role-name checks or implicit owner/ancestor grants are introduced. The following authority increment must provide explicit configurable mappings under SYS-SEC-002.

## Strict shared DTOs and definition format

Proposed pure contracts belong in a new `packages/domain/src/business-domain-contracts.ts`; parsing/resolution belongs in separate pure modules. `AttributeDefinition`, `AttributeValues`, `LifecycleDefinition`, `MigrationPlan`, `ModelChange` and `ValidationIssue` refer to the existing shared pure grammar. Their existing formats and hashes are unchanged. `UUID`, `Version`, `SafeKey`, `UTC` and `Digest` below denote validated strings/numbers, not unchecked TypeScript aliases.

UUIDs use canonical lowercase notation. Versions are positive database integers through 2,147,483,647, except the explicit placement version-zero state. Safe keys use the existing 64-character identifier grammar and reserved-key rejection. Names/labels are 1–200 well-formed Unicode characters; reasons 1–500; descriptions 0–4,000. Reject forbidden control characters, unknown/repeated fields, duplicate raw/escaped JSON keys, malformed Unicode, non-data properties/prototypes, nonfinite numbers and coercion. Preserve precise decimal strings and the existing typed date/duration/URI behavior. All DTO fields shown are required; nullable values are explicit.

```ts
interface DomainTypePin { typeId: UUID; version: Version }
interface DomainTypeDefinition {
  formatVersion: 1; kind: 'domain-type'; id: SafeKey; version: Version;
  label: string; parents: DomainTypePin[];
  attributes: Record<string, AttributeDefinition>;
  overrideAttributes: SafeKey[]; requiredOwner: boolean;
  lifecycle: LifecycleDefinition | null;
}
interface ResolvedDomainType {
  attributes: Record<string, AttributeDefinition>;
  requiredOwner: boolean; lifecycle: LifecycleDefinition;
  dependencies: DomainTypePin[];
}
interface DomainTypeView {
  typeId: UUID; key: SafeKey; version: Version; currentVersion: Version;
  definition: DomainTypeDefinition; resolved: ResolvedDomainType;
  definitionHash: Digest; resolutionHash: Digest;
  createdAt: UTC; createdBy: UUID;
}
interface DomainTuple {
  name: string; description: string; parentId: UUID | null;
  type: DomainTypePin; attributes: AttributeValues;
  ownerId: UUID | null; state: SafeKey; status: 'active' | 'retired';
}
interface DomainView extends DomainTuple {
  id: UUID; version: Version;
  createdAt: UTC; createdBy: UUID; updatedAt: UTC; updatedBy: UUID;
}
interface DomainRevision {
  formatVersion: 1; domain: DomainView;
  action: 'created' | 'updated' | 'moved' | 'state-changed'
    | 'retired' | 'restored' | 'type-migrated';
  reason: string; correlationId: string;
}
interface DomainPlacementView {
  assetId: UUID; version: number; domainId: UUID | null;
  recordedAssetVersion: Version | null;
  recordedDomainVersion: Version | null;
  recordedAt: UTC | null; recordedBy: UUID | null;
}
interface DomainPlacementRevision {
  formatVersion: 1; placement: DomainPlacementView;
  reason: string; correlationId: string;
}
interface DomainScopeDescriptor {
  formatVersion: 1; kind: 'asset-domain-scope'; tenantId: UUID;
  assetId: UUID; assetVersion: Version; placementVersion: number;
  domainId: UUID | null;
  ancestry: { domainId: UUID; domainVersion: Version }[];
  scopeFence: string;
}
interface Page<T> { items: T[]; nextCursor: string | null }
```

`DomainScopeDescriptor` is an internal authorization input, not a bearer credential or a new public tenant selector. Its ancestry is ordered root-to-current-domain, includes the domain itself and is empty when unassigned. Current canonical reads construct it. `scopeFence` is an opaque keyed token, never a raw hierarchy counter. Do not serialize the descriptor wholesale into public errors, audit, search documents or Temporal payloads.

Domain inheritance adopts the established bounded exact-pin semantics: at most 8 immediate parents, 64 distinct transitive pins and 8 ancestry levels; reject duplicate logical parents, cycles, conflicting versions of an ancestor and ambiguous inherited values. Equal inherited attributes coalesce; `overrideAttributes` exactly names local replacements. Required owner is inherited with OR. An explicit lifecycle replaces inheritance; null requires one unambiguous inherited lifecycle and is invalid at a root. Resolve/revalidate against all existing attribute limits. Type ancestry has no effect on the domain's organizational parent or permissions.

Domain-type files contain exactly `DomainTypeDefinition`; export then validate/import must preserve canonical authored meaning and hashes. Parent UUID pins remain explicit. A definition file is not a complete cross-installation portability package; CORE-010/AT-PORT-01/E2E-27 still require identity mapping and full packages. Create allocates the opaque type UUID server-side and requires definition version 1. Publication requires the same immutable key and exactly current head+1. Existing domain and child-type pins never float to the new head.

## Canonical schema and storage obligations

The adopted [SQL011 storage/service contract](BUSINESS_DOMAIN_STORAGE.md) fixes exact migration and ordinary-write preparation/seal envelopes, private claims, journal/deferred success proof and the original PostgreSQL `transaction_timestamp()` deadline. Ordinary preparation establishes the complete authorized lock union before canonical DML; idempotency/ledger waits cannot restart the deadline. These are implementation refinements, not executed storage evidence. SQL011 source work follows the current required-participation targeted/full browser gates; all qualification and broader programme limitations below remain open.

Proposed tables, all with explicit `tenant_id`, forced RLS and composite references:

| Table | Identity/current data | Immutable evidence and constraints |
| --- | --- | --- |
| `domain_types` | `(tenant_id,id)` UUID; unique `(tenant_id,key)`; current version; creator/time. | UUID/key/creator immutable; head references an actual exact version. |
| `domain_type_versions` | `(tenant_id,type_id,version)`; authored/resolved JSON and hashes; creator/time. | Append-only; recomputed exact dependency closure and resolved policy; no generic asset-model foreign keys. |
| `domain_type_dependencies` | Exact child and parent domain-type version references. | Append-only normalized closure; exact membership in its parent definition/resolution, not arbitrary extra pins. |
| `domains` | `(tenant_id,id)`; DomainTuple columns/validated JSONB; version and attribution. | Tenant-safe parent/type/owner FKs; legal exact policy; immutable identity/creation metadata. Parent hierarchy checked under the shared fence. |
| `domain_revisions` | `(tenant_id,domain_id,version)`; DomainRevision. | Append-only exact actual canonical snapshot; created/updated actions and legal sequence; same-transaction audit/outbox completeness. |
| `asset_domain_placements` | `(tenant_id,asset_id)`; current domain nullable, own positive version and recording references. | One current row per asset; exact asset/domain revision FKs; immutable asset identity; no row deletion or version reset. |
| `asset_domain_placement_revisions` | `(tenant_id,asset_id,version)`; DomainPlacementRevision. | Append-only, exact canonical placement/recorded references; consecutive versions and matching journals. |
| `domain_scope_state` | One private tenant row with a monotonically advancing scope epoch. | Runtime cannot set or decrement it; canonical type/domain/placement mutations advance it. Public output uses a keyed fence. |
| `domain_type_migrations` | Immutable operation UUID, actor/time, exact plan/target/digest, complete receipt. | Runtime cannot invent a successful receipt; exact before/after definitions, revisions and journal effects must exist. |
| `domain_type_migration_domains` | `(tenant_id,migration_id,domain_id)` with before/after revision references and tuple hashes. | Normalized children equal the parent's complete cohort and actual immutable snapshots. |

Every domain definition, parent/child reference, placement, revision, receipt, audit/outbox record and private operation derives tenant authority from authenticated membership. All SQL lookup predicates remain explicitly tenant-scoped even where RLS is present, including membership queries that can expose the actor's other memberships.

The new migration adds tables/functions/guards only; it preserves old asset snapshots and old model/graph receipt formats. Applied SQL checksums must remain identical. Domain/placement audit action prefixes and resource kinds need explicit handling in both global audit and resource history. They must not fall into the existing audit query's generic non-asset allowance. A placement event uses the asset UUID as its subject, includes only minimal version references and has `resourceKind:'asset-domain-placement'`; a same-UUID domain is a different resource kind. Current asset/domain read permission gates its disclosure.

Ordinary row guards validate types, pins, ownership, lifecycle, hierarchy and versions; deferred completeness verifies actual snapshots and journals. Exceptional domain-type migration cannot be authorized by a caller-controlled GUC, trigger depth, tuple hash or a forged receipt. Use transaction/actor-bound private operation claims, checked against the actual complete source cohort before exceptional writes, followed by seal/final completeness checks. Runtime may not directly modify private claims/epochs or immutable children. Security-definer functions, if necessary, require fixed safe search paths, non-bypass owners, revoked PUBLIC execution and narrow runtime grants. Do not grant UPDATE on identities/memberships to acquire locks.

### Frozen journal and event contract

Service producers and deferred SQL completeness guards use these exact literals. `resourceId` and CloudEvents `subject` are the stated opaque UUID, never a display name or logical type key. The audit `version`, changes `resourceVersion` and outbox `resource_version`/`resourceVersion` equal the stated committed version. Each required action has exactly one matching audit/outbox pair, sharing event UUID, tenant, actor, correlation ID and time. A no-op creates none.

| Action / outbox event type | `resourceKind` | Subject and version | Version-one event data |
| --- | --- | --- | --- |
| `domain_type.created`, `domain_type.published` | `domain-type` | Domain-type UUID; new definition version | `typeId`, `previousVersion` (null on create), `version`, `definitionHash`, `resolutionHash`, `migrationId` (null outside migration) |
| `domain.created`, `domain.updated`, `domain.moved`, `domain.state_changed`, `domain.retired`, `domain.restored`, `domain.type_migrated` | `domain` | Domain UUID; new domain revision version | `domainId`, `previousVersion` (null on create), `version`, `revisionHash`, `migrationId` (null outside migration) |
| `asset_domain_placement.assigned`, `asset_domain_placement.reassigned`, `asset_domain_placement.unassigned` | `asset-domain-placement` | Asset UUID; new placement revision version | `assetId`, `previousVersion` (zero for first assignment), `version`, `recordedAssetVersion`, `recordedDomainVersion` (nullable), `domainId` (nullable), `revisionHash` |
| `domain_type_migration.executed` | `domain-type-migration` | Migration receipt UUID; version1 | `migrationId`, `typeId`, `fromHeadVersion`, `targetVersion`, `planHash`, `previewDigest`, `receiptHash` |

Each data object has exactly its listed fields plus `schemaVersion:1` and `resourceKind`. Its hashes cover the exact canonical definition/resolution/revision/receipt, using the shared canonical hashing grammar. Audit changes contain that data plus `reason`; the shared journal adds `resourceVersion` consistently with the hashed envelope. Outbox uses the existing CloudEvents1.0 base fields plus the matching `resourceKind` extension and `data` object. Outbox data excludes reason, names, descriptions, attributes, permission contents and raw scope epochs. Add an explicitly typed event-data argument to the shared atomic journal producer; do not patch a previously recorded envelope or change legacy event bytes.

`assigned` means absent/unassigned to a domain; `reassigned` means a different non-null domain; `unassigned` means a non-null domain to null. Migration produces one `domain.type_migrated` pair per actual changed domain, one `domain_type.published` pair for its new head and one `domain_type_migration.executed` pair. Even an empty migration records the head and receipt, with no invented domain event. Its receipt version is1; its target type version is a separate field.

The new action families must be excluded from generic audit visibility and reintroduced only through resource-kind-aware current authorization and original-scope checks. Domain-type migration audit uses the same complete recorded-scope authorization as receipt reads. Placement audit requires current access to its asset and referenced domain history. Event consumers must authorize any subsequent resource fetch and deduplicate by event UUID; event delivery itself grants no resource access.

## Service authorization, lock order and atomicity

Proposed actions are `domains:read`, `domains:write`, `domains:assign`, `models:read`, `models:write`, `catalog:read`, `catalog:write` and existing `audit:read`. They are permission identifiers, never role-name conditions. Register and seed explicit permission sets; do not infer a new permission from an existing role label or silently grant it to every member.

- Domain-type reads require `models:read`; authoring/publication requires `models:read/write`. A complete type preview/migration additionally requires `domains:read`, and execution requires `domains:write`.
- Domain reads require `domains:read`; mutations require `domains:read/write`.
- Placement reads require `catalog:read` plus `domains:read` and current visibility of the asset. Assign/move/unassign additionally requires `catalog:write` and `domains:assign`. A target domain must be current, visible and active. Owner selection never grants these actions.
- Domain asset lists require `domains:read` and `catalog:read`; filter with current canonical asset authorization before returning rows, counts or names. No totals are returned in this slice.
- Domain/placement historical reads require the same current resource access as their current read. A full migration receipt requires current access to every original recorded domain, not merely whatever remains bound to the type now. Idempotent replay performs the same checks before returning stored output.
- Domain moves/retirement inspect the complete affected subtree and current placement cohort. Require visibility of all affected assets before returning an impact count or executing; inaccessible scope is a generic403. Ordinary rename/description edits do not enumerate unrelated assets. Type publication/migration is scoped to directly bound domain instances; it does not expose or rewrite their asset collections.

The initial read policy for domain objects is tenant membership plus these explicit actions. Domain placement has no access-grant effect in this increment. All service entry points re-read active identity/membership and relevant permissions, including non-HTTP callers and replay. Future policy introduction must replace this bounded decision consistently, not bolt a UI-only domain filter onto it.

Use one transaction deadline, initially 30 seconds with lock timeout bounded by 5 seconds and the remaining deadline. Configure the PostgreSQL statement timer in a separate command before executing the protected statement, as current `relationQuery` does; changing its GUC inside an already-running function is not proof that its current outer statement timer is armed. This follows PostgreSQL17's command-start timer activation and the absence of a statement-timeout assignment hook ([command/timer source](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/tcop/postgres.c), [GUC source](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/utils/misc/guc_tables.c)). Apply the budget before the first advisory/row lock; nested calls never restart it. Explicit clock checks also bound discovery/validation iterations and late finalization. The exact values are proposed development limits, not measured throughput guarantees. Wrap every database wait and check the remaining application budget while processing. Deadline/deadlock/serialization/lock failures roll back and return `DOMAIN_RETRY` with `Retry-After:5`.

Global order for all new writers and complete-cohort previews:

1. Mutation idempotency advisory lock when applicable, then existing tenant ledger.
2. Existing tenant model-scope advisory lock when any type definition/pin is involved; new tenant domain-scope advisory lock and the private scope-state row. Ordinary domain/placement writers also take the domain-scope lock. No writer first obtains the tenant ledger after canonical row locks.
3. Relevant domain-type heads in UUID order; complete canonical domain union in UUID order. Discover all parents, ancestors, moving descendants and directly bound migration domains under the ledger before locking this union.
4. Complete asset union in UUID order, then existing placement rows in asset UUID order. Never acquire an additional lower-order domain/asset after entering the next phase. Absence of a placement row is serialized by its asset lock and the tenant/domain fence.
5. One complete principal union: globally sorted identity UUIDs, then tenant memberships in the same order, using the reviewed narrow locking capability. Include actor and all old/new domain owners. Re-read active status, permission sets, expected versions and the entire relevant closure after waits.

New operations do not nest model/graph asset mutation services; no relation/binding rows are changed. Existing model/graph operations continue their established order. Future operations combining these modules must acquire a single canonical-kind/head/domain/asset/relation/binding/principal union agreed by root, before any canonical writes. Audited identity/membership revocation must continue acquiring applicable tenant ledgers before identity/member rows; global identity changes require deterministic multi-tenant ordering.

All canonical domain/placement/type changes, their immutable revisions, domain-scope epoch, audit, outbox, normalized migration receipt and idempotency success commit together. Recheck deferred constraints before returning. A late failure rolls back everything. Each placement mutation records the actual locked asset revision and target domain revision without writing an artificial asset revision. No asset mutation, source effect or notification delivery is represented as part of that placement write.

Idempotency binds tenant, actor, operation and canonical request digest including expected versions/reason/preview. Reuse with different content conflicts. Successful same-request replay returns the existing result after current authorization and recorded-scope checks; replay does not fail merely because its original optimistic version is now old. Do not persist a success response until its complete canonical evidence is sealed. Preview is not a mutation and does not create an execution/approval record.

## Publication, migration and hierarchy preview

Compatible publication enumerates every directly pinned domain instance, including retired instances and mixed historical versions, while preserving their existing pins. Descendant type definitions and their domains remain unchanged. Any destructive attribute/policy change, or a target that cannot validate the complete directly bound cohort, requires the explicit migration route. An empty cohort still produces a real publication and version evidence; no fictional domain revisions are created.

```ts
type DomainPolicyChange = 'parents_changed' | 'required_owner_changed' | 'lifecycle_changed';
interface DomainTypeMigrationPlan {
  formatVersion: 1; kind: 'domain-type-migration'; typeId: UUID;
  attributes: MigrationPlan;
  owner: { default: 'preserve'; overrides: { domainId: UUID; ownerId: UUID | null }[] };
  lifecycle: {
    onUnmapped: 'preserve' | 'error';
    mappings: { sourceVersion: Version; from: SafeKey; to: SafeKey }[];
  };
  acknowledgedPolicyChanges: DomainPolicyChange[];
}
interface DomainMigrationOutcome {
  domainId: UUID; fromVersion: Version; toVersion: Version;
  before: DomainTuple; after: DomainTuple;
}
interface DomainTypeMigrationContext {
  coverage: 'complete-direct-domain-type-bindings';
  type: DomainTypeView; sources: DomainTypeView[]; domains: DomainView[];
}
interface DomainTypePreview {
  typeId: UUID; expectedHeadVersion: Version;
  target: Omit<DomainTypeView, 'createdAt' | 'createdBy'>;
  coverage: 'complete-direct-domain-type-bindings';
  mode: 'preserve-pins' | 'migrate';
  changes: ModelChange[]; policyChanges: DomainPolicyChange[];
  domains: { before: DomainView; proposed: DomainTuple; issues: ValidationIssue[] }[];
  pinsPreserved: boolean; requiresMigration: boolean;
  ready: boolean; previewDigest: Digest | null;
}
interface DomainTypeMigrationReceipt {
  formatVersion: 1; id: UUID; typeId: UUID; fromHeadVersion: Version;
  targetVersion: Version; plan: DomainTypeMigrationPlan;
  planHash: Digest; previewDigest: Digest;
  sourcePolicies: { pin: DomainTypePin; definitionHash: Digest; resolutionHash: Digest }[];
  targetDefinitionHash: Digest; targetResolutionHash: Digest;
  outcomes: DomainMigrationOutcome[];
  actorId: UUID; occurredAt: UTC; reason: string; correlationId: string;
}
interface DomainHierarchyChange {
  kind: 'move' | 'retire' | 'restore';
  domainId: UUID; expectedVersion: Version;
  parentId: UUID | null; reason: string;
}
interface DomainHierarchyPreview {
  coverage: 'complete-affected-domain-subtree'; change: DomainHierarchyChange;
  domains: { domainId: UUID; version: Version; parentId: UUID | null }[];
  assets: { assetId: UUID; assetVersion: Version; placementVersion: Version }[];
  ready: boolean; issues: ValidationIssue[]; previewDigest: Digest | null;
}
```

The preview target is proposed data: its `currentVersion` is the expected committed head, `version` is head+1, and publication creator/time are absent. No caller may interpret it as a published version. In preserve-pins mode, `proposed` is the hypothetical target-validation tuple, `pinsPreserved:true`, and the UI explicitly explains that publication retains actual current domain pins/values. In migrate mode, `proposed` is the actual intended after tuple and `pinsPreserved:false`. Migration context contains the current head, each distinct actual source policy sorted by version, and the complete directly bound domains sorted by UUID; it is authorized and bounded as a whole. Context is editing data, not executable consent.

The nested attribute plan uses the domain type's immutable safe key as `modelId`; source/target versions refer only to domain-type versions in this service. It never calls legacy asset migration persistence. Its `sourceVersions` exactly equals the sorted complete direct-domain cohort, including retired instances; existing attribute acknowledgements/conversions remain unchanged. Source owner inactivity may be repaired only by explicit valid replacement or acknowledged removal of a required-owner policy. An explicitly selected non-null owner must always be active. Existing invalid attributes/state/history are storage or source-validation failures, not silent repairs. Lifecycle mapping keys are sourceVersion/from; state movement outside an ordinary transition is permitted only by the explicitly previewed migration.

Type migration preserves each domain's identity, name, description, parent and administrative status; it changes only type pin, attributes, owner, state, version and update attribution. It migrates every directly bound instance to the one new target version in one transaction. An unclaimed intermediate publication/write is invalid even if the final head would accept it. The receipt's outcomes and normalized rows must exactly equal actual before/after domain revisions. A hash alone is insufficient. Forward repair is a new explicitly previewed migration; historical receipts never change.

For move, `parentId` is the proposed parent. For retire/restore it must equal the current parent; those operations cannot conceal a simultaneous move. Preview includes the complete moving/retiring/restoring subtree and its placed assets, all currently authorized, with exact versions. It also binds the destination ancestor chain and current hierarchy fence internally. For retirement, an active child or placement produces `ready:false`; restore rejects an inactive parent or invalid current policy. The execution changes only the selected domain and advances the scope fence; it does not pretend every descendant/asset received a new metadata revision.

Complete contexts/previews/receipts are bounded single documents, never one page of a larger consent scope. `ready:false` always has `previewDigest:null`. Only a complete authorized valid result supplies a digest. Consent binds authenticated tenant/actor, operation, canonical plan/change/reason, exact heads/parents/source and target resolutions, complete domain/asset/placement versions, owner activity and current permission evidence/fence. Execution re-derives all of this under locks before any mutation. Adding a bound domain or changing an ancestor/placement/permission invalidates affected consent; changing only UI state cannot retain the old confirmation.

Proposed aggregate profile: 1,000 affected domains, 1,000 affected assets, 32 domain-hierarchy levels, 2,001 distinct principals, 64 attribute transformation operations, 100 returned issues, 100,000 retained JSON nodes, 256 KiB per definition and 512 KiB total retained canonical projected values/plan/preview/receipt data. Shared totals cover copies and nested inputs, not a separate allowance per domain. Preflight PostgreSQL count/byte representations before materializing large payloads, including JSONB exponent expansion; authorize complete scope before reporting a profile limit. No partial execution, silently truncated preview or sampled cohort is permitted. Larger durable migrations remain required programme work.

## HTTP, failures and pagination

All routes use `/api/v1`, authenticated membership, existing browser CSRF rules, strict OpenAPI input/output schemas and sanitized Problem Details. Body JSON is strict before schema validation; unknown/repeated query parameters and coerced values fail. All successful mutations require `Idempotency-Key`. Definition publication/migration and domain edits use `If-Match` for the current head/domain version. Placement alone accepts `If-Match:0` for the explicit absent initial state; its body also requires the current positive asset version and target domain version when assigning.

| Method/path | Input and permissions above | Response |
| --- | --- | --- |
| GET `/domain-types` | `limit,cursor,q` | `Page<{typeId,key,label,currentVersion}>` |
| POST `/domain-types/validate` | `{text}`; model read | `{definition:DomainTypeDefinition}`; pure parse only |
| POST `/domain-types` | `{definition,reason}`; version1 | 201 `{type:DomainTypeView}` |
| GET `/domain-types/:typeId[/versions/:version]` | Exact UUID/version | `{type:DomainTypeView}` |
| POST `/domain-types/:typeId/previews` | `{definition,reason}`, If-Match | `{preview:DomainTypePreview}` with mode preserve-pins |
| POST `/domain-types/:typeId/versions` | `{definition,reason,previewDigest}`, If-Match | 201 `{type:DomainTypeView}` |
| POST `/domain-types/migration-plans/validate` | `{text}`; model read | `{plan:DomainTypeMigrationPlan}`; pure parse only |
| GET `/domain-types/:typeId/migration-context` | Complete-scope model/domain read authorization; no query fields | `DomainTypeMigrationContext` |
| POST `/domain-types/:typeId/migration-previews` | `{definition,plan,reason}`, If-Match | `{preview:DomainTypePreview}` with mode migrate |
| POST `/domain-types/:typeId/migrations` | `{definition,plan,reason,previewDigest}`, If-Match | 201 `{type:DomainTypeView,receipt:DomainTypeMigrationReceipt}` |
| GET `/domain-types/:typeId/migrations/:id` | Original-scope reauthorization | `{receipt:DomainTypeMigrationReceipt}` |
| GET `/domains` | `limit,cursor,q,parentId,status`; root parent uses literal `root`; omitted parent means all permitted domains | `Page<DomainView>` |
| GET `/domains/owner-candidates` | `limit,cursor,q`; domains read/write; current active tenant members only | `Page<{id:UUID,name:string}>` |
| POST `/domains` | `{name,description,parentId,type,attributes,ownerId,reason}` | 201 `{domain:DomainView}`; initial pinned state and active status |
| GET `/domains/:id` | Exact UUID | `{domain:DomainView}` |
| PATCH `/domains/:id` | `{name,description,attributes,ownerId,reason}`, If-Match; full editable tuple | `{domain:DomainView}`; no implicit parent/type/state/status change |
| POST `/domains/:id/state` | `{state,reason}`, If-Match | `{domain:DomainView}` |
| POST `/domains/:id/hierarchy-previews` | `{change:DomainHierarchyChange}`, expectedVersion equals If-Match and route ID | `{preview:DomainHierarchyPreview}` |
| POST `/domains/:id/hierarchy-changes` | `{change,previewDigest}`, If-Match | `{domain:DomainView}` |
| GET `/domains/:id/history` | `limit,cursor` | `Page<DomainRevision>` |
| GET `/domains/:id/assets` | `limit,cursor`; current authorized direct placements only | `Page<{assetId,name,assetVersion,placementVersion}>` |
| GET `/assets/:id/domain-placement` | Current asset/domain read authorization | `{placement:DomainPlacementView,domain:DomainView|null}` |
| PUT `/assets/:id/domain-placement` | `{assetVersion,domainId,domainVersion,reason}`, placement If-Match; domainVersion null iff domainId null | `{placement:DomainPlacementView,domain:DomainView|null}` |
| GET `/assets/:id/domain-placement/history` | `limit,cursor`; current asset/domain read authorization | `Page<DomainPlacementRevision>` |

Unassign with a non-null domain version or assign without a positive target domain version is invalid. Assignment to the same current domain is a no-change error; refreshing a recorded domain revision is not a new assignment. Domain creation accepts exact type pins, not moving heads. The domain-type migration UI obtains complete source tuples/policies through migration context before constructing a plan; ordinary definition/version reads supply editable target parents. Do not use paginated history as a complete migration cohort.

Read queries use keyset pagination. Default limit 50, integer 1–100; q is a bounded 200-character literal substring, safely escaped and never executable query syntax. Type/domain inventories and owner candidates sort immutable UUID ascending after filtering; history sorts own revision descending; direct domain asset lists sort asset UUID ascending. No offset, totals, partial hidden counts or descendant counts. Status accepts `active|retired|all`, default active. Parent filters require current read access to the referenced parent before enumeration. Owner candidates expose only active tenant-member identity/name for domain-owner selection; never role contents, permissions, other-tenant memberships or inactive identity names. Selection remains subject to mutation-time eligibility/authorization checks. Register the static owner-candidates route ahead of UUID resource interpretation.

Signed opaque cursors bind version, distinct purpose, authenticated tenant/actor, resource/type IDs, normalized filters, page size, order, last key and a 43-character HMAC scope fence. Maximum cursor length 1,024. Purpose strings are `domain-types`, `domains`, `domain-history`, `domain-assets`, `domain-placement-history` and `domain-owner-candidates`; never accept a cursor from another purpose. Store no raw/base64 counter in the public payload. Recompute the fence and reauthorize each page before returning rows. Fence mismatch returns 409 `DOMAIN_PAGE_STALE`, without identifying what changed. Conservative invalidation from another domain change is allowed and is not an existence/count response. Identity/membership revocation is checked even if the scope epoch did not change. Owner candidates are a current authorized keyset traversal, not a historical directory snapshot: activity/name changes are read fresh each page and are not falsely claimed to be fenced by domain mutations. History access checks every referenced currently protected object; if a complete immutable page cannot be disclosed safely, refuse generically rather than exposing hidden historical names.

| HTTP | Stable code | Meaning |
| --- | --- | --- |
| 400 | `DOMAIN_JSON_INVALID` / `DOMAIN_PAGE_INVALID` | Malformed/duplicate JSON, unknown outer fields, invalid query/cursor binding or noncoercion failure. |
| 400/409 | `IDEMPOTENCY_REQUIRED` / `IDEMPOTENCY_CONFLICT` | Missing invalid key / reused key with different canonical request. |
| 401/403 | Existing session errors / `FORBIDDEN` | Authentication or missing current action permission. |
| 404 | `DOMAIN_NOT_FOUND` / `DOMAIN_TYPE_NOT_FOUND` / `DOMAIN_MIGRATION_NOT_FOUND` / existing `ASSET_NOT_FOUND` | Missing or inaccessible direct resource; indistinguishable externally. |
| 403 | `DOMAIN_SCOPE_UNAVAILABLE` | Complete required scope/history cannot be authorized; no IDs/counts/issues. |
| 428 | `VERSION_REQUIRED` / `DOMAIN_PREVIEW_REQUIRED` | Missing expected version or executable consent. |
| 409 | `VERSION_CONFLICT` / `DOMAIN_PREVIEW_STALE` / `DOMAIN_PAGE_STALE` | Exact version, complete consent or page fence became stale. |
| 409 | `DOMAIN_TYPE_EXISTS` | Tenant logical domain-type key already exists; only after authorizing its inventory scope. |
| 422 | `DOMAIN_INVALID` / `DOMAIN_TYPE_INVALID` / `DOMAIN_MIGRATION_INVALID` | Invalid values, pins, current-owner eligibility, lifecycle or migration rules. |
| 422 | `DOMAIN_HIERARCHY_CYCLE` / `DOMAIN_IN_USE` / `DOMAIN_RETIRED` / `DOMAIN_NO_CHANGE` | Invalid authorized tree, nonempty retirement, inactive destination/resource or no-op. |
| 422 | `DOMAIN_MIGRATION_REQUIRED` / `DOMAIN_PROFILE_LIMIT` | Explicit migration required / complete authorized scope exceeds the bounded profile. |
| 503 | `DOMAIN_RETRY` | Deadline/lock/deadlock/serialization failure; transaction rolled back; Retry-After5. |
| 500 | `DOMAIN_STORAGE_INVALID` | Stored definition/tuple/revision/receipt inconsistency; sanitized correlation ID, no invented repair. |

Validation-only raw file endpoints do not require idempotency or mutation versions. A valid but target-invalid complete preview may return 200 with `ready:false`; execution can never accept it. Unsupported future definition formats fail explicitly, without silently dropping fields. Error responses expose no SQL, stack, credentials, hidden parent names, raw epochs, unauthorized owner IDs or request literals.

## UI, synthetic data and executable gates

Proposed browser routes are `/domains`, `/domains/new`, `/domains/:id`, `/domains/:id/edit`, `/domain-types`, `/domain-types/new`, `/domain-types/:id`, `/domain-types/:id/edit`, `/domain-types/:id/migrate`, and `/domain-types/:id/migrations/:migrationId`. Root delegates shared App/navigation/i18n/styles before parallel edits. Use the existing design system and truthful domain context; a context selector filters authorized work and does not select a tenant or confer authority.

The real UI provides the typed editor, exact parent pins, required owner/lifecycle controls, declarative roundtrip, complete before/after previews, explicit confirmation, stale recovery, immutable receipts, domain hierarchy/history, asset placement and unassignment. It obtains server permissions/data through supported APIs. A consumer lacking domain-read permission receives no domain names or IDs through an asset detail convenience field. The proposed owner-candidates API supplies authorized current eligible members for this specific purpose; the existing catalog-write-only `/members` endpoint is not automatically a domain administration contract.

Seed original Harbor Retail/Summit Logistics domain trees with finance, sales, supply-chain and product examples, duplicate display names, retired domains, independently restricted assets and explicit tenant-safe placement. Seed permissions explicitly and preserve existing fixtures. English/Arabic/RTL, light/dark, mobile/desktop, keyboard focus, labelled errors, non-color status and stale/network recovery are required for new flows. UI language support does not by itself implement multilingual business glossary content.

The following are proposed required tests, not executed results:

1. Pure definition/value/migration parsing and resolution: strict keys, typed values, exact parent pins, inheritance diamonds/conflicts, kind confusion, owner/lifecycle rules, byte/node/depth bounds, canonical roundtrip and complete source-version rules.
2. Isolated forward upgrade from the actually qualified prior schema: old SQL checksums, asset/model/graph snapshots/receipts, users and source data preserved; forced RLS/runtime ownership/ACL checks; no invented placement history. Replay is idempotent and malformed-state upgrade rolls back.
3. Direct PostgreSQL negatives: foreign tenant references, forged normalized dependencies/receipts, missing journals, invalid snapshots, skipped versions, private-claim writes, caller-GUC/nested-trigger bypasses, hierarchy cycles and early constraints cannot commit an incomplete mutation.
4. Real service/API domain journey: create type/domain, place scanned asset, rename/move without changing asset identity or old asset snapshot, inspect actual placement/domain history, unassign, retire/restore, publish compatible pins and migrate a mixed-version cohort including retired domains.
5. Concurrency/retry: concurrent first placement, place versus retirement, moves creating a cycle, type publication versus new domain binding, stale hierarchy/asset/placement/owner/member state, both membership-revocation lock orderings, replay after privilege loss, bounded timeout and all late-write rollback points.
6. Authorization/privacy: two tenants, duplicate UUID/key across resource kinds where fixtures permit, hidden assets in impacted subtrees, hidden historical references and receipt members, cursor purpose/filter/actor mismatch, canonical filtering before rows/counts, audit resource-kind handling and revoked same-request replay.
7. Actual scanner/model/relation regressions: scan refresh/unavailability, ownership/attribute edits, type migrations and participation repair preserve placement and existing immutable snapshots. A placement change does not pretend a new asset metadata revision exists. No legacy ingress can edit placement through generic metadata JSON.
8. Targeted browser authoring/placement/migration/history and tenant-denial journeys, then the affected full browser gate, with no silently skipped paths. Inspect actual English/Arabic desktop/phone renderings, scoped axe, keyboard and explicit stale-confirmation behavior. Independent human language/accessibility review remains separately recorded.
9. Evidence binds actual source/image/SQL/tool versions and commands; preserve original failures and record exact limitations. Run relevant existing model/relation/API gates and required hosted checks before merging. No throughput, restore, external qualification or full-release claim follows from the bounded local tests.

## Ownership and follow-on implementation dependencies

Contract adoption does not itself assign source ownership. For implementation: root owns shared contracts, transaction/authorization integration, API/audit/index integration, records/evidence/CI/Git; a separately assigned storage worker owns the new forward migration and real upgrade/storage/concurrency tests; a pure-model worker can own new pure modules/units; a web worker can own new domain UI/browser files after shared-route delegation. All workers are not alone in the checkout and must preserve others' work. Never modify sources being qualified by another worker or publish this draft as a verified capability.

The required next authority contract covers `CORE-004`, `SPEC-076/077/085`, `SYS-DATA-001.01`, `SYS-SEC-002.01–.03` and `UX-36/37`: multiple editable role assignments, versioned responsibility types, current scoped responsibility assignments, explicit configurable authority mappings, policy AST/deny/inheritance semantics, revocation fencing and semantic equivalence across reference evaluation/PostgreSQL/OpenSearch. It must bind placement and ancestry state in existing graph/type previews, executions, historical receipts, audit, search and all future approvals; old asset-version-only checks are insufficient. Groups/SCIM and the remaining organizational scopes remain required work with explicit qualifications.

Glossary approval then requires `CAT-006`, `UX-09`, `GOV-001/003/004/011`, `SYS-DATA-004`, `SYS-SEC-005`, `E2E-05` and `AT-WF-01`: multilingual meaning/aliases/examples/links, scoped independent decisions where policy requires, pinned canonical decisions, durable Temporal orchestration/restart/replay and discovery projection. Reference publication requires `REF-001–006`, `UX-21`, `E2E-13` and `AT-REF-01`: real effective-dated values/crosswalks, approval/activation/history, governed import and versioned export/webhooks. REF-005 and AT-REF-01 additionally require real source-backed quality checks. None is satisfied by a domain screen, enum definition or generic CRUD scaffold.

## Adopted material decisions

The lead adopts each proposed choice below, with the alternatives retained as decision context. See `../adr/0009-business-domains-and-placement.md`. No alternative is silently implemented and no end-user approval is outstanding.

1. **Additive placement version versus new asset-snapshot format.** Proposed: separate placement revisions and composite scope state, preserving existing asset snapshot/receipt bytes. Alternative: a new explicitly versioned asset-snapshot format plus forward guard/reader upgrades across every writer. The alternative increases this increment's touched security/receipt surface. The additive choice is adopted; silently extending `assetView` is invalid.
2. **One primary domain versus multiple memberships.** Proposed: one nullable primary domain with an explicit unassigned version-zero state. The source requires domain/collection scope but does not prescribe multiplicity. If multiple domains are chosen now, grant inheritance, deny semantics, placement DTOs and migration/preview closure must be redesigned before implementation.
3. **Domain authorization boundary.** Proposed: explicit tenant/action checks now, followed by a separate mandatory scoped-responsibility contract before glossary approval. Alternative: combine full current-interface scoped policy enforcement into this increment and expand its tests/ownership. A domain chooser or owner field must never be presented as completed scoped authority.
4. **Independent domain-type storage and bounded migration.** Proposed: separate versioned domain types, reuse pure validators, preserve asset-model formats and require explicit complete direct-domain migration. Alternative: a versioned polymorphic operating-model foundation spanning kinds. The latter needs a compatibility ADR before changing existing IDs/pins and must not collapse domains into scanned assets.
5. **Hierarchy policy and limits.** Proposed: single parent, 32 levels, complete authorized bounded move/retirement preview, retirement blocked by current placements/active children. These are engineering choices, not claims that the specification mandates those exact limits. These choices and the 512 KiB/1,000-resource profile are adopted development limits, subject to real qualification.
6. **Domain-owner selector.** Proposed: the bounded `/domains/owner-candidates` API above, authorized by domain read/write and returning active tenant-member identity/name only. Alternative: an explicitly permission-aware shared member-selector service replacing the existing `/members` assumptions. The purpose-specific exposure boundary is adopted for parallel API/UI work.

These decisions do not reduce the full programme. Scoped authority, collections, other model kinds and all-ingress validation remain mandatory follow-on work. Implementation ownership and qualification remain separate from contract adoption.
