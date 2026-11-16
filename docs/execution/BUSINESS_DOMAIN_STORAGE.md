# Business-domain storage and service boundary — SQL011 contract

Current status, 2026-11-16: **SQL011 IMPLEMENTED, ISOLATED GATE PASSED, APPLIED TO CORE AND IMMUTABLE.** The final isolated gate records eight upgrade checks,18 storage cases and nine concurrency cases; the separate real core API gate passes154 cases. Refer to `../verification/business-domains-upgrade-final-source.json`, `../verification/business-domains-api.json` and `STATE.md` for exact source/checksum bindings and limits. These scoped checks do not complete the broader authority or release obligations.

Original adoption checkpoint (2026-11-15): **CONTRACT ADOPTED; implementation and execution had not begun.** Root reviewed and adopted this concrete storage/service boundary, including the original-transaction clock, ordinary-write preparation/seal pair, tagged envelopes, server-allocated create identity, projection hashes and exact journal/deferred proof. It specifies the storage/service obligations of the adopted [business-domain contract](BUSINESS_DOMAINS.md) and [ADR0009](../adr/0009-business-domains-and-placement.md); it is not a working capability. No approval is outstanding. No requirement, milestone, runtime or release status advances through this document.

SQL001–011 are applied and immutable. SQL011 was qualified first against an isolated copy of the actual prior schema, after the preceding required-participation browser gates. Corrections require a new forward migration and a separate isolated upgrade gate. The governing [BUILD_SPEC](../product/BUILD_SPEC.md) and canonical [requirement register](../product/requirements.yaml) retain their full scope. This contract contributes to CORE-001/002/006/007/009, MOD-001/002/003, SYS-DATA-001.01–.05, SYS-DATA-002/004, SYS-API-001.01–.03, SYS-SEC-002.01–.03 and SYS-SEC-003. It does not complete scoped authority, full M2, AT-MOD-01, AT-TEN-01, AT-AUD-01 or release qualification.

## Boundaries and unchanged formats

Use the exact public DTOs, type resolution, hierarchy semantics, aggregate limits, permissions, journal literals and HTTP failures in BUSINESS_DOMAINS.md. Domain types use their own UUID/version storage. Their safe definition key is separate from the UUID; neither an asset-model key nor an asset/relation type UUID may satisfy a domain-type reference. New SQL validates these distinctions independently of TypeScript.

Placement remains an additive subresource. It never changes `assetView`, `GraphAssetTuple`, an existing asset version, source identity, SQL007 typed tuples or SQL009 graph tuples. Every positive placement revision references an actual immutable asset revision and, when assigned, an actual immutable domain revision. The canonical absence of placement is unrecorded version zero, not a stored row or fabricated revision. Unassignment retains a positive-version row and history. No new operation invokes legacy asset/model/graph mutation services or writes relation/participation rows.

PostgreSQL independently proves complete scope, policy, projection, revision, journal and success consistency. A TypeScript preview, tuple hash, caller GUC, trigger depth, supplied receipt or knowledge of an operation UUID is not permission to bypass an ordinary invariant. SQL may reuse the established pure attribute transformation/value functions through exact domain-model adapters; it must not manufacture an asset row or use legacy persistence as a shortcut. A shared helper's existing semantics and signatures remain unchanged.

## Frozen physical columns for service integration

Root and the storage worker adopt the following SQL011 columns. All named tables are in `public`; every identity/reference includes `tenant_id`. These column names are an implementation interface, not a claim that the tables exist. Types, composite foreign keys, forced RLS, immutable history, positive versions and prepared-write guards retain all obligations below and in BUSINESS_DOMAINS.md.

| Table | Frozen service-visible columns |
| --- | --- |
| `domain_types` | `tenant_id, id, key, current_version, created_at, created_by` |
| `domain_type_versions` | `tenant_id, type_id, version, definition, resolved, definition_hash, resolution_hash, created_at, created_by` |
| `domain_type_dependencies` | `tenant_id, type_id, version, parent_type_id, parent_version`; the exact transitive closure, not only direct parents |
| `domains` | `tenant_id, id, name, description, parent_id, type_id, type_version, attributes, owner_id, state, status, version, created_at, created_by, updated_at, updated_by` |
| `domain_revisions` | `tenant_id, domain_id, version, snapshot`; snapshot is the **full DomainRevision envelope**, not only DomainView |
| `asset_domain_placements` | `tenant_id, asset_id, version, domain_id, recorded_asset_version, recorded_domain_version, recorded_at, recorded_by` |
| `asset_domain_placement_revisions` | `tenant_id, asset_id, version, snapshot`; snapshot is the **full DomainPlacementRevision envelope**, not only DomainPlacementView |
| `domain_type_migrations` | `tenant_id, id, type_id, from_head_version, target_version, plan, plan_hash, preview_digest, target_definition_hash, target_resolution_hash, source_policies, receipt, executed_by, executed_at` |
| `domain_type_migration_domains` | `tenant_id, migration_id, domain_id, from_version, to_version, before_tuple_hash, after_tuple_hash` |

Revision event hashes cover the full stored revision envelope. A migration's normalized member row references actual `(tenant_id,domain_id,from_version)` and `(tenant_id,domain_id,to_version)` revisions; its tuple hashes cover the corresponding DomainTuple values and are checked against the full parent receipt and actual snapshots. There is no stored placement version zero.

Runtime has SELECT on public canonical/history/type/dependency/receipt tables, INSERT/UPDATE on canonical type heads/domains/placements, and INSERT on immutable type versions/revisions, subject to prepared claims and all guards. Normalized type dependencies and migration parent/member rows are written only by protected storage helpers. Runtime has no table privileges on private operation contexts, claims, transaction bindings or scope state. PUBLIC execution is revoked from new helpers; runtime EXECUTE is limited to the four adopted begin/seal functions, the read-only scope-epoch function and the narrow replay-authorization function defined below. Existing shared pure/hash and narrow principal-lock helper semantics and privileges are unchanged.

## Migration entry points and exact envelopes

Only the following migration entry points are runtime-callable. Their implementation is security-definer only where private storage requires it; all internal helpers remain private.

```sql
gc_domain_type_migration_begin(
  operation_id uuid,
  idempotency_key text,
  request_body jsonb,
  correlation_id text
) RETURNS jsonb

gc_domain_type_migration_seal(operation_id uuid) RETURNS jsonb
```

The request has exactly these fields, all required:

```ts
interface DomainMigrationExecutionRequest {
  typeId: UUID;
  expectedHeadVersion: Version;
  definition: DomainTypeDefinition;
  plan: DomainTypeMigrationPlan;
  reason: string;
  previewDigest: Digest;
}
interface DomainMigrationBeginResult {
  operationId: UUID;
  occurredAt: UTC;
  projectionHash: Digest;
  receiptHash: Digest;
}
interface DomainMigrationSealResult {
  type: DomainTypeView;
  receipt: DomainTypeMigrationReceipt;
}
```

`request_body` is the exact object passed to idempotency hashing: the HTTP adapter binds the path UUID and `If-Match` value into it. SQL rechecks both against definition, plan, actual head and cohort. The reserved idempotency operation is exactly `domain-type-migration.execute`; there is no arbitrary operation-name argument. The key uses the existing 8–128-character contract. Correlation uses the existing validated correlation contract. Strict raw JSON validation happens before JSONB conversion, since JSONB cannot recover duplicate keys discarded during parsing. SQL additionally validates exact fields, types, bounds and canonical values for direct callers.

`operation_id` is a fresh server-generated UUID, allocated only inside the non-replay branch. It identifies the protected operation and eventual receipt; it is not part of the caller's idempotency request digest. Tenant and actor come from validated transaction context and current membership, never these envelopes. A second operation in the same transaction, a duplicate operation UUID, a changed actor/tenant, repeated begin, repeated seal or a call after closure fails. An HTTP retry uses a new transaction and existing idempotency state, not a second begin on an already-started operation.

Begin returns no source rows, permission state, counts, raw scope epoch or caller-editable claims. The service obtains editing/preview data through the existing complete authorized context contract and rederives it under the locks held by begin. Seal accepts only the operation UUID. It builds and returns the public response from actual verified rows; it never accepts a client receipt, normalized outcome list, final response or success flag.

For comparison between independent SQL and pure projection, `projectionHash` covers the shared canonical encoding of exactly:

```ts
{
  formatVersion: 1,
  kind: 'domain-type-migration-projection',
  typeId, fromHeadVersion, targetVersion, planHash,
  sourcePolicies, targetDefinitionHash, targetResolutionHash, outcomes
}
```

Here `sourcePolicies` and `outcomes` are the exact receipt fields: source policies ordered by version for the one logical type, outcomes ordered by domain UUID. Definitions and plans retain authored array order; do not sort one side differently from the idempotency/definition canonical grammar. All hashes use the existing canonical hash grammar, not PostgreSQL JSONB display text. `receiptHash` hashes the exact expected `DomainTypeMigrationReceipt`, without a self-hash field.

The opaque preview digest remains a service consent check. SQL binds its exact value into the protected request and receipt, but does not treat it as authority or require access to an application HMAC secret. SQL's independent scope/policy/projection checks remain necessary even when a direct SQL caller supplies a syntactically valid arbitrary digest. The service must rederive and compare the current consent digest under locks before it writes.

## Original transaction deadline

The protected start is **PostgreSQL `transaction_timestamp()`**, with its full timestamp precision. The deadline is that value plus 30 seconds. No helper uses its own wall-clock entry time, caller-supplied timestamp, GUC or newly created operation row time as a fresh start. Begin after an idempotency or ledger wait has only the original transaction's remaining budget. Savepoints, nested helpers, retry within the transaction, seal and deferred finalization cannot reset it. A new external retry is a new transaction and must repeat authorization and consent checks.

The operation's product attribution time is `date_trunc('milliseconds', transaction_timestamp())`, serialized to canonical UTC with milliseconds. This provides one exact `occurredAt` for the new type version, changed domain update attribution, revisions, receipt and associated journals. It is a platform mutation time, not source observation or effective business validity. Deadline accounting uses the original untruncated timestamp, not this serialization value.

The service establishes its bounded transaction before the first membership query or advisory/row-lock wait, including the first `once` idempotency wait. Before each protected SQL statement it executes a separate budget command, obtains the remaining server deadline, and arms `statement_timeout` to no more than that remaining time and `lock_timeout` to no more than the lesser of five seconds and that remaining time. Preserve any earlier positive configured timeout that is shorter. Round remaining milliseconds down; less than one millisecond remaining expires immediately. Never set a timeout to zero after rounding, since zero disables the timer. An existing zero/unlimited setting supplies no smaller positive bound. The application also maintains a monotonic remaining budget; server/application minima may shorten it, never extend it. Check the budget during pure processing and before scheduling each query. The original server start is not inferred from an unsynchronized application wall clock.

The budget-setting command and protected statement must be separate PostgreSQL commands. Changing `statement_timeout` inside an already executing function does not prove that the current outer statement timer is armed. The new path must therefore wrap `once`, ledger acquisition, preparation, reads, writes, journal calls, idempotency insertion, constraint forcing and final checks; wrapping only begin/seal is insufficient. The SQL guard itself checks `clock_timestamp()` against the original start on entry, after each wait, before/after each materialization or validation phase, within bounded iteration/projection loops, during seal, and before/after final completeness validation. The guard fails closed with SQLSTATE `57014` once exhausted.

For direct SQL with an outer `statement_timeout` of zero, SQL011 promises cooperative expiry and rejection of expired finalization, **not a universal hard interrupt at exactly 30 seconds inside an arbitrary outer statement**. Do not report a faster discovery benchmark as that stronger guarantee. Service qualification must separately demonstrate the prearmed statement timer and the original-clock checks, including time spent before begin.

## Private operation state and claims

SQL011 adds the canonical tables in BUSINESS_DOMAINS.md and the minimum private tables needed for the following records. The names below are the storage interface vocabulary; helpers do not expose raw private rows through runtime SELECT.

| Private record | Required protected contents and uniqueness |
| --- | --- |
| `domain_transaction_bindings` | `tenant_id, transaction_id xid8, actor_id text, kind, started_at`; primary tenant/transaction key plus **global UNIQUE(transaction_id)**. Kind is `domain` or `legacy`. Forced tenant RLS and private writes bind one original transaction to one tenant/actor/mutation family, including after seal/finalization. |
| `domain_operation_contexts` | Unique tenant/current transaction; authenticated actor; exact original start; mode `ordinary` or `migration`; operation UUID; fixed namespace/key, exact request/hash, reason/correlation/attribution time, expected response/projection/hash and retained-byte/node counters for either mode; initial scope epoch; protected epoch increment count; state `open`, `sealed`, `finalized`. No second operation or expanding scope after preparation. |
| `domain_migration_operations` | Tenant/operation/current transaction/actor; reserved idempotency namespace/key; exact request and hash; correlation; attribution time; from-head/target versions; target authored/resolved policy and hashes; complete source-policy pins/hashes; exact expected projection/receipt and hashes; retained-byte/node counters. |
| `domain_operation_type_claims` | Exact locked source head and new head/version expectation; immutable target definition/resolution; exact dependency closure; expected creator/time; consumption state. Validation-only parent/source versions cannot become write claims. |
| `domain_operation_domain_claims` | Domain UUID and role `changed` or `validate`; actual before canonical row and immutable revision reference; exact projected after tuple/view/version/attribution for changed members; pin/policy evidence; row and revision consumption state. Ancestors and other validation-only members cannot be mutated. |
| `domain_operation_placement_claims` | Ordinary placement's actual old row/absence, actual locked asset revision, old/new domain union and actual target domain revision; exact next placement/view/revision; consumption state. No migration placement writes. |
| `domain_operation_journal_claims` | Exact action, resource kind, resource UUID, committed version, event data, reason, actor, correlation and time; first accepted event UUID; exactly-once audit and outbox consumption flags. Key includes resource kind, so equal UUIDs in different resource kinds never alias. |

Every domain begin and guarded legacy statement first establishes its private transaction binding with `INSERT ... ON CONFLICT(transaction_id) DO NOTHING`, then requires an existing binding for the exact current tenant, actor and permitted family. A prior binding hidden by forced RLS makes that check fail generically; a global-read or BYPASSRLS capability is unnecessary. Domain begin rejects a prior legacy binding and repeated domain begin; guarded legacy statements reject a domain binding in any operation state. Repeated legacy statements within the same tenant/actor transaction remain legal. The binding's actor is exact `gc_actor()` text so existing nonmember site/scanner principals retain their standalone legacy behavior; this non-authorizing marker has no membership FK. Domain begin and its operation context separately require a canonical UUID, active identity/membership and their tenant/member FK. The binding's start is the original `transaction_timestamp()`. No runtime DML, GUC or tenant/actor switch can erase or replace the binding. This normalization implements the protected bidirectional legacy-mutation marker required below.

An implementation may normalize these private records further without weakening any field or invariant. It must not replace exact tuples with hashes alone. Every lookup and FK includes tenant scope even with forced RLS. Claims match `pg_current_xact_id()` and current authenticated actor as well as operation UUID. Runtime cannot INSERT/UPDATE/DELETE claims, operation state, epoch or normalized dependency/receipt children. Private functions cannot be called through an attacker-controlled search path or an unqualified object name.

Use fixed safe search paths, qualified relation/function references, row security on, non-superuser/non-BYPASSRLS owners, no runtime table ownership, revoked PUBLIC execution and only the narrow runtime grants needed. Do not grant UPDATE on identities or memberships merely to lock them. Scope state and private records themselves use forced tenant RLS and composite references. Retained private records are not a second public read API; any later cleanup design must preserve immutable public evidence and idempotency guarantees.

## Complete scope, locks and independent projection

Begin first validates current action permissions and resource existence, then obtains the locks below. Both the service and SQL use the same existing idempotency and tenant-ledger lock keys. SQL must not acquire a different key that merely looks equivalent. A direct function caller still follows this order even if the service would normally already hold the first locks.

1. Reserved tenant/actor/operation/key idempotency advisory lock, then tenant ledger.
2. Existing tenant model-scope advisory lock for any type definition/pin operation, then tenant domain-scope advisory lock and the private `domain_scope_state` row.
3. Relevant domain-type heads in UUID order, then the complete canonical domain union in UUID order.
4. Complete asset union in UUID order, then existing placement rows in asset UUID order.
5. One complete globally sorted identity UUID union, followed by tenant memberships in that same order, through the reviewed narrow locking capability.

Discover the entire identity-only type/domain/ancestor/asset/placement/principal union under the ledger and scope fence before crossing its lock phase. Include the actor and every old/proposed owner. Do not acquire an additional lower-order domain or asset after progressing to principal locks. Recheck actor activity, membership, permissions, owner eligibility, exact versions, hierarchy, dependency closure and full affected scope after all waits. Audited membership revocation continues to obtain applicable tenant ledgers before identity/member locks; global identity changes retain deterministic multi-tenant ordering.

A domain-type migration's changed cohort is **every direct binding** to its logical type, including retired domains and mixed historical pins. Its validation closure includes relevant ancestors and exact source/target type dependencies. Descendant types and their differently pinned domains are unchanged. This migration does not enumerate the domains' placed-asset collections, lock relation/binding rows or require asset visibility merely because an asset happens to be placed in a migrating domain. A hierarchy operation separately includes the complete affected subtree, destination ancestor chain and all affected current placements/assets. Ordinary name/description edits do not scan unrelated assets.

Materialize a narrow identity closure once, and reuse it for authorization, limits, locks and the later payload query. Complete current scope authorization must finish before database-derived counts, physical-byte limits, issue lists or large JSON aggregation. Use an explicit successful authorization phase or equivalent demonstrated evaluation gate; a reorderable SQL WHERE/AND predicate is not proof of authorization-before-count. Missing/inaccessible complete scope returns only the generic scope error. Request-local structural limits may reject data supplied by the caller without reading stored scope; this is not permission to report stored-value limits before scope authorization. The HTTP reader likewise authorizes direct resources without revealing whether a foreign UUID exists.

After authorization, independently enforce 1,000 affected domains, 1,000 affected assets, 32 hierarchy levels, 2,001 principals, 64 attribute operations, 100 returned issues, 100,000 retained JSON nodes, 256 KiB per definition and 512 KiB shared retained canonical data. Count all retained copies of request/definitions/source tuples/projected tuples/preview/receipt; do not give each nested member a fresh allowance. Check actual PostgreSQL physical JSONB representations, including exponent expansion, before large canonical serialization or aggregation. Avoid repeated full-tenant closure discovery per row. No sample, partial page or hidden truncation can stand in for complete consent.

SQL independently resolves exact source and target domain policies, rejects missing/extra/conflicting dependency pins, verifies actual source revisions, validates source tuples and runs the plan over each complete cohort member. `sourceVersions` equals the sorted distinct actual bound versions; owner/lifecycle/attribute acknowledgements have their adopted exact semantics. Migration preserves identity, creation metadata, name, description, parent and administrative status. Only the pin, attributes, owner, state, version and update attribution may change. The expected after version is exactly before+1; overflow fails before any write. A retired domain is included and may migrate without restoration. An empty cohort still claims one new type version and one receipt, with no invented domain claim.

Before returning, begin stores the exact independently derived projection and expected receipt and fixes their attribution. The service then rereads/rederives the pure preview under these locks, compares the protected projection hash and current consent digest, and performs no write unless both match. Projection disagreement is a storage/implementation inconsistency; changed consent is the stale-preview failure. Neither case permits the service to replace SQL's expected projection with its own.

## Ordinary writers: prepare before canonical DML

**Adopted exact interface:** use one narrow ordinary-write preparation/seal pair to establish the complete authorized scope before canonical DML. A BEFORE ROW trigger sees endpoints only after PostgreSQL has already locked the row, and a BEFORE STATEMENT trigger cannot inspect NEW endpoints. This pair lets SQL derive and lock the complete scope before DML; it is not a generic arbitrary-SQL capability.

```sql
gc_domain_write_begin(
  operation_id uuid,
  idempotency_key text,
  request_body jsonb,
  correlation_id text
) RETURNS jsonb

gc_domain_write_seal(operation_id uuid) RETURNS jsonb
```

The exact tagged request is one of the following; unknown fields/kinds fail. The discriminator also selects the fixed idempotency operation namespace. Every envelope is the same object used by `once`, with route/version bindings included. On create, the server allocates `operation_id` inside the non-replay branch and uses it as the new resource UUID; that server-generated UUID is deliberately absent from the idempotency request.

| `kind` / reserved idempotency operation | Other required request fields |
| --- | --- |
| `domain-type.create` | `definition`, `reason` |
| `domain-type.publish` | `typeId`, `expectedHeadVersion`, `definition`, `reason`, `previewDigest` |
| `domain.create` | `name`, `description`, `parentId`, `type`, `attributes`, `ownerId`, `reason` |
| `domain.update` | `domainId`, `expectedVersion`, `name`, `description`, `attributes`, `ownerId`, `reason` |
| `domain.state` | `domainId`, `expectedVersion`, `state`, `reason` |
| `domain.hierarchy` | `change:DomainHierarchyChange`, `previewDigest` |
| `domain.placement` | `assetId`, `expectedPlacementVersion`, `assetVersion`, `domainId`, `domainVersion`, `reason` |

Ordinary begin returns exactly `{operationId,occurredAt,projectionHash}`. Its hash covers `{formatVersion:1,kind:'domain-write-projection',request:request_body,response:expectedResponse}` using the same canonical grammar. The response is the public mutation response: `{type}` for type create/publication, `{domain}` for domain mutations, or `{placement,domain}` for placement. Ordinary seal returns that exact response, derived again from actual rows. There is no public ordinary-operation receipt or invented revision for unchanged resources. One request has one logical ordinary mutation; bulk composition requires a separate future contract.

Preparation uses the original clock, complete locks, current authorization and shared budget above, derives exact ordinary changes independently, and captures read/validation claims as needed. Compatible type publication checks every direct domain binding while preserving its actual pin and value; target incompatibility/destructive changes require migration. Hierarchy preparation rederives complete consent and does not turn descendant impact into descendant metadata writes. A placement operation locks both old and new domain references before its asset/placement and principal phase. It verifies the expected asset version and actual current immutable asset revision; assignment also verifies expected current target domain version, active status and actual domain revision. No missing revision may be synthesized. Record the actual referenced versions, including on unassignment, and never refresh history through a same-domain no-op.

The BEFORE STATEMENT guards reject canonical domain/type/placement DML without a matching open prepared context, and check the original deadline before row locking begins. They do not create permission from GUCs or discover a broader operation opportunistically. BEFORE ROW guards check each actual OLD/NEW row against its exact unconsumed private claim, enforce ordinary versions/policy/identity and record consumption. Revision guards independently compare exact actual canonical snapshots and metadata. Normalized type dependency rows are created/checked by protected storage helpers, not freely authored by runtime. Direct DML without preparation, extra rows, transient intermediate heads, wrong action, missing revisions and writes after seal all fail.

Domain/placement operations cannot coexist in one transaction with legacy asset/model/graph mutations. Forward statement guards reject incompatible legacy canonical, revision, receipt, normalized-child and graph/preparation writes when a domain context is open, sealed or finalized. They also record a protected tenant/transaction mutation marker before incompatible legacy writes when no domain context exists; domain begin rejects that marker. This covers both operation orderings. A graph-context lookup alone is insufficient because the existing standalone model and authored-type migration paths have no protected operation-context row. Marker storage and helpers are private, forced-tenant-scoped and unavailable to runtime DML; a caller GUC cannot create, erase or replace this proof. An attempted no-op legacy write may conservatively mark the transaction. Existing legacy transactions outside a domain operation retain their canonical behavior. Do not edit historical migrations or old row/snapshot contracts to add these guards. No future bulk path may call the single-mutation preparation repeatedly to evade the complete-union or aggregate budget.

## Scope epoch and future authority

Each actual logical type-head creation/advance, domain row mutation or placement row mutation advances the protected tenant scope epoch once, atomically. Revision, dependency, journal and receipt inserts do not increment it again. Thus a type migration advances it by one plus its changed-domain count; an empty migration still advances once. The context records the initial epoch and protected increment count, and finalization requires their exact resulting sum. Runtime cannot set, decrement, reset or directly advance the epoch. Overflow fails, rather than wrapping. Rollback restores both canonical state and epoch.

The trusted service reads only fence material through `gc_domain_scope_epoch() RETURNS bigint`. This narrow read-only SECURITY DEFINER helper uses a fixed safe search path and forced row security, verifies current active identity/tenant membership and at least `models:read` or `domains:read`, then returns only the current tenant's epoch, or zero when its row is absent. It performs no writes and returns no private operation or claim data. PUBLIC execution is revoked; `gc_app` receives EXECUTE, without SELECT on `domain_scope_state`. The service uses this internal scalar in the adopted HMAC fence; no API, cursor payload, error, event or receipt exposes the raw epoch. The four frozen mutation entry points are unchanged. The service obtains original-clock/remaining-time settings through separate ordinary SQL commands; no new deadline capability is required.

This counter is conservative invalidation state, not a count API or permission grant. Public cursors/consent use an opaque keyed fence; errors, events and receipt DTOs never disclose the raw epoch. A prepared operation compares its initial fence and accounts for only its own recorded increments, so its own valid writes do not look like an unrelated stale preview. Current identity/membership is always checked independently, even if the domain epoch did not change.

Placement and owner labels confer no authority. The initial permission matrix is exactly the adopted tenant/action matrix. Later required scoped policy must use the composite asset version, placement version, current domain ancestry/versions and fence in every relevant read, mutation, replay, receipt, search and approval path. This storage contract creates that foundation; it does not claim the later authorization integration exists.

## Exact journals, seal and deferred success

Use the frozen journal table in BUSINESS_DOMAINS.md without changing its action/resource-kind/subject/version literals. The shared producer needs an explicitly typed event-data argument and protected attribution for these new calls; legacy envelopes and bytes remain unchanged. Both SQL and the producer derive the same exact event data. Audit changes contain that data plus reason and the shared `resourceVersion`; the hashed audit envelope must agree with the stored changes. Outbox contains the exact CloudEvents base/extension/data contract, excludes restricted business values and uses the same event UUID/time/actor/correlation as its audit partner.

Begin fixes `occurredAt`, actor, correlation, reason and all expected projected views. Any audit actor display name comes from the locked current identity, not a stale caller-supplied principal label. For migration begin constructs the complete expected receipt **before** any journal is written and returns its hash. The `domain_type_migration.executed` event can therefore contain `receiptHash` without a circular dependency: the receipt contains no audit/outbox UUID or audit-chain hash. Journal guards independently reconstruct/check the fixed expected data, not a caller-provided receipt hash. The first accepted pair member binds its event UUID; the other must match. Duplicate, missing, mismatched or additional unclaimed domain-family journal pairs fail.

Migration requires exactly one `domain.type_migrated` pair per changed domain at its new domain version, one `domain_type.published` pair at target type version, and one `domain_type_migration.executed` pair at receipt version 1. An empty cohort requires only the last two pairs. Domain type versions, domain revisions and the receipt carry the protected actor/time; existing domain creation metadata is preserved. The returned target `DomainTypeView` uses the new immutable version's creator/time consistently with version views. Placement uses the asset UUID as subject but the **placement** version and `asset-domain-placement` kind, never an invented asset revision event.

Seal requires all expected canonical/head/version/revision and journal claims exactly consumed once, no unexpected writes, and current authorization/policy still valid. It rederives the receipt from actual immutable before/after revisions and actual target definition/resolution; compares full tuples and exact expected receipt, not hashes alone; inserts the immutable migration and normalized domain children through protected storage; then marks the context sealed and returns the exact response. Each normalized child references real before/after domain revisions and equals its parent's complete outcome. Empty cohorts have no child rows. Ordinary seal performs the equivalent exact-response/revision/journal checks without creating a migration receipt.

The ingress owns insertion of idempotency success after seal. Deferred constraint triggers require, before commit:

1. A sealed operation whose tenant, transaction, actor, original clock, scope epoch, complete source cohort and independent final policy remain consistent.
2. Exactly the claimed canonical transitions, normalized definitions/dependencies and immutable revisions, with no omitted, extra, intermediate or reused claims.
3. Exact audit/outbox pairs and, for migration, exact immutable receipt plus complete normalized children matching the real snapshots.
4. One reserved idempotency success for the same tenant/actor/operation/key/request hash with the **exact** sealed public response; no arbitrary subset, extra field or caller replacement.
5. No pending validation/consumption work, and original-deadline checks both before and after final validation.

The finalizer marks the private context finalized only after these checks; it does not erase evidence to hide incomplete work. Repeated deferred invocations may verify an already finalized context without creating or consuming more evidence; they still reject subsequent writes. Forcing constraints early cannot make missing claims optional or permit subsequent writes after finalization. Final cohort comparison uses the captured actual before revisions and exact final member set, not an expectation that migrated rows still have their old source pins. The normal service sequence is bounded transaction → current authorization → `once` lock/replay decision → begin → locked pure consent/projection check → canonical/revision/journal writes → seal → `once` success insert → `SET CONSTRAINTS ALL IMMEDIATE` → final budget check → commit. Any late failure rolls back canonical changes, private claims, scope epoch, revisions, audit, outbox, receipt and idempotency success together.

SQL011 rejects insertion of a reserved idempotency success without its sealed operation, and rejects UPDATE/DELETE or forged replacement of those successes. Before installing this guard, the isolated upgrade checks every tenant for preexisting rows using the newly reserved namespaces. An unexpected collision aborts the upgrade with a sanitized diagnostic; it does not delete or silently bless history. Upgrade validation runs through an explicitly scoped, non-bypass process that actually visits every tenant despite forced RLS.

## Replay and historical disclosure

The current generic `once` helper returns a matching stored response directly. Domain integration must add an explicit replay-authorization hook or equivalent bounded domain wrapper **before** that return. A request-digest match does not authorize the stored response. Re-read active identity/membership and required action permissions, then authorize every currently protected resource in the original immutable recorded scope. For migrations use the original normalized receipt members, not today's newly selected direct cohort. Placement replay/history requires current asset access and access to every referenced protected domain history. Refuse complete responses generically if any recorded resource cannot be disclosed.

Replay does not enter begin, create claims, advance epochs, write journals or allocate a new resource ID. It does not reject solely because the original optimistic version is now old. It returns the original exact response, time and IDs only after current authorization; a changed canonical request remains an idempotency conflict. Its authorization reads and waits share the new request transaction's deadline. A new current preview is necessary for a new mutation, not for disclosure of an otherwise authorized same-request result.

New domain action families are excluded from generic audit visibility and admitted only through resource-kind-aware current authorization. Type-migration audit uses complete original receipt scope. Same UUIDs across domain/type/asset/placement kinds cannot select the wrong authorization predicate. Event delivery itself conveys no fetch permission. No hidden count or historical name appears in denial, profile or retry responses.


### Adopted original-scope replay authorization

The runtime-visible read-only `gc_domain_replay_authorize(operation text, key text) RETURNS boolean` is the sixth narrowly granted entry point. It derives current tenant/actor from validated transaction context and finds the exact finalized protected operation and matching immutable idempotency success for that actor, namespace and key. It rechecks current active identity/membership/actions and every resource in the originally captured domain/type/asset scope, including the original immutable revision references. An ordinary hierarchy's current subtree cannot replace that original scope after later moves. The helper returns only a boolean, never private rows, counts, scope identities, epochs or cached values. It performs no writes, allocation, lease renewal or claim consumption. Missing, foreign, inaccessible or inconsistent scope is refused generically. The service separately verifies the canonical request digest, locks the current ledger/domain scope and actor, invokes this helper through the original transaction budget, and returns the existing success only when allowed. Both ordinary and migration replay use it; public migration-receipt reads retain their existing original normalized-member checks.

This addition is necessary because ordinary success responses contain only the changed resource; their complete original scope remains private. Granting read access to operation claims or reconstructing today's scope would violate the established contract. The helper's fixed search path, forced RLS, permissions, deadline checks, exact stored-success binding and post-move/post-revocation behavior require real isolated tests. Implementation and verification remain separate.

## SQLSTATE and service failure contract

Map only explicit stable SQL domain codes/known named constraints. Never translate every FK/check violation into user validation or expose a PostgreSQL exception message as public detail.

| Storage condition | SQLSTATE / explicit discriminator | Public result |
| --- | --- | --- |
| Missing current action permission | `42501`, `FORBIDDEN` | 403 `FORBIDDEN` |
| Unavailable complete current/recorded scope | `42501`, `DOMAIN_SCOPE_UNAVAILABLE` | 403 generic `DOMAIN_SCOPE_UNAVAILABLE`; no IDs/counts/issues |
| Missing/inaccessible direct resource after authorized lookup | Explicit domain/asset not-found code | Corresponding indistinguishable 404 from BUSINESS_DOMAINS.md |
| Known value/type/owner/lifecycle/plan/tree/no-op rule | `23514` plus exact adopted domain validation code | Corresponding sanitized 422; issues only for already authorized scope |
| Expected head/domain/asset/placement version or consent changed | `23514`, `VERSION_CONFLICT` or `DOMAIN_PREVIEW_STALE` | Corresponding 409 |
| Existing tenant type key | `23505`, exact tenant-domain-type-key unique constraint | 409 `DOMAIN_TYPE_EXISTS`, only after inventory authorization |
| Authorized aggregate/physical profile overflow | `54000`, `DOMAIN_PROFILE_LIMIT` | 422 `DOMAIN_PROFILE_LIMIT` |
| Lock/deadline/deadlock/serialization failure | `55P03`, `57014`, `40P01`, `40001` | 503 `DOMAIN_RETRY`, `Retry-After:5`, full rollback |
| Inconsistent stored policy/revision/projection, forged/incomplete claim, receipt/journal/success mismatch or unexpected integrity failure | Explicit `DOMAIN_STORAGE_INVALID`, or unexpected storage check/FK/unique failure | 500 `DOMAIN_STORAGE_INVALID`, sanitized correlation only |

Raw HTTP envelope, missing version/consent, cursor and idempotency failures retain their adopted 400/428/409 codes. Public errors do not contain SQL, stack, request literals, hidden references, raw epochs or permission contents. A cooperative SQL timeout does not mean the service may commit a partial result or record idempotency success on a failed transaction.

## Required isolated qualification and handoff

The following are unexecuted acceptance obligations for SQL011 and its integration, not reported test results:

- Upgrade the actual SQL010 schema and replay migrations with SQL001–010 hashes unchanged; preserve legacy snapshots/receipts/source data and verify no invented placement rows/history. Exercise reserved-namespace collisions and malformed prior state with full rollback. Inspect every new table's forced RLS, owner, ACL and composite references.
- Prove direct SQL cannot commit foreign references, wrong dependency closure, extra/missing/intermediate cohort writes, missing actual asset/domain revisions, forged receipts/children, missing/wrong journals or reserved success without sealing. Exercise GUC, trigger nesting, premature constraints, duplicate begin/seal, actor/tenant changes and both orderings of legacy standalone model/type/graph mutations with domain begin; sealed/finalized contexts still prohibit later incompatible writes.
- Prove complete mixed-version/retired and empty migrations against independently calculated actual snapshots. Reject omitted or newly bound members and inactive owners except the explicit supported repair. Test physical JSONB expansion and aggregate retained copies after authorization.
- Prove concurrent first placement, placement versus retirement, opposite hierarchy moves, publication versus new binding, complete union ordering and both membership-revocation orderings. Denied hidden scope must precede overflow/count results. Actual scanner/model/relation operations preserve additive placement and historical asset formats.
- Prove original-transaction expiry before begin after idempotency/ledger waits, phase/loop expiry, seal/finalizer expiry and service-prearmed timer cancellation. Include direct SQL with outer timer zero to establish the narrower cooperative guarantee. Check rollback of every protected write and idempotency success at late failure points.
- Prove exact journal resource kinds/versions/data, stable receipt hash attribution, original-scope historical reads and same-request replay after permission loss. Passing migration alone is not proof that the generic audit or replay paths are safe.
- Record exact source/image/SQL/tool versions, commands, timings and retained failed attempts. Run affected real API/browser/upgrade/concurrency and historical regression gates before advancing the bounded increment. All full requirement profiles, hosted checks and broader programme/release gates remain separate.

Root owns service transaction/idempotency/journal/auth integration and contract freeze. The separately assigned storage worker owns SQL011 and its real isolated upgrade/storage/concurrency tests. Pure definition adapters retain their separate ownership; UI work does not change storage formats. This document author owns no source, migration or execution-state file.

Root adopted the ordinary-write preparation/seal pair and all exact tagged request/response contracts above. There is no outstanding design approval. Source ownership is assigned separately after the preceding gates. Any later material alternative needs an explicit contract revision preserving the complete authorized union and protected original-clock context before canonical row locks, exact row/revision/journal/idempotency completeness and direct-SQL enforcement. A BEFORE ROW trigger alone is insufficient evidence of the prescribed lock order.
