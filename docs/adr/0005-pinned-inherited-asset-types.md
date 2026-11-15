# ADR 0005: Pinned inherited asset types

Status: accepted for the development implementation. Verification is recorded separately in the evidence manifest. Full MOD-001/002 and M2 remain open.

## Decision

Keep the existing formatVersion1 attribute model unchanged. An authored asset type is a separate strict format containing exact parent version pins, local attributes, explicit override declarations, required ownership and a lifecycle. Its immutable resolved attribute model is stored in the existing model-version table, alongside companion authored and resolved metadata. A type has an immutable opaque UUID as well as its human-readable logical key.

Resolve inheritance deterministically using a pure shared domain module. Equal inherited attributes coalesce; conflicting fields require an explicit local override. Overrides must name exactly the local fields that replace inherited fields. Reject logical cycles, mixed ancestor versions and ambiguous inherited lifecycles. Required ownership is inherited with logical OR. An explicit local lifecycle replaces the inherited lifecycle; a null lifecycle inherits only an unambiguous parent policy. Ownership does not grant authorization.

Bound immediate parents to8, distinct transitive parents to64, ancestry to8 edges, lifecycle states to32 and transitions to256. Existing typed attribute limits still apply to the resolved model. File, graph materialization, complete-cohort preview and issue budgets fail explicitly rather than returning partial results. No evaluation, coercion or dynamic code enters resolution.

SQL006 adds forced tenant RLS, immutable authored versions and normalized composite tenant/version references. The database checks the exact dependency closure against each parent's immutable resolved metadata, retaining correctness for parent/child rows in the same SQL statement before AFTER-trigger projections exist. It preserves required ownership and lifecycle inheritance and requires matching authored metadata for every flat model version of a type. Existing untyped and attribute-only assets remain compatible. Applied migrations are never rewritten.

Publication stores exact parent pins. Updating a parent head cannot move an existing child or asset. Compatible child publication leaves old asset pins intact; a user explicitly reassigns an asset to a later version. Reassigning the same logical type preserves lifecycle state. Assigning a different type initializes its lifecycle. Existing attribute assignment, ordinary owner edits and explicit lifecycle transitions enforce pinned constraints. Direct legacy model publication and attribute-only migrations reject authored asset types.

The application uses the existing tenant ledger, model and asset lock order. Previews enumerate the complete bounded authorized cohort and bind canonical versions, parent pins, values, owners, owner activity and lifecycle states into a digest. Hidden cohorts fail closed. Mutations and immutable revisions, audit events and outbox entries commit together. Idempotent replays recheck current permission and asset visibility after waiting for their locks. Stored resolutions are hash checked and recomputed from exact authored parents before assignment and lifecycle operations.

## Consequences and remaining work

The companion format preserves existing model files and receipt history while providing actual inheritance, owner policy and lifecycle behavior. It introduces a second immutable representation that must remain consistent; database constraints, domain recomputation and rollback tests enforce that boundary.

Destructive authored-type changes and target policies incompatible with existing assets remain blocked pending complete explicit type migrations. Attribute-only migration execution cannot silently drop ownership or lifecycle constraints. Relation/domain/attribute type authoring, relation cardinality, scoped overrides, additional responsibility roles and enforcement through future workflow/import/MCP ingresses remain required implementation work. Optional runtime activation does not remove those requirements.

See the [shared contract](../execution/INHERITED_ASSET_TYPES.md), [current state](../execution/STATE.md) and [evidence manifest](../verification/evidence-manifest.json). Synthetic Docker qualification is distinct from released-version upgrade, vendor-live, enterprise and release qualification.
