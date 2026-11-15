# Inherited asset-type increment contract

Status: implementation contract for the next verified increment, not capability completion. Parent programme MOD-001/002/003, SYS-DATA-001/002 and later glossary/reference work remain binding. Existing formatVersion1 attribute models and their hashes remain unchanged. Applied SQL001–005 is immutable.

## Authored and resolved definitions

A new, distinct asset-type file has `formatVersion:1`, `id` (existing safe64-character model key), positive integer `version`, `parents:[{id,version}]`, `attributes` (the existing typed attribute grammar), `overrideAttributes:string[]`, `requiredOwner:boolean`, and `lifecycle:null|{initial:string,states:string[],transitions:[{from,to}]}`. Every field is required, unknown fields fail, and raw JSON imports retain duplicate-key detection. This format is an authored asset-type definition, not an extension of the existing attribute-model file.

Parents are exact immutable asset-type version pins, never moving heads or arbitrary attribute models. Up to8 immediate parents,64 distinct transitive definitions and8 ancestry levels. Reject duplicate pins/logical IDs, cyclic logical ancestry, inconsistent versions of the same ancestor and unknown dependencies. A diamond sharing the same ancestor pin is valid. Dependency ordering is deterministic. Authored attributes use the existing pure validator without coercion or precision loss.

Resolved attributes combine parents and local fields. Equal inherited fields may coalesce. Conflicting inherited fields require an explicit local field. `overrideAttributes` must exactly enumerate local keys that replace inherited keys, even when equal. It cannot name an absent local or inherited key. The resolved attribute model is revalidated against all existing size/depth/property limits. Required ownership is inherited with logical OR and cannot be weakened. Explicit lifecycle replaces the inherited lifecycle; null inherits only a single unambiguous effective lifecycle and is invalid at a root. Lifecycle has1–32 safe identifiers, an initial state in that set, at most256 unique non-self directed transitions with both endpoints in the set. This supported policy is recorded explicitly; scoped overrides, non-owner responsibilities and full relation/domain/attribute-type programmes remain open.

The domain module `asset-type.ts` exports interfaces `TypePin`, `LifecycleDefinition`, `AssetTypeDefinition`, `ResolvedAssetType`, plus `parseAssetTypeDefinition(input)`, `parseAssetTypeFile(text)` and `resolveAssetType(input, dependencies)`, returning the existing ValidationResult shape. `ResolvedAssetType` contains `definition`, `dependencies:TypePin[]` (transitive, excluding root), `model:ModelDefinition` (fully resolved), `requiredOwner:boolean`, `lifecycle:LifecycleDefinition`. Resolution is pure and accepts supplied authored dependency definitions, never performs IO.

## Persistence and invariants (root-owned)

New SQL006 creates immutable tenant-scoped `asset_type_versions` and `asset_type_dependencies` referencing actual governance model versions. Each authored version stores its resolved attribute-model hash, required-owner/lifecycle constraints and resolution digest. Model heads receive an immutable opaque type UUID for authored asset types; existing logical keys remain compatible. The existing model-version row stores the resolved formatVersion1 attribute model. Direct legacy model publication/migration must reject authored asset types, requiring the asset-type service. Reads may show the resolved model. Asset assignment and ordinary owner edits enforce the pinned authored constraints, including fresh active owner membership. Same-type reassignment preserves lifecycle state; a different type starts at its initial state. An explicit state transition follows the pinned lifecycle, with optimistic version and normal audit/outbox/revision writes. Ownership does not confer permission.

Every service reauthorizes current membership and uses tenant ledger → model lock → model head → deterministic asset lock order. Creation/publication, exact parent references and journals commit together. Publication preserves existing child/asset pins. Preview enumerates the complete visible bounded cohort, validates proposed resolved attributes and constraints, and binds parents, head, canonical versions, owners and lifecycle into its digest. Destructive schema changes or invalid target constraints fail publication; explicit inherited-type migration remains required next work, not silently delegated to the attribute-only migration path.

## API/UI contract

All prefixes are `/api/v1`. Authentication/CSRF/Problem Details/If-Match/Idempotency-Key conventions are unchanged. models:read reads types; models:write authors; catalog:read is required for preview and catalog:write for assignments/transitions.

- `GET /asset-types?limit=&cursor=&q=` returns `{items:[{id,currentVersion,createdAt,createdBy,typeId}],nextCursor}` with signed bounded keyset pagination.
- `POST /asset-types/validate {text}` returns `{definition}` (strict file parse; dependency resolution occurs in preview/create).
- `POST /asset-types {definition}` returns201 `{type}`; initial version1 only.
- `GET /asset-types/:id[/versions/:version]` returns `{type}`.
- `POST /asset-types/:id/previews {definition}`, If-Match, returns `{preview}`.
- `POST /asset-types/:id/versions {definition,previewDigest}`, If-Match and Idempotency-Key, returns201 `{type}`.
- Type view: `{id,typeId,version,currentVersion,definition,resolved:{model,requiredOwner,lifecycle,dependencies},definitionHash,resolutionHash,createdAt,createdBy}`.
- Preview: `{typeId,modelId,currentVersion,proposedVersion,assetCount,coverage:'complete-tenant-model-bindings',changes,assets:[{assetId,currentIssues,proposedIssues}],requiresExplicitMigration,compatibleWithProvidedAssets,pinsPreserved:true,previewDigest}`.
- `GET /assets/:id/type-state` returns `{assetId,assetVersion,modelId,modelVersion,state,requiredOwner,lifecycle}`; untyped/attribute-only assets have null state/lifecycle and requiredOwnerfalse.
- `POST /assets/:id/type-state {state}`, If-Match and Idempotency-Key, returns the same shape after an authorized transition.

Browser routes `/asset-types`, `/asset-types/new/definition`, `/asset-types/:id`, `/asset-types/:id/edit`. Model list links authored types to the type page; asset chooser still uses resolved definitions. Asset detail displays pinned lifecycle and allowed actions with the normal permission/error states. File export preserves authored definitions. UI supports visual parents/overrides/owner/lifecycle editing, raw file roundtrip, resolved inheritance evidence, stale-preview recovery, required-owner denial, immutable parent/child pins, English/Arabic, keyboard, light/dark and responsive behavior. Do not expose a misleading attribute-only migration action for these types.

## Ownership and qualification

Root owns SQL006, shared persistence/service/API/legacy enforcement and central records/CI/Git. Domain worker owns only new pure `asset-type.ts` and unit tests. Web worker owns `apps/web/**`, route inventory and new browser tests. Integration worker owns new `tests/integration/asset-types.test.ts` against this contract. All workers preserve others' edits; contract changes require coordination.

Meaningful gates include pinned parent upgrades preserving old child/asset behavior, explicit child preview and compatible publication, cycle/conflict/ambiguous-pin denial, inherited required-owner enforcement through assignment and ordinary edits, illegal transitions, stale digests/If-Match, hidden-cohort refusal, tenant/FK isolation and late-write rollback. Tests execute against actual services; no fixture or unexecuted screen is represented as completed capability.
