# Inherited asset-type development operations

The Asset types workspace authors immutable type versions. Select exact parent versions, declare local overrides, choose whether ownership is required, and define or inherit a lifecycle. A parent publication never repins existing children or assets. Exported files preserve authored definitions; the resolved view shows inherited fields and exact dependency pins.

Before publishing a new version, preview its complete authorized asset cohort. A changed asset, owner, owner activity or lifecycle state invalidates the preview digest. Reload and review a fresh preview before confirming. The editor retains a last valid draft when a raw import fails validation. Destructive schema changes or incompatible target constraints remain blocked; the attribute-only migration editor cannot bypass a type policy.

Assign a pinned type version from an asset's attribute editor. A required owner must be an active identity and member of that organization. Clearing that owner is rejected through the ordinary ownership form as well. Same-type reassignment preserves the asset's lifecycle state; a different type starts in its initial state. Use the Lifecycle panel for allowed transitions. Concurrent edits return a version conflict and require reloading. Ownership alone provides no new permission.

```sh
./dev up --profile core
./dev test --suite security
./dev test --suite asset-type-upgrade
```

The upgrade command uses an isolated PostgreSQL container with no published ports or production volumes. It applies the actual checksum migrator, preserves a pre006 legacy model/asset/revision, checks replay and runtime roles, and executes storage invariants against the non-owner runtime role. It must report failure for unexecuted, skipped or failed checks. The broader security suite runs actual API and domain mutations against the core services. The required hosted browser gate also includes inherited-type authoring and asset lifecycle journeys.

No rollback rewrites or deletes an applied schema migration. An application transaction that fails before commit must leave type heads, versions, normalized references and journals unchanged; retry only with a fresh preview and idempotency key when the intended request changes. Unexpected stored-policy verification failures require investigation and a reviewed forward repair, never a permissive fallback. Existing migration receipts retain their own integrity and historical exception rules.

The exact executed status and image/source evidence live in the [manifest](../verification/evidence-manifest.json). This development runbook does not claim disaster recovery, released-version upgrade or full authored-type migration qualification.
