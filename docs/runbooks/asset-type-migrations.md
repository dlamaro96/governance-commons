# Complete authored-type migrations

The bounded development service passes isolated upgrade, core API and complete 12-journey browser gates. Inspect the current-state record and evidence manifest for the exact qualified source and scope; this runbook is not execution evidence.

Open an authored asset type and choose its migration workflow. Review the proposed definition with exact parent pins. The server resolves inherited attributes and lifecycle rules. Configure attribute operations, explicit owner replacements or removals, and state mappings for each affected historical source version. Two versions can give the same state label different meanings. Review and acknowledge the actual head-to-target attribute and policy changes.

Run a complete preview. It must include every directly bound asset visible to the operator; hidden assets fail the entire operation. Inspect before/after attributes, owners, state, pins and revision numbers. A missing or inactive required source owner needs an explicit eligible replacement, or an acknowledged target policy that removes required ownership. Explicit non-null replacements always require an active identity and tenant membership. Corrupt source attributes and lifecycle states cannot be silently repaired by this operation.

Confirm the exact preview digest to execute. The resulting receipt contains the full plan, source resolutions and immutable before/after tuple hashes. Check the linked asset revisions and audit history. Parent migration preserves child definitions, their parent pins and their assets. Exported files contain the values the operator could read; store them using the same access controls as the corresponding data.

If execution reports a stale scope, reload current versions and cohort, retain the intended draft changes, review new acknowledgements and generate a fresh preview. A retryable lock-window error rolled back the transaction; retry using the same idempotency key. A successful replay returns the existing receipt only while the original cohort remains authorized. Do not edit receipt rows or immutable migrations to force a retry.

Developer gates:

```sh
./dev test --suite type-migration-upgrade
./dev up --profile core
./dev test --suite security
pnpm exec playwright test --config .github/playwright.ci.config.ts
```

The first command uses a disposable PostgreSQL namespace with no ports or production volumes. It validates the 006-to007 upgrade, legacy preservation, restricted-role storage invariants and concurrent revocation orderings. It requires the existing cached application and pinned PostgreSQL images, and stops below the documented disk floor. Local source mounts and exact dependency-manifest checks are recorded separately from execution against the rebuilt core image. Raw diagnostics stay in ignored `.local/evidence`; publish only reviewed summaries.

Rollback means transaction rollback before commit. A committed migration is repaired with a new reviewed forward migration. These checks do not establish production restoration or high-availability readiness.
