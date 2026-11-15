# ADR 0004 — Explicit transactional model migration

Status: accepted for the bounded development profile; executed browser and storage evidence is tracked separately from full programme qualification.

A compatible publication preserves existing asset pins. A destructive change needs an explicit transformation and a fresh preview of every bound asset. Silent reinterpretation would lose precision, hide inaccessible assets or leave different ingress paths with different rules.

Use one bounded declarative migration plan and one shared application service. Plans specify exact source pins, target version, destructive acknowledgements and ordered typed operations. Exact decimal strings never pass through floating-point conversion. The service validates every source and transformed value, then binds the plan, target definition, historic definition hashes and complete canonical asset versions/hashes into a preview digest. The UI displays authorized before/after values and requires confirmation of that exact preview.

Execution reacquires the common tenant ledger/model locks and canonical rows, rechecks active permissions and complete visibility, recomputes the digest, and commits the definition, pins, revisions, receipt, audit and outbox in one PostgreSQL transaction. Runtime roles remain non-owning and subject to forced RLS. A receipt remains protected by the original affected assets even after reassignment. Idempotency does not bypass current authorization.

The synchronous profile is deliberately bounded to1000 assets and512KiB of aggregate input/output attributes, with independent node and historical-definition limits. These limits make transaction rollback a concrete recovery path. A larger cohort fails before writes. Resumable Temporal execution and measured concurrency are still required; they cannot be inferred from this small transaction profile.

An unsuccessful request is different from an unsuccessful canonical migration. A denied replay can refer to an already committed receipt. Record a sanitized attempt failure separately, without claiming rollback of the prior commit or persisting plan literals in broadly visible model audit events.

SQL004 preserves immutable receipts. SQL005 strengthens plan/column identity and tenant-scoped references from each receipt asset to its actual before/after revisions. The local pre005 direct-service fixtures exposed missing initial revisions. Existing immutable history must not be fabricated or deleted to conceal this gap. The upgrade records narrowly scoped legacy exceptions for those missing references, and receipt reads fail closed for incomplete normalization. Newly inserted receipts must have complete references. Fresh installations do not inherit these development-fixture exceptions. The corrected fixture creates its initial revision before exercising migration.

This decision supports transactional rollback before commit and explicit subsequent forward migrations after commit. It does not support deleting a committed version, reinstalling an old image to undo data, or promising restoration of removed values from hashes. Production backup/restore and previous-release upgrade qualification remain separate open gates. See the recovery runbook for the supported boundary.

Revisit when implementing durable large-cohort migrations, relation/inheritance migration, field-sensitive policies, measured tenant concurrency and a supported released predecessor. Preserve the same application-service authorization and immutable receipt contracts.

Model inventory growth also requires bounded discovery. Use signed keyset cursors with tenant, actor, query, page-size and deterministic-sort binding, fresh authorization on every page and literal search escaping. Signing does not grant access and rotation restarts pagination. This development inventory is a live view, not a snapshot or a qualified cross-service pagination system. The HMAC/constant-time primitives follow the [Node24 crypto API](https://nodejs.org/docs/latest-v24.x/api/crypto.html).
