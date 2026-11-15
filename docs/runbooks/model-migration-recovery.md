# Model migration and recovery

This runbook covers the bounded synchronous attribute-model migration development profile. Full operating-model, bulk migration and release recovery qualification remain open.

## Prepare and execute

1. Sign in with current model and catalog read/write permissions. Open the model's explicit migration screen. The server loads the complete authorized cohort and its actual pinned versions; inaccessible or oversized scope stops the operation.
2. Create the next definition, specify typed transformation operations and acknowledge each destructive schema change. Exported model and plan JSON preserve exact types and decimal strings. Review imported files before use; parsing rejects duplicate keys and executable extensions.
3. Run preview. Inspect the exact asset count, source/target pins, changes and before/after values. A successful preview represents the complete bounded cohort, not a sample.
4. Confirm the displayed preview. Execution sends its digest with the expected head and an idempotency key. Any edited definition, plan, binding or asset version requires a new preview. Keep the resulting immutable receipt identifier and correlation identifier with the change record.

## Failure before commit

Invalid source/target values, inaccessible scope, exceeded limits and stale digests stop the operation. The transaction aborts if any later revision, receipt, audit or outbox write fails. The tested late-failure case injects a journal failure after receipt insertion and asset updates, then verifies the old head, pins, values and all journals remain unchanged. This is a deliberate real-PostgreSQL fault test, not a production incident.

Reload the current model and affected assets. Correct the plan or permission problem and run preview again. An aborted transaction does not reserve a successful idempotency result; the corrected operation may retry. If the request timed out after a possible commit, retry the identical request with its original key or inspect the receipt before proposing another migration. A changed request under an already successful key conflicts. A denied replay does not mean the original migration rolled back.

Failure audit contains a sanitized code and attempt result. It omits raw values and plan literals. If writing that separate failure audit also fails, the API logs only the correlation identifier and a redacted failure-audit event; investigate service availability using that identifier.

## Recovery after commit

A committed migration is immutable. An old application image does not undo schema or data. Use a new explicit forward migration from the current head when the required repair data is available and validated. Removed values are not recoverable from receipt hashes; immutable asset revisions may contain prior values subject to authorization, but automated reconstruction/forward-repair orchestration is not qualified in this increment.

Do not perform a production migration that depends on an untested restore procedure. The programme still requires a clean-environment backup/restore drill, supported previous-release upgrade checks and large-cohort durable recovery. Their absent evidence remains a release gate.

## Historical receipt integrity

The pre005 local direct-service fixture once omitted the initial asset revision. SQL005 preserves those original receipts and records explicit immutable legacy exceptions for missing references; it does not invent snapshots. Such receipts fail verification. New receipts require tenant-scoped references to both actual revisions and model versions, and corrected fixtures create the initial history. A fresh installation has no inherited legacy fixture exceptions. Any other malformed historical receipt must stop migration for investigation rather than be silently accepted.

The documented `./dev test --suite model-upgrade` command creates a disposable isolated PostgreSQL instance, applies real001–004 migrations, introduces explicitly synthetic complete and legacy-gap receipts, and applies005. It checks forced-RLS tenant backfill, replay without changes, fail-closed rollback for malformed historical identity, forged nested-trigger rejection and duplicate-reference rejection. It removes only its own disposable container. This development-schema check is not a released-predecessor or production restore qualification.

Use the receipt API and the evidence manifest for verified outcomes. Do not treat a raw database receipt row, a static screen or an unexecuted test as migration qualification.
