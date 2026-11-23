# Stable classification label identities

Status: implemented; isolated native qualification passes. Integrated and hosted qualification are tracked separately.

Classification rules need a stable label reference before their reviewed results
can become authorization facts. SQL034 adds private tenant-scoped label UUIDs,
installation baselines and immutable version bindings. Existing taxonomy
schemas, review records, assignments and their history remain unchanged.

A retained active key keeps its UUID through name or description edits. Removing
or deprecating a key permanently retires that identity. A later definition may
mention the retired key as deprecated, but cannot make it active. Authors must
publish a new key for a new classification. The API reports this authoring error
as `422 CLASSIFICATION_LABEL_RETIRED`; unrelated database details remain private.

Existing taxonomies receive a baseline at their current version. Every key found
in their historical definitions is reserved; absent and deprecated keys are
retired at the baseline. Only current-version labels receive bindings. Older
versions and assignments are preserved without inventing identity continuity:
a historically reused string key does not prove that its meaning stayed the
same. Fresh taxonomies start their baseline at version one.

Maintenance runs in the existing taxonomy publication transaction, after the
immutable definition is inserted. It verifies the current head and complete
previous binding, persists UUIDs and retirement, then binds every label. A
deferred check validates the final head, allowing multiple sequential
publications within one transaction. Any failure rolls back canonical rows,
identity data, audit, outbox, idempotency and the SQL033 content revision together.
Only the original taxonomy head mutation advances that revision.

The three sidecar tables force row-level security. Runtime roles receive no
access, and ordinary owner DML and truncation are refused. Trigger maintenance
uses fixed schema-qualified objects, derives tenant scope from the canonical
version and restores the prior tenant setting. Migration installation holds the
canonical taxonomy tables against concurrent writes and preserves prior data,
function definitions, privileges and trigger behavior.

Qualification is `./dev test --suite classification-label-identities`. The local
run passes all 50 native cases: 27 predecessor cases and 23 identity cases. It
upgrades populated SQL033, checks historical-key reservation and current-pin-only
bindings, preserves previous rows and installation boundaries, and replays without
changes. Native cases cover publication, retirement, tenant isolation, concurrent
transactions and held repeatable-read snapshots. Its existing execution and
cleanup budgets remain 780 and 90 seconds inside the 900-second wrapper.

This increment neither emits classification authorization facts nor activates
canonical content authority. An explicitly trusted producer, complete approval
provenance and held-snapshot effect execution remain separate required work.
