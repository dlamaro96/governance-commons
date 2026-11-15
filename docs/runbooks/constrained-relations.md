# Constrained asserted relations

The bounded implementation passes its local API, upgrade and browser gates; hosted checks are pending. Consult STATE and the evidence manifest for the exact executed source; this runbook is not evidence of a passing test.

Create authored endpoint asset types first. Under Models → Relation types, define endpoint type rules, optional allowed states, directed or undirected structure, maxima and cycle policy. Add relation-owned fields, ownership and lifecycle. The visual and JSON editors share validation. Imported definition files reject duplicate keys and unknown fields; export preserves exact decimal strings. Required participation with a positive minimum is not yet implemented and fails explicitly.

Open an asset's Relations tab to assert a relationship. Select visible endpoints and a current relation-type version, enter fields, an eligible owner and optional canonical UTC validity interval. Restricted edge membership does not grant access to either endpoint. After saving, inspect the exact type pin, current endpoint revisions, asserted provenance and immutable history. An edge may transition only through its pinned lifecycle. Removal creates a tombstone; reasserting the pair creates a new identity with separate history.

Publication requires a fresh complete preview. Compatible labels/fields preserve old edge pins. Structural policy or destructive field changes with live edges are blocked until explicit relation migration is implemented. Hidden edges needed for validation cause a generic scope refusal before counts are exposed. Asset lifecycle/assignment and complete type migrations also check surviving relations; a rejected change leaves assets, relations and journals unchanged.

The graph applies type, direction and business-validity filters before expansion. Omitted graph validity freezes to the first page's instant; the ordinary relation table without a date includes all live dates. Expand a visible node or reduce depth/filter if the bounded traversal is too large. The table is an accessible equivalent. A stale graph/list cursor requires restarting; its opaque revision is neither a count nor a permission grant. Transaction-time historical graphs remain required future work.

Retryable lock errors roll back and return503 with Retry-After5; retry a mutation using the same idempotency key. Stale versions or previews require reloading current state and reviewing the preserved draft. Do not alter immutable SQL, history or graph counters to force a retry. Source rescans, rename, empty or failed scans must preserve asserted edge ownership, values, dates and history.

Developer gates:

```sh
./dev test --suite relations-upgrade
./dev up --profile core
./dev test --suite security
pnpm exec playwright test --config .github/playwright.ci.config.ts
```

The isolated upgrade creates a disposable local PostgreSQL namespace with no exposed ports or production volumes. It uses pinned cached images, source mounts and exact dependency-manifest checks; it records these separately from rebuilt core API execution. It tests 007→008 preservation, checksum replay, forced RLS/runtime privileges, storage invariants and actual concurrency. Stop below the2GiB free-disk floor. Raw diagnostics remain private under ignored .local/evidence; publish only reviewed summaries. The historical006→007 harness retains its original storage checks and explicitly records later schema additions before testing current services.

Required adjacent work includes participation/minima, explicit relation migrations/repair, inheritance/scoped overrides, imported/derived claims, authorization grants, all other required ingress adapters, temporal graph reconstruction and production upgrade/restore qualification.

The synchronous service checks a shared monotonic30-second operation budget between bounded calls and before commit, with a five-second maximum lock wait. Nested calls do not reset the budget. A multi-query legacy journal block can exceed the elapsed deadline before the final rollback check; this is not a hard30-second wall-clock cancellation guarantee.
