# Required participation and relation operations

Implementation is in progress. The final isolated gate passes eight upgrade
checks, twenty storage tests and thirteen concurrency tests, with all 51 executed
source hashes matched at execution and the initial readback. Later API/service
corrections require fresh qualification; they are not covered by those original
hashes. The gate verifies exact SQL008-to009 preservation separately
from the forward SQL010 discovery correction and current storage/concurrency
regressions. See [the original gate report](../verification/relation-participation-upgrade.json)
and [the retained failure and review record](../verification/relation-scope-discovery-review.json).

SQL001–010 are applied and immutable. SQL010 was applied to local core at
2026-11-15T23:09:01.017Z; all ten migration checksums match. The API, workflow and
site image for the passing API gate is
`sha256:a46ee55375ce71f7f0c15d6da0504a835247fe2370077ea54b764e8a778066c4`.
The corrected third core API run passes all 123 cases in 100137.967837 ms, with
no failures, cancellations, skips or todos and 76 actual-image source hashes
matched. The first interrupted attempt and second three-failure run remain
recorded in [the API evidence](../verification/m2-relation-participation-api.json).
The first targeted browser attempt failed both journeys on undersized nested
evidence controls before screenshot capture; correction and retesting are pending.
Real-time preparation expiry is running, and hosted qualification remains pending.
These separate gates are not established by the API pass. Consult
[STATE](../execution/STATE.md) for subsequent execution records.

Run the isolated gate first; advance to the running services only after it passes:

```sh
./dev test --suite relation-participation-upgrade
./dev up --profile core
./dev test --suite security
./dev test --suite relation-preparation-expiry
pnpm exec playwright test tests/e2e/relation-migrations.spec.ts
```

The upgrade command creates only its own disposable local PostgreSQL container,
uses existing pinned images, applies the actual checksum migrator and runs real
runtime-role storage/concurrency tests. It preserves earlier data/history and
archives each failed diagnostic separately. No production volumes or unrelated
containers are used. A failed test, skipped case or changed source
snapshot prevents a passing qualification. Core application follows this gate.
Run heavy qualification jobs serially and stop below 2 GiB free disk space.
Never edit an applied migration to resolve a failure; use a reviewed forward
migration and repeat the isolated gate before applying it to core.

The expiry command requires the matching core image, SQL001–010 and seeded synthetic
personas. It takes at least fifteen real minutes and has a twenty-three-minute
outer limit. It observes database time without changing the lease or protected
rows. It verifies unused-preparation expiry, creator isolation and completed
operation retries after expiry. Capture the actual image, source hashes and TAP
result separately; the isolated upgrade gate does not qualify this command.

Create a relation preparation for a new format-two type, then capture its complete
graph context. The preparation reserves an identity for fifteen minutes; retries
return the original expiry. An expired, unused preparation returns 410 and requires
a new reservation and preview. A completed operation retry returns its existing
receipt after reauthorization; it does not renew the preparation. Historical
format-one types retain their zero-minimum participation behavior. Edit the
complete plan in the visual editor or strict declarative JSON.
Include a disposition for every live edge/binding of each explicit type, and
review zero-edge required participants. Positive requirements may require joint
asset assignments and initial assertions in the same operation.

Preview must report ready with no blocking issues before execution. Changing a
definition, plan, cohort or principal eligibility invalidates consent. Reuse the
same idempotency key only with the identical original request. A retry with altered
content is a conflict; a stale preview requires a fresh context and preview. A
failed operation must leave canonical data, revisions, audit/outbox and success
records rolled back together. Sanitized failed-attempt audit is separate.

Read the immutable operation receipt to inspect actual before/after revisions,
policy pins, created identities and replacements. Readers need current access to
the whole original operation, including predecessor subjects. Nested type receipts
inherit that boundary. Forward repair references the original receipt and targets
part of its original scope; it creates new history and never rewrites a receipt.

The bounded profile allows at most eight explicit relation targets, eight nested
typed targets, one thousand live edges, two thousand candidate assets, four
thousand bindings, one thousand changed assets and 512 KiB retained graph data.
Queries and nested work share the original thirty-second deadline. The service
sets the remaining statement timeout in a separate database command before each
operation statement. SQL010 also checks the protected original operation start
during candidate discovery and projection. The isolated controlled-delay test
verifies those cooperative discovery checks with outer timeouts disabled.

Setting `statement_timeout` inside an already running SQL function does not arm
that outer statement's timer. Inherited set-based final validation retains
phase-boundary checks; the discovery test does not prove a universal hard
thirty-second bound for arbitrary direct SQL with timeouts disabled. Preserve
the service's prearmed timer and shared deadline when adding callers. Do not
increase the budget or edit protected claims/history to force an operation
through. Limits and incomplete authorization fail before a partial result or
execution. Large durable migrations and production restore remain separate
required qualifications.
