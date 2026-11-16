# Required participation and relation operations

Implementation remains in progress. The latest graph copier correction passes
[204 pure tests and typechecks](../verification/relation-participation-graph-copy-pure.json)
with 115 source hashes, plus [eight upgrade checks, twenty storage tests and
thirteen concurrency tests](../verification/relation-participation-graph-copy-upgrade.json)
with 51 source hashes. Historical execution records remain unchanged.

SQL001–010 are applied and immutable. SQL010 was applied to local core at
2026-11-15T23:09:01.017Z. The sixth rebuilt core API gate passes all 123 cases in
131897.250185 ms with zero failures, cancellations, skips or todos. Its 76
actual-image source hashes match API/workflow/site image
`sha256:2522b4c06fb2c1725f717d59134907bd74b020cbc15d56d8340daf14dbc7eae5`.
The [API report](../verification/m2-relation-participation-api-graph-copy.json)
retains the exact private sixth-attempt archive and earlier diagnostic outcomes.

The [real preparation-expiry gate](../verification/m2-relation-participation-expiry.json)
passed one case in 900531.036454 ms on the earlier image, with 82 executed files
bound to commit `46d5b57ca8ba102ee4939f98fce85f0d41ce9998`. Later copier corrections
are outside that historical wall-clock snapshot; no later-source expiry result
is inferred.

The first three targeted browser runs retained failures in control size,
accessible-name composition and phone history overflow. The fourth passes both
journeys after narrow corrections; all sixteen resulting screenshots were
inspected. A positioned table container now contains its absolute screen-reader
labels, preserving both accessibility and horizontal table scrolling. The full
sixteen-journey gate passes against the later graph copier image, with zero
failures, skips or retries and 139 source hashes plus 22 served assets matched.
All sixteen final screenshots were inspected; see the [UI report](../verification/m2-relation-participation-ui.json). Original screenshots and reports remain archived. Hosted
participation qualification remains open. Draft PR16 needs its main-branch
conflict reconciled with histories preserved. Consult [STATE](../execution/STATE.md)
for subsequent qualification and source binding.

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
Archive the original execution report and log under ignored evidence before
rerunning, with a SHA256 manifest and exact image/source bindings. Publish only
the scoped summary. A subsequent commit binding does not constitute a rerun,
and a changed parser or service is not qualified by the earlier wall-clock result.

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
