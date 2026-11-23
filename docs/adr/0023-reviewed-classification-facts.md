# Reviewed classification facts from canonical approvals

Status: implemented; isolated native qualification passes all 98 cases, with
preservation, both migration replays and owned cleanup. Content authority remains
inactive. Core qualification passes all 172 API cases and the selected real
classification browser journey. Hosted and release qualification are separate.

The authority evaluator needs classification facts whose provenance can be
verified against canonical records. A taxonomy label or a matched suggestion
alone does not establish reviewed approval. This increment joins the complete
current assignment partition to immutable evaluations, rule and taxonomy pins,
approval requests, workflows, tasks and decisions in the same database snapshot
as protected authentication, authority grants and the asset security revision.

SQL035 introduces an explicit private producer installation. Registration in an
authority registry does not by itself enable production, including a known-empty
classification partition. A native owner installs an exact active tenant-scoped
`classifications` producer using the fixed `reviewed-metadata-classification-v1`
implementation. Bind and revoke operations validate expected database, owner,
generation, authentication fence, authority epoch, registry and previous binding.
They advance the existing authority epoch atomically and append an immutable
receipt. Exact idempotent replay returns the original receipt without changing
current state. Conflicting replay, stale expectations and concurrent request
collisions fail closed.

The two new tables force RLS and grant no access to runtime roles. Installation
uses the existing sealed write binding and tenant locks. Deferred checks require
the exact receipt, current head, real epoch change and transaction identity.
Only the existing binding-completion trigger's function target changes; prior
functions, privileges and other trigger behavior remain intact. The replacement
still validates ordinary lifecycle writes and independently validates producer
writes. Receipt and head must have the same inserting transaction ID, while the
receipt separately binds the current top-level transaction and backend. This
preserves atomic provenance when the installer uses a PostgreSQL subtransaction;
comparing its row transaction ID directly with the parent would reject a valid
installation. Migration does not install a producer or activate authority.

The new repository operation uses a native-owner, read-only repeatable-read
transaction. The authenticated session determines its tenant; callers cannot
choose a producer, timestamp, source query or fact filter. It verifies complete
approval provenance, including immutable hashes, requester/reviewer separation,
distinct reviewer assignments, stage quorum, task versions, deadlines and the
published result. Unanswered tasks cancelled after quorum are valid historical
evidence. The actual assignment UUID and version identify each emitted fact;
its value is the stable label UUID introduced by SQL034.

An active assignment must still match the selected current asset metadata and
the current rule and taxonomy pins. A retired label or an assignment below its
migration identity baseline is unavailable. Any stale active assignment makes
the complete classification partition unavailable; valid siblings cannot hide
it. Withdrawn assignments retain their historical validation but emit no fact.
A known-empty partition therefore requires both an available installed producer
and complete canonical discovery.

Discovery admits counts and byte measurements before retrieving proof bodies.
The profile allows at most 256 assignment heads, 4,096 tasks and decisions in
total, and 256 of each per request. Both canonical and database JSON proof
representations must fit 2 MiB including array overhead; emitted facts fit 1 MiB.
The complete proof shares the existing context's 8 MiB physical admission budget.
No SQL limit can turn an oversized partition into a successful partial result.
The original 30-second operation deadline and finite statement, lock and idle
timeouts remain in force. A final protected-session check precedes commit.

The returned closed envelope is inactive provenance. Its digest cannot authorize
a later effect, and a repeatable-read snapshot does not claim to observe a
revocation committed after that snapshot. A held-snapshot executor, live
revocation checks, field projections and complete ingress integration remain
required before authority activation.

Qualification uses `./dev test --suite reviewed-classification-facts`. The
isolated gate preserves the populated predecessor schema, runs its original
cases before SQL035, checks exact object changes and old rows, exercises the
producer and reader, and replays migration before and after native mutations.
The 780-second execution and 90-second cleanup budgets remain inside the
900-second developer wrapper. Raw database, authentication and private harness
records are not published as CI artifacts.

The [scoped native evidence](../verification/reviewed-classification-facts-local.json)
retains three failed upgrade attempts and separate fresh-schema diagnostics. The
256-head case admits the count then refuses the oversized proof before reading
its body; it does not claim that 256 complete facts fit the byte budget. The
4,096 aggregate task/decision cap is unit-covered, with no positive native
4,096-proof qualification. Statement and lock cancellation mapping is checked
using synthetic driver errors; real cancellation at every proof query is separate.

The [integrated record](../verification/reviewed-classification-facts-integrated-local.json)
binds all 347 application/worker/build inputs to immutable images and running
services before API execution and after the browser journey. All 35 migration
checksums match; three of fourteen captures were inspected. The browser covers
the existing reviewed-classification workflow; the new private producer and fact
reader are qualified separately by the native gate.
