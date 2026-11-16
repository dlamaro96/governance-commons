# ADR 0008: Required participation and atomic graph operations

Status: accepted design; implementation in progress; runtime qualification pending.

Required participation cannot be enforced by counting existing edges alone. An
eligible asset with no edge still has an obligation, and changing a type, asset
pin or lifecycle can change that obligation. The complete specification remains
the release target; these transactional limits define a development profile.

Use explicit, stable participation identities with immutable revisions. Relation
format two supports minimum and maximum degrees, including zero maxima. Existing
format-one definitions retain their original meaning. Positive requirements
derive participation from the complete eligible asset set under actual nominal
ancestry and state, including assets with no edges. Degree counts all live edges
independently of display-time validity filters.

An explicit graph operation combines relation publication, edge dispositions,
binding enrollment/repinning/release, direct asset assignments/transitions and
complete typed migrations. Capture and authorize the entire affected graph before
returning counts, limits or diagnostics. Preview binds exact policy and asset
pins, principal eligibility, complete before/final projections and normalized
intent. Execution recaptures this scope and rejects stale consent.

PostgreSQL independently derives protected operation claims from the original
request and a narrowly normalized semantic plan. Neither a digest, a caller-set
session variable nor nested trigger depth grants authority. Claimed canonical
writes must consume their exact permissions once; actual immutable snapshots,
paired audit/outbox records, receipt references and idempotency success must all
exist before deferred finalization. Applied SQL001–008 are immutable. SQL009
requires isolated upgrade/storage/concurrency qualification before core use.

The application takes idempotency, tenant ledger/model scope, canonical model and
relation heads, assets, edges, bindings and one sorted principal union in that
order. The original deadline bounds nested work. Pre-operation endpoint versions
express creation intent; the final graph observes final endpoint versions.
Preserved rows retain their own canonical/history versions. Tombstones precede
successor inserts so immediate live-pair uniqueness permits same-pair replacement.

Operation receipts authorize every original subject on every read, including
removed edges and nested typed receipts. Participation pages authorize their
complete degree scope before pagination; history also authorizes each original
operation. Opaque keyed fences and purpose/actor/query-bound cursors avoid exposing
raw revision counters. Preparations are creator-only and retain their original
fixed expiry across retries.

Consequences: the development profile fails explicitly beyond its documented
asset/edge/byte/time limits, with no partial migration. Durable large operations
and every remaining programme capability still require implementation and separate
qualification. See [the full contract](../execution/RELATION_PARTICIPATION_MIGRATIONS.md)
and [the runbook](../runbooks/relation-participation.md).
