# ADR 0017: Reuse registry validation within one authority read

Status: accepted and applied to the local development runtime; isolated native qualification complete. Combined API/browser and hosted qualification remain open. Date: 17 November 2026.

## Context

The canonical authority loader validates every retained grant before returning an inactive candidate closure. The bounded 512-origin fixture repeatedly parses the same registry. A source-bound diagnostic measured 512 grant validations and 513 registry parses; registry parsing accounted for 15.757 seconds of inclusive function time. Hosted execution exceeded the existing 25-second SQL limit. These are separate observations, not a cross-environment performance comparison.

SQL013 is already applied and remains immutable. The read path must preserve the complete validation contract and its 25-second statement and 30-second operation deadlines.

## Decision

Add the forward migration `031_authority_read_grants.sql`. The loader calls an owner-only batch validator after admitting the complete bounded closure. It keeps one parsed registry in local function variables for the duration of that invocation.

The cache key is the database-derived tuple `(id, version, digest, registry_document)`, including the exact retained JSON document. A different tuple replaces the single entry and invokes the existing registry parser. The caller cannot provide a parsed registry. No entry survives the function call; there is no session setting, temporary table or persisted cache.

Each grant starts with fresh ancestry and beneficiary state. Beneficiary/origin cardinality, connected-parent proofs, depth and cycle bounds, temporal and scope containment, effect/delegation/control ceilings, policy parsing, human/service-action separation, projection measures and deadline checks remain in place. Policies are still parsed for every grant. The original write validator is unchanged.

The helper requires the migration owner, matching tenant context and a read-only repeatable-read transaction. It has no `PUBLIC` or application-role execution grant. The loader's signature, closure representation, hashing, resource bounds, row security and final protected-session recheck remain unchanged.

## Alternatives and consequences

Raising deadlines would hide the failing boundary. A cross-request cache would require a separate revocation and invalidation design. Caching policy results or changing canonical JSON would broaden this repair beyond the measured registry cost. The single local entry removes repeated registry parsing while keeping those concerns out of scope. Alternating registry keys can still cause reparsing; bounded correctness takes priority over maximizing cache hits.

The authority foundation remains inactive for content authorization as described in [ADR0014](0014-inactive-canonical-authority-foundation.md). This migration does not activate scoped policy enforcement, supply missing runtime fact producers, or establish PostgreSQL/OpenSearch decision equivalence.

## Qualification

Two isolated PostgreSQL gates passed against their recorded sources:

- SQL001–013 followed by SQL031: 133 cases, including the original authentication/authority assertions and ten new cache regressions.
- SQL001–030 followed by SQL031: 423 cases, including current quality suites before and after the upgrade, authority regressions, table/ledger/privilege preservation and inert replay.

Both retain the original deadlines and verify source bindings and owned-resource cleanup. The new cases cover complete old/new closure equivalence, repeated and alternating keys, invocation isolation, corrupt registry/policy/grant data, and role/tenant refusal. This is evidence for the forward migration, not a pass for the historical SQL013-only loader gate. Earlier failures remain retained.

SQL001–031 is applied to the local development runtime at `514ddee`, with running-image source readback. The integrated tree includes later CI, documentation and qualification-wrapper changes. Recorded native manifests retain those differences rather than being described as byte-identical current executions. The API regression currently fails in a business-domain test process and is under investigation; the volume target passes, while full 37 browser and fresh hosted checks remain separate prerequisites. The predecessor full 36 browser pass does not qualify the new increment.
