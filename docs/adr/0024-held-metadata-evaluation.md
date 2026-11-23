# 0024: Evaluate canonical metadata authority inside the held snapshot

Status: implemented; isolated native qualification passed 140/140 cases on
2026-11-23. The [local qualification record](../verification/held-metadata-authority-local.json)
binds the exact 281 source files in the working tree. Integrated qualification is tracked
separately in the current-state record. Content authority remains inactive.

The reviewed-classification reader provides canonical facts, but a detached
context cannot authorize a later operation. The next integration must compose
the decision and invoke the reference evaluator before releasing the same
native-owner, read-only repeatable-read transaction.

`evaluateHeldHumanAssetMetadata` accepts only a protected session hash, asset ID
and expected asset version. Canonical membership determines tenant and subject;
the action is fixed to `asset:metadata.read`. The installed registry must contain
one supported human adapter and intent guard, each with the canonical asset
visibility ceiling, asset placement and forbidden dependency elevation. Other
profiles refuse explicitly. No request may supply a registry, adapter, subject,
clock, producer, proof or permission result.

Composition retains the complete candidate and issuer closure. Scope anchors
come only from the selected asset and its actual domain ancestry. Reviewed
classifications come from the installed SQL035 producer; unavailable tags,
purpose and environment remain unavailable. Missing proof is never invented.
The actual evaluator runs before the final protected-session check and commit.

The context, producer snapshot, full private source proof, composition and
evaluation share one aggregate byte/node admission budget. The original
30-second operation deadline spans database reads and synchronous computation.
Statement, lock and idle transaction limits remain unchanged. Refusals roll
back and destroy the connection, returning fixed errors without source details.

The returned envelope explicitly says `contentAuthority: false`. Its decision
is diagnostic and grants no post-commit capability. Repeatable read preserves
one coherent snapshot; it does not observe a later committed revocation. Actual
effect delivery, current revocation fences, field projection and all-ingress
integration remain separate prerequisites for activation. The known-empty
producer lifetime is not advertised as a reusable decision-cache deadline.

## Forward scope correction

Integration exposed a literal scope-direction mismatch in the original storage
guards. SQL036 aligns the grant's own scope with its effect ceiling, requires
onward scope inside both, and checks connected scopes and lifetimes against
the parent's grant, effect and onward ceilings. The canonical rule that an
effect lifetime stays inside its own grant remains stronger than the generic
evaluator's interval intersection. Applied SQL001–035 stay immutable.

SQL036 replaces exactly three function bodies. It changes no data, table,
trigger, policy, role, ACL, activation state or function identity. Before
replacement, a bounded atomic preflight checks every tenant's lifecycle-active
grants, including future and expired grants and their retained ancestors.
NOWAIT locks exclude writers of the checked facts. An incompatible active graph
refuses the entire migration; an administrator must explicitly revoke the
incompatible grant under the old contract before retrying. Revoked unreferenced
history remains retained and cannot authorize a new connected chain.

Installation ceilings are 30 seconds, 10,000 tenants, 100,000 active roots and
1,000,000 visited rows. These are refusal limits, not qualified throughput.
The isolated gate uses `./dev test --suite held-metadata-authority`, preserves
the populated SQL035 predecessor and checks actual migration, rollback, lock
contention, cross-tenant scanning, retained history and held evaluation. It
retains the 780-second execution and 90-second cleanup budgets inside the
900-second wrapper. The completed native run passed preservation and replay
checks for all 147 canonical tables, the exact three function replacements and
owned-resource cleanup. The actual 2MiB source-proof boundary passed native
qualification; overflow of the 8MiB aggregate and node limits remains covered
only by synthetic-query unit controls.
