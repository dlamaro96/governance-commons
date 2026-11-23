# ADR 0016: Fixed CI groups on independent runners

Status: accepted and integrated in the local working tree; hosted qualification of the 45-outcome configuration is pending. Date: 17 November 2026.

## Context

The serial behavior job has a 90-minute limit. Retained local measurements total about 99 minutes for a subset of its work, before cold installation and several current gates. These measurements span different revisions and are not a hosted benchmark. Running isolated database gates concurrently on one Docker host would violate their resource-inventory checks.

## Decision

Run five fixed groups on separate GitHub-hosted Ubuntu runners: foundation, governance, quality basics, freshness/volume and browser. Each independently bootstraps, starts, verifies object storage and seeds synthetic services. The current mapping has 45 mandatory stage outcomes and keeps the sequential 37-journey browser graph together, with no retries. Each job retains its 90-minute limit; product and test-operation deadlines remain unchanged.

Seven explicit repaired-chain commands replace the corresponding historical CI obligations one-for-one; two standalone SQL032 scopes add the remaining outcomes to the preceding 43-outcome mapping. Historical commands remain available with their original schema meaning and are recorded as `HISTORICAL_NOT_EXECUTED` in the new mapping. They cannot substitute for repaired results. See the [operating runbook](../runbooks/repaired-governance-gates.md) and [ADR0018](0018-bounded-relation-candidate-validation.md).

The checked-in assignment in `policies/ci_shards.py` defines every common and assigned obligation. The collector requires every assigned result to succeed, verifies the checked-out commit and run identity, and rejects missing, skipped, contradictory or foreign evidence. `NOT_IN_SHARD` is derived only for unassigned stages. Static tests verify the complete assignment, literal commands and workflow conditions.

The stable `behavior` check requires the entire matrix to succeed; `required` continues to require quality, secrets and behavior. No artifact is downloaded, merged or executed to decide this result. Each group uploads only the existing bounded, redacted artifact allowlist under a unique group/commit/run/attempt name. Cleanup failures remain job failures.

## Consequences and qualification

Independent groups expose more failures in one run and avoid the serial critical path. Repeated setup increases runner minutes. Cold hosted cost and the longest complete group must be measured before claiming a speedup. No failure or unexecuted stage becomes a pass through this change.

The original 40-outcome implementation passed 156 host controls and 14 constructor/save probes for nested report routing; those results remain bound to that revision. The local 45-outcome composition is not a hosted pass. Current results and source scopes are recorded in the [execution state](../execution/STATE.md) and [evidence manifest](../verification/evidence-manifest.json). Future migration or feature gates require an explicit assignment update and complete-union tests; the mapping never infers required work from available results.
