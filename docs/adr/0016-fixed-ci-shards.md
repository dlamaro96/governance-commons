# ADR 0016: Fixed CI groups on independent runners

Status: accepted for development CI; hosted qualification pending. Date: 17 November 2026.

## Context

The serial behavior job has a 90-minute limit. Retained local measurements total about 99 minutes for a subset of its work, before cold installation and several current gates. These measurements span different revisions and are not a hosted benchmark. Running isolated database gates concurrently on one Docker host would violate their resource-inventory checks.

## Decision

Run five fixed groups on separate GitHub-hosted Ubuntu runners: foundation, governance, quality basics, freshness/volume and browser. Each independently bootstraps, starts, verifies object storage and seeds synthetic services. Keep every existing command and all 40 mandatory stage outcomes. Keep the sequential 36-journey browser graph together, with no retries. Each job retains its 90-minute limit; product and test-operation deadlines remain unchanged.

The checked-in assignment in `policies/ci_shards.py` defines every common and assigned obligation. The collector requires every assigned result to succeed, verifies the checked-out commit and run identity, and rejects missing, skipped, contradictory or foreign evidence. `NOT_IN_SHARD` is derived only for unassigned stages. Static tests verify the complete assignment, literal commands and workflow conditions.

The stable `behavior` check requires the entire matrix to succeed; `required` continues to require quality, secrets and behavior. No artifact is downloaded, merged or executed to decide this result. Each group uploads only the existing bounded, redacted artifact allowlist under a unique group/commit/run/attempt name. Cleanup failures remain job failures.

## Consequences and qualification

Independent groups expose more failures in one run and avoid the serial critical path. Repeated setup increases runner minutes. Cold hosted cost and the longest complete group must be measured before claiming a speedup. No failure or unexecuted stage becomes a pass through this change.

The implementation passes 156 host controls, plus 14 constructor/save probes for nested report routing. Fresh hosted execution remains required. Future migration or feature gates require an explicit assignment update and complete-union tests; the mapping never infers required work from available results.
