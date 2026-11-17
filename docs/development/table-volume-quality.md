# Table-volume quality

Volume rules count every row of one authorized PostgreSQL table. They use an explicit table target, not a synthetic column. The rule passes when `minimumRows <= rowCount <= maximumRows`; both bounds are integers from 0 to 100,000. An empty table produces an exact zero and passes only when zero is within the bounds. Null-valued rows still count.

The authored maximum is a verdict threshold. It is separate from the fixed execution ceiling: six rows against a maximum of five produces a measured `FAIL`; 100,001 rows produces `QUALITY_RESOURCE_LIMIT` with no successful measurement. Volume measurements have no null-count metric or `NO_DATA` verdict.

## Implementation

`packages/domain/src/quality-contracts.ts` defines the closed rule, table target and measurement variants. `quality.ts` validates them; `quality-service.ts` resolves current catalog authority. SQL030 extends the protected publication, execution, history and monitoring commands. The existing API, workflow and site-runner paths dispatch the volume variant to `python/governance_workers/quality.py`.

The worker validates the exact database, schema and relation identities, acquires an access-share lock, and executes a generated bounded `COUNT(*)` in a read-only repeatable-read transaction. It returns the count, observation window, source/adapter versions, query-template identifier, plan estimates and settings hash. Source values and credentials are absent from the public measurement and workflow payload.

`volumeHash` is SHA-256 over canonical compact JSON containing `comparison`, `formatVersion`, `kind`, `maximumRows`, `minimumRows` and `scope`. It identifies settings, not the entire execution: immutable definition/input records separately pin the table, source and rule version. Editing bounds creates a new rule version and leaves prior measurements and verdicts intact.

Current support is PostgreSQL ordinary tables without partitioning, inheritance or row-level security. Schema usage and table-level `SELECT` are required. Views, materialized views and column-only grants are unsupported. Row filters, partition scope and anomaly baselines remain separate required work.

## Checks

```sh
pnpm typecheck
node --import tsx --test tests/unit/quality-volume.test.ts tests/unit/quality-volume-presentation.test.ts
./dev test --suite volume-upgrade
./dev test --suite volume-worker
```

The upgrade gate uses an owned isolated database and retains predecessor data, ledger and replay checks. The worker gate requires the local core/source services and exercises real PostgreSQL counts and refusals. It does not establish API, Temporal or browser behavior. Do not run isolated gates concurrently on the same Docker host: their resource-inventory checks require a stable environment.

`tests/e2e/quality-volume.spec.ts` specifies the real login, scan, rule-history, timer-driven incident, recovery, reopening and permission journey. English/Arabic desktop/mobile captures and accessibility assertions belong to that browser gate; authoring the test is not execution evidence.

The recorded isolated upgrade passes 320 cases; the real worker passes 15 checks with eight measurements. SQL001–031 is applied to the local development core at `514ddee`, and running-image source readback passes. The integrated API regression fails in a business-domain test process and is under investigation; the volume target passes with all 18 captures inspected; the full 37 graph remains unexecuted. The earlier 36-journey pass covers the predecessor application. Later qualification-wrapper changes require explicit source-equivalence records and do not turn these earlier executions into current-tree reruns.
