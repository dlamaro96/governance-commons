# Operate table-volume checks

Apply the reviewed forward migrations through the normal deployment process and use a PostgreSQL source account with schema usage and table-level read access. The account must not be a superuser or bypass row security. Scan the source so the catalog contains current active table and parent-schema identities.

Open the table's **Quality** tab and create a **Volume (rows)** rule. Enter its purpose, owner, severity, **Minimum rows** and **Maximum rows**. Bounds are inclusive. Use a manual run to inspect **Pinned row bounds**, the **Volume settings hash**, exact count and observation window before enabling scheduled monitoring.

Reading requires current `catalog:read`, `quality:read` and visibility of the table and its schema. Publishing additionally requires `quality:write`; requesting or cancelling execution requires `quality:execute`. A monitor uses its immutable executor and pinned rule. Current permissions and source/target state are checked again during execution and recovery.

## Interpret outcomes

| Outcome | Meaning and next action |
|---|---|
| `PASS` | The exact observed count is within the pinned bounds. It does not establish schema, value or anomaly quality. |
| `FAIL` | Execution succeeded and the count is outside the bounds. Review the count and source observation window before changing data or thresholds. |
| `QUALITY_RESOURCE_LIMIT` | Execution exceeded an admitted resource limit, or a source statement/lock wait exhausted its bound. No passing/failing data result should be inferred. |
| `QUALITY_DEADLINE_EXCEEDED` | The execution deadline or usable claim lease expired. Retain the failed attempt and review source latency before submitting another run. |
| `QUALITY_TARGET_STALE` | The catalog/source identity no longer matches the pinned target. Rescan and review the current target before submitting another run. |
| `QUALITY_TARGET_UNSUPPORTED` | The relation is outside the supported ordinary-table scope. Check for a view, partition, inheritance or row-security configuration. |
| `QUALITY_SOURCE_FAILED` | Source execution or its response could not be accepted. Check connectivity and the source account's read scope and privilege configuration. Private worker refusals such as `SOURCE_SCOPE_DENIED` and `SOURCE_PRIVILEGE_TOO_BROAD` map to this public outcome. |

The fixed execution limits are 100,000 rows, a 30-second total operation budget, statements of at most 15 seconds, estimated plan cost of 1,000,000 and estimated scan bytes of 64 MiB. The byte limit is a planner estimate, not a measurement of physical I/O. Source lock waits remain bounded. The worker counts at most 100,001 rows to detect overflow and returns aggregates only.

Scheduled failures use the existing deduplicated incident workflow. Acknowledgement does not resolve an incident. Record the root cause and remediation, run a linked recovery check, and use **Verify resolution** only when the server accepts current comparable evidence. A later failure can reopen the incident while retaining the prior resolution and its evidence. Product quality execution does not rewrite source rows.

## Local qualification and troubleshooting

Use `./dev test --suite volume-upgrade` for isolated storage/upgrade checks and `./dev test --suite volume-worker` for real source counts. Retain the command result, exact source hashes, migration ledger and cleanup result. A missing prerequisite or cleanup failure is not a pass.

The local synthetic fixture helper is restricted to its exact owned fixture:

```sh
python3 scripts/runtime-volume-fixture.py --run-core --step read
```

`prepare` creates the six-row fixture or validates its existing six-row state; it refuses an existing five-row state. `fail` and `repair` explicitly switch its admitted six/five-row states for acceptance tests. `read` is inert. These commands are not remediation tools for user tables. A revoked read grant or unexpected schema/data is refused rather than silently repaired.

The isolated migration and source-worker checks passed against recorded sources. SQL001–031 is applied to the local development core at `514ddee`, with running-image source readback. The integrated API regression fails in a business-domain test process and is under investigation; the volume target passes with all 18 captures inspected; the full 37 graph remains unexecuted. Consult the [current state](../execution/STATE.md) and source-bound evidence before treating it as qualified for a deployment profile.
