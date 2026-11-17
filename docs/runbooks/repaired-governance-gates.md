# Repaired governance upgrade gates

SQL032 bounds relation validation to its nominal candidates while preserving exact eligibility, authorization and the existing operation budget. Applied migrations remain immutable. These gates distinguish the original schema from the forward repair; a later passing result does not rewrite a historical failure.

The commands and 45-outcome CI mapping are integrated in the local working tree. Hosted qualification is pending. SQL032 is not yet applied to the shared development core. This runbook describes isolated qualification, not a production migration procedure.

## Choose the scope

Each repaired chain applies SQL001–018, proves the SQL032 repair and replay, then applies the requested suffix while retaining SQL032. It runs the original population and downstream assertions with their original deadlines.

| Command | Chain endpoint |
| --- | --- |
| `./dev test --suite glossary-population-repaired-upgrade` | SQL018 plus SQL032; glossary population |
| `./dev test --suite quality-repaired-upgrade` | Through SQL019; completeness quality |
| `./dev test --suite lineage-repaired-upgrade` | Through SQL020; PostgreSQL view lineage |
| `./dev test --suite classification-repaired-upgrade` | Through SQL021; reviewed classification |
| `./dev test --suite reference-repaired-upgrade` | Through SQL022; reference-data publication |
| `./dev test --suite reference-quality-repaired-upgrade` | Through SQL023; reference-allowed-values quality |
| `./dev test --suite reference-structure-repaired-upgrade` | Through SQL024; hierarchies and crosswalks |

Two standalone commands qualify SQL032 itself:

| Command | Isolated scope |
| --- | --- |
| `./dev test --suite relation-candidate-original` | SQL001–018 followed by SQL032; unchanged original assertions plus repair regressions |
| `./dev test --suite relation-candidate-current` | Populated SQL001–031 followed by SQL032; complete preservation, replay and repair regressions |

The original commands remain available: `glossary-population-upgrade`, `quality-upgrade`, `lineage-upgrade`, `classification-upgrade`, `reference-upgrade`, `reference-quality-upgrade` and `reference-structure-upgrade`. Invoke them with the same `./dev test --suite` prefix. They retain their historical schema scope and do not silently apply SQL032. Their reports cannot satisfy the corresponding repaired CI steps. Running the SQL024 chain also does not establish that all seven separately named modes ran.

## Run and inspect

Use the pinned development tools and run `./dev doctor` first. The gates require the expected cached images and sufficient local resources. Each gate creates and removes its own isolated database resources and generated credentials. Run one isolated gate at a time on a Docker host; do not rebuild, prune Docker resources or run another resource-changing task during its inventory checks. A missing prerequisite is not a pass.

Reports are private under `.local/evidence/`. Each repaired report uses its suite name plus `.json`; the standalone reports are `relation-candidate-original.json` and `relation-candidate-current.json`. Retain the exact command/profile, commit, source manifests, ledger, preservation/replay results, native test results and cleanup outcome. Source bytes are checked at process startup and exit, including explicitly pinned predecessor modules. Missing, duplicated, skipped or failing tests refuse qualification. Cleanup failure also fails the gate.

Keep failed attempts and their evidence. Diagnose the recorded failing phase before changing a fixture or implementation, then run the affected scope again. Do not change applied migration bytes, enlarge an operation deadline or substitute an older report to obtain a passing result.

## CI and failure diagnostics

The checked-in `policies/ci_shards.py` assigns every command to one of five independent runners. All 45 outcomes and the unretried 37-journey browser graph remain mandatory. The collector verifies commit/run identity and rejects missing, contradictory, skipped or foreign evidence. Historical stages are explicitly `HISTORICAL_NOT_EXECUTED`; only unassigned stages are `NOT_IN_SHARD`.

For a failed or cancelled `quality-repaired-upgrade`, the collector may publish `quality-repaired-upgrade-diagnostic.json` after validating the exact report, source inventory and selected log hash. It contains only the known phase, bounded test counts, static file/line coordinates and closed failure categories. It preserves the first failure rather than replacing it with a later readback or cleanup error. Missing or malformed diagnostics leave the cause unavailable and never imply success.

Declared effective-source hashes in that diagnostic identify admitted mounts; they do not establish completed startup/exit readback or schema application. Raw test titles, messages, SQL, source values, stack traces and credentials remain private. Upload only the existing collector allowlist, not the raw evidence directory.

## Recorded scope at integration: 17 November 2026, 09:41 UTC

The two standalone SQL032 scopes each pass 37 native cases on their recorded 113-source candidate. An earlier repaired SQL019 run passes 113 cases across five suites with cleanup verified, bound to 130 source inputs. The composed diagnostic version has 132 inputs; that earlier result is not a rerun of these bytes. At integration, the final SQL024 composition had not run and there was no hosted 45-outcome pass.

Use the [current execution state](../execution/STATE.md) and [evidence manifest](../verification/evidence-manifest.json) for subsequent results. These isolated checks do not qualify the shared application, source workers, browser, external connectors or release programme.
