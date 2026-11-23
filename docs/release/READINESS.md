# Release readiness

**Development preview — not a supported release.** Updated 23 November 2026.

The active integration includes real catalog/ownership/audit workflows, operating models and graph migrations, glossary/reference publication, PostgreSQL lineage/classification, and several source-executed quality families with scheduled incidents and recovery. These have scoped local evidence; they do not complete the entire product baseline. See [product status](../product/STATUS.md) for the remaining capability areas.

The latest completed hosted checkpoint, `b08b88d`, has 42 successful outcomes, two failures and one dependent skip across all 45 required outcomes. Its API suite passes 171 cases, inactive-authentication foundation passes 35 and main browser suite passes all 37 journeys without retries. SQL024 and protected login fail. Five authenticated archives and exact source coordinates are verified. [Hosted record](../verification/hosted-checkpoint-b08b88d.json).

Source security at that checkpoint verifies all 1,522 files, three authenticated archives and three stored analyses with zero findings on attempt 2. The initial Actions installer failure is retained. This is source analysis, not container/dependency, SQL/RLS or enterprise-security certification. [Source-security record](../verification/source-security-b08b88d.json).

Implementation checkpoint `5d9e501` passes the complete local 263-case SQL024 chain within its original limits and fresh immutable-image protected login with 15 native and two real browser cases. All 203 protected inputs match Git, the 32-migration ledger is preserved and cleanup passes. The rebuilt core is healthy, matching 300 application and 13 worker files. Fresh hosted qualification on the published correction is required before protected merge. [SQL024 correction](../verification/reference-snapshot-batching-local.json), [protected-login correction](../verification/protected-authentication-tool-admission-local.json).

Prior native, worker, API and browser outcomes retain their original sources and limitations in the [evidence manifest](../verification/evidence-manifest.json). None of these corrections completes the full capability or release programme.

## Blocking release work

- Finish the remaining M0–M10 implementation and all 354 named baseline requirements. Optional activation does not remove required implementation.
- Pass clean installation, complete declared browser/security suites, current immutable-image CI and contributor onboarding.
- Qualify required connectors and identity providers against their declared real environments; retain exact external prerequisites until executed.
- Execute Kubernetes/OpenShift, offline, upgrade/restore, failure/recovery and measured load/soak profiles.
- Complete artifact/container/dependency scans, licence/SBOM inventories, signing/attestation and offline verification.
- Complete independent security, accessibility/Arabic and architecture review, plus a functioning private conduct-reporting/escalation route.

No production, parity, scale, high availability, backup/restore, live-vendor or certification claim is made. The qualified local host profile is Linux arm64 containers under Docker Desktop. GitHub source publication is allowed independently of supported-release qualification; protected merge/release gates stay blocking.
