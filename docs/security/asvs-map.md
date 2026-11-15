# Preliminary ASVS 5.0 evidence map

Target: applicable Level 2 controls plus stronger tenant, source-credential, audit
and release-identity controls justified by [the threat model](threat-model.md).
Source: [official ASVS 5.0.0 release](https://asvs.owasp.org/downloads/), verified
15 November 2026. This is an initial control-area map, **not an exhaustive
control-ID register, a completed assessment or certification**. Import/version the
full standard, assess applicability per control ID and attach exact-revision
results before claiming coverage. Do not infer PASS from a test filename.

| Control area | Product requirements / threats | Current implementation and intended evidence | Assessment |
| --- | --- | --- | --- |
| Input validation, encoding and browser controls | SYS-SEC-006; TM-02, TM-09 | TypeBox API schemas, React text rendering, CSP/CSRF, bounded worker input; malicious-origin integration case; runtime headers and malicious metadata browser cases needed | Partial source controls; verification pending |
| Authentication, OAuth/OIDC and sessions | SYS-SEC-001; TM-01 | PKCE, state/nonce, JWT signature/claim verification, hashed session cookie; actual IdP acceptance plus adversarial callback/replay/expiry cases | Partial source controls; adversarial evidence incomplete |
| Authorization and tenancy | CORE-002, SYS-SEC-002, SYS-SEC-003, AT-TEN-01; TM-03, TM-04, TM-06 | Runtime role checks, forced RLS, tenant FKs, active membership, current visibility before search/counts; integration isolation cases; all remaining storage/execution surfaces need cases | Slice coverage only; full surface incomplete |
| API, service communication and external execution | SYS-SEC-004, SYS-SEC-005; TM-05, TM-06, TM-10 | Secret references, fixture destination restriction, read-only source role, ID-only orchestration; source conformance and retry/revocation tests | Local profile only; production workload identity/egress incomplete |
| Cryptography and data protection | CORE-006, SYS-SEC-004; TM-01, TM-05, TM-07, TM-10 | Cryptographic random tokens, token hashing, constant-time comparisons; operator encryption/KMS, tenant-aware object/export protection and key lifecycle evidence required | Partial; production key/secret lifecycle unqualified |
| Logging and error handling | CORE-008; TM-07 | Structured safe errors, transactional audit envelope/chain/outbox, immutable runtime records; denied/security events and confidentiality still need coverage | Partial; external checkpoints/retention/holds incomplete |
| Files, untrusted content and plugins | SYS-SEC-004; TM-09 | Current metadata scanner bounds; future archives, uploads and plugin execution require sanitization, path/zip-bomb cases and sandboxing | Broader surfaces not implemented |
| Configuration, dependencies and build integrity | OSS-002, OSS-005, OSS-006, OSS-007, OSS-008; TM-09 | Pinned Actions, frozen lock, restricted PR permissions, current dependency-license and gitleaks reports | Scoped checks executed; vulnerability/SAST/SBOM/signing qualification pending |
| Architecture, availability and recovery | SYS-SEC-003, OSS-009; TM-03, TM-11 | Threat model, trust boundaries and development resource limits; load, recovery, break-glass and independent review required | Architecture documented; recovery/HA evidence pending |

Selected stronger controls are a deliberate project requirement: enforce tenant
scope before counts/snippets, reauthorize durable effects, keep source credentials
out of workflow histories, externally anchor tamper evidence, and bind release
verification to repository/workflow identity and digest. These descriptions are
project controls and do not assert specific higher-level ASVS IDs as satisfied.
