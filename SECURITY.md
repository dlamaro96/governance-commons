# Security policy

Governance Commons is development software. No stable production release,
security certification, independent penetration test or enterprise assurance is
claimed. Only the current development line receives best-effort community fixes;
there is no LTS commitment, contractual SLA or guaranteed response time.

## Report a vulnerability privately

The intended private route is GitHub's repository vulnerability report:
[dlamaro96/governance-commons security advisory](https://github.com/dlamaro96/governance-commons/security/advisories/new).
**Enablement has not yet been verified.** The repository readiness report records
the read-back result; a link in this file does not prove that reporting is on.
If GitHub does not offer the private form, open a public issue asking only for a
private security contact, without vulnerability details, secrets or affected
customer information. No project security email address has been appointed.

Include affected version/commit and profile, a minimal synthetic reproduction,
impact and authorization boundary, and suggested mitigation if available. Do not
test against someone else's deployment or send production datasets. Keep reports
private while maintainers assess exposure, reproduce the issue and coordinate
fixes and any advisory/CVE. Best-effort triage aims to acknowledge within seven
days, but this is a target rather than a staffed guarantee. Communicate a missed
target without posting exploit details publicly.

## Boundaries and release policy

Tenant separation, authentication/session handling, source-secret protection,
connector isolation, restricted egress, parser safety, source mutation approval,
audit integrity and release supply chain are essential boundaries. Report a
bypass even if the relevant capability is marked experimental. Development
fixtures and localhost defaults do not qualify a production deployment.

Applicable unresolved critical/high vulnerabilities block a supported release
unless a specific, reviewed, time-bounded risk exception records the affected
package/version, exposure, mitigation, owner and expiry. Evidence-based false
positive decisions remain visible. Pins need scheduled rescanning; a dependency
does not become permanently safe when locked. See policies and the release
readiness/evidence records for actual scanner and qualification outcomes.
