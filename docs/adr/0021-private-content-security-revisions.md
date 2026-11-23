# Private content-security revisions

Status: implemented; the isolated local gate passes. Integrated and hosted qualification remain separately tracked.

SQL033 adds a positive, monotone PostgreSQL bigint per tenant in the private
`gc_authority.content_security_heads` table. The existing SQL032 asset-context
reader remains available. A separate versioned reader obtains this revision and
the canonical asset context in the same authenticated, native-owner, read-only
repeatable-read snapshot. Neither reader authorizes a later effect.

Every successful row insert, update or delete on assets, domains, placements,
classification taxonomies, classification rules and classification assignments
advances the tenant revision in the same transaction. No-op updates conservatively
advance it too. Rejected writes and rollbacks leave both content and revision
unchanged. Immutable version inserts do not independently advance the revision;
their corresponding canonical head or pin change does.

Installation locks the tenant and covered source tables, seeds existing tenants
at one and installs the new-tenant trigger in the migration transaction. A
missing head is an integrity error. There is no lazy initialization, UPSERT,
reset, wraparound or caller-supplied revision. Direct head writes are refused.
Tenant deletion or identifier reuse requires a future purge/tombstone contract;
this migration refuses it. Truncation of covered heads and immutable read pins
is refused, including through cascading truncation.

The trigger derives its tenant from the source row, uses fixed schema-qualified
objects, temporarily sets the forced-RLS tenant context and restores the prior
context on success or failure. The table and new trigger functions receive no
runtime grants. Existing source-table and function privileges remain unchanged.

Writers use the same transaction advisory-lock key as the canonical ledger,
domain and classification paths. A nonblocking advisory lock and `FOR UPDATE
NOWAIT` on the existing revision head refuse contention with SQLSTATE `55P03`.
Callers must retry the complete operation in a fresh transaction; the trigger
never waits while holding a source row or retries part of an operation. Counter
exhaustion fails with `54000`, and a missing head fails with `23514`.

The versioned envelope has its own digest and the same aggregate byte, node and
depth limits as its inner context. Its revision is an exact decimal string,
including values beyond JavaScript's safe-integer range. The original 30-second
repository deadline applies to the entire operation without renewal.

This revision covers the six declared mutable content heads. It does not attest
live memberships, identity status, approval tasks, purpose or environment, and
does not manufacture approved classification or tag facts. Those producers and
the held-snapshot native executor remain required before authority activation.

The isolated qualification command is `./dev test --suite
content-security-revision`. Its 780-second execution budget includes source
admission, followed by up to 90 seconds for owned cleanup inside the 900-second
developer wrapper. It upgrades populated SQL032, checks full preservation and
replay, then exercises real concurrent PostgreSQL transactions. Historical
upgrade gates admit the named successor without applying it; current reference
import and protected authentication explicitly adopt SQL001–033. Pipeline
outcomes disclose their scope and do not publish private raw authority evidence.
