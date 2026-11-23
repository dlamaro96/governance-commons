# 0020: Canonical asset context before authority activation

Status: accepted for the inactive foundation. This decision does not activate a
policy executor or change runtime database privileges.

The authority closure already binds protected identity, membership and the
registered policy graph. It must obtain asset and domain facts from the same
canonical snapshot before it can safely evaluate a resource. Request-provided
asset attributes and the domain version recorded when an asset was placed are
insufficient: assets and domain hierarchies can change afterward.

`loadHumanAssetContext` therefore admits only a protected session digest, asset ID
and expected asset version. It uses the existing native owner restriction and
one read-only, repeatable-read transaction with the existing 30-second deadline.
The protected session supplies tenant and actor. Exact tenant-scoped reads obtain
the current asset, complete bounded identity ACL, placement, current nearest-first
domain ancestry and domain epoch. The repository then loads the existing closure
and exact pinned registry in that transaction. It restores prior transaction
context before returning the connection.

Historical placement versions remain provenance; they cannot replace current
asset or domain versions. Missing placement and explicit unassignment are
separate states. Invalid versions, unknown statuses, malformed ACLs, cycles,
missing ancestors and profile overflow fail closed. The stored hierarchy limit is
32 total nodes. Retired and source-unavailable assets remain distinguishable
facts; this reader does not grant their discovery or content access.

The returned envelope is strictly parsed and hashed after canonical registry
normalization. Closure, registry and resource facts share the existing aggregate
physical limits. The digest identifies this inactive context; it is neither a
security revision nor a reusable authorization capability. Classification,
approved tags, purpose and environment are explicitly unavailable. No approved
fact or current security revision is fabricated.

The implementation needs no migration or additional runtime grant. Native tests
use isolated PostgreSQL with SQL001–032, exercise a concurrent committed domain
move against a held snapshot, and preserve rows, migration ledgers, function ACLs
and role boundaries. The new development-pipeline outcome is separate from both
existing authority-read upgrade profiles.

A later executor still requires a canonical security revision, complete trusted
fact producers, revocation fencing, read-filter equivalence, effect-bound
capabilities and every-ingress qualification. The current API continues to use
its existing membership and asset-visibility checks until that programme is
implemented and verified.
