# ADR0009: Business domains and versioned asset placement

Status: accepted implementation design, 2026-11-15. Implementation NOT_STARTED; verification NOT_RUN. This decision does not advance M2 or any release gate.

The specification requires immutable business-domain identities, domain types, domain context and scoped responsibilities. Existing asset and graph receipts reference exact immutable asset snapshots. Adding convenience fields to those snapshots would invalidate their historical and storage contracts.

We adopt the contract in `../execution/BUSINESS_DOMAINS.md` with these choices:

- A business domain is an independent tenant resource with a single parent, at most 32 hierarchy levels, an exact domain-type pin and immutable revisions. It is never a security tenant.
- Each asset has one nullable primary-domain placement with its own optimistic version and revision stream. Initial absence is explicitly unrecorded version zero. Placement preserves existing asset identity, versions and snapshots; revisions reference actual asset/domain revisions.
- Domain types use separate versioned storage and exact inheritance pins while reusing pure typed-value validation. Their complete bounded migrations cannot call asset persistence as a shortcut.
- New domain actions use explicit current tenant permissions. Owner labels and placement grant no authority. A separate mandatory scoped-policy increment must bind placement, ancestry and permission state across every existing read, mutation, receipt, search and approval path before scoped authority is claimed.
- Hierarchy moves require complete authorized impact preview; retirement requires no current placements or active children. The development profile bounds affected domains and assets to 1,000 each and retained canonical data to 512 KiB. Larger durable operations remain required work.
- A purpose-specific, bounded owner selector exposes active tenant-member identity/name to domain readers/writers. It does not reuse an unrelated role-name or catalog-only permission assumption.

The adopted implementation refinement in [BUSINESS_DOMAIN_STORAGE.md](../execution/BUSINESS_DOMAIN_STORAGE.md) fixes exact SQL011 migration and ordinary-write preparation/seal contracts. SQL prepares the complete authorized lock union before canonical DML and independently proves actual revisions, journals, receipts and idempotency success. Its deadline is anchored to the original PostgreSQL `transaction_timestamp()`, including earlier idempotency/ledger waits; service statements prearm the remaining timer separately. This design refinement supplies no implementation or execution evidence and does not bypass the preceding browser gates or any broader qualification requirement.

The additive placement approach avoids rewriting historical formats but requires future authorization to use composite asset/placement/ancestry state and a private scope fence. An asset version alone is insufficient. Multiple domain memberships, a polymorphic type-store rewrite and an expanded shared directory were considered; each would require a separate explicit compatibility and authority design.

The next source work starts after the preceding relation correction is qualified. It must implement the full adopted domain contract, real SQL/API/browser tests, original synthetic fixtures and precise evidence. Domains alone do not satisfy multilingual glossary approval, responsibility enforcement, reference publication, collections, reusable attribute identities or the full operating model.


The storage integration additionally adopts a narrow read-only original-scope replay authorization helper. Ordinary hierarchy responses do not expose their complete original scope, while private claims cannot be granted to the runtime. The helper returns only a current authorization decision for the exact authenticated actor's finalized operation/key/success; it does not mutate, disclose claims or grant authority from a digest. This preserves reauthorization after descendants or placements later move. See BUSINESS_DOMAIN_STORAGE.md for the exact sixth entry point and qualification obligations.

## Repeatable synthetic seed

The explicit harbor-demo seed grants the declared domain actions to the known steward, owner, auditor, engineer and Summit personas once. Each actor has a durable versioned idempotency marker; later seed invocations do not restore revoked domain permissions. An inactive, changed-role or baseline-restricted persona is not upgraded. The older repeatable model-action upgrade is removed: fresh inserts declare model actions, while existing memberships remain authoritative and missing model actions are never reconstructed from catalog access. Identity and initial membership are inserted atomically only for a newly inserted persona identity; a deleted membership is not recreated on repeat seed. Consumer receives no domain action. Real runtime-role service mutations create two typed synthetic trees with immutable revisions, audit and outbox; stable keys preserve IDs and later user changes. Each mutation has its own transaction and current authorization. If required seed authority has since been revoked, rerunning seed fails explicitly rather than restoring it.

Paged domain selectors bind normalized filters through a canonical digest so a valid 200-code-point Unicode search remains within the existing 1024-character cursor profile. Purpose, actor, tenant, page size, ordering, scope fence and last key stay separately bound and validated.
