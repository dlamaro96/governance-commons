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
