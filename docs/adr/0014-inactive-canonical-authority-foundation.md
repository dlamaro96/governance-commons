# ADR0014: Inactive canonical authority storage and candidate selection

Date: 2026-11-16. Status: accepted for implementation; native verification and runtime content integration remain open. Adopts the [foundation contract](../execution/CANONICAL_AUTHORITY_FOUNDATION_CONTRACT.md).

The pure authority engine and protected authentication transport need canonical definitions, grants, connected parents and current identity evidence. Supplying these as caller-authored arrays would leave provenance and completeness unverified. Persist normalized private records with tenant keys, forced row security, immutable issuance, explicit lifecycle history and independently derived projection measures. A native owner-only loader obtains a real protected session and returns a complete candidate graph in one fresh read-only repeatable-read snapshot.

Separate immutable issuance pins from mutable lifecycle heads so revoking a parent makes existing children ineffective without invalidating their historical references. Preserve exact policy pins and all relevant direct membership proof, including referenced revoked history. Select elevation uses deterministically for their exact protected session and charge session-dependent projections without reusing an invariant grant hash.

This increment uses a conservative scope superset because production containment and fact producers are separate unfinished components. It refuses complete over-limit graphs without truncation. That refusal does not qualify production capacity or permit narrowing existing capabilities. The result remains private inactive evidence; the loader cannot authorize a response or mutation. SQL012 runtime executor grants and existing content authorization remain intact until a separately qualified atomic cutover.

The added private schema, bridge, history and independent SQL/TypeScript validation increase implementation work. They make canonical provenance and bounded completeness directly testable before adding authorized administration and all-ingress enforcement. All later capabilities remain required.
