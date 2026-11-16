# Scoped authority expression interpreter contract

Status: **ROOT-ADOPTED FOR THIS PURE MODULE ONLY**, 2026-11-16, after root commit `27a3b07`. Implementation and test results must be recorded separately. This permits only `packages/authority/src/expressions.ts` and `tests/unit/authority-expressions.test.ts`; the existing policy/types/actions files and earlier frozen contracts remain unchanged. It does not activate a loader, SQL, HTTP route, administration, policy decision, grant, field projection, service capability or runtime authority.

Inputs are the exact PolicyExpr vocabulary in the [pure policy contract](SCOPED_AUTHORITY_PURE_CONTRACT.md) and authority candidate SHA-256 `443a6b796354f6b8daf2dea3b98e83426faca19d4c57139e89a526c533433802`. The administration candidate and unresolved aggregate system budgets are not implemented by this module. The governing [BUILD_SPEC](../product/BUILD_SPEC.md) and [STATE](STATE.md) retain the full programme.

## Exact interface and trusted input boundary

Export `evaluatePolicyExpression(expression: PolicyExpr, facts: ExpressionFacts): ExpressionTruth`, where truth is only `'match' | 'no-match' | 'indeterminate'`. Export these module-local context types; existing shared files are not expanded:

```ts
type ExpressionTruth = 'match' | 'no-match' | 'indeterminate';
type Fact<T> = { readonly status: 'known'; readonly value: T }
  | { readonly status: 'unavailable' };
type ExpressionRequest = {
  readonly action: ActionId; readonly resource: ResourceRef;
  readonly revision: Version | null; readonly field: FieldId | null;
};
type RequestRoleFacts = {
  readonly subject: SubjectRef; readonly request: ExpressionRequest;
  readonly roles: readonly RolePin[];
};
type ExpressionFacts = {
  readonly subject: SubjectRef; readonly request: ExpressionRequest; readonly now: UTC;
  readonly groups: Fact<readonly UUID[]>;
  readonly requestRoles: Fact<RequestRoleFacts>;
  readonly domainPath: Fact<readonly UUID[]>;
  readonly classifications: Fact<readonly UUID[]>;
  readonly approvedTags: Fact<readonly UUID[]>;
  readonly purpose: Fact<UUID | null>;
  readonly environment: Fact<UUID>;
};
```

`ExpressionRequest` has the exact proposed AtomicRequest shape. Canonical subject kind/UUID, action, resource tenant/kind/UUID, revision, field and UTC are checked structurally. A field string must be well-formed, nonempty and within the existing 256-byte registered-field representation bound; its actual registry membership/provenance remains the trusted producer's obligation. No action-to-field pairing, activity, ACL, tenant eligibility, role name, owner authority or grant result is inferred from these structural checks.

The producer must supply a fully admitted, complete, canonical context for this exact request and database time. It must establish current identity/group membership, exact role assignment/version, origin grant, connected current delegation chain, authority scope/field/validity, approved fact provenance and registration before marking facts known. The module cannot prove any of these from a UUID list. `requestRoles` is **not** a raw union of all roles held elsewhere: its explicit subject and entire request tuple must equal the outer context, including subject kind/UUID, action, resource tenant/kind/UUID, revision and field. A mismatch or malformed binding is indeterminate. Matching the tuple proves only input consistency, never database provenance or chain validity.

Callers must first use the existing strict policy parser on external documents and bound raw/materialized context bytes, fact cardinality and total work through the future trusted admission contract. A typed JavaScript parameter or an already allocated array is not admission. This module neither invents a universal group/population cap nor certifies a maximum-size runtime profile. Its descriptor/own-key validation scales with already admitted metadata; it does not claim bounded reflection on arbitrary huge existing objects. Proxy/accessor/exotic/inherited/symbol-bearing data, sparse arrays and duplicate set facts are rejected without executing their getters or proxy traps. Inputs are never mutated.

## Predicate semantics

Every AST node is checked against the exact grammar. Existing limits remain 128 cumulative expression nodes, depth 8 with root depth 1, and 256 entries in an AST finite set/children array. These are existing policy grammar limits, not new aggregate authority limits. Whole-policy byte/rule limits remain the upstream parser's responsibility. Unknown operators, malformed AST, invalid dates/versions, cycles or exceeded bounds yield indeterminate, never a thrown success or permissive fallback.

Known empty arrays mean complete facts with no members; unavailable means the producer could not establish the fact. A malformed, missing or unavailable **used** fact yields indeterminate. All context slots are required, and unknown root properties invalidate the context; explicit unavailable slots that the expression does not use do not affect its truth. Fact payloads are validated lazily when used, while their root descriptor shape cannot contain executable properties.

| Operator | Exact behavior |
|---|---|
| `all` / `any` | Evaluate every child, with no boolean short-circuit. Any indeterminate child dominates. Otherwise use ordinary conjunction/disjunction. Ordered children retain order; duplicate child expressions remain valid. |
| `subject-in` | Exact `(kind,id)` membership of the context subject. Human and service identities never alias. |
| `group-any` | Nonempty intersection with the complete known direct-group UUID set. No nested groups or names. |
| `role-any` | Nonempty exact `(roleId,version)` intersection, only after the request-role binding checks above. No version fallback or cross-request role reuse. |
| `action-in` | Exact registered action equality; no wildcard/prefix/alias expansion. |
| `resource-kind-in` | Exact canonical resource kind; authored asset types remain `model-definition`. |
| `domain-in` | Known path is direct domain first, followed by current canonical ancestors. With `includeAncestors:false`, compare only the first entry; otherwise compare the entire path. Known `[]` is an unassigned resource and does not match. |
| `classification-any` / `approved-tag-any` | Nonempty intersection with the respective known approved canonical UUID set. Source metadata is not approval evidence. |
| `purpose-in` | Known UUID tests membership. Known `null` proves there is no approved purpose and gives no-match. Unavailable is indeterminate; do not collapse these cases. |
| `environment-in` | Membership of the single known registered environment UUID. Null is malformed, not a default environment. |
| `time-within` | Test canonical supplied `now` against `[notBefore,expiresAt)`. Null endpoints are unbounded; equal/reversed finite endpoints are malformed. No wall-clock read or timer is created. |

The authority candidate says **32 canonical domain ancestors** and defines direct-domain-first paths. Interpret this as at most **33** entries, direct domain plus up to 32 ancestors. Empty path is allowed; duplicates, malformed UUIDs and a 34th entry are indeterminate even if the requested direct domain appears first. This interpretation is limited to expression facts and does not change any existing business-domain operation guard. The producer still proves actual current ancestry; a structurally valid path alone is not proof.

There is no effect/deny/allow aggregation here. An `any` containing one match and one indeterminate returns indeterminate; an `all` containing one no-match and one indeterminate also returns indeterminate. This is the selected conservative rule, not a claim of ordinary short-circuit or Kleene semantics. A matching expression does not authorize its subject and does not imply active membership, matching grant scope or an allowed action. No `PureDecision`, explanation, lease, policy hash, valid-until cache bound or authority fence is produced.

## Required focused evidence

Exercise every operator's positive and negative cases; service/human and canonical-kind separation; known empty/null versus unavailable; malformed used facts and complete fact validation after an early matching entry; all exact request-role tuple components, stale pin versions and malformed/cyclic input; both time endpoints and invalid UTC; indeterminate in either child order inside otherwise matching any/failing all; 128/129 nodes, depth 8/9, 256/257 AST sets, and domain paths 33/34. Include proxy/accessor rejection without trap execution and input immutability. Use the real policy parser for canonical valid examples and direct malformed casts only for negative robustness checks.

Run the focused Node 24 unit tests and root/web typechecks with exact source hashes in private evidence. Root owns combined qualification/publication. These tests cannot qualify SQL equivalence, canonical facts, full authorization decisions, administration, revocation, browser behavior or runtime safety. No earlier policy or browser report is rewritten to claim those capabilities.
