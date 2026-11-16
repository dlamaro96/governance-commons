# Scoped authority: proposed next contract

Status: **DRAFT FOR ROOT REVIEW — NOT ADOPTED, NOT IMPLEMENTED, NOT VERIFIED.** Prepared 2026-11-16 while the separate business-domain qualification runs. This document changes no policy, permission, schema, requirement status or release claim. The complete [BUILD_SPEC](../product/BUILD_SPEC.md), frozen SHA256 `8bde0eb8d185958cce46c217c01d7263f6708823a11bb1f45cec7a3a3cb24d61`, remains authoritative. [BUSINESS_DOMAINS](BUSINESS_DOMAINS.md) and [BUSINESS_DOMAIN_STORAGE](BUSINESS_DOMAIN_STORAGE.md) supply the current domain/placement contracts; their runtime status must be read from STATE, not inferred from this proposal.

## 1. Required target and proposed increment

PostgreSQL must be the single authority for active membership, roles/grants, explicit responsibility-to-authority mappings, supported relationship grants, security classifications and versioned policy. Ownership documents accountability; it never creates authority implicitly. A business domain is not a tenant. A domain chooser is an authorized filter, not a security boundary or grant.

| Governing requirement IDs | Complete required outcome | Proposed next increment and remaining work |
|---|---|---|
| CORE-001/004; SPEC-076/077/085; SYS-DATA-001.01 | Immutable identity/group/role/grant/responsibility entities, multiple editable role assignments, scoped owner/steward authority and all starter personas | Implement tenant groups, editable versioned role/responsibility definitions and explicit tenant/domain/asset assignments. Organizational-unit/workspace administration remains required follow-on; no synthetic domain is advertised as a workspace. |
| SYS-SEC-002.01–.04; ACC-004 | Deterministic default-deny policy, explicit denies, inheritance, field sensitivity, approved bounded relationship grants, typed conditions and PostgreSQL/OpenSearch/reference equivalence | Implement the bounded policy core and all currently deployed resource paths together. Relationship-derived authority and other organizational scopes require the separate extension below; unsupported constructs fail validation, never become an ignored allow. |
| CORE-002/005; SYS-SEC-001.02; SYS-SEC-003.01–.03; SYS-EDGE-001 | Tenant isolation, no implicit operator content access, machine identity, current revocation at every boundary, SCIM/group deprovisioning and safe site execution | Qualify current API/search/graph/audit/history/replay/site paths. Add explicit expiring operator elevation and service-grant plumbing. Complete SCIM, rotating site identity and offline leases remain mandatory separately qualified work. |
| CORE-006/007; SYS-DATA-004/005; SYS-SEC-005.01; GOV-004 | Atomic auditable decisions, bounded delegation, immutable approvals, independent review where configured and execution-time revalidation | Provide the authority/delegation primitives and exact decision references now. Durable tasks, out-of-office assignment, reminders and approval execution are required in the glossary/workflow slice, not claimed by a role editor. |
| UX-36/37; SYS-API-001; MOD-001 | Real identity/scope administration, safe simulation and consistent supported API/UI/import/worker/MCP behavior | Implement effective-access/admin/simulation UI against real services and every existing ingress. Future import/MCP surfaces must use the same contracts; their absence is not an equivalence pass. |
| AT-TEN-01; AT-AUD-01; E2E-02/05/12/20/22/29; AT-WF-01 | Adversarial isolation, faithful history, permission-safe business approval and revocation despite stale jobs/indexes/notifications | Add the focused authority gates below. Full journeys remain open until their workflow, export, notification, source and other dependent capabilities are implemented and executed. |
| ACC-001–008; NB-002/004; AI-007/008; MCP-003/005/006/009; DOC-003/007 | Native source access, result/AI/document permissions and deterministic tool enforcement | Reuse the decision model, but retain distinct source identity, native enforcement/read-back and artifact authorization contracts. Metadata access never means source SELECT, sample, export, tool execution or native grant authority. |

Recommended sequencing: **A1 current-surface scoped authority**, then **A2 bounded relationship grants plus organizational/workspace scope and provisioning**, with glossary approval depending on A1 and its real delegation/independence gates. All A2 and dependent programme work remains required. Administrators disabling a feature does not remove its implementation obligation.

A1 must not ship as “domain UI filtering.” It is a coordinated authority cutover covering current catalog/search/facets, asset fields/history, model/type migrations, asserted relations/participation/graph repair, domain hierarchy/placement, audit, idempotent replay, source configuration/jobs and existing workers. New grants cannot be activated while any of those paths still treats the old broad permission array as final authority.

## 2. Observed implementation seams

This is source inspection, not new runtime evidence:

- `packages/authz/src/index.ts` currently implements `permits` by membership permission inclusion and `canView` by tenant plus `catalog:read` plus asset visibility/identity allowlist. Its boolean helpers are insufficient as the new authority source.
- `apps/api/src/security.ts` authenticates OIDC/BFF sessions and reads current identity/membership. Keep that authenticated identity and CSRF boundary; do not trust a browser-selected tenant, role, group, purpose or delegation chain.
- `business-domain-store.ts` rechecks current membership, locks ledger/model/domain scopes and principals, preflights materialization and supplies an opaque domain epoch. `business-domain-read.ts` and SQL011's original-scope replay helper are replacement seams for resource-aware decisions, not reasons to rewrite their public DTOs.
- `apps/api/src/repository.ts` has per-family audit filters and a replay-authorization hook. Existing relation/type services and SQL007–011 independently guard complete scopes and journals. Inventory every permission/visibility predicate, including SQL helpers, before cutover.
- Catalog search currently supplies a canonical allowed-ID set to OpenSearch; `apps/api/src/search.ts` projects asset content and resource versions. Keep authorization before search counts/snippets and add policy/placement/field security fencing; eventual indexing alone cannot revoke access.
- Existing Temporal/site scanning transports tenant/job IDs and rechecks initiating membership at control-plane claim/complete boundaries. Static site credentials are not the full required service-principal/short-lived-lease implementation. Preserve current behavior until its replacement is qualified.
- The domain seed is being made non-regranting: repeat seed must preserve administrator revocations. The authority migration must follow the same rule.

## 3. Proposed storage model

Names below are provisional interface choices for root to freeze. Every tenant-owned key/FK/unique includes `tenant_id`; enable and force RLS. Runtime owns no tables and has neither superuser nor BYPASSRLS. Global identity authentication remains distinct from per-tenant eligibility; do not merge identities by email.

| Proposed records | Identity and invariant |
|---|---|
| `authority_groups`, `authority_group_memberships`, immutable membership revisions | Tenant UUIDs; active direct identity membership with validity and provenance. A1 rejects group nesting; A2 may add explicitly bounded acyclic nesting with the same deny/revocation semantics. Imported IdP/SCIM membership is observed/provisioned evidence, not a tenant-admin role by itself. |
| `authority_roles`, `authority_role_versions` | Immutable role UUID/key; current version and immutable versioned action sets. Starter names are templates, never authorization branches. Grants pin a role version; publishing v2 does not silently rewrite existing assignments. Explicit role-assignment migration previews affected grants. |
| `responsibility_types`, `responsibility_type_versions`, `responsibility_assignments` and revisions | Versioned business responsibility definition, scoped identity/group assignee, validity, reason and history. Assignment alone is descriptive. A separate reviewed versioned mapping may produce authority for selected actions and scope. No automatic mapping from asset/domain owner fields. |
| `authority_policies`, `authority_policy_versions`, `authority_policy_bindings` | Immutable bounded AST/version/hash and explicit effective binding to a scope. Activating a new policy version is an audited mutation with complete impact/compatibility preview and epoch advance; it is not an unnoticed pointer change. |
| `authority_grants` and immutable grant revisions | Identity/group/service subject, exact role/policy/responsibility mapping version, typed scope, allow/deny effect, validity, grantor, reason, approval/delegation reference and revoked state. No role-name special cases or implicit wildcard future actions. |
| `authority_delegations`, `authority_elevations` and revisions | Bounded issuer/beneficiary, exact source grants/actions/scopes, expiry and chain; independent revocation. Operator elevation is an explicit tenant grant with reason/expiry, not an operator bypass. |
| `tenant_authority_state`, identity/membership security revisions | Protected monotonic security epoch plus current subject/group/grant revisions. Policy/grant/group/responsibility/ACL/classification changes advance the appropriate fence transactionally. Identity deactivation is also checked live; no eventual fan-out is the only revocation control. |
| `resource_security_facts`, `resource_field_security` and revisions | Typed resource-kind + UUID + tenant; trusted classification/approved-tag/field-label facts with source/provenance/version. Arbitrary catalog metadata or connector text cannot mint trusted security facts. Unknown facts fail closed where a rule requires them. |
| `authorization_decisions`, `authorization_decision_resources` | Private immutable decision evidence: actor/service, effective subject/delegation, action, input/policy/grant hashes, resource/version/scope references, decision/reason, expiry and current fence. A stored historical allow never grants present access. |
| `operation_authorization_bindings`, `history_authorization_references` | Additive protected companions keyed by tenant + operation/resource kind + UUID + exact revision. Bind decisions and observed scope references to existing operations/history without modifying assetView, immutable snapshots or any SQL007–011 receipt format. |

Use normalized typed scope columns with tenant-safe FKs: exactly one of tenant scope, domain scope or resource scope in A1. A resource identity includes kind; equal UUIDs across asset/domain/type/operation kinds must not alias. A protected resource-reference registry, if used, must itself be derived from real canonical rows, with no free caller-created resource identities. Future organizational/workspace scopes need real canonical entities and containment checks before the parser accepts them.

Grant administration requires explicit `authority:read`, `authority:simulate`, `authority:manage-policy`, `authority:assign-role`, `authority:assign-responsibility`, `authority:delegate` or `authority:revoke` authority as appropriate. A scoped administrator may grant only within the actions/scope/validity ceiling explicitly delegated to them; knowing a role UUID is insufficient. Define and test tenant recovery without a hidden all-content account. Deactivation and revocation remain possible when the original grantor leaves.

## 4. Actions, inheritance and deterministic evaluation

Freeze a registry of action IDs and resource kinds before parallel implementation. At minimum distinguish discover, metadata read, sensitive-field read, sample/result read, export, edit, certify, execute check, request access, approve access, connector administration, secret resolution and policy administration. Domain read/write/assignment and model definition read/write remain distinct. `ownerId` never satisfies any action.

Legacy strings such as `catalog:read` may be compatibility inputs to one explicit migration table, but cannot remain a second allow path. Split privileges without granting previously unavailable capabilities: converting catalog-read must not add sample/export/certify/native-query rights. `Principal.permissions` becomes an optional UI capability hint; server decisions use current canonical grants and resource context.

Proposed A1 AST v1: schema-validated `all`/`any` plus explicit atomic predicates over subject/group/role ID, action, resource kind/domain, approved tag/classification, declared purpose, server environment and UTC validity interval. Omit free-form expressions, regex, SQL, script and arbitrary traversal. Unknown operators, attributes, resource kinds or unsupported compiler constructs reject publication. Suggested development bounds: 128 AST nodes, depth8, 64KiB definition, 256 values per finite set and 32 ancestors. Bounds are engineering proposals, not measured scale support.

Reference decision procedure:

1. Validate authenticated tenant context, active global identity, active tenant membership or explicit scoped service/elevation binding, and supported action/resource kind. A body field cannot supply authority.
2. Resolve current resource scope from canonical placement and domain ancestry; resolve grants/groups, trusted security facts, pinned policy versions and one database decision time. An unassigned asset inherits tenant scope only. Retired domains retain historical identity; retirement alone neither grants access nor silently erases a deny.
3. Check non-policy security ceilings, including source ACL/content rights and migration compatibility ACL constraints. An allow cannot override missing source authorization or tenant membership.
4. Evaluate applicable exact-scope and explicitly inheritable ancestor rules. Any matching explicit deny overrides every allow, including a narrower child allow. No match denies. Missing required predicate data, invalid state, evaluation/lookup errors or exceeded bounds deny; errors must not silently turn a deny predicate into “not matched.”
5. Return action/field obligations and minimal decision evidence. Denying metadata also denies discovery unless a separate discover allow intentionally exposes an approved discovery projection. Field redaction must be a typed egress projection; restricted field values cannot enter search text, snippets, ordering, facets or explanations.

Inheritance is opt-in on each binding (`self` or `self-and-descendants`), with exact parent identity and current ancestry evidence. A child may add restrictions. Removing an inherited deny requires changing that deny's own reviewed policy/binding, not adding a local override allow. Multiple role/grant allows union only after ceilings/denies. Classification/role policies cannot acquire priority merely by being newer or closer.

Relations require authority on the relation and both endpoints; graph traversal must never walk hidden bridges to reveal reachable counts, paths or layout. Structural integrity still uses the complete canonical graph. A mutation with hidden affected members fails generically before counts or preview; hiding an edge never removes it from cardinality/cycle validation. Responsibility selectors and effective-access explanations expose only authorized subjects, rule details and resources.

A2 relationship grants use a separately approved finite relation-type/direction/path-length rule, with cycle handling, bounded expansion, endpoint authorization and provenance. Ordinary asserted relations cannot become grants just because their label resembles “owns.” No arbitrary transitive graph reachability is an A1 permission condition.

## 5. Shared service/compiler boundary

Propose a pure reference evaluator plus one protected application service. Freeze input/output schemas before parallel work:

```ts
// Provisional contracts, not exported executable code.
type ResourceRef = { kind: ResourceKind; id: UUID; version?: number };
type AuthorizationRequest = {
  action: ActionId; resources: readonly ResourceRef[];
  purpose: PurposeId | null; delegationId: UUID | null;
};
// Principal, tenant, time, environment, groups and resource facts are loaded by
// trusted adapters, never accepted as caller assertions.
type AuthorizationDecision = {
  allowed: boolean; decisionId: UUID; reasonCode: string;
  fieldProjection: FieldProjection; validUntil: string | null;
  opaqueFence: string;
};
```

Internal service operations: `authorizeOne`, `authorizeCompleteScope`, `compileAuthorizedRead`, `authorizeReplay`, `claimExecution` and `explainAuthorizedDecision`. Resource adapters own exact current and immutable-reference discovery; they cannot pass a pre-filtered page as the complete write scope. Decision evidence and compiler inputs remain private; public simulation has a filtered DTO.

- PostgreSQL compiler emits parameterized predicates over validated identifiers and typed facts. Independently enforce supported write authority in protected DB guards; a client-generated decision JSON/hash/GUC is never a capability. Private decisions bind actual transaction/actor/action/resources and expire with the transaction unless an explicit execution-command protocol says otherwise.
- OpenSearch compiler implements the same supported predicate set over trusted indexed security fields, with a current canonical fence. Keep the existing bounded canonical allowed-ID fallback while it is correct; over its qualified bound fail closed, never post-filter unauthorized search hits after totals. Unsupported search policies reject activation for affected searchable resources until an exact plan is available.
- Index security version must cover policy, group/grant, classification, placement/ancestry and resource revisions independently of asset metadata version. Placement changes do not mint asset revisions; the projector needs corresponding events or a canonical authorization intersection. Stale security projections deny or use the canonical fallback before aggregation. Stale field content must not influence authorized snippets/facets/ranking.
- The UI consumes effective capabilities and authorized simulation; hiding buttons is convenience only. CLI/import/API/MCP/workers call the same application service. A Python worker may evaluate a versioned compiled bundle only within an explicit short-lived lease and tested evaluator parity; it never invents permissions from a job payload.
- The simulator uses synthetic input or currently authorized resource facts. Inspecting someone else's effective access needs explicit authority; hidden policies/resources produce generic explanations, not names or counts. Simulation is never executable consent.

## 6. Revocation, concurrency and existing complete operations

Use one authority snapshot/fence per bounded transaction, read from the primary. Reauthorize immediately before protected results/effects. Every page/replay/download begins with current identity, membership and resource authorization even if its domain or graph epoch did not change. Cache keys bind tenant, actor/effective subject, action, purpose, policy/security revisions and field projection. Time-only expiry is checked against the current server clock; it needs no scheduled epoch update to deny. No cached decision lives past its earliest grant/lease expiry.

Preserve the established lock hierarchy: idempotency reservation first where applicable, then tenant ledger, then a protected authority fence, then existing model/domain/type/domain-row/asset/placement/relation order, then the single globally sorted identity/membership union. The exact cross-module order must be frozen against SQL007–011 before implementation. Do not add a blocking advisory lock in a BEFORE ROW trigger after arbitrary canonical locks. Direct incompatible writes require a BEFORE STATEMENT fail-fast fence or a narrow protected preparation function. Preserve one original transaction deadline, prearmed statement timers and late rollback checks.

Membership/grant changes and domain moves/asset placement changes participate in the same authority fence as authorization-sensitive mutations. Global identity deactivation must not acquire tenant ledgers after holding an identity row that another transaction needs: either use the predeclared complete sorted tenant lock set, or make the isolated global identity update the serialization point and require live identity revision/activity checks in all decisions without synchronous tenant-lock fan-out. Root must freeze one tested strategy; do not rely on asynchronous epoch propagation for denial.

A domain move or placement change changes effective scope even when an asset version is unchanged. The preview binds both old and proposed scope, membership/grant/role/policy revisions, group state, current placement/ancestry, trusted classification/field facts and expiry. Require explicit authority to move from the old scope and assign into the new scope, plus authorization over the complete affected resource union. A move cannot be used to evade a deny and then edit. Recompute under locks and reject stale consent before canonical writes.

Existing model/type/graph/domain migrations retain their complete-cohort invariants. Update service and forward SQL authorization seams together. Keep structural validation independent of visibility. A cached success must reauthorize its **original normalized scope**, current protected references and field disclosures; today's subtree or only the changed top-level resource is insufficient. A new policy may make an old success undisclosable; it must not cause that operation to execute twice. Continue namespaced request-hash conflict behavior and generic hidden-scope denial.

## 7. Delegation, approvals and worker effects

Delegation is an explicitly created, versioned, revocable authority record. Its scope/actions/validity must be subsets of live delegable source grants; expiration is the earliest bound in the chain. Proposed chain limit4, no cycles, and no further delegation unless explicitly permitted. Recheck every ancestor grant, active issuer/beneficiary and policy at use; revoking the parent invalidates descendants immediately without rewriting historical decisions. A group assignment cannot evade those checks.

Out-of-office task reassignment changes task responsibility, not permissions. Delegation does not erase the requester identity or independence rules: requester-as-delegate cannot self-approve when separation of duties is required; approval by aliases/service principals controlled by the same prohibited subject needs an explicit policy rather than a display-name comparison. Record effective actor, issuer chain and canonical requester. Do not fabricate approval functionality before the workflow slice exists.

A durable approval binds exact action/arguments/resource and policy versions, beneficiary, purpose, environment, expiry and delegation evidence. PostgreSQL commits decision+audit+outbox; Temporal signals cannot invent the decision. An activity reauthorizes and atomically claims a canonical execution command immediately before effects. Epoch/policy changes require fresh evaluation; incompatible resource/action changes invalidate approval. Current scanner jobs likewise recheck actor and source/site grants at claim, page/result completion and reconciliation. Permission loss cannot prove source deletion.

Revocation linearizes against committed protected effects. A mutation already authorized and committed before revocation remains historical fact; no new effect starts after revocation is observed. Long streams use bounded chunks and revalidation; do not promise to recall bytes already delivered. External source expiry/revocation is separate: an unavailable source leaves a visible pending/failed operation, not a false assertion that native access ended. Unknown external effects require read-back or explicit review before retry.

## 8. History, audit and compatibility

Do not alter canonical assetView, domain/placement revisions, graph snapshots or existing migration receipt JSON/hash formats. Record new authorization evidence in protected companion tables keyed by exact existing identity/revision, and new versioned authority-specific events. Existing journal envelopes must remain byte-identical; use a companion event/decision reference for old event families unless a separately versioned contract is adopted. Atomic companion completeness is enforced in the same transaction as canonical/audit/outbox/idempotency writes.

Historical inspection uses **current** authority to the resource, every referenced protected object and the disclosed fields. Historical allow/ownership/policy never overrides current denial. New sidecars capture actual before/after scope references under locks. Do not invent historical domain placement for pre-authority records: their existing immutable references plus current scope determine access under an explicit documented legacy-history rule. Where required source/sensitivity/scope evidence is absent, deny that protected disclosure; offer no broad “legacy bypass.” Root must adopt this rule and tests before cutover. A receipt that cannot be safely disclosed remains unchanged and receives a generic refusal, not an edited/redacted hash-bearing receipt claiming original integrity.

Authority audit contains actor/effective subject/delegation, action, policy/grant versions, minimal authorized scope references, decision/result, reason, time and correlation. Store denied attempts separately when the business transaction rolls back, without serializing hidden names/attributes or arbitrary submitted payloads. Audit search, export and decision explanations need their own current authorization predicate; `audit:read` must not mean all content. Successful scope-admin audit does not automatically reveal sensitive evidence. Retention, tamper evidence and external anchoring remain SYS-DATA-005 work; no local hash chain is described as tamper-proof.

## 9. Forward migration and activation plan

1. After SQL011 is actually applied/qualified, allocate the next forward migration at implementation time; do not preclaim SQL012 or edit applied SQL001–011. Inspect and checksum the selected schema, current memberships, ACLs and history. Add forced-RLS authority tables/guards/sidecars without rewriting receipts or granting access.
2. Inventory every existing action/visibility check and ingress. Create deterministic compatibility role versions and explicit grants from **actual current** membership permissions, preserving inactive/revoked state and current asset ACL ceilings. Do not infer grants from role labels, owners, seeded templates or past sessions; repeat migration/seed never regrants. Record provenance and require exact before/after decision equivalence across old reachable resources.
3. Keep one active authority source. A compatibility epoch may serve the old semantics while the new evaluator runs diagnostic comparisons; shadow results never grant. Activation is an atomic tenant-wide switch only when every existing ingress, worker, search/audit/replay reader and protected SQL path is ready. No permissive union of legacy and new decisions. New scoped assignments cannot be activated earlier.
4. Review the explicit impact of removing a legacy tenant-wide grant; adding a narrow domain grant while keeping the broad one is not restriction. The UI must show the remaining broad source of access. Preserve imported/native ACL provenance; administrator policy allow cannot silently override connector/source denial. Any broadening requires an explicit authorized policy/grant change.
5. Backfill only derivable current scope and historical reference facts, label unknown history, and create no fake asset/domain revisions. Rebuild security projections with separately versioned security sequence/fence while canonical denial remains live. Preserve prior indexes until safe cutover; stale aliases cannot resurrect access.
6. Run isolated upgrade/rollback qualification, exact direct-SQL guards, full current API/worker/browser regressions and real OpenSearch parity/revocation tests. Only then activate core with an audited checkpoint. Rollback after activation cannot restore a permissive old evaluator: fail closed or apply an explicit forward repair, retaining every denial/grant/history record.

## 10. Required qualification before A1 claims

These are proposed test families, **not executed tests**:

| Gate | Required real assertions |
|---|---|
| Evaluator/compiler parity | One immutable fixture corpus evaluated by reference, parameterized PostgreSQL and real OpenSearch; all/any, missing facts, invalid predicates, UTC boundaries, overlapping roles, group revocation, ancestor denies, field visibility and unsupported compilation agree. Include randomized bounded cases. |
| Direct storage/upgrade | Forced RLS/nonowner/nonbypass roles; foreign FKs, kind-alias UUIDs, forged decisions, raw grant DML, GUC/actor/tenant switching, extra writes, early constraints, missing audit/outbox and success without exact protected authorization fail. Legacy receipt/snapshot hashes and revoked memberships are unchanged. |
| Current read surfaces | Unique hidden names/field values never appear in hits, counts, facets, suggestions, sort/ranking explanations, graph paths, owner selectors, audit, receipts/history, exports or errors. Test current placement and earlier referenced scopes, same-name tenants and hidden graph bridges. |
| Concurrency and replay | Both orderings of revoke vs edit/approve/job claim; role publish/explicit grant upgrade; group removal; move/placement vs preview; expiry during waits; opposite hierarchy changes; old idempotency replay after descendant move and revocation; time-only expiry; no duplicate effects and full late rollback. |
| Source/worker | Real PostgreSQL scan under a scoped site/job actor; revoke before claim and during result completion; reduced source permissions cannot tombstone assets. Temporal restart/duplicate delivery carries IDs, not stale authority. Later native grants/downloads/MCP retain their own independent gates. |
| UI | Real role/responsibility assignment, deny explanation, effective-access inspection and scoped move/preview through supported APIs; owner-only actor denied, limited steward allowed only assigned domain, independent approver rules, operator without elevation denied. English/Arabic/RTL, phone/desktop/themes/keyboard and scoped axe; actual rendered inspection. |
| Index/cache revocation | Hold projection consumers, revoke or move scope, replay old outbox events, rebuild/cut over index and retry cached pages/results. Canonical/fenced decisions deny before counts; stale permission replicas or cached responses never restore access. |
| Disclosure and time | Denied simulation cannot reveal matched hidden rule/resource details. Replays after expiry/revocation do not expose old success. Current permission to history is checked separately from original authority; missing legacy scope evidence fails closed where required. |

Evidence must name exact source/migration/image/tool hashes, profile, commands, before/after states, actual failures and unexecuted/external qualifications. Existing M1/M2 passes are regression inputs, not proof of the new authority model. No full requirement, release or human review claim follows from adopting this draft.

## 11. Decisions root should freeze before implementation

Adopt or revise: A1 surface inventory and compatibility action mapping; scope/role pin semantics; deny inheritance and legacy ACL ceilings; trusted classification/field facts; finite AST/compiler support; global deactivation lock strategy; private decision/sidecar interfaces and legacy-history rule; grant delegation ceilings/operator recovery; activation/rollback guard. Then assign separate pure/compiler, SQL/storage/concurrency, application/worker and UI owners against those shared contracts. No user permission question or infrastructure purchase is implied by this engineering review.
