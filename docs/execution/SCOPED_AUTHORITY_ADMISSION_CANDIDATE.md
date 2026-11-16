# Scoped authority admission candidate

Status: **DRAFT — ROOT ADOPTION REQUIRED; NO IMPLEMENTATION, RUNTIME ACTIVATION OR CAPACITY QUALIFICATION.** Prepared 2026-11-16 against root commit `974105cdf571fac655a624335d387b165e7033f8`. This proposes a bounded admission contract for the next pure full-decision engine. It does not change the frozen [policy](SCOPED_AUTHORITY_PURE_CONTRACT.md), [expression](SCOPED_AUTHORITY_EXPRESSION_CONTRACT.md), [authority](SCOPED_AUTHORITY_CONTRACT_CANDIDATE.md), [administration](SCOPED_AUTHORITY_ADMIN_CANDIDATE.md), [storage](SCOPED_AUTHORITY_STORAGE_CANDIDATE.md) or [projection](SCOPED_AUTHORITY_PROJECTIONS_CANDIDATE.md) documents. Their implementation status remains in [STATE](STATE.md); the full [BUILD_SPEC](../product/BUILD_SPEC.md) and requirements remain authoritative.

The [budget baseline](SCOPED_AUTHORITY_BUDGET_BASELINE.md) records existing source guards, not approved authority limits. The numbers below are NEW authority-data proposals. None is a tenant population limit, a reduction of existing business-operation profiles or evidence that maximum workloads finish within the original deadline. Exact grant, role, issuer, ceiling and reference proof shapes belong to the separate decision contract; admission proves bounded data, never authority or provenance.

## 1. Unit of admission and independent module boundary

One admitted **decision bundle** consists of one requested atomic decision and its complete acyclic dependency graph. Dependencies include every required non-field prerequisite and every current delegation/elevation issuer decision; a service adapter may additionally require the initiating human decision. All dependency nodes share this one budget. Splitting issuer checks into fresh calls does not reset counters or convert asserted `issuerAllowed` booleans into evidence. The exact dependency schema and canonical node identity belong to the decision contract.

The bundle is distinct from a complete business operation. An operation can require many bundles for different resources, fields, current/proposed states or historical references. A graph mutation or migration must evaluate every such obligation, using bounded streaming, without a new cumulative operation-wide policy, principal, field or decision-count cap. No page, batch, memo eviction or successful dependency node proves the remaining operation allowed.

Proposed independent `packages/authority/src/admission.ts` interface, importing the existing `Parsed` result and issue vocabulary without editing frozen types:

```ts
export type AuthorityJSON = null | boolean | number | string
  | readonly AuthorityJSON[] | { readonly [key: string]: AuthorityJSON };
export type AdmissionMetrics = {
  readonly rawBytes: number | null; // UTF-8 file bytes; null for an object input
  readonly canonicalBytes: number;
  readonly nodes: number;
  readonly depth: number;
};
export type AdmittedJSON = {
  readonly data: AuthorityJSON;
  readonly metrics: AdmissionMetrics;
};
export function admitAuthorityInput(input: unknown): Parsed<AdmittedJSON>;
export function parseAuthorityInputFile(text: string): Parsed<AdmittedJSON>;
// Export frozen AUTHORITY_ADMISSION_LIMITS with the exact numbers below.
```

Both functions return a detached deeply frozen JSON snapshot and measured metrics. This wrapper is an ordinary result, not an unforgeable capability. The decision engine does not trust caller-supplied wrappers, counters, completeness flags or hashes: its public entry point invokes admission and then validates its exact closed schema and semantic budgets. A separate raw-file entry point may pass a module-private admitted result directly, avoiding redundant copying without exposing a caller bypass. It must still apply all semantic validation.

Generic admission enforces physical byte/node/depth limits and valid data shape only. Exact properties, action/resource applicability, policy pins and cumulative proof categories belong to the decision engine. Unknown or unsupported schema data never becomes allowed merely because generic admission accepted it. A public decision boundary maps a physical or semantic limit to a denied `profile_limit`, malformed or unavailable required evidence to denied `indeterminate`, with no thrown success. Submitted-input parser issues use the existing `limit`, `invalid_json`, `duplicate`, `type` and related codes, at most 64 deterministic entries with bounded paths/messages; do not expose private loaded values. Future HTTP adapters preserve authorization-before-cardinality: an unavailable complete scope yields its generic scope denial before any visible profile diagnosis. A private budget counter does not justify disclosing hidden cohort size.

## 2. Exact physical admission

All byte units are binary: KiB = 1,024 bytes; MiB = 1,048,576 bytes. JSON bytes mean UTF-8 serialization, including escaped keys/values, delimiters and punctuation, not JavaScript UTF-16 length, database heap size or process RSS. Root container depth is 1. A JSON node is each container or scalar value; property names contribute bytes but are not additional value nodes. Repeated values are charged at every serialized occurrence.

| Counter / proposed exported key | Maximum | Enforcement |
|---|---:|---|
| `rawBytes` | 8,388,608 | Check a file/string before JSON materialization, including whitespace. Reject duplicate decoded keys, including escaped spellings of the same key, before they can be overwritten. |
| `canonicalBytes` | 8,388,608 | Charge the detached snapshot's complete canonical JSON; semantic normalization must independently remain within this same total. No uncharged attached proof records. |
| `jsonNodes` | 262,144 | Cumulative across the entire bundle and all nested values, not per array, policy or context. |
| `jsonDepth` | 32 | Physical JSON nesting, distinct from AST depth, delegation edges and dependency depth. |
| `issues` | 64 | Bounded submitted-input diagnostics; returning fewer deterministic issues is permitted. This does not truncate decisions or match witnesses. |

JSON scalar numbers must be finite safe integers and cannot be negative zero; versions and other semantic ranges are checked later. Strings and keys must be well-formed Unicode. No coercion, getters, setters, symbols, functions, undefined, bigint, exotic objects, sparse arrays, extra array properties, cycles or proxies. Object input is restricted to own enumerable data properties of ordinary or null-prototype objects, and dense ordinary arrays. Reject proxies before reflection or property access. Construct copied objects through safe data-property materialization, preserving literal keys without invoking inherited setters; generic admission does not invent a domain-key grammar. Canonical output sorts object keys by the existing code-unit comparator and preserves arrays. Shared input references are copied/charged per occurrence; cycles are rejected.

The object-input API assumes a trusted producer has already bounded allocation before calling it. `Reflect.ownKeys`, descriptors and preexisting strings can already consume memory: this proposal does not claim constant-memory handling of an arbitrarily allocated hostile JavaScript object. External documents use the bounded raw entry point. Future SQL loaders must preflight physical rows/counts before retrieving payloads, then retain cumulative measurements while loading; checking `JSON.stringify` after fetching an unlimited result is insufficient. Bounds do not make raw `gc_app` assertions trustworthy.

## 3. Complete decision-bundle semantic limits

These limits are cumulative over the full root/dependency bundle, including live issuer content decisions, role evidence, field prerequisites, inherited and resource-wide denies, and adapter-bound narrow references. All constraints apply simultaneously; the table does not promise that all maxima coexist. Subtotal byte counters charge portions of the complete canonical input; they are not extra allowances added to 8 MiB.

| Counter / proposed exported key | Maximum | Exact charging rule |
|---|---:|---|
| `contexts` | 128 | Unique canonical decision-context nodes. A repeated exact context may share a node only when every subject/request/currentness/fact input is identical. |
| `dependencyEdges` | 1,024 | Unique directed context-to-context dependency edges. A cycle, unresolved edge or duplicate declared edge is invalid, irrespective of capacity. |
| `dependencyReferences` | 4,096 | Every serialized dependency reference, including reuse by separate bindings/roles. Deduplicating graph edges cannot hide fan-out work. |
| `dependencyDepth` | 8 | Maximum context nodes on a root-to-leaf path, counting root and leaf. Iterative graph validation must not recurse into an unbounded graph. |
| `policyPins` | 32 | Distinct exact policy `(id,version,hash)` definitions in the complete conservative candidate set. Identical bytes/pins can share parsing; conflicting definitions cannot. |
| `policyBytes` | 2,097,152 | Sum of canonical policy-definition bytes, once per exact pin. Existing 65,536 raw and normalized bytes per definition still apply. |
| `policyRules` | 4,096 | Sum of rules over exact distinct definitions, before predicate evaluation. Existing 128 per policy still applies. |
| `expressionNodes` | 4,096 | Sum of AST nodes over exact distinct definitions. Existing 128 nodes per definition, depth 8 and 256 entries per finite set/children remain unchanged. |
| `bindingInstances` | 512 | Each derived `(context, exact grant path, policy pin)` instance after expanding EVERY policy pin of the resolved role/responsibility/service grant, including independent scope/validity/lineage variants. The same grant used in two contexts costs two instances. A candidate grant count or caller-filtered binding list is insufficient. Do not count only unique policy pins or matched allows. |
| `roleInstances` | 256 | Each exact request-scoped role-proof instance in a context, including its full current assignment/origin/membership/connected lineage. Sharing an exact role definition does not deduplicate these proofs. |
| `originGrants` | 512 | Distinct exact original grant/version proof records referenced by bindings or roles; complete canonical provenance remains mandatory. |
| `delegationRecords` | 1,024 | Distinct exact delegation/elevation proof records used anywhere in the bundle. No unrelated global grant inventory is required. |
| `delegationDepth` | 4 | Delegation edges on each connected origin-to-beneficiary path, preserving the admin proposal. This is not context dependency depth. |
| `lineageEdgeOccurrences` | 3,072 | Sum of path-edge occurrences over binding and role instances: `(512 + 256) × 4`. Repeated shared records still cost occurrences. Additional dependency references also consume their separate counter. |
| `authorityPrincipals` | 2,048 | Distinct exact subject/identity/membership proof subjects required by the bundle, including live issuers and beneficiaries. This is a new authority-evidence budget, separate from the existing 2,001 business principal-lock union. |
| `proofBytes` | 2,097,152 | Complete binding, role, grant, lineage, principal, direct-group membership and their provenance records. Charge each serialized copy; factored references do not remove required referenced records from this subtotal. |
| `directGroupsPerSubject` | 1,024 | Complete current direct memberships in NEW authority groups for each subject requiring group facts. Include memberships for issuer contexts; no nested groups and no first-N or policy-mentioned-only membership sample. The total proof bytes/node limits still apply across all subjects. |
| `approvedFactIds` | 4,096 | Cumulative classification/tag fact occurrences over complete canonical resource/field fact records in all contexts, including inherited facts and their provenance. Reusing a fact record requires exact identity/version/meaning; different provenance is not the same fact. |
| `factBytes` | 1,048,576 | Complete approved classification/tag, domain path, purpose and environment fact records/provenance. Direct-group records are charged under proof bytes. Metadata and suggested tags are not approved facts. |
| `domainPathEntries` | 33 | Per complete expression fact path: direct domain plus at most 32 ancestors, no repeats/cycles. This preserves the expression interpretation, not a change to the existing business-domain hierarchy depth 32. |
| `catalogEntries` / `catalogBytes` / `fieldBytes` | 16,384 / 131,072 / 256 | The existing relevant trusted field-handle catalog per admitted bundle/parser call, including handles needed by all candidate policies. Exact unique entries and UTF-8 field bytes; not a global registry or operation field-inventory cap. |
| `ruleEvaluations` / `predicateVisits` | 65,536 / 65,536 | Instantiated work, not definition count: each of 512 binding instances can evaluate at most 128 rules / cumulative AST nodes. Count repeats after memo eviction. Finite-set membership and proof validation work are additionally bounded by the admitted arrays and physical node budget. |
| `matchWitnesses` / `matchBytes` | 65,536 / 33,554,432 | Complete compact match tuples, factored by context and exact binding/rule references. No copied policy or full lineage per tuple. This is an output budget distinct from the 8-MiB input; never silently truncate a claimed complete witness. |

The decision contract may use factored maps/arrays rather than duplicated nested objects. That changes encoding, not the logical counters: an edge occurrence or binding evaluation still counts even when its immutable record is shared. A registered context with no policy bindings costs a context and its facts; it does not manufacture a default allow. Every declared record must be exact, unique under the declared key and justified by the complete dependency closure. Unresolved, conflicting or extraneous records are schema/integrity failures, not an opportunity to guess which one was intended.

The conservative policy set is selected using exact canonical subject/group/assignment, declared action/field, scope/ancestry and protected deny-intent provenance. It must include every possibly relevant allow or deny before evaluating `when`. No omission based on a matching allow, a failing child of `all`, an early matching child of `any`, an unavailable fact or a currently false predicate. Time-disjoint/future bindings remain part of admission overlap analysis; a runtime loader may exclude a proven revoked or definitely expired binding only under the decision contract's exact canonical validity/completeness rules. Uncertainty fails closed. Do not charge only current successful predicates and let future activation overflow unannounced.

Rationale: 32 policies align with the proposed maximum pins in one new role/responsibility definition; 32 × 64 KiB = 2 MiB and 32 × 128 = 4,096 nodes/rules. The 512 instance budget permits many independently scoped grants while limiting repeated rule evaluation to 65,536. The four-edge lineage cap already appears in the admin draft. Larger context/proof/group budgets are practical starting proposals for explicit admission testing, not measurements or a maximum-supported tenant profile. A role containing 32 policies can still be refused if its issuer/prerequisite dependency closure exceeds the total bundle limit.

## 4. New authority-data admission before activation

New policy/role publication, assignment/responsibility/delegation/elevation issuance, group membership, approval-fact changes and imports must preserve the complete-bundle limits before authority becomes usable. Publication alone is inert, but activation or pinning must validate every affected conservative candidate closure. A group with a million members is not intrinsically over this profile: each affected subject's direct memberships and decision closure are evaluated completely. No maximum group-member count or tenant-user count is introduced. The 1,024 limit is a new direct-group relation admission limit per subject, not a limit on the number of users who can share a group.

The future loader/storage gate must also cover scope moves, registry additions, parent/delegation edits and validity-window changes that can increase overlap or dependency depth. Serialize competing admissions under the protected tenant authority fence and recheck affected exact versions before commit; independently successful local counts must not combine into an over-limit state. Consider potentially overlapping future half-open validity windows, not only database `now`. Removals/revocations that strictly reduce closure remain available under their ordinary authorization and integrity checks; remediation must not require retaining an invalid grant.

This proposal does not assert that such impact checking is implemented or that arbitrary future overlap can be determined cheaply. Before runtime activation, qualify either a complete conservative index/proof or complete streamed impact examination for each actual mutation adapter. An unknown impact, deadline exhaustion or over-limit proposed authority state causes the entire new admission to fail with the existing `AUTHORITY_PROFILE_LIMIT` or retry contract as appropriate; never approve the first subset. No asynchronous staged activation protocol is introduced by this document.

For existing legacy permissions, migration must preserve every supported identity, membership, service principal and explicit permission byte/meaning; it cannot delete grants, shorten scopes, silently drop deny rules or classify ownership as authority to fit these limits. Verify the generated compatibility closure and its issuer/prerequisite contexts before cutover. If it cannot fit or if the loader cannot preserve any existing admitted business cohort/field product within its original operation guards, activation remains blocked pending an explicit reviewed contract revision. Runtime detection of corrupt, missing or over-limit evidence denies safely and retains diagnostics; it does not turn the configured profile into permission to repair existing data automatically.

## 5. Request work, memory and deadlines

The single-bundle data limits do not bound a whole operation's number of field decisions. For example, 1,000 assets with 128 sparse optional fields already require 128,000 combinations per phase; nested models and before/after/reference projections add obligations. Never materialize that whole resource × field × policy product or reset the business deadline at each bundle. A field-catalog buffer is a relevant working set; all canonical fields required by every actual projection must eventually be processed. Batching has no meaning outside the one original operation fence/snapshot.

Proposed scheduling/resource constants for future qualified loaders:

| Resource | Proposed bound / rule |
|---|---|
| Selector batch | At most 64 atomic descriptors or 262,144 canonical descriptor bytes, whichever comes first. A larger valid single descriptor is handled alone under its existing business guard and the bundle's 8-MiB bound, not truncated or rejected merely for exceeding this batching target. |
| Time checkpoints | At entry/exit, every external query, at most 32 completed bundles, and every 4,096 predicate visits within a bundle. Proof/field enumeration checks at most every 4,096 visited values. These are maximum work quanta between deadline observations, not new success permissions. |
| Query concurrency | One outstanding authority query per operation in the initial reference loader. Each query receives the remaining original timeout; parallel loader qualification is separate. This is not a tenant-wide request limit. |
| Memo | At most 1,024 complete descriptor entries or 8,388,608 accounted bytes, whichever comes first; eviction recomputes. Do not evict pending dependency nodes to evade the per-bundle counts or claim a partial proof complete. |
| Accounted retained authority representation | At most 67,108,864 bytes: 8 MiB raw input buffer + 8 MiB normalized input + 8 MiB retained compiled/index representations + 8 MiB memo + 32 MiB compact result witnesses. Charge retained copies to their category, release buffers between bundles, and fail rather than allocate an unaccounted retained payload. |
| Operation deadline | Keep the original adapter/DB transaction deadline. Existing protected mutations retain their original 30 seconds and at most 5-second lock wait; admission, queries, dependencies, replay, constraints and completion all consume the same original window. No fresh 30 seconds for a nested check or retry. A future read adapter must receive a finite original deadline; this document does not redefine every existing HTTP route's timeout. |

The 64-MiB figure is a canonical/accounted retained-representation budget, **not a demonstrated hard JavaScript heap or RSS limit**. Object headers, maps, native driver buffers, garbage collection, parser temporaries and transient indexes require real memory qualification. The independent pure evaluator is deterministic over supplied canonical time and does not claim to interrupt an arbitrary synchronous CPU task at 30 seconds. Future runtime loaders must prearm database/network timers and validate cooperative CPU scheduling; the time-check quantum is not a universal wall-clock interrupt guarantee. No process-wide worker concurrency, heap setting or supported-machine capacity is adopted here.

Pure metrics must report actual visited rules/predicates/proof records; admission counters are not caller assertions. Identical immutable policy parsing can be shared, but instantiated bindings/rules still consume work. Evaluate each context once in validated topological order and retain its compact result for the bundle; the optional operation memo must not evict an unresolved dependency and force unbounded repeated evaluation. A bundle may stop once its complete result is safely denied, without disclosing which hidden dependency failed; an allow requires every dependency and required rule. Existing expression semantics still validate the full AST and evaluate all branches of each evaluated `all`/`any`, with indeterminate dominating. A diagnostic short circuit cannot suppress an indeterminate predicate to produce allow.

Memo keys include exact tenant/subject/session or service identity, action/resource/revision/field, canonical context/proposed-or-current state, policies and all proof/fact versions, projection/registry, authority generation/epoch, original consistency window and relevant validity boundary. Reuse stays within that operation; no cross-request stale cache is authorized. Each dependency's earliest expiry bounds the root's `validUntil`. SQL, service and search do not accept an old memo or a pure result as a capability.

Authority evidence is charged to these new authority counters. It is never added to the existing business 512-KiB/100,000-node payload budgets or the 2,001 business principal guard. Required new authority principal locking remains part of the shared canonical lock order and separate admission/work counters. A lock count cannot be used to omit an issuer or reduce an otherwise supported model/domain/graph cohort.

## 6. Required qualification and remaining dependencies

For the independent generic module, require exact/over-bound UTF-8 raw and canonical bytes, whitespace and escaped duplicate keys, node/depth boundaries, safe-integer/Unicode handling, cycles/sparse arrays/exotics/accessors/proxies, inherited setter/read-only properties, detached frozen output and accurate repeat-occurrence metrics. Preserve original failing attempts; do not add runtime claims to a host-only parser test.

For the full pure decision engine, test cumulative limits across multiple dependency nodes, shared definitions with repeated binding work, exact 128/129 contexts and depth 8/9, cycles/missing references, 32/33 policy pins, 512/513 binding instances, complete groups including issuers, lineage edge counts, denied/indeterminate dependencies, matched-witness completeness and whole-bundle failure. Generic admission success alone cannot satisfy these tests. Exact proof equations and DTOs remain the separately reviewed decision contract, not this budget document.

Before runtime activation, the remaining mandatory gates are complete selector/count preflight; concurrent authority admission and revocation; future validity overlap; subject/group/issuer churn; scope and registry changes; current/historical aliases and field prerequisites; compatibility migration; and SQL/service/OpenSearch equivalence. Include the existing maximum admitted business scopes with sparse and nested fields, current/proposed phases, many denies, many distinct policy pins across the operation, and memo eviction/recomputation. Measure CPU, actual peak memory, query counts and original-deadline behavior. A complete operation can legitimately span more than 32 policy pins or 2,048 authority subjects across different bundles; tests must prevent accidental global caps.

No maximum-size workload, parser, full-decision or runtime test was executed for this document. The exact numeric draft requires root adoption; physical admission can be implemented independently once adopted. Full pure decisions additionally require the separate exact evidence schema. Loader/index admission feasibility, physical memory qualification and all-ingress activation remain unfinished, without weakening these negative gates.

## 7. Frozen source references

SHA256 values identify the documents actually consulted; this candidate does not rewrite their hashes or imply their draft sections are implemented.

| Document | SHA256 |
|---|---|
| `SCOPED_AUTHORITY_CONTRACT_CANDIDATE.md` | `443a6b796354f6b8daf2dea3b98e83426faca19d4c57139e89a526c533433802` |
| `SCOPED_AUTHORITY_STORAGE_CANDIDATE.md` | `c35e1754db65487b69f8a7e021c03bf7b20798ba4dfb60394e54ef70d81f526f` |
| `SCOPED_AUTHORITY_PROJECTIONS_CANDIDATE.md` | `c0fe7d452e4b07a84810577c657e1625eaf371bc29ae3a83ac9cce42dec04eae` |
| `SCOPED_AUTHORITY_ADMIN_CANDIDATE.md` | `ee7b0fcc6d604338239641390da033b95058a63fe2ee2e6680e294ce8e0f8692` |
| `SCOPED_AUTHORITY_BUDGET_BASELINE.md` | `432da20390e76b0e94041ea2955a00b8d20a90eecb5735d44e5f53e5013f6fe0` |
| `SCOPED_AUTHORITY_PURE_CONTRACT.md` | `00fd5a4aee6e067bd81ed66ef4b812f7019851fc4082a27609098c531fb36dd6` |
| `SCOPED_AUTHORITY_EXPRESSION_CONTRACT.md` | `2ecf3356ceeae2fc52be7e77a1725ec585d722da60d54bfb0ba64283ae5e269f` |
