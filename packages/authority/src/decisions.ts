// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { AUTHORITY_ADMISSION_LIMITS as LIMITS } from './admission.ts';
import { DecisionBudget, canonicalDecisionBytes, AUTHORITY_RETAINED_LIMITS } from './decision-budget.ts';
import { parseDecisionInput, parseDecisionInputFile } from './decision-schema.ts';
import { validateDecisionIdentities } from './decision-identity.ts';
import { prepareContext } from './decision-context.ts';
import { prepareChains, resolveChains } from './decision-chains.ts';
import { evaluatePolicyExpression, type ExpressionFacts, type ExpressionTruth } from './expressions.ts';
import { DecisionInputError, policyKey, subjectKey, type DecisionInput, type DecisionBundleResult,
  type DecisionNode, type NodePlan, type NodeId, type NodeDecision, type MatchWitness,
  type DecisionReason, type EffectiveBinding } from './decision-types.ts';
import type { AuthorityIssue, Parsed, PolicyExpr, PolicyRule, UTC } from './types.ts';

const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** Only internally admitted values enter canonical hashing; strings are streamed
 * individually and the complete fact object is never serialized into a buffer. */
function factDigest(value: unknown): string {
  const hash = createHash('sha256');
  function write(row: unknown): void {
    if (row === null || typeof row !== 'object') { hash.update(JSON.stringify(row)); return; }
    if (Array.isArray(row)) {
      hash.update('['); row.forEach((child, index) => { if (index) hash.update(','); write(child); }); hash.update(']');
    } else {
      hash.update('{'); Object.keys(row).sort(compare).forEach((key, index) => {
        if (index) hash.update(','); hash.update(JSON.stringify(key)); hash.update(':'); write((row as Record<string, unknown>)[key]);
      }); hash.update('}');
    }
  }
  write(value); return hash.digest('hex');
}
function expressionText(value: PolicyExpr): string {
  function text(row: unknown): string {
    if (row === null || typeof row !== 'object') return JSON.stringify(row);
    if (Array.isArray(row)) return `[${row.map(text).join(',')}]`;
    return `{${Object.keys(row).sort(compare).map(key => `${JSON.stringify(key)}:${text((row as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  return text(value);
}
function expressionNodes(expression: PolicyExpr): number {
  return 1 + (expression.op === 'all' || expression.op === 'any' ? expression.children.reduce((n, child) => n + expressionNodes(child), 0) : 0);
}
function future(now: UTC, values: readonly (UTC | null)[]): UTC | null {
  let result: UTC | null = null;
  for (const value of values) if (value !== null && value > now && (result === null || value < result)) result = value;
  return result;
}
function expressionBoundaries(expression: PolicyExpr): UTC[] {
  if (expression.op === 'all' || expression.op === 'any') return expression.children.flatMap(expressionBoundaries);
  return expression.op === 'time-within' ? [expression.validity.notBefore, expression.validity.expiresAt].filter((v): v is UTC => v !== null) : [];
}
function usedFacts(expression: PolicyExpr, used = new Set<keyof ExpressionFacts>()): ReadonlySet<keyof ExpressionFacts> {
  used.add('subject'); used.add('request'); used.add('now');
  if (expression.op === 'all' || expression.op === 'any') for (const child of expression.children) usedFacts(child, used);
  else {
    const field: Partial<Record<PolicyExpr['op'], keyof ExpressionFacts>> = {
      'group-any': 'groups', 'role-any': 'requestRoles', 'domain-in': 'domainPath',
      'classification-any': 'classifications', 'approved-tag-any': 'approvedTags',
      'purpose-in': 'purpose', 'environment-in': 'environment',
    };
    const name = field[expression.op]; if (name) used.add(name);
  }
  return used;
}
/** JSON value nodes plus own data properties. Arrays contribute their indices
 * and their own length property; scalar primitive metadata is not an object. */
function validationVisits(value: unknown): number {
  if (value === null || typeof value !== 'object') return 1;
  const children = Object.values(value);
  return 1 + children.length + Number(Array.isArray(value)) + children.reduce<number>((n, child) => n + validationVisits(child), 0);
}

function chargeInput(input: DecisionInput, budget: DecisionBudget): void {
  const { bundle, registry } = input;
  budget.retain('normalized', input.admission.canonicalBytes);
  if (input.admission.rawBytes !== null) budget.retain('raw', input.admission.rawBytes);
  budget.charge('contexts', bundle.nodes.length, '/bundle/nodes');
  budget.charge('policyPins', bundle.policies.length, '/bundle/policies');
  for (const evidence of bundle.policies) {
    const policy = input.parsedPolicies.get(policyKey(evidence.pin));
    if (!policy) budget.fail('invalid', 'required', '/bundle/policies', 'Missing parsed exact policy pin.');
    const bytes = canonicalDecisionBytes(policy);
    budget.charge('policyBytes', bytes); budget.retain('compiled', bytes);
    budget.charge('policyRules', policy.rules.length);
    for (const rule of policy.rules) budget.charge('expressionNodes', expressionNodes(rule.when));
  }
  budget.charge('originGrants', bundle.grants.filter(row => row.ref.kind === 'grant').length);
  budget.charge('delegationRecords', bundle.grants.filter(row => row.ref.kind !== 'grant').length);
  const subjects = new Set<string>();
  for (const row of bundle.principals) subjects.add(subjectKey(row));
  for (const row of bundle.grants) { subjects.add(subjectKey(row.issuer)); subjects.add(`${row.beneficiary.kind}:${row.beneficiary.id}`); }
  for (const row of bundle.memberships) subjects.add(`human:${row.identityId}`);
  for (const row of bundle.nodes) subjects.add(subjectKey(row.subject));
  budget.charge('authorityPrincipals', subjects.size);
  const proofTables = ['principals', 'groups', 'memberships', 'principalGroups', 'sessions', 'credentials',
    'definitions', 'grants', 'candidates', 'chainLinks', 'visibility', 'creators', 'serviceAssignments', 'sources', 'jobs', 'claims',
    'leases', 'projectionEvents', 'journalClaims', 'terminals'] as const;
  for (const name of proofTables) for (const row of bundle[name]) budget.charge('proofBytes', canonicalDecisionBytes(row), `/bundle/${name}`);
  for (const row of bundle.principalGroups) if (row.memberships.status === 'known' && row.memberships.value.length > LIMITS.directGroupsPerSubject) {
    budget.fail('profile_limit', 'limit', '/bundle/principalGroups', 'A complete direct-group proof exceeds its subject profile.');
  }
  for (const row of [...bundle.approvedFacts, ...bundle.contextFacts]) budget.charge('factBytes', canonicalDecisionBytes(row));
  for (const row of bundle.approvedFacts) budget.charge('approvedFactIds', row.values.length);
  for (const row of bundle.contextFacts) if (row.value !== null) budget.charge('approvedFactIds', 1);
  function path(value: DecisionNode['resource']['containment']['domainPath']): void {
    if (value.status === 'known' && value.value.length > LIMITS.domainPathEntries) budget.fail('profile_limit', 'limit', '/bundle', 'A complete domain path exceeds the existing profile.');
  }
  for (const row of bundle.nodes) {
    path(row.resource.containment.domainPath);
    budget.charge('factBytes', canonicalDecisionBytes(row.resource.containment));
    budget.charge('factBytes', canonicalDecisionBytes({ classifications: row.resource.classifications,
      approvedTags: row.resource.approvedTags, purpose: row.purpose, environment: row.environment }));
    budget.charge('dependencyReferences', Number(row.intentGuard !== null) + Number(row.guardOrigin !== null));
    if (row.projection) budget.charge('dependencyReferences', row.projection.prerequisites.length + Number(row.projection.sensitiveDecision !== null));
    if (row.service && 'initiatingDecision' in row.service && row.service.initiatingDecision !== null) budget.charge('dependencyReferences', 1);
  }
  for (const row of bundle.scopeAnchors) { path(row.containment.domainPath); budget.charge('factBytes', canonicalDecisionBytes(row)); }
  for (const row of bundle.operations) {
    budget.charge('factBytes', canonicalDecisionBytes(row));
    for (const member of row.members) path({ status: 'known', value: member.domainPath });
  }
  budget.charge('dependencyReferences', bundle.chainLinks.length);
  for (const row of bundle.journalClaims) budget.charge('dependencyReferences', row.parentDecisions.length);
  budget.charge('catalogEntries', registry.fields.length);
  for (const field of registry.fields) {
    const bytes = Buffer.byteLength(field, 'utf8');
    if (bytes > LIMITS.fieldBytes) budget.fail('profile_limit', 'limit', '/registry/fields', 'A field handle exceeds its byte profile.');
    budget.charge('catalogBytes', bytes);
  }
  // Index records hold keys and references to already charged immutable records,
  // not repeated serialized copies of those records.
  for (const index of Object.values(input.indexes)) for (const key of index.keys()) budget.retain('compiled', canonicalDecisionBytes([key, key]));
}

function graph(input: DecisionInput, budget: DecisionBudget): { plans: ReadonlyMap<NodeId, NodePlan>; order: readonly NodeId[]; dependencies: ReadonlyMap<NodeId, readonly NodeId[]> } {
  const plans = new Map<NodeId, NodePlan>(), dependencies = new Map<NodeId, readonly NodeId[]>(), used = new Set<object>();
  for (const node of [...input.bundle.nodes].sort((a, b) => compare(a.id, b.id))) {
    const context = prepareContext(input, node, budget), chains = prepareChains(input, node, budget);
    budget.retain('compiled', canonicalDecisionBytes({ facts: context.facts, mandatoryDependencies: context.mandatoryDependencies,
      intentGuard: context.intentGuard, denialReasons: context.denialReasons, derivedOrdinaryFieldAllow: context.derivedOrdinaryFieldAllow,
      validUntil: context.validUntil }));
    plans.set(node.id, { node, context, chains }); used.add(node);
    for (const row of context.usedRecords) used.add(row);
    for (const row of chains.usedRecords) used.add(row);
    const references = [...context.mandatoryDependencies, ...chains.dependencies];
    if (context.intentGuard !== null) references.push(context.intentGuard);
    const unique = [...new Set(references)].sort(compare);
    budget.charge('dependencyEdges', unique.length);
    for (const dependency of unique) if (dependency === node.id || !input.indexes.nodes.has(dependency)) {
      budget.fail('invalid', 'scope', '/bundle/nodes', 'A dependency must identify another exact bundle node.');
    }
    dependencies.set(node.id, unique);
    budget.retain('compiled', canonicalDecisionBytes({ nodeId: node.id, dependencies: unique }));
    if (node.mode === 'authorize') {
      if (node.guardOrigin !== null || node.intentGuard === null || context.intentGuard !== node.intentGuard) budget.fail('invalid', 'scope', '/bundle/nodes', 'An authorization requires its exact intent guard.');
      const guard = input.indexes.nodes.get(node.intentGuard);
      if (!guard || guard.mode !== 'resource-wide-deny') budget.fail('invalid', 'scope', '/bundle/nodes', 'Intent guards must identify an exact deny-guard node.');
    } else {
      const origin = node.guardOrigin === null ? undefined : input.indexes.nodes.get(node.guardOrigin);
      if (node.intentGuard !== null || !origin || origin.mode !== 'authorize' || origin.intentGuard !== node.id) budget.fail('invalid', 'scope', '/bundle/nodes', 'A deny guard requires one reciprocal authorization origin.');
    }
  }
  const root = input.indexes.nodes.get(input.bundle.root);
  if (!root || root.mode !== 'authorize') budget.fail('invalid', 'scope', '/bundle/root', 'The root must be an authorization node.');
  const visiting = new Set<NodeId>(), complete = new Set<NodeId>(), depths = new Map<NodeId, number>();
  function visit(id: NodeId): number {
    if (visiting.has(id)) budget.fail('invalid', 'scope', '/bundle/nodes', 'The complete authority dependency graph must be acyclic.');
    if (complete.has(id)) return depths.get(id)!;
    visiting.add(id); let depth = 1;
    for (const dependency of dependencies.get(id)!) depth = Math.max(depth, 1 + visit(dependency));
    budget.maximum('dependencyDepth', depth); visiting.delete(id); complete.add(id); depths.set(id, depth); return depth;
  }
  visit(root.id);
  if (complete.size !== plans.size) budget.fail('invalid', 'scope', '/bundle/nodes', 'The bundle contains nodes outside the complete root dependency closure.');
  for (const [name, rows] of Object.entries(input.bundle)) if (Array.isArray(rows)) for (const row of rows) {
    if (!used.has(row)) budget.fail('invalid', 'scope', `/bundle/${name}`, 'Every supplied evidence record must be used by the complete dependency closure.');
  }
  for (const row of input.registry.producers) if (used.has(row)) budget.charge('factBytes', canonicalDecisionBytes(row), '/registry/producers');
  for (const row of input.registry.leaseIssuers) if (used.has(row)) budget.charge('proofBytes', canonicalDecisionBytes(row), '/registry/leaseIssuers');
  // Stable Kahn ordering, dependencies first. Node IDs only break available ties.
  const order: NodeId[] = [], pending = new Set(complete);
  while (pending.size) {
    const ready = [...pending].filter(id => dependencies.get(id)!.every(dependency => !pending.has(dependency))).sort(compare);
    if (!ready.length) budget.fail('invalid', 'scope', '/bundle/nodes', 'The complete dependency graph has no evaluable node.');
    const id = ready[0]; pending.delete(id); order.push(id);
  }
  return { plans, order, dependencies };
}

function applicable(rule: PolicyRule, node: DecisionNode): boolean {
  return rule.actions.includes(node.request.action) && (rule.fields === null ? node.request.field === null : node.request.field !== null && rule.fields.includes(node.request.field));
}
function ceilingApplies(binding: Pick<EffectiveBinding, 'ceiling'>, node: DecisionNode): boolean {
  return binding.ceiling.actions.includes(node.request.action) && binding.ceiling.resourceKinds.includes(node.request.resource.kind)
    && (node.request.field === null || binding.ceiling.fields === null || binding.ceiling.fields.includes(node.request.field));
}
function marked(input: DecisionInput, policy: EffectiveBinding['policy'], rule: PolicyRule, node: DecisionNode): boolean {
  if (node.mode === 'authorize') return true;
  return rule.effect === 'deny' && !!input.indexes.policies.get(policyKey(policy))?.resourceWideIntents.some(intent =>
    intent.ruleId === rule.id && intent.resourceKinds.includes(node.request.resource.kind) && intent.expandedActions.includes(node.request.action));
}
function witnessCompare(a: MatchWitness, b: MatchWitness): number {
  return compare(a.policy.policyId, b.policy.policyId) || a.policy.version - b.policy.version || compare(a.policy.hash, b.policy.hash)
    || compare(a.ruleId, b.ruleId) || compare(a.grant.kind, b.grant.kind) || compare(a.grant.id, b.grant.id)
    || a.grant.version - b.grant.version || compare(a.effect, b.effect);
}
const precedence: readonly DecisionReason[] = ['inactive_subject', 'tenant_denied', 'expired', 'ceiling_denied', 'scope_unavailable', 'indeterminate', 'explicit_deny', 'no_allow', 'allowed'];
function reason(reasons: ReadonlySet<DecisionReason>): DecisionReason {
  for (const value of precedence) if (reasons.has(value)) return value;
  return 'no_allow';
}

type MemoEntry = { truth: ExpressionTruth; bytes: number };
class PredicateMemo {
  private readonly rows = new Map<string, MemoEntry>();
  private bytes = 0;
  constructor(private readonly budget: DecisionBudget) {}
  evaluate(expression: PolicyExpr, facts: ExpressionFacts, digest: string): ExpressionTruth {
    const normalized = expressionText(expression), key = `${normalized}\n${digest}`;
    const keyBytes = canonicalDecisionBytes(key);
    this.budget.retain('compiled', keyBytes);
    const hit = this.rows.get(key);
    if (hit) { this.budget.charge('memoHits', 1); this.budget.release('compiled', keyBytes); return hit.truth; }
    this.budget.charge('chargedPredicateNodeVisits', expressionNodes(expression));
    let visits = 0; for (const field of usedFacts(expression)) visits += validationVisits(facts[field]);
    this.budget.charge('factValidationVisits', visits);
    this.budget.charge('actualPredicateCalls', 1);
    const truth = evaluatePolicyExpression(expression, facts);
    const bytes = canonicalDecisionBytes({ key, truth });
    while (this.rows.size && (this.rows.size >= 1_024 || bytes > AUTHORITY_RETAINED_LIMITS.memo - this.bytes)) {
      const oldest = this.rows.keys().next().value!; const removed = this.rows.get(oldest)!;
      this.rows.delete(oldest); this.bytes -= removed.bytes; this.budget.release('memo', removed.bytes);
    }
    this.budget.retain('memo', bytes); this.bytes += bytes; this.rows.set(key, { truth, bytes });
    this.budget.release('compiled', keyBytes);
    return truth;
  }
}

function evaluateNode(input: DecisionInput, plan: NodePlan, dependencies: readonly NodeId[], decisions: ReadonlyMap<NodeId, NodeDecision>, memo: PredicateMemo, budget: DecisionBudget): NodeDecision {
  const { node, context, chains } = plan;
  const resolved = resolveChains(input, chains, decisions, budget);
  const facts: ExpressionFacts = { ...context.facts, requestRoles: resolved.requestRoles };
  const factsBytes = canonicalDecisionBytes(facts); budget.retain('compiled', factsBytes);
  const digest = factDigest(facts), reasons = new Set(context.denialReasons);
  if (chains.indeterminate || resolved.indeterminate) reasons.add('indeterminate');
  for (const id of context.mandatoryDependencies) {
    const dependency = decisions.get(id)!;
    if (dependency.mode !== 'authorize') budget.fail('invalid', 'scope', '/bundle/nodes', 'A prerequisite must be an authorization, never a deny guard.');
    if (!dependency.allowed) reasons.add(dependency.reason === 'indeterminate' ? 'indeterminate' : 'ceiling_denied');
  }
  if (context.intentGuard !== null) {
    const guard = decisions.get(context.intentGuard)!;
    if (guard.mode !== 'resource-wide-deny') budget.fail('invalid', 'scope', '/bundle/nodes', 'An intent guard must be a deny-guard decision.');
    if (!guard.clear) reasons.add(guard.reason === 'indeterminate' ? 'indeterminate' : 'ceiling_denied');
  }
  const boundaries: (UTC | null)[] = [context.validUntil, ...chains.boundaries, ...resolved.boundaries];
  for (const id of dependencies) boundaries.push(decisions.get(id)!.validUntil);
  // Time endpoints from currently ineffective but structurally relevant paths
  // still bound a negative decision and cannot disappear behind a current allow.
  for (const path of chains.paths) if (path.requestApplicable) for (const pin of path.policies) {
    for (const rule of input.parsedPolicies.get(policyKey(pin))!.rules) if (applicable(rule, node) && marked(input, pin, rule, node)) boundaries.push(...expressionBoundaries(rule.when));
  }
  const matched: MatchWitness[] = [], seen = new Set<string>();
  for (const binding of resolved.bindings) {
    const policy = input.parsedPolicies.get(policyKey(binding.policy))!;
    for (const rule of policy.rules) {
      budget.charge('actualRuleVisits', 1);
      if (!ceilingApplies(binding, node) || !applicable(rule, node) || !marked(input, binding.policy, rule, node)) continue;
      const truth = memo.evaluate(rule.when, facts, digest);
      if (truth === 'indeterminate') reasons.add('indeterminate');
      if (truth !== 'match') continue;
      const witness: MatchWitness = { policy: binding.policy, ruleId: rule.id, grant: binding.terminal, effect: rule.effect };
      const key = `${policyKey(witness.policy)}:${witness.ruleId}:${witness.grant.kind}:${witness.grant.id}@${witness.grant.version}:${witness.effect}`;
      if (!seen.has(key)) { budget.charge('matchWitnesses', 1); seen.add(key); matched.push(witness); }
      if (rule.effect === 'deny') reasons.add('explicit_deny'); else reasons.add('allowed');
    }
  }
  budget.release('compiled', factsBytes);
  // The resolver's derived bindings are consumed here and no plan retains them.
  // Their cumulative proof/work charges remain; their live representation ends.
  budget.release('compiled', canonicalDecisionBytes({ bindings: resolved.bindings, requestRoles: resolved.requestRoles }));
  matched.sort(witnessCompare);
  const validUntil = future(input.bundle.snapshot.now, boundaries);
  if (node.mode === 'resource-wide-deny') {
    reasons.delete('allowed'); reasons.delete('no_allow');
    const negative = reasons.size ? reason(reasons) : null;
    if (negative === 'allowed' || negative === 'no_allow') budget.fail('invalid', 'scope', '/bundle/nodes', 'A deny guard cannot resolve as an ordinary authorization.');
    return freeze({ nodeId: node.id, mode: 'resource-wide-deny', clear: negative === null, reason: negative ?? 'clear', validUntil, matched });
  }
  if (context.derivedOrdinaryFieldAllow) reasons.add('allowed');
  if (!reasons.has('allowed')) reasons.add('no_allow');
  const result = reason(reasons);
  return freeze({ nodeId: node.id, mode: 'authorize', allowed: result === 'allowed', reason: result,
    derivedOrdinaryFieldAllow: context.derivedOrdinaryFieldAllow, validUntil, matched });
}

function finish(outcome: DecisionBundleResult['outcome'], root: DecisionBundleResult['root'], nodes: readonly NodeDecision[], issues: readonly AuthorityIssue[], budget: DecisionBudget): DecisionBundleResult {
  // No serialized result is allocated. Twenty decimal positions reserve the
  // self-referential metric's entire representable safe-integer width.
  const metrics = { ...budget.metrics, outputBytes: 0 }, result = { outcome, root, nodes, issues, metrics };
  canonicalDecisionBytes(result, LIMITS.matchBytes - 20);
  for (let attempt = 0; attempt < 20; attempt++) {
    const bytes = canonicalDecisionBytes(result);
    if (bytes === metrics.outputBytes) {
      budget.maximum('outputBytes', bytes);
      const retained = budget.retainedBytes().output;
      if (retained > bytes) budget.release('output', retained - bytes); else budget.retain('output', bytes - retained);
      return freeze(result);
    }
    metrics.outputBytes = bytes;
  }
  return budget.fail('invalid', 'range', '', 'Output byte accounting did not converge.');
}
function run(parse: () => Parsed<DecisionInput>): DecisionBundleResult {
  let budget = new DecisionBudget();
  try {
    const parsed = parse();
    if (!parsed.ok) {
      const outcome = parsed.issues.some(issue => issue.code === 'limit') ? 'profile_limit'
        : parsed.issues.some(issue => issue.code === 'unsupported') ? 'unsupported' : 'invalid';
      return finish(outcome, null, [], parsed.issues.slice(0, LIMITS.issues), budget);
    }
    const input = parsed.value; budget = new DecisionBudget(input.admission);
    chargeInput(input, budget); validateDecisionIdentities(input);
    const { plans, order, dependencies } = graph(input, budget), decisions = new Map<NodeId, NodeDecision>(), memo = new PredicateMemo(budget);
    for (const id of order) {
      const decision = evaluateNode(input, plans.get(id)!, dependencies.get(id)!, decisions, memo, budget);
      budget.retain('output', canonicalDecisionBytes(decision)); decisions.set(id, decision);
    }
    const nodes = [...decisions.values()].sort((a, b) => compare(a.nodeId, b.nodeId)), root = decisions.get(input.bundle.root)!;
    if (root.mode !== 'authorize') budget.fail('invalid', 'scope', '/bundle/root', 'The root must authorize an atomic request.');
    return finish('evaluated', root as Extract<NodeDecision, { mode: 'authorize' }>, nodes, [], budget);
  } catch (error) {
    budget.release('output', budget.retainedBytes().output);
    const failure = error instanceof DecisionInputError ? error : new DecisionInputError('invalid', {
      code: 'type', path: '', message: 'Authority evidence could not be evaluated completely.',
    });
    return finish(failure.outcome, null, [], [failure.issue], budget);
  }
}
/** Pure data only: neither entry point authenticates a producer or issues a capability. */
export function evaluateAuthority(bundle: unknown, registry: unknown): DecisionBundleResult {
  return run(() => parseDecisionInput(bundle, registry));
}
export function evaluateAuthorityFile(text: string, registry: unknown): DecisionBundleResult {
  return run(() => parseDecisionInputFile(text, registry));
}
