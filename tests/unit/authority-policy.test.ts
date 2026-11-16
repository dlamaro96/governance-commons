// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS } from '../../packages/authority/src/actions.ts';
import { canonicalPolicyJSON, parsePolicy, parsePolicyFile, policyHash, POLICY_LIMITS } from '../../packages/authority/src/policy.ts';
import type { AuthorityIssue, Parsed, PolicyExpr } from '../../packages/authority/src/types.ts';

const id = (value: number): string => `00000000-0000-0000-0000-${value.toString(16).padStart(12, '0')}`;
const subject = () => ({ op: 'subject-in', subjects: [{ kind: 'human', id: id(3) }] });
const rule = (index = 2, when: unknown = subject()) => ({ id: id(index), effect: 'allow', actions: ['asset:discover'], fields: null as null | string[], when });
const policy = (when: unknown = subject()) => ({ formatVersion: 1, id: id(1), version: 1, rules: [rule(2, when)] });
function ok<T>(result: Parsed<T>): T { assert.equal(result.ok, true, JSON.stringify(result)); if (!result.ok) throw new Error('Expected parsed result'); return result.value; }
function fails(result: Parsed<unknown>, code?: AuthorityIssue['code'], path?: string): readonly AuthorityIssue[] {
  assert.equal(result.ok, false, JSON.stringify(result)); if (result.ok) throw new Error('Expected rejection');
  assert.ok(result.issues.length > 0 && result.issues.length <= 64);
  if (code) assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
  return result.issues;
}
const fieldPolicy = (fields: string[]) => ({ ...policy(), rules: [{ ...rule(), actions: ['field:read'], fields }] });

test('strict parsing returns a fresh frozen policy while retaining rule and child order', () => {
  const input = { ...policy(), rules: [rule(4, { op: 'any', children: [
    { op: 'group-any', groupIds: [id(8), id(7)] }, { op: 'group-any', groupIds: [id(6), id(5)] },
  ] }), rule(2)] };
  const before = JSON.stringify(input), parsed = ok(parsePolicy(input));
  assert.equal(JSON.stringify(input), before); assert.equal(Object.isFrozen(input), false); assert.notEqual(parsed,input);
  assert.deepEqual(parsed.rules.map(row => row.id), [id(4),id(2)]);
  assert.deepEqual(parsed.rules[0].when, { op: 'any', children: [
    { op: 'group-any', groupIds: [id(7),id(8)] }, { op: 'group-any', groupIds: [id(5),id(6)] },
  ] });
  function frozen(value: unknown): void { if (value && typeof value === 'object') { assert.ok(Object.isFrozen(value)); for (const child of Object.values(value)) frozen(child); } }
  frozen(parsed); assert.deepEqual(ok(parsePolicyFile(JSON.stringify(input))), parsed);
});
test('all declared predicates accept their exact grammar and normalize scalar or tuple sets', () => {
  const examples = [
    { op: 'all', children: [subject()] }, { op: 'any', children: [subject()] }, subject(),
    { op: 'group-any', groupIds: [id(4),id(3)] },
    { op: 'role-any', roles: [{ roleId: id(5), version: 10 }, { roleId: id(5), version: 2 }, { roleId: id(4), version: 9 }] },
    { op: 'action-in', actions: ['source:create','asset:discover'] },
    { op: 'resource-kind-in', kinds: ['source','model-definition','asset-domain-placement'] },
    { op: 'domain-in', domainIds: [id(8),id(7)], includeAncestors: true },
    ...['classification-any','approved-tag-any','purpose-in','environment-in'].map(op => ({ op, ids: [id(8),id(7)] })),
    { op: 'time-within', validity: { notBefore: '2024-02-29T00:00:00.000Z', expiresAt: '2024-02-29T00:00:00.001Z' } },
  ];
  for (const expression of examples) {
    const parsed = ok(parsePolicy(policy(expression)));
    assert.deepEqual(ok(parsePolicy(parsed)), parsed);
    assert.equal(ok(policyHash(parsed)), typeHash(parsed));
  }
  const roles = ok(parsePolicy(policy(examples[4]))).rules[0].when;
  assert.deepEqual(roles, { op:'role-any',roles:[{roleId:id(4),version:9},{roleId:id(5),version:2},{roleId:id(5),version:10}] });
  const mixedSubjects = { op:'subject-in',subjects:[{kind:'service',id:id(4)},{kind:'human',id:id(4)}] };
  assert.deepEqual((ok(parsePolicy(policy(mixedSubjects))).rules[0].when as Extract<PolicyExpr,{op:'subject-in'}>).subjects.map(s => s.kind), ['human','service']);
});
test('canonical JSON and SHA-256 match independently calculated Python vectors and project hashing', () => {
  const expected = '{"formatVersion":1,"id":"00000000-0000-0000-0000-000000000001","rules":[{"actions":["asset:discover"],"effect":"allow","fields":null,"id":"00000000-0000-0000-0000-000000000002","when":{"op":"subject-in","subjects":[{"id":"00000000-0000-0000-0000-000000000003","kind":"human"}]}}],"version":1}';
  assert.equal(ok(canonicalPolicyJSON(policy())),expected);
  assert.equal(ok(policyHash(policy())),'305f7dedc37dfc4f85da39ccbe190b7dff7631449434e896033db34fb7b15d26');
  assert.equal(typeHash(ok(parsePolicy(policy()))),ok(policyHash(policy())));
  const first = { ...policy(), rules:[{...rule(),actions:['source:create','asset:discover']}] };
  const second = { version:1,rules:[{when:subject(),fields:null,actions:['asset:discover','source:create'],effect:'allow',id:id(2)}],id:id(1),formatVersion:1 };
  assert.equal(ok(policyHash(first)),ok(policyHash(second)));
  assert.notEqual(ok(policyHash({...policy(),rules:[rule(2),rule(4)]})),ok(policyHash({...policy(),rules:[rule(4),rule(2)]})));
  const childA = {op:'group-any',groupIds:[id(4)]}, childB = {op:'group-any',groupIds:[id(5)]};
  assert.notEqual(ok(policyHash(policy({op:'all',children:[childA,childB]}))),ok(policyHash(policy({op:'all',children:[childB,childA]}))));
});
test('canonical Unicode vector uses UTF-16 lexical sets and exact escaping without Unicode normalization', () => {
  // Python hashlib over independently serialized canonical JSON; UTF-16BE is
  // the explicit Python sort key for these supplementary-plane field strings.
  const fields=['\ue000','😀','é','e\u0301','a\n"\\'];
  const parsed=ok(parsePolicy(fieldPolicy(fields),fields));
  assert.deepEqual(parsed.rules[0].fields,['a\n"\\','e\u0301','é','😀','\ue000']);
  assert.equal(ok(policyHash(parsed,fields)),'b13d57c904d474b2e60aa773cfd510b129c0a26d23d09c081b989833b63417d6');
  assert.equal(ok(policyHash(parsed,fields)),typeHash(parsed));
  assert.notEqual(ok(policyHash(fieldPolicy(['é']),fields)),ok(policyHash(fieldPolicy(['e\u0301']),fields)));
});
test('JSON ingestion rejects actual duplicate and escaped duplicate keys before materialization', () => {
  const text = JSON.stringify(policy());
  for (const input of ['', '{', text+' false', '{"formatVersion":01}', text.replace('"version":1','"version":1,"version":2'),
    text.replace('"id":', '"id":"ignored","\\u0069d":'), text.replace('"kind":"human"','"kind":"human","ki\\u006ed":"service"')]) {
    fails(parsePolicyFile(input));
  }
  fails(parsePolicyFile(text.replace('"version":1','"version":1,"version":2')),'duplicate');
  fails(parsePolicyFile(text.replace('"kind":"human"','"kind":"human","ki\\u006ed":"service"')),'duplicate');
  fails(parsePolicyFile(text.replace('"version":1','"version":1e999')),'invalid_json');
  fails(parsePolicyFile(text.replace('"version":1','"version":-0')),'invalid_json');
  fails(parsePolicyFile(text.replace('"effect":"allow"','"effect":"\\ud800"')),'format');
  fails(parsePolicyFile(4 as unknown as string),'type');
});
test('all grammar objects require exact own properties and reject unsupported discriminators', () => {
  const expressions = [
    subject(), {op:'all',children:[subject()]}, {op:'group-any',groupIds:[id(3)]},
    {op:'role-any',roles:[{roleId:id(3),version:1}]}, {op:'action-in',actions:['asset:discover']},
    {op:'resource-kind-in',kinds:['asset']}, {op:'domain-in',domainIds:[id(3)],includeAncestors:false},
    {op:'classification-any',ids:[id(3)]}, {op:'time-within',validity:{notBefore:null,expiresAt:null}},
  ];
  for (const expression of expressions) {
    fails(parsePolicy(policy({...expression,extra:true})),'unknown_field');
    for (const key of Object.keys(expression)) { const missing = Object.fromEntries(Object.entries(expression).filter(([name]) => name !== key)); fails(parsePolicy(policy(missing)),'required'); }
  }
  for (const key of ['formatVersion','id','version','rules']) fails(parsePolicy(Object.fromEntries(Object.entries(policy()).filter(([name])=>name!==key))),'required',`/${key}`);
  for (const key of ['id','effect','actions','fields','when']) fails(parsePolicy({...policy(),rules:[Object.fromEntries(Object.entries(rule()).filter(([name])=>name!==key))]}),'required',`/rules/0/${key}`);
  fails(parsePolicy({...policy(),extra:true}),'unknown_field');
  fails(parsePolicy({...policy(),rules:[{...rule(),extra:true}]}),'unknown_field');
  fails(parsePolicy(policy({op:'subject-in',subjects:[{kind:'human',id:id(3),extra:true}]})),'unknown_field');
  fails(parsePolicy(policy({op:'role-any',roles:[{roleId:id(3),version:1,extra:true}]})),'unknown_field');
  fails(parsePolicy(policy({op:'time-within',validity:{notBefore:null,expiresAt:null,extra:true}})),'unknown_field');
  for (const when of [{op:'script',code:'true'},{op:'not',child:subject()},{op:'resource-kind-in',kinds:['asset-type']},{op:'subject-in',subjects:[{kind:'group',id:id(3)}]},{op:'action-in',actions:['asset:*']}]) fails(parsePolicy(policy(when)),'unsupported');
  fails(parsePolicy({...policy(),formatVersion:2}),'unsupported');
  fails(parsePolicy({...policy(),rules:[{...rule(),effect:'permit'}]}),'unsupported');
});
test('duplicate rule IDs and all declared set members fail rather than being discarded', () => {
  fails(parsePolicy({...policy(),rules:[rule(),rule()]}),'duplicate');
  const expressions = [
    {op:'subject-in',subjects:[{kind:'human',id:id(3)},{kind:'human',id:id(3)}]},
    {op:'role-any',roles:[{roleId:id(3),version:1},{roleId:id(3),version:1}]},
    {op:'group-any',groupIds:[id(3),id(3)]}, {op:'action-in',actions:['asset:discover','asset:discover']},
    {op:'resource-kind-in',kinds:['asset','asset']}, {op:'domain-in',domainIds:[id(3),id(3)],includeAncestors:false},
    ...['classification-any','approved-tag-any','purpose-in','environment-in'].map(op=>({op,ids:[id(3),id(3)]})),
  ];
  for (const expression of expressions) fails(parsePolicy(policy(expression)),'duplicate');
  fails(parsePolicy({...policy(),rules:[{...rule(),actions:['asset:discover','asset:discover']}]}),'duplicate');
  fails(parsePolicy(fieldPolicy(['a','a']),['a']),'duplicate');
  // all/any children are ordered expressions, not normalized sets.
  ok(parsePolicy(policy({op:'all',children:[subject(),subject()]})));
});
test('null fields and exact registered field sets never confer alternate action kinds', () => {
  fails(parsePolicy(fieldPolicy(['asset.description'])),'unsupported','/rules/0/fields/0');
  const catalog = ['asset.description','asset.owner'];
  assert.deepEqual(ok(parsePolicy(fieldPolicy([...catalog].reverse()),catalog)).rules[0].fields,catalog);
  fails(parsePolicy(fieldPolicy([]),catalog),'required');
  fails(parsePolicy(fieldPolicy(['asset.unknown']),catalog),'unsupported');
  fails(parsePolicy({...policy(),rules:[{...rule(),actions:['field:read']}]}),'scope');
  fails(parsePolicy({...fieldPolicy(['asset.description']),rules:[{...rule(),fields:['asset.description']} ]},catalog),'scope');
  fails(parsePolicy({...fieldPolicy(['asset.description']),rules:[{...rule(),actions:['field:read','asset:discover'],fields:['asset.description']} ]},catalog),'scope');
  ok(parsePolicy({...policy(),rules:[{...rule(),actions:['source:create','scan-job:claim','authority:read']}] }));
  const all = [...COMPATIBILITY_ACTIONS.flatMap(([ids])=>[...ids]),...ADMIN_ACTIONS,...FIELD_ACTIONS,...SERVICE_ACTIONS];
  assert.equal((ok(parsePolicy(policy({op:'action-in',actions:all}))).rules[0].when as Extract<PolicyExpr,{op:'action-in'}>).actions.length,136);
});
test('UUIDs, versions and half-open validity intervals have exact canonical boundaries', () => {
  for (const bad of [id(10).toUpperCase(),'not-a-uuid','00000000-0000-0000-0000-00000000000','{'+id(1)+'}',1]) fails(parsePolicy({...policy(),id:bad}));
  ok(parsePolicy({...policy(),version:2_147_483_647}));
  for (const bad of [0,-1,2_147_483_648,'1',1.5,NaN,Infinity,-Infinity,Number.MAX_SAFE_INTEGER+1,-0,1n]) fails(parsePolicy({...policy(),version:bad}));
  for (const bad of ['2024-02-30T00:00:00.000Z','2024-01-01T00:00:00Z','2024-01-01T00:00:00.000+00:00','2024-01-01T24:00:00.000Z','2024-01-01T00:00:60.000Z','2024-01-01t00:00:00.000z']) fails(parsePolicy(policy({op:'time-within',validity:{notBefore:bad,expiresAt:null}})),'format');
  for (const validity of [{notBefore:null,expiresAt:null},{notBefore:'0000-01-01T00:00:00.000Z',expiresAt:'9999-12-31T23:59:59.999Z'},{notBefore:null,expiresAt:'2024-01-01T00:00:00.000Z'}]) ok(parsePolicy(policy({op:'time-within',validity})));
  for (const expiresAt of ['2024-01-01T00:00:00.000Z','2023-12-31T23:59:59.999Z']) fails(parsePolicy(policy({op:'time-within',validity:{notBefore:'2024-01-01T00:00:00.000Z',expiresAt}})),'range');
});
test('raw UTF-8 boundary accepts 64KiB exactly and rejects one additional byte', () => {
  const text = JSON.stringify(policy()), exact = text+' '.repeat(65_536-Buffer.byteLength(text));
  ok(parsePolicyFile(exact)); fails(parsePolicyFile(exact+' '),'limit');
  const unicodeField = '😀'.repeat(64), input = fieldPolicy([unicodeField]);
  const json = JSON.stringify(input), raw = json+' '.repeat(65_536-Buffer.byteLength(json));
  ok(parsePolicyFile(raw,[unicodeField])); fails(parsePolicyFile(raw+' ',[unicodeField]),'limit');
  fails(parsePolicyFile(' '.repeat(65_537)),'limit');
});
test('canonical normalized policy accepts exact 64KiB and rejects one more byte', () => {
  const fields = Array.from({length:252},(_,index)=>`${index.toString().padStart(3,'0')}:`+'x'.repeat(252));
  let input = fieldPolicy(fields), size = Buffer.byteLength(JSON.stringify(input));
  assert.ok(size > 65_536 && size-65_536 < 252);
  fields[251] = fields[251].slice(0,256-(size-65_536));
  input = fieldPolicy(fields); assert.equal(Buffer.byteLength(JSON.stringify(input)),65_536);
  const parsed = ok(parsePolicy(input,fields)); assert.equal(Buffer.byteLength(ok(canonicalPolicyJSON(parsed,fields))),65_536);
  assert.equal(ok(policyHash(parsed,fields)),typeHash(parsed));
  const oversized = [...fields]; oversized[251]+='x';
  fails(parsePolicy(fieldPolicy(oversized),oversized),'limit');
});
test('128 rules and cumulative expression nodes, depth8 and finite-set256 boundaries are exact', () => {
  const rows = Array.from({length:128},(_,index)=>rule(index+10));
  ok(parsePolicy({...policy(),rules:rows})); fails(parsePolicy({...policy(),rules:[...rows,rule(500)]}),'limit');
  const tooManyNodes = [...rows]; tooManyNodes[0] = rule(10,{op:'all',children:[subject()]});
  fails(parsePolicy({...policy(),rules:tooManyNodes}),'limit');
  function chain(depth: number): unknown { return depth===1 ? subject() : {op:'all',children:[chain(depth-1)]}; }
  ok(parsePolicy(policy(chain(8)))); fails(parsePolicy(policy(chain(9))),'limit');
  const ids = Array.from({length:256},(_,index)=>id(index));
  ok(parsePolicy(policy({op:'group-any',groupIds:ids}))); fails(parsePolicy(policy({op:'group-any',groupIds:[...ids,id(500)]})),'limit');
  ok(parsePolicy(policy({op:'all',children:Array.from({length:127},subject)})));
  // The cumulative128-node ceiling dominates children256. There is no valid
  // pass-at256-child document;127 children plus the root is the actual maximum.
  fails(parsePolicy(policy({op:'all',children:Array.from({length:128},subject)})),'limit');
  fails(parsePolicy(policy({op:'all',children:Array.from({length:257},subject)})),'limit');
  assert.equal(POLICY_LIMITS.domainAncestors,32); // Future loader bound, not an AST field or an implemented evaluator.
});
test('all nonempty grammar collections reject empty arrays', () => {
  fails(parsePolicy({...policy(),rules:[]}),'required');
  fails(parsePolicy({...policy(),rules:[{...rule(),actions:[]}]}),'required');
  for (const when of [{op:'all',children:[]},{op:'any',children:[]},{op:'subject-in',subjects:[]},{op:'role-any',roles:[]},{op:'action-in',actions:[]},{op:'resource-kind-in',kinds:[]},{op:'group-any',groupIds:[]},{op:'domain-in',domainIds:[],includeAncestors:false},...['classification-any','approved-tag-any','purpose-in','environment-in'].map(op=>({op,ids:[]}))]) fails(parsePolicy(policy(when)),'required');
});
test('catalog has independent entry, byte and field limits and never leaks trusted values', () => {
  const catalog = Array.from({length:16_384},(_,index)=>index.toString(16).padStart(4,'0'));
  ok(parsePolicy(fieldPolicy([catalog[0]]),catalog)); fails(parsePolicy(policy(),[...catalog,'extra']),'limit');
  const byteCatalog = Array.from({length:512},(_,index)=>index.toString(16).padStart(4,'0')+'x'.repeat(252));
  assert.equal(byteCatalog.reduce((sum,field)=>sum+Buffer.byteLength(field),0),131_072);
  ok(parsePolicy(fieldPolicy([byteCatalog[0]]),byteCatalog)); fails(parsePolicy(policy(),[...byteCatalog,'z']),'limit');
  ok(parsePolicy(fieldPolicy(['x'.repeat(256)]),['x'.repeat(256)])); fails(parsePolicy(policy(),['x'.repeat(257)]),'limit');
  ok(parsePolicy(fieldPolicy(['😀'.repeat(64)]),['😀'.repeat(64)])); fails(parsePolicy(policy(),['😀'.repeat(65)]),'limit');
  for (const invalid of [[''],['\ud800'],['same','same'],[1],new Set(['a'])]) {
    const issues=fails(parsePolicy(policy(),invalid as string[])); assert.ok(issues.every(issue=>issue.path==='' && !issue.message.includes('same')));
  }
  const mutable=['first']; const parsed=ok(parsePolicy(fieldPolicy(mutable),mutable)); mutable[0]='second'; assert.deepEqual(parsed.rules[0].fields,['first']);
});
test('bounded issues are deterministic, refer to submitted paths and stop at64', () => {
  const input={...policy(),rules:Array.from({length:128},(_,index)=>({...rule(index+10),effect:'invented'}))};
  const first=fails(parsePolicy(input)); assert.equal(first.length,64);
  assert.deepEqual(first,fails(parsePolicy(input)));
  assert.deepEqual(first.map(issue=>issue.path),Array.from({length:64},(_,index)=>`/rules/${index}/effect`));
  assert.ok(first.every(issue=>!issue.message.includes('invented')));
});
test('accessors, symbols, exotic/inherited objects, proxies and malformed Unicode never execute or silently copy', () => {
  let touched=0;
  const accessor={...policy()}; Object.defineProperty(accessor,'rules',{enumerable:true,get(){ touched++; return []; }});
  const setter={...policy()}; Object.defineProperty(setter,'rules',{enumerable:true,set(){ touched++; }});
  const hidden={...policy()}; Object.defineProperty(hidden,'extra',{value:true});
  const symbol={...policy(),[Symbol('extra')]:true};
  const arrayAccessor: unknown[]=[]; Object.defineProperty(arrayAccessor,'0',{enumerable:true,get(){touched++;return rule();}});
  const proxy=new Proxy(policy(),{get(){touched++;throw new Error('get');},ownKeys(){touched++;throw new Error('keys');},getPrototypeOf(){touched++;throw new Error('prototype');}});
  const revoked=Proxy.revocable(policy(),{}); revoked.revoke();
  const cycle={...policy()}; cycle.rules[0].when=cycle;
  const extra=Object.assign([rule()],{extra:true}), arraySymbol=[rule()]; Object.defineProperty(arraySymbol,Symbol('extra'),{value:true});
  const inputs=[accessor,setter,hidden,symbol,proxy,revoked.proxy,cycle,Object.create(policy()),new Date(),new Map(),()=>true,
    {...policy(),rules:arrayAccessor},{...policy(),rules:new Array(1)},{...policy(),rules:extra},{...policy(),rules:arraySymbol},
    {...policy(),id:'\ud800'},{...policy(),id:'\udc00'},{...policy(),rules:undefined},{...policy(),rules:Symbol('value')}];
  for (const input of inputs) { fails(parsePolicy(input)); fails(canonicalPolicyJSON(input)); fails(policyHash(input)); }
  const catalogAccessor: string[]=[]; Object.defineProperty(catalogAccessor,'0',{enumerable:true,get(){touched++;return 'field';}});
  assert.equal(fails(parsePolicy(policy(),catalogAccessor))[0].path,''); fails(parsePolicy(policy(),new Proxy([], {ownKeys(){touched++;throw new Error('catalog');}})));
  assert.equal(touched,0);
  const nullPrototype=Object.assign(Object.create(null),policy()); ok(parsePolicy(nullPrototype));
});
test('prototype setters and inherited readonly fields cannot intercept safe normalization', () => {
  const previous=Object.getOwnPropertyDescriptor(Object.prototype,'formatVersion'); let touched=0;
  try {
    Object.defineProperty(Object.prototype,'formatVersion',{configurable:true,set(){touched++;}});
    const parsed=ok(parsePolicy(policy())); assert.equal(parsed.formatVersion,1); assert.equal(touched,0);
    Object.defineProperty(Object.prototype,'formatVersion',{configurable:true,value:99,writable:false});
    assert.equal(ok(parsePolicy(policy())).formatVersion,1);
  } finally { if(previous) Object.defineProperty(Object.prototype,'formatVersion',previous); else Reflect.deleteProperty(Object.prototype,'formatVersion'); }
  const malicious=JSON.parse(JSON.stringify(policy()).replace('"formatVersion":1','"formatVersion":1,"__proto__":{"polluted":true}'));
  fails(parsePolicy(malicious),'unknown_field'); assert.equal(Object.hasOwn(Object.prototype,'polluted'),false);
});
test('wide, deep and huge-length hostile inputs stop at bounded preflight', () => {
  fails(parsePolicy({...policy(),rules:new Array(2**32-1)}),'limit');
  const wide=Object.fromEntries(Array.from({length:1000},(_,index)=>[`x${index}`,true])); fails(parsePolicy(wide),'limit');
  let deep: unknown=null; for(let index=0;index<1000;index++) deep={child:deep}; fails(parsePolicy(deep),'limit');
  fails(parsePolicy({...policy(),id:'x'.repeat(65_537)}),'limit');
  fails(parsePolicyFile('['.repeat(1000)+']'.repeat(1000)),'limit');
});
