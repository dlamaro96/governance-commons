// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {parseApprovalDefinition,evaluateApprovalStage} from '../../packages/domain/src/approval.ts';
import {APPROVAL_LIMITS,type ApprovalStageInput} from '../../packages/domain/src/approval-contracts.ts';
import {MODEL_LIMITS,type ValidationResult} from '../../packages/domain/src/model.ts';

const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const stage=(name='review',count=3):any=>({id:name,name:'Review',assignments:Array.from({length:count},(_,i)=>`reviewer_${i}`),quorum:2,deadlineSeconds:3600,rejection:'any'});
const definition=():any=>({formatVersion:1,id:'term_approval',version:1,name:'Term approval',separationOfDuties:true,stages:[stage()]});
function evaluation(count=3):any{return {stage:stage('review',count),requesterId:id(1),separationOfDuties:true,
  tasks:Array.from({length:count},(_,i)=>({id:id(i+10),version:3,assignment:`reviewer_${i}`,assignedIdentityId:id(i+100)})),decisions:[],now:1000,expiresAt:2000};}
const decision=(input:any,index=0,choice='approve')=>({taskId:input.tasks[index].id,taskVersion:input.tasks[index].version,
  assignedIdentityId:input.tasks[index].assignedIdentityId,actorId:input.tasks[index].assignedIdentityId,decision:choice,reason:'Reviewed the submitted evidence.'});
function ok<T>(result:ValidationResult<T>):T{if(!result.ok)assert.fail(JSON.stringify(result.issues));return result.value;}
function failure(result:ValidationResult<unknown>,code?:string,path?:string){
  assert.equal(result.ok,false);if(result.ok)return;
  assert.ok(result.issues.length>0&&result.issues.length<=MODEL_LIMITS.issues);
  assert.equal(Object.hasOwn(result,'value'),false);
  if(code)assert.ok(result.issues.some(issue=>issue.code===code&&(path===undefined||issue.path===path)),JSON.stringify(result.issues));
  return result.issues;
}
const evaluate=(value:unknown)=>evaluateApprovalStage(value as ApprovalStageInput);

test('definition parsing normalizes NFC display names and returns a detached immutable versioned definition',()=>{
  const value=definition();value.name='  Cafe\u0301 approval  ';value.stages[0].name='  Re\u0301vision  ';
  const before=structuredClone(value),result=ok(parseApprovalDefinition(value));
  assert.equal(result.name,'Café approval');assert.equal(result.stages[0]!.name,'Révision');assert.equal(result.formatVersion,1);
  assert.deepEqual(result.stages[0]!.assignments,value.stages[0].assignments);
  assert.equal(Object.isFrozen(result),true);assert.equal(Object.isFrozen(result.stages[0]!.assignments),true);
  assert.deepEqual(value,before);assert.equal(Object.isFrozen(value),false);
  value.stages[0].assignments[0]='changed';assert.equal(result.stages[0]!.assignments[0],'reviewer_0');
  assert.deepEqual(ok(parseApprovalDefinition(result)),result);
});

test('definition and stage schemas require exact fields without silently dropping unknown data',()=>{
  for(const section of ['definition','stage']){
    const value=definition(),target=section==='definition'?value:value.stages[0],path=section==='definition'?'':'/stages/0';
    for(const key of Object.keys(target)){const saved=target[key];delete target[key];failure(parseApprovalDefinition(value),'required',`${path}/${key}`);target[key]=saved;}
    target['future/field~']=true;failure(parseApprovalDefinition(value),'unknown_field',`${path}/future~1field~0`);
  }
  const value=definition();value.formatVersion=2;failure(parseApprovalDefinition(value),'invalid_definition','/formatVersion');
  value.formatVersion='1';failure(parseApprovalDefinition(value),'invalid_definition','/formatVersion');
  value.formatVersion=1;value.stages[0].rejection='quorum';failure(parseApprovalDefinition(value),'enum','/stages/0/rejection');
});

test('safe identifiers, versions, booleans and display bounds never coerce or erase controls',()=>{
  for(const bad of ['','__proto__','prototype','constructor','invalid id','1first','x'.repeat(65),1]){
    const value=definition();value.id=bad;failure(parseApprovalDefinition(value),'format','/id');
    value.id='term';value.stages[0].id=bad;failure(parseApprovalDefinition(value),'format','/stages/0/id');
    value.stages[0].id='review';value.stages[0].assignments[0]=bad;failure(parseApprovalDefinition(value),'format','/stages/0/assignments/0');
  }
  for(const bad of [0,-0,-1,1.5,'1',2_147_483_648,NaN,Infinity]){const value=definition();value.version=bad;failure(parseApprovalDefinition(value));}
  const maximum=definition();maximum.version=2_147_483_647;maximum.id='x'.repeat(64);assert.equal(ok(parseApprovalDefinition(maximum)).version,2_147_483_647);
  for(const bad of ['true',1,null]){const value=definition();value.separationOfDuties=bad;failure(parseApprovalDefinition(value));}
  for(const bad of ['','  ','\ud800','\udc00','x\u0000','x\t','x\n','x\u007f','x\u0085','x'.repeat(241)]){const value=definition();value.name=bad;failure(parseApprovalDefinition(value));}
  const unicode=definition();unicode.name='😀'.repeat(120);assert.equal(ok(parseApprovalDefinition(unicode)).name.length,240);
});

test('ordered stages and per-stage assignments have exact nonempty bounds and explicit duplicate errors',()=>{
  const value=definition();value.stages=Array.from({length:16},(_,i)=>stage(`stage_${i}`,16));
  const parsed=ok(parseApprovalDefinition(value));assert.equal(parsed.stages.length,16);assert.equal(parsed.stages[0]!.assignments.length,16);
  assert.deepEqual(parsed.stages.map(row=>row.id),value.stages.map((row:any)=>row.id));
  value.stages.push(stage('extra'));failure(parseApprovalDefinition(value),'limit','/stages');
  value.stages=[];failure(parseApprovalDefinition(value),'required','/stages');
  value.stages=[stage(),stage()];failure(parseApprovalDefinition(value),'duplicate','/stages/1/id');
  value.stages=[stage()];value.stages[0].assignments.push('reviewer_0');failure(parseApprovalDefinition(value),'duplicate','/stages/0/assignments/3');
  value.stages[0].assignments=[];failure(parseApprovalDefinition(value),'required','/stages/0/assignments');
  value.stages[0].assignments=Array.from({length:17},(_,i)=>`a${i}`);failure(parseApprovalDefinition(value),'limit','/stages/0/assignments');
  value.stages=[stage('first'),stage('second')];assert.equal(ok(parseApprovalDefinition(value)).stages.length,2,'Assignments may recur in different ordered stages');
});

test('quorum and deadline accept exact endpoints and reject underflow overflow fractions and strings',()=>{
  for(const quorum of [1,3]){const value=definition();value.stages[0].quorum=quorum;assert.equal(ok(parseApprovalDefinition(value)).stages[0]!.quorum,quorum);}
  for(const quorum of [0,4,-1,1.5,'2']){const value=definition();value.stages[0].quorum=quorum;failure(parseApprovalDefinition(value),undefined);}
  for(const seconds of [1,APPROVAL_LIMITS.maxDeadlineSeconds]){const value=definition();value.stages[0].deadlineSeconds=seconds;assert.equal(ok(parseApprovalDefinition(value)).stages[0]!.deadlineSeconds,seconds);}
  for(const seconds of [0,-1,APPROVAL_LIMITS.maxDeadlineSeconds+1,1.5,'60']){const value=definition();value.stages[0].deadlineSeconds=seconds;failure(parseApprovalDefinition(value));}
});

test('all valid canonical decisions count and every combination follows an independent quorum/rejection/expiry oracle',()=>{
  for(let mask=0;mask<27;mask++)for(const quorum of [1,2,3])for(const expired of [false,true]){
    const value=evaluation();value.stage.quorum=quorum;value.now=expired?value.expiresAt:1999;
    let rest=mask,approvals=0,rejections=0,count=0;
    for(let i=0;i<3;i++){const state=rest%3;rest=Math.floor(rest/3);if(!state)continue;
      value.decisions.push(decision(value,i,state===1?'approve':'reject'));count++;if(state===1)approvals++;else rejections++;
    }
    const expected={outcome:expired?'expired':rejections?'rejected':approvals>=quorum?'approved':'pending',approvals,pending:3-count};
    assert.deepEqual(ok(evaluate(value)),expected);
    value.decisions.reverse();value.tasks.reverse();assert.deepEqual(ok(evaluate(value)),expected,'Canonical set ordering does not change the decision');
  }
});

test('deadline equality wins over an otherwise approved or rejected set and never infers a prior completion',()=>{
  const value=evaluation();value.decisions=[decision(value,0),decision(value,1),decision(value,2,'reject')];
  assert.deepEqual(ok(evaluate(value)),{outcome:'rejected',approvals:2,pending:0});
  value.now=2000;assert.deepEqual(ok(evaluate(value)),{outcome:'expired',approvals:2,pending:0});
  value.decisions.pop();assert.deepEqual(ok(evaluate(value)),{outcome:'expired',approvals:2,pending:1});
  value.now=1999;assert.equal(ok(evaluate(value)).outcome,'approved');
  value.now=0;value.expiresAt=0;assert.equal(ok(evaluate(value)).outcome,'expired');
  value.expiresAt=Number.MAX_SAFE_INTEGER;assert.equal(ok(evaluate(value)).outcome,'approved');
  value.now=Number.MAX_SAFE_INTEGER;assert.equal(ok(evaluate(value)).outcome,'expired');
  for(const field of ['now','expiresAt'])for(const bad of [-1,-0,1.5,Infinity,NaN,Number.MAX_SAFE_INTEGER+1,'2000',new Date()]){
    const invalid=evaluation();invalid[field]=bad;failure(evaluate(invalid));
  }
});

test('evaluation uses the same stage grammar even when empty decisions or expiration could otherwise short-circuit it',()=>{
  for(const mutate of [(v:any)=>v.stage.quorum=4,(v:any)=>v.stage.deadlineSeconds=0,(v:any)=>v.stage.assignments.push('reviewer_0'),
    (v:any)=>v.stage.rejection='all',(v:any)=>v.stage.name=' ',(v:any)=>v.stage.extra=true]){
    const value=evaluation();value.now=value.expiresAt;mutate(value);failure(evaluate(value));
  }
  const value=evaluation();delete value.stage;failure(evaluate(value),'required','/stage');
});

test('task set covers assignments exactly once using unique task UUIDs and independent assignee identities',()=>{
  const missing=evaluation();missing.tasks.pop();failure(evaluate(missing),'required','/tasks');
  const extra=evaluation();extra.tasks.push({id:id(50),version:1,assignment:'extra',assignedIdentityId:id(150)});failure(evaluate(extra),'enum','/tasks/3/assignment');
  const assignment=evaluation();assignment.tasks[1].assignment=assignment.tasks[0].assignment;failure(evaluate(assignment),'duplicate','/tasks/1/assignment');
  const task=evaluation();task.tasks[1].id=task.tasks[0].id;failure(evaluate(task),'duplicate','/tasks/1/id');
  const assignee=evaluation();assignee.tasks[1].assignedIdentityId=assignee.tasks[0].assignedIdentityId;
  assignee.decisions=[decision(assignee,0),decision(assignee,1)];failure(evaluate(assignee),'duplicate','/tasks/1/assignedIdentityId');
  const maximum=evaluation(16);maximum.stage.quorum=16;maximum.decisions=maximum.tasks.map((_:unknown,i:number)=>decision(maximum,i));
  assert.deepEqual(ok(evaluate(maximum)),{outcome:'approved',approvals:16,pending:0});
  maximum.tasks.push({id:id(60),version:1,assignment:'extra',assignedIdentityId:id(160)});failure(evaluate(maximum),'limit','/tasks');
});

test('decision ownership is the exact task version, recorded assignee and actual actor; no cross-task substitution',()=>{
  const cases:[string,(v:any)=>void,string,string][]=[
    ['unknown',(v)=>v.decisions[0].taskId=id(999),'invalid_definition','/decisions/0/taskId'],
    ['version',(v)=>v.decisions[0].taskVersion=2,'model_version','/decisions/0/taskVersion'],
    ['assignee',(v)=>v.decisions[0].assignedIdentityId=v.tasks[1].assignedIdentityId,'invalid_definition','/decisions/0/assignedIdentityId'],
    ['actor',(v)=>v.decisions[0].actorId=v.tasks[1].assignedIdentityId,'invalid_definition','/decisions/0/actorId'],
    ['both',(v)=>{v.decisions[0].actorId=id(999);v.decisions[0].assignedIdentityId=id(999);},'invalid_definition','/decisions/0/actorId'],
    ['choice',(v)=>v.decisions[0].decision='abstain','enum','/decisions/0/decision'],
  ];
  for(const[,mutate,code,path]of cases){const value=evaluation();value.decisions=[decision(value)];mutate(value);failure(evaluate(value),code,path);}
  const value=evaluation();value.tasks[0].version=2_147_483_647;value.decisions=[decision(value)];assert.equal(ok(evaluate(value)).approvals,1);
});

test('duplicate decisions are invalid even when identical or after quorum; later records cannot be ignored',()=>{
  for(const choice of ['approve','reject']){const value=evaluation();value.decisions=[decision(value,0),decision(value,1),decision(value,0,choice)];failure(evaluate(value),'duplicate','/decisions/2/taskId');}
  const invalid=evaluation();invalid.decisions=[decision(invalid,0),decision(invalid,1),{...decision(invalid,2),reason:' '}];failure(evaluate(invalid),'required','/decisions/2/reason');
  invalid.now=invalid.expiresAt;failure(evaluate(invalid),'required','/decisions/2/reason');
  const over=evaluation();over.decisions=Array.from({length:17},()=>decision(over));failure(evaluate(over),'limit','/decisions');
});

test('separation of duties rejects requester assignment before a decision and requester action when enabled',()=>{
  const assigned=evaluation();assigned.tasks[0].assignedIdentityId=assigned.requesterId;failure(evaluate(assigned),'invalid_definition','/tasks/0/assignedIdentityId');
  assigned.decisions=[decision(assigned)];failure(evaluate(assigned),'invalid_definition','/decisions/0/actorId');
  assigned.separationOfDuties=false;assert.equal(ok(evaluate(assigned)).approvals,1,'An explicitly disabled rule permits the assigned requester');
  const actor=evaluation();actor.decisions=[{...decision(actor),actorId:actor.requesterId}];failure(evaluate(actor),'invalid_definition','/decisions/0/actorId');
  actor.separationOfDuties=false;failure(evaluate(actor),'invalid_definition','/decisions/0/actorId');
  for(const bad of ['false',0]){const value=evaluation();value.separationOfDuties=bad;failure(evaluate(value),'type','/separationOfDuties');}
});

test('decision reasons are nonblank bounded well-formed NFC text and may contain explicit multiline whitespace',()=>{
  const value=evaluation();value.decisions=[decision(value)];value.decisions[0].reason='  Cafe\u0301 evidence\r\nReviewed\tand accepted.  ';
  const before=structuredClone(value);assert.equal(ok(evaluate(value)).approvals,1);assert.deepEqual(value,before);
  value.decisions[0].reason='x'.repeat(4096);assert.equal(ok(evaluate(value)).approvals,1);
  for(const reason of ['', ' \t\r\n ', 'x'.repeat(4097), '\ud800', 'reason\u0000','reason\u000b','reason\u007f','reason\u0085',false]){
    value.decisions[0].reason=reason;failure(evaluate(value));
  }
});

test('evaluation, tasks and decisions reject unknown or missing fields and malformed identities or versions',()=>{
  for(const section of ['evaluation','task','decision']){
    const value=evaluation();value.decisions=[decision(value)];const target=section==='evaluation'?value:section==='task'?value.tasks[0]:value.decisions[0];
    const path=section==='evaluation'?'':section==='task'?'/tasks/0':'/decisions/0';
    for(const key of Object.keys(target)){const saved=target[key];delete target[key];failure(evaluate(value),'required',`${path}/${key}`);target[key]=saved;}
    target.extra=true;failure(evaluate(value),'unknown_field',`${path}/extra`);
  }
  for(const field of ['id','assignedIdentityId']){const value=evaluation();value.tasks[0][field]='ABC00000-0000-4000-8000-000000000001';failure(evaluate(value),'format');}
  for(const field of ['taskId','assignedIdentityId','actorId']){const value=evaluation();value.decisions=[decision(value)];value.decisions[0][field]='not-uuid';failure(evaluate(value),'format');}
  for(const version of [0,-0,-1,1.1,'3',2_147_483_648]){const value=evaluation();value.tasks[0].version=version;failure(evaluate(value));value.tasks[0].version=3;value.decisions=[decision(value)];value.decisions[0].taskVersion=version;failure(evaluate(value));}
});

test('aggregate input byte budget is enforced exactly even when each individual reason is valid',()=>{
  const value=evaluation(16);value.decisions=value.tasks.map((_:unknown,i:number)=>({...decision(value,i),reason:'x'}));
  let remaining=APPROVAL_LIMITS.bytes-Buffer.byteLength(JSON.stringify(value));assert.ok(remaining>0);
  for(const row of value.decisions){const extra=Math.min(4095,remaining);row.reason+='x'.repeat(extra);remaining-=extra;}
  assert.equal(remaining,0);assert.equal(Buffer.byteLength(JSON.stringify(value)),APPROVAL_LIMITS.bytes);assert.equal(ok(evaluate(value)).approvals,16);
  const room=value.decisions.find((row:any)=>row.reason.length<4096);assert.ok(room);room.reason+='x';failure(evaluate(value),'limit');
  const unicode=evaluation(16);unicode.decisions=unicode.tasks.map((_:unknown,i:number)=>({...decision(unicode,i),reason:'😀'.repeat(2048)}));failure(evaluate(unicode),'limit');
});

test('both entry points refuse getters, symbols, nonenumerable data and toJSON without executing supplied code',()=>{
  let called=0;const getter=()=>{called++;throw new Error('Must not run');};
  for(const [make,parse]of [[definition,parseApprovalDefinition],[evaluation,evaluate]]as const){
    const value=make();Object.defineProperty(value,'name',{enumerable:true,get:getter});failure(parse(value),'invalid_json');
    const symbol=make();symbol[Symbol('private')]=true;failure(parse(symbol),'invalid_json');
    const hidden=make();Object.defineProperty(hidden,'hidden',{value:true});failure(parse(hidden),'invalid_json');
    const json=make();json.toJSON=()=>{called++;return {};};failure(parse(json),'invalid_json');
  }
  const nested=evaluation();Object.defineProperty(nested.tasks[0],'assignedIdentityId',{enumerable:true,get:getter});failure(evaluate(nested),'invalid_json','/tasks/0/assignedIdentityId');
  const array=evaluation();Object.defineProperty(array.tasks,'0',{enumerable:true,get:getter});failure(evaluate(array),'invalid_json');assert.equal(called,0);
});

test('sparse arrays, cycles, hostile reflection and non-JSON scalars fail without partial outcomes or caller mutation',()=>{
  const sparse=evaluation();sparse.tasks=Array(3);failure(evaluate(sparse),'invalid_json');
  const extra=definition();extra.stages.extra=true;failure(parseApprovalDefinition(extra),'invalid_json');
  const cycle=evaluation();cycle.self=cycle;failure(evaluate(cycle),'cycle');
  const revoked=Proxy.revocable(evaluation(),{});revoked.revoke();failure(evaluate(revoked.proxy),'invalid_json');
  let inspected=0;const thrown=new Proxy({},{getPrototypeOf(){inspected++;throw new Error('Do not inspect untrusted thrown objects');}});
  for(const [make,parse]of [[definition,parseApprovalDefinition],[evaluation,evaluate]]as const){
    const hostile=new Proxy(make(),{getPrototypeOf(){throw thrown;}});failure(parse(hostile),'invalid_json');
  }
  assert.equal(inspected,0);
  for(const bad of [undefined,null,1n,()=>{},Symbol('value'),new Date(),new Map()]){const value=definition();value.name=bad;failure(parseApprovalDefinition(value));}
  const deep=evaluation();let target=deep;for(let i=0;i<23;i++){target.child={};target=target.child;}failure(evaluate(deep),'limit');
  const keys=evaluation();Object.assign(keys,Object.fromEntries(Array.from({length:129},(_,i)=>[`key${i}`,false])));failure(evaluate(keys),'limit');
  const clean=evaluation(),before=structuredClone(clean),result=ok(evaluate(clean));assert.deepEqual(clean,before);assert.equal(Object.isFrozen(clean),false);assert.equal(Object.isFrozen(result),true);
});
