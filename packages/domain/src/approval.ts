// SPDX-License-Identifier: Apache-2.0
import {MODEL_LIMITS,parseBoundedJSONEnvelope,type ValidationIssue,type ValidationIssueCode,type ValidationResult} from './model.ts';
import {APPROVAL_LIMITS,type ApprovalDefinitionParser,type ApprovalStageEvaluator,type ApprovalStageDefinition,
  type ApprovalTask,type ApprovalDecision} from './approval-contracts.ts';

/** Pure versioned approval semantics. Inputs must be assembled by the canonical
 * transaction; this module neither authenticates actors nor resolves assignments. */
type Fields=Record<string,unknown>;
const identifier=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved=new Set(['__proto__','constructor','prototype']);
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const malformedUnicode=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const controls=/[\u0000-\u001f\u007f-\u009f]/;
const multilineControls=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const encoder=new TextEncoder();
const at=(path:string,key:string|number)=>`${path}/${String(key).replaceAll('~','~0').replaceAll('/','~1')}`;
class Issues{
  readonly values:ValidationIssue[]=[];
  add(code:ValidationIssueCode,path:string,message:string){
    if(this.values.length<MODEL_LIMITS.issues-1)this.values.push({code,path,message});
    else if(this.values.length===MODEL_LIMITS.issues-1)this.values.push({code:'limit',path:'',message:'Further approval issues were omitted.'});
  }
  result<T>(value:T):ValidationResult<T>{return this.values.length?{ok:false,issues:this.values}:{ok:true,value};}
}

/** Detached descriptor copying precedes serialization. As in the existing model
 * parser, own-key reflection scales with a materialized object's existing keys;
 * it is not a hostile-proxy sandbox or a substitute for raw HTTP admission. */
function snapshot(input:unknown):ValidationResult<unknown>{
  const active=new Set<object>();let nodes=0,bytes=0;
  let failure:ValidationIssue|undefined;
  function fail(code:ValidationIssueCode,path:string,message:string):never{failure={code,path,message};throw new Error('Invalid approval data.');}
  const charge=(size:number,path:string)=>{bytes+=size;if(bytes>APPROVAL_LIMITS.bytes)fail('limit',path,'Approval JSON exceeds the permitted byte budget.');};
  const copy=(value:unknown,path:string,depth:number):unknown=>{
    if(++nodes>MODEL_LIMITS.valueNodes||depth>MODEL_LIMITS.valueDepth+5)fail('limit',path,'JSON node or nesting budget exceeded.');
    if(typeof value==='string'){
      if(value.length>MODEL_LIMITS.stringLength)fail('limit',path,'String length exceeds its permitted bound.');
      if(malformedUnicode.test(value))fail('format',path,'Strings must contain well-formed Unicode.');
      charge(encoder.encode(JSON.stringify(value)).length,path);return value;
    }
    if(typeof value==='boolean'){charge(value?4:5,path);return value;}
    if(typeof value==='number'){
      if(!Number.isFinite(value)||Object.is(value,-0))fail('type',path,'Expected a finite JSON number without negative zero.');
      charge(String(value).length,path);return value;
    }
    if(value===null||typeof value!=='object')fail('invalid_json',path,'Expected non-null JSON data.');
    if(active.has(value))fail('cycle',path,'JSON values cannot contain cycles.');
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
    if(array?prototype!==Array.prototype:prototype!==Object.prototype&&prototype!==null)fail('invalid_json',path,'Expected a plain JSON object or array.');
    const keys=Reflect.ownKeys(value),length=array?Object.getOwnPropertyDescriptor(value,'length')?.value:keys.length;
    if(array&&(!Number.isSafeInteger(length)||length<0||length>MODEL_LIMITS.listItems))fail('limit',path,'Array length exceeds its permitted bound.');
    if(!array&&keys.length>MODEL_LIMITS.properties)fail('limit',path,'Object property count exceeds its permitted bound.');
    if(array&&keys.length!==length+1)fail('invalid_json',path,'Sparse arrays and extra array properties are not permitted.');
    charge(2+Math.max(0,length-1),path);active.add(value);
    try{
      const items:unknown[]=[],entries:[string,unknown][]=[];
      for(const key of array?Array.from({length},(_,index)=>String(index)):keys){
        if(typeof key!=='string')fail('invalid_json',path,'Symbol keys are not JSON.');
        if(key.length>256||malformedUnicode.test(key))fail('limit',path,'Property names must be bounded, well-formed strings.');
        const child=at(path,key),descriptor=Object.getOwnPropertyDescriptor(value,key);
        if(!descriptor?.enumerable||!Object.hasOwn(descriptor,'value'))fail('invalid_json',child,'Only enumerable data properties are permitted.');
        if(!array)charge(encoder.encode(JSON.stringify(key)).length+1,path);
        const next=copy(descriptor.value,child,depth+1);
        if(array)items.push(next);else entries.push([key,next]);
      }
      // Entries are owned tuples: no caller-controlled key is assigned to an
      // existing object. Preserve the detached object's null prototype.
      return array?items:Object.setPrototypeOf(Object.fromEntries(entries),null);
    }finally{active.delete(value);}
  };
  try{return parseBoundedJSONEnvelope(JSON.stringify(copy(input,'',0)));}
  catch{return {ok:false,issues:[failure??{code:'invalid_json',path:'',message:'JSON data could not be read safely.'}]};}
}
function fields(value:unknown,path:string,expected:readonly string[],issues:Issues):Fields|undefined{
  if(value===null||typeof value!=='object'||Array.isArray(value)){issues.add('type',path,'Expected an object.');return;}
  for(const key of Object.keys(value))if(!expected.includes(key))issues.add('unknown_field',at(path,key),'Unknown approval field.');
  for(const key of expected)if(!Object.hasOwn(value,key))issues.add('required',at(path,key),'Required approval field is missing.');
  return value as Fields;
}
function list(value:unknown,path:string,maximum:number,issues:Issues):unknown[]{
  if(!Array.isArray(value)){issues.add('type',path,'Expected an array.');return [];}
  if(value.length>maximum){issues.add('limit',path,'Array length exceeds its permitted bound.');return [];}
  return value;
}
function safeId(value:unknown,path:string,issues:Issues):value is string{
  if(typeof value==='string'&&identifier.test(value)&&!reserved.has(value))return true;
  issues.add('format',path,'Expected a safe identifier of at most 64 characters.');return false;
}
function identity(value:unknown,path:string,issues:Issues):value is string{
  if(typeof value==='string'&&uuid.test(value))return true;
  issues.add('format',path,'Expected a canonical lowercase UUID.');return false;
}
function integer(value:unknown,path:string,minimum:number,maximum:number,issues:Issues):value is number{
  if(typeof value!=='number'||!Number.isSafeInteger(value)||Object.is(value,-0)){issues.add('type',path,'Expected a safe integer without negative zero.');return false;}
  if(value<minimum||value>maximum){issues.add('range',path,'Integer is outside its permitted range.');return false;}return true;
}
function text(value:unknown,path:string,maximum:number,multiline:boolean,issues:Issues):string{
  if(typeof value!=='string'){issues.add('type',path,'Expected display text.');return '';}
  if((multiline?multilineControls:controls).test(value))issues.add('format',path,'Text contains a prohibited control character.');
  const normalized=value.normalize('NFC').trim();
  if(value.length>maximum||normalized.length>maximum)issues.add('limit',path,'Text exceeds its permitted length.');
  if(!normalized)issues.add('required',path,'Text must not be blank.');return normalized;
}
function boolean(value:unknown,path:string,issues:Issues):value is boolean{
  if(typeof value==='boolean')return true;issues.add('type',path,'Expected a boolean.');return false;
}
function freeze<T>(value:T):T{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
function stage(value:unknown,path:string,issues:Issues):ApprovalStageDefinition|undefined{
  const source=fields(value,path,['id','name','assignments','quorum','deadlineSeconds','rejection'],issues);if(!source)return;
  safeId(source.id,at(path,'id'),issues);
  const name=text(source.name,at(path,'name'),APPROVAL_LIMITS.name,false,issues);
  const raw=list(source.assignments,at(path,'assignments'),APPROVAL_LIMITS.assignments,issues),assignments:string[]=[],seen=new Set<string>();
  if(!raw.length)issues.add('required',at(path,'assignments'),'At least one assignment is required.');
  for(const[index,value]of raw.entries()){
    const item=at(at(path,'assignments'),index);
    if(safeId(value,item,issues)){if(seen.has(value))issues.add('duplicate',item,'Duplicate stage assignment.');seen.add(value);assignments.push(value);}
  }
  integer(source.quorum,at(path,'quorum'),1,raw.length,issues);
  integer(source.deadlineSeconds,at(path,'deadlineSeconds'),1,APPROVAL_LIMITS.maxDeadlineSeconds,issues);
  if(source.rejection!=='any')issues.add('enum',at(path,'rejection'),'Only rejection by any assigned approver is supported.');
  return {id:source.id as string,name,assignments,quorum:source.quorum as number,deadlineSeconds:source.deadlineSeconds as number,rejection:'any'};
}

export const parseApprovalDefinition:ApprovalDefinitionParser=(input)=>{
  const copied=snapshot(input);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['formatVersion','id','version','name','separationOfDuties','stages'],issues);
  if(!source)return issues.result(undefined as never);
  if(source.formatVersion!==1)issues.add('invalid_definition','/formatVersion','Only approval format version 1 is supported.');
  safeId(source.id,'/id',issues);integer(source.version,'/version',1,2_147_483_647,issues);boolean(source.separationOfDuties,'/separationOfDuties',issues);
  const name=text(source.name,'/name',APPROVAL_LIMITS.name,false,issues);
  const raw=list(source.stages,'/stages',APPROVAL_LIMITS.stages,issues),stages:ApprovalStageDefinition[]=[],seen=new Set<string>();
  if(!raw.length)issues.add('required','/stages','At least one approval stage is required.');
  for(const[index,value]of raw.entries()){
    const parsed=stage(value,at('/stages',index),issues);if(!parsed)continue;
    if(seen.has(parsed.id))issues.add('duplicate',at(at('/stages',index),'id'),'Duplicate stage identifier.');seen.add(parsed.id);stages.push(parsed);
  }
  if(issues.values.length)return issues.result(undefined as never);
  return issues.result(freeze({formatVersion:1,id:source.id as string,version:source.version as number,name,separationOfDuties:source.separationOfDuties as boolean,stages}));
};

export const evaluateApprovalStage:ApprovalStageEvaluator=(input)=>{
  const copied=snapshot(input);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['stage','requesterId','separationOfDuties','tasks','decisions','now','expiresAt'],issues);
  if(!source)return issues.result(undefined as never);
  const current=stage(source.stage,'/stage',issues);
  identity(source.requesterId,'/requesterId',issues);boolean(source.separationOfDuties,'/separationOfDuties',issues);
  integer(source.now,'/now',0,Number.MAX_SAFE_INTEGER,issues);integer(source.expiresAt,'/expiresAt',0,Number.MAX_SAFE_INTEGER,issues);
  const tasks=new Map<string,ApprovalTask>(),assignments=new Set<string>(),assignees=new Set<string>();
  const rawTasks=list(source.tasks,'/tasks',APPROVAL_LIMITS.assignments,issues);
  for(const[index,value]of rawTasks.entries()){
    const path=at('/tasks',index),task=fields(value,path,['id','version','assignment','assignedIdentityId'],issues);if(!task)continue;
    identity(task.id,at(path,'id'),issues);integer(task.version,at(path,'version'),1,2_147_483_647,issues);
    safeId(task.assignment,at(path,'assignment'),issues);identity(task.assignedIdentityId,at(path,'assignedIdentityId'),issues);
    const row=task as unknown as ApprovalTask;
    if(tasks.has(row.id))issues.add('duplicate',at(path,'id'),'Duplicate task identity.');tasks.set(row.id,row);
    if(assignments.has(row.assignment))issues.add('duplicate',at(path,'assignment'),'Each stage assignment requires exactly one task.');assignments.add(row.assignment);
    if(assignees.has(row.assignedIdentityId))issues.add('duplicate',at(path,'assignedIdentityId'),'Stage assignments must bind distinct identities.');assignees.add(row.assignedIdentityId);
    if(!current?.assignments.includes(row.assignment))issues.add('enum',at(path,'assignment'),'Task assignment is not in this stage.');
    if(source.separationOfDuties===true&&row.assignedIdentityId===source.requesterId)issues.add('invalid_definition',at(path,'assignedIdentityId'),'The requester cannot be an assigned approver when duties are separated.');
  }
  if(current&&(rawTasks.length!==current.assignments.length||current.assignments.some(assignment=>!assignments.has(assignment))))issues.add('required','/tasks','Tasks must cover every stage assignment exactly once.');
  const decisions=new Set<string>();let approvals=0,rejected=false;
  for(const[index,value]of list(source.decisions,'/decisions',APPROVAL_LIMITS.assignments,issues).entries()){
    const path=at('/decisions',index),decision=fields(value,path,['taskId','taskVersion','assignedIdentityId','actorId','decision','reason'],issues);if(!decision)continue;
    identity(decision.taskId,at(path,'taskId'),issues);integer(decision.taskVersion,at(path,'taskVersion'),1,2_147_483_647,issues);
    identity(decision.assignedIdentityId,at(path,'assignedIdentityId'),issues);identity(decision.actorId,at(path,'actorId'),issues);
    text(decision.reason,at(path,'reason'),APPROVAL_LIMITS.reason,true,issues);
    if(!['approve','reject'].includes(decision.decision as string))issues.add('enum',at(path,'decision'),'Expected approve or reject.');
    const row=decision as unknown as ApprovalDecision,task=tasks.get(row.taskId);
    if(decisions.has(row.taskId))issues.add('duplicate',at(path,'taskId'),'A task may have only one canonical decision.');decisions.add(row.taskId);
    if(!task)issues.add('invalid_definition',at(path,'taskId'),'Decision does not belong to a supplied task.');
    else{
      if(row.taskVersion!==task.version)issues.add('model_version',at(path,'taskVersion'),'Decision must match the exact task version.');
      if(row.assignedIdentityId!==task.assignedIdentityId)issues.add('invalid_definition',at(path,'assignedIdentityId'),'Decision must match the task assignee.');
      if(row.actorId!==task.assignedIdentityId)issues.add('invalid_definition',at(path,'actorId'),'Decision actor must be the task assignee.');
    }
    if(source.separationOfDuties===true&&row.actorId===source.requesterId)issues.add('invalid_definition',at(path,'actorId'),'The requester cannot decide when duties are separated.');
    if(row.decision==='approve')approvals++;else if(row.decision==='reject')rejected=true;
  }
  if(issues.values.length||!current)return issues.result(undefined as never);
  // Evaluate the supplied current instant, not a reconstructed past completion.
  // Even expired/rejected stages validate and count all canonical decisions.
  const outcome=(source.now as number)>=(source.expiresAt as number)?'expired':rejected?'rejected':approvals>=current.quorum?'approved':'pending';
  return issues.result(Object.freeze({outcome,approvals,pending:tasks.size-decisions.size}));
};
