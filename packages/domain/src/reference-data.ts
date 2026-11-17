// SPDX-License-Identifier: Apache-2.0
// Pure reference-code validation and representation. Input checks establish no authority or stored facts.
import {createHash} from 'node:crypto';
import {types as nodeTypes} from 'node:util';
import {parseBoundedJSONEnvelope} from './model.ts';
import {LIMITS,type ApprovalDigestPreimage,type ApprovalPayload,type Audience,type Download,type EffectiveSelection,type Issue,type Labels,
 type LocalizedLabel,type Proposal,type PublicationResult,type PublishedBundle,type ReferenceValue,
 type ReleaseInput,type Result,type WorkflowPin} from './reference-data-contracts.ts';

type Json=null|boolean|number|string|Json[]|{[key:string]:Json};
type Fields=Record<string,Json>;
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const controls=/[\u0000-\u001f\u007f-\u009f]/;
const multilineControls=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved=new Set(['__proto__','constructor','prototype','toJSON']);
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;
const at=(path:string,key:string|number)=>`${path}/${String(key).replaceAll('~','~0').replaceAll('/','~1')}`;
class Invalid extends Error {constructor(readonly issue:Issue){super(issue.code);}}
function fail(code:Issue['code'],path:string,message:string):never{throw new Invalid({code,path,message});}
function need(condition:unknown,code:Issue['code'],path:string,message:string):asserts condition{if(!condition)fail(code,path,message);}
function run<T>(work:()=>T):Result<T>{try{return {ok:true,value:work()};}catch(error){return {ok:false,issues:[error instanceof Invalid?error.issue:{code:'INVALID_JSON',path:'',message:'Data could not be read safely.'}]};}}
function take<T>(result:Result<T>):T{if(!result.ok)throw new Invalid(result.issues[0]);return result.value;}

/** Descriptor snapshot: rejects proxies before reflective traps, getters,
 * toJSON, symbols, sparse arrays, exotic prototypes and active-path cycles.
 * Every recursive visit charges node, UTF-16 and actual JSON UTF-8 budgets.
 * Reflection is proportional to already materialized keys; raw JSON is bounded
 * before parsing. No input object is passed to JSON.stringify or user code. */
function snapshot(input:unknown,maximum:number):Json {
 let bytes=0,nodes=0,utf16=0;const active=new Set<object>();
 function charge(count:number,path:string){bytes+=count;need(bytes<=maximum,'LIMIT',path,'JSON byte budget exceeded.');}
 function string(value:string,path:string){
  utf16+=value.length;
  need(value.length<=LIMITS.stringUtf16&&utf16<=LIMITS.totalUtf16,'LIMIT',path,'UTF-16 string budget exceeded.');
  need(!malformed.test(value),'FORMAT',path,'Unicode must be well formed.');
  charge(Buffer.byteLength(JSON.stringify(value),'utf8'),path);return value;
 }
 function copy(value:unknown,path:string,depth:number):Json {
  need(++nodes<=LIMITS.nodes&&depth<=LIMITS.depth,'LIMIT',path,'JSON structural budget exceeded.');
  if(value===null){charge(4,path);return null;}
  if(typeof value==='string')return string(value,path);
  if(typeof value==='boolean'){charge(value?4:5,path);return value;}
  if(typeof value==='number'){need(Number.isFinite(value)&&!Object.is(value,-0),'INVALID_JSON',path,'Expected a finite JSON number.');charge(String(value).length,path);return value;}
  need(typeof value==='object'&&!nodeTypes.isProxy(value),'INVALID_JSON',path,'Expected plain JSON data.');
  need(!active.has(value),'INVALID_JSON',path,'Cycles are not JSON data.');
  const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
  need(array?prototype===Array.prototype:prototype===Object.prototype||prototype===null,'INVALID_JSON',path,'Unexpected object prototype.');
  const keys=Reflect.ownKeys(value),length=array?Object.getOwnPropertyDescriptor(value,'length')?.value:keys.length;
  need(Number.isInteger(length)&&length>=0&&length<=(array?LIMITS.array:LIMITS.properties),'LIMIT',path,'Container size exceeded.');
  need(!array||keys.length===length+1,'INVALID_JSON',path,'Sparse arrays and extra array keys are not supported.');
  charge(2+Math.max(0,length-1),path);active.add(value);
  try{
   const names=array?Array.from({length},(_,index)=>String(index)):keys;
   const items:Json[]=[],entries:[string,Json][]=[];
   for(const key of names){
    need(typeof key==='string'&&key.length<=256&&!reserved.has(key),'INVALID_JSON',path,'Reserved or invalid property key.');
    const d=Object.getOwnPropertyDescriptor(value,key),child=at(path,key);
    need(d?.enumerable&&Object.hasOwn(d,'value'),'INVALID_JSON',child,'Only enumerable data properties are supported.');
    if(!array){string(key,child);charge(1,child);}
    const next=copy(d.value,child,depth+1);
    if(array)items.push(next);else entries.push([key,next]);
   }
   // Construct from owned pairs rather than assigning caller keys onto an
   // object. Keep the detached record free of inherited properties/hooks.
   return array?items:Object.setPrototypeOf(Object.fromEntries(entries),null);
  }finally{active.delete(value);}
 }
 return copy(input,'',0);
}
function fields(value:Json,path:string,keys:readonly string[]):Fields {
 need(value!==null&&typeof value==='object'&&!Array.isArray(value),'FIELDS',path,'Expected an object.');
 need(Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key)),'FIELDS',path,'Provide exactly the declared fields.');return value;
}
function list(value:Json,path:string,maximum:number,minimum=0):Json[]{need(Array.isArray(value)&&value.length>=minimum&&value.length<=maximum,'LIMIT',path,'Array length is outside its bounds.');return value;}
function text(value:Json,path:string,maximum:number,multiline=false):string {
 need(typeof value==='string','FORMAT',path,'Expected text.');
 // Match the SQL text boundary: trim/NFC cannot erase original over-limit
 // padding or disallowed controls. Recheck normalized length for NFC expansion.
 need(value.length<=maximum&&!(multiline?multilineControls:controls).test(value),'FORMAT',path,'Original text is invalid or too long.');
 const normalized=value.normalize('NFC').trim();
 need(normalized.length>=1&&normalized.length<=maximum,'FORMAT',path,'Normalized text is empty or too long.');return normalized;
}
function uuid(value:Json,path:string):string{need(typeof value==='string'&&UUID.test(value)&&value!=='00000000-0000-0000-0000-000000000000','FORMAT',path,'Expected a canonical nonzero UUID.');return value;}
function integer(value:Json,path:string,zero=false):number{need(typeof value==='number'&&Number.isInteger(value)&&value>=(zero?0:1)&&value<=LIMITS.version,'FORMAT',path,'Expected a bounded version.');return value;}
function instant(value:Json,path:string):string {
 need(typeof value==='string'&&/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value)&&!value.startsWith('0000'),'FORMAT',path,'Expected an exact UTC millisecond timestamp.');
 need(Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value,'FORMAT',path,'Timestamp is not a real instant.');return value;
}
const bound=(value:Json,path:string)=>value===null?null:instant(value,path);
function interval(from:string|null,until:string|null,path:string){need(from===null||until===null||from<until,'INTERVAL',path,'An interval must be nonempty and half-open.');}
function status(value:Json,path:string):'active'|'deprecated'{need(value==='active'||value==='deprecated','FORMAT',path,'Unknown reference status.');return value;}
function localized(value:Json,path:string):LocalizedLabel {const v=fields(value,path,['label','description']);return {label:text(v.label,at(path,'label'),LIMITS.label),description:text(v.description,at(path,'description'),LIMITS.description,true)};}
function labels(value:Json,path:string):Labels{const v=fields(value,path,['en','ar']);return {en:localized(v.en,at(path,'en')),ar:localized(v.ar,at(path,'ar'))};}
function referenceValue(value:Json,path:string,seen?:Set<string>):ReferenceValue {
 const v=fields(value,path,['code','labels','ownerId','status','validFrom','validUntil']);
 need(typeof v.code==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(v.code),'FORMAT',at(path,'code'),'Expected an exact code identifier.');
 if(seen){need(!seen.has(v.code),'DUPLICATE',at(path,'code'),'Duplicate exact code key.');seen.add(v.code);}
 const from=bound(v.validFrom,at(path,'validFrom')),until=bound(v.validUntil,at(path,'validUntil'));interval(from,until,path);
 return {code:v.code,labels:labels(v.labels,at(path,'labels')),ownerId:uuid(v.ownerId,at(path,'ownerId')),status:status(v.status,at(path,'status')),validFrom:from,validUntil:until};
}
function values(value:Json,path:string):ReferenceValue[]{
 const seen=new Set<string>();return list(value,path,LIMITS.values,1).map((row,index)=>referenceValue(row,at(path,index),seen)).sort((a,b)=>compare(a.code,b.code));
}
/** Shared exact row grammar; this parser grants no owner or publication authority. */
export const parseReferenceValue=(input:unknown):Result<ReferenceValue>=>run(()=>freeze(referenceValue(snapshot(input,LIMITS.releaseBytes),'')));

function audience(value:Json,path:string):Audience{
 const v=fields(value,path,['visibility','allowedIdentityIds']);need(v.visibility==='tenant'||v.visibility==='restricted','FORMAT',at(path,'visibility'),'Unknown visibility.');
 const ids=list(v.allowedIdentityIds,at(path,'allowedIdentityIds'),LIMITS.principals).map((id,i)=>uuid(id,at(at(path,'allowedIdentityIds'),i)));
 need(new Set(ids).size===ids.length,'DUPLICATE',path,'Audience identities must be unique.');
 need(v.visibility==='tenant'?ids.length===0:ids.length>0,'FORMAT',path,'Tenant audiences are empty; restricted audiences are explicit.');
 return {visibility:v.visibility,allowedIdentityIds:ids.sort(compare)};
}
function freeze<T>(value:T):T{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
/** Only owned, descriptor-checked or constructed data reaches this encoder. */
function canonical(value:unknown):string {
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort(compare).map(key=>JSON.stringify(key)+':'+canonical((value as Record<string,unknown>)[key])).join(',')+'}';
}
function budget(value:unknown,maximum:number,path:string){need(Buffer.byteLength(canonical(value),'utf8')<=maximum,'LIMIT',path,'Canonical JSON byte budget exceeded.');}
function principalLimit(ids:readonly string[],path:string){need(new Set(ids).size<=LIMITS.principals,'LIMIT',path,'Complete principal union exceeds its bound.');}
function release(value:Json,path:string):ReleaseInput {
 const v=fields(value,path,['formatVersion','kind','labels','ownerId','status','activation','validUntil','values']);
 need(v.formatVersion===1&&v.kind==='reference-code-list','FORMAT',path,'Unknown reference format.');
 const a=v.activation;need(a!==null&&typeof a==='object'&&!Array.isArray(a),'FIELDS',at(path,'activation'),'Expected an activation object.');
 let activation:ReleaseInput['activation'];
 if(a.kind==='on-publication'){fields(a,at(path,'activation'),['kind']);activation={kind:'on-publication'};}
 else{fields(a,at(path,'activation'),['kind','at']);need(a.kind==='at','FORMAT',at(path,'activation'),'Unknown activation mode.');activation={kind:'at',at:instant(a.at,at(at(path,'activation'),'at'))};}
 const out:ReleaseInput={formatVersion:1,kind:'reference-code-list',labels:labels(v.labels,at(path,'labels')),ownerId:uuid(v.ownerId,at(path,'ownerId')),status:status(v.status,at(path,'status')),activation,validUntil:bound(v.validUntil,at(path,'validUntil')),values:values(v.values,at(path,'values'))};
 if(activation.kind==='at')interval(activation.at,out.validUntil,path);
 principalLimit([out.ownerId,...out.values.map(row=>row.ownerId)],path);budget(out,LIMITS.releaseBytes,path);return out;
}
function payload(value:Json,path:string):ApprovalPayload {
 const v=fields(value,path,['formatVersion','kind','setId','expectedVersion','audience','release']);need(v.formatVersion===1&&v.kind==='reference-publication','FORMAT',path,'Unknown publication format.');
 const expectedVersion=integer(v.expectedVersion,at(path,'expectedVersion'),true);need(expectedVersion<LIMITS.version,'LIMIT',at(path,'expectedVersion'),'No successor version remains.');
 const out:ApprovalPayload={formatVersion:1,kind:'reference-publication',setId:uuid(v.setId,at(path,'setId')),expectedVersion,audience:audience(v.audience,at(path,'audience')),release:release(v.release,at(path,'release'))};
 principalLimit([out.release.ownerId,...out.release.values.map(row=>row.ownerId),...out.audience.allowedIdentityIds],path);budget(out,LIMITS.payloadBytes,path);return out;
}
export const parseRelease=(input:unknown):Result<ReleaseInput>=>run(()=>freeze(release(snapshot(input,LIMITS.releaseBytes),'')));
export const parseApprovalPayload=(input:unknown):Result<ApprovalPayload>=>run(()=>freeze(payload(snapshot(input,LIMITS.payloadBytes),'')));
export function parseProposal(input:unknown,requesterId:unknown):Result<Proposal>{return run(()=>{
 const v=fields(snapshot(input,LIMITS.envelopeBytes),'',['id','setId','expectedVersion','audience','release','workflow','assignments','expiresAt']);
 const p=payload({formatVersion:1,kind:'reference-publication',setId:v.setId,expectedVersion:v.expectedVersion,audience:v.audience,release:v.release},'');
 const w=fields(v.workflow,'/workflow',['id','version','definitionHash']);
 need(typeof w.id==='string'&&KEY.test(w.id)&&!reserved.has(w.id),'FORMAT','/workflow/id','Expected a workflow key.');
 need(typeof w.definitionHash==='string'&&/^[0-9a-f]{64}$/.test(w.definitionHash),'FORMAT','/workflow/definitionHash','Expected a hash.');
 const workflow:WorkflowPin={id:w.id,version:integer(w.version,'/workflow/version'),definitionHash:w.definitionHash};
 const a=v.assignments;need(a!==null&&typeof a==='object'&&!Array.isArray(a),'FIELDS','/assignments','Expected assignment keys.');
 const keys=Object.keys(a).sort(compare);need(keys.length>0&&keys.length<=LIMITS.assignments,'LIMIT','/assignments','Assignment count is outside its bound.');
 const requester=uuid(snapshot(requesterId,128),'/requesterId'),assignments:Record<string,string>=Object.create(null),reviewers:string[]=[];
 for(const key of keys){need(KEY.test(key),'FORMAT',at('/assignments',key),'Invalid assignment key.');const id=uuid(a[key],at('/assignments',key));need(id!==requester&&!reviewers.includes(id),'FORMAT',at('/assignments',key),'Reviewers must be distinct and not the requester.');assignments[key]=id;reviewers.push(id);}
 principalLimit([requester,...reviewers,p.release.ownerId,...p.release.values.map(row=>row.ownerId),...p.audience.allowedIdentityIds],'');
 if(p.audience.visibility==='restricted')need([requester,...reviewers].every(id=>p.audience.allowedIdentityIds.includes(id)),'FORMAT','/audience','Requester and reviewers must be in the restricted audience.');
 return freeze({id:uuid(v.id,'/id'),setId:p.setId,expectedVersion:p.expectedVersion,audience:p.audience,release:p.release,workflow,assignments,expiresAt:instant(v.expiresAt,'/expiresAt')});
 });}
export function parseProposalJSON(raw:unknown,requesterId:unknown):Result<Proposal>{return run(()=>{
 need(typeof raw==='string'&&raw.length<=LIMITS.envelopeBytes&&Buffer.byteLength(raw,'utf8')<=LIMITS.envelopeBytes,'LIMIT','','Raw JSON budget exceeded.');
 const parsed=parseBoundedJSONEnvelope(raw);need(parsed.ok,'INVALID_JSON','','Malformed or duplicate-key JSON.');return take(parseProposal(parsed.value,requesterId));
 });}
/** Complete immutable approval identity, excluding trusted requester/tenant
 * columns. It is not merely the release/payload hash. SQL must use this exact
 * normalized preimage; a caller cannot provide its own binding or outcome. */
export function approvalDigestPreimage(input:unknown,requesterId:unknown):Result<ApprovalDigestPreimage>{return run(()=>{
 const p=take(parseProposal(input,requesterId));
 return freeze({id:p.id,binding:'reference.publish',payload:{formatVersion:1,kind:'reference-publication',setId:p.setId,expectedVersion:p.expectedVersion,audience:p.audience,release:p.release},workflow:p.workflow,assignments:p.assignments,expiresAt:p.expiresAt});
 });}
export const proposalDigest=(input:unknown,requesterId:unknown):Result<string>=>run(()=>digest(canonical(take(approvalDigestPreimage(input,requesterId)))));
function bundle(value:Json,path:string):PublishedBundle {
 const v=fields(value,path,['formatVersion','kind','setId','version','labels','ownerId','status','publishedAt','effectiveFrom','validUntil','values']);
 need(v.formatVersion===1&&v.kind==='reference-code-list','FORMAT',path,'Unknown published format.');
 const out:PublishedBundle={formatVersion:1,kind:'reference-code-list',setId:uuid(v.setId,at(path,'setId')),version:integer(v.version,at(path,'version')),labels:labels(v.labels,at(path,'labels')),ownerId:uuid(v.ownerId,at(path,'ownerId')),status:status(v.status,at(path,'status')),publishedAt:instant(v.publishedAt,at(path,'publishedAt')),effectiveFrom:instant(v.effectiveFrom,at(path,'effectiveFrom')),validUntil:bound(v.validUntil,at(path,'validUntil')),values:values(v.values,at(path,'values'))};
 need(out.effectiveFrom>=out.publishedAt,'INTERVAL',path,'A release cannot backdate publication.');interval(out.effectiveFrom,out.validUntil,path);
 principalLimit([out.ownerId,...out.values.map(row=>row.ownerId)],path);budget(out,LIMITS.payloadBytes,path);
 need(canonical(v)===canonical(out),'NON_CANONICAL',path,'Stored bundles must already be normalized and ordered.');return out;
}
export const parsePublishedBundle=(input:unknown):Result<PublishedBundle>=>run(()=>freeze(bundle(snapshot(input,LIMITS.payloadBytes),'')));
/** New-effect preconditions only. An application must authorize a retained
 * receipt and return it BEFORE calling this helper on an exact replay. */
export function preparePublication(input:unknown):Result<PublishedBundle>{return run(()=>{
 // Each child has its own byte cap; inspect the outer envelope without invoking accessors.
 need(input!==null&&typeof input==='object'&&!nodeTypes.isProxy(input),'INVALID_JSON','','Expected publication context.');
 const prototype=Object.getPrototypeOf(input);need(prototype===Object.prototype||prototype===null,'INVALID_JSON','','Invalid context prototype.');
 const keys=Reflect.ownKeys(input),wanted=['payload','publishedAt','previous','previousAudience'];need(keys.length===wanted.length&&wanted.every(key=>keys.includes(key)),'FIELDS','','Invalid publication context.');
 const context:Record<string,unknown>=Object.create(null);for(const key of wanted){const d=Object.getOwnPropertyDescriptor(input,key);need(d?.enumerable&&Object.hasOwn(d,'value'),'INVALID_JSON',at('',key),'Context must use data fields.');context[key]=d.value;}
 const p=take(parseApprovalPayload(context.payload)),now=instant(snapshot(context.publishedAt,128),'/publishedAt');
 const previous=context.previous===null?null:take(parsePublishedBundle(context.previous));
 const previousAudience=context.previousAudience===null?null:audience(snapshot(context.previousAudience,8192),'/previousAudience');
 need((previous===null)===(previousAudience===null),'CONFLICT','','Previous bundle and audience must agree.');
 need(previous===null?p.expectedVersion===0:previous.setId===p.setId&&previous.version===p.expectedVersion&&previous.publishedAt<=now,'CONFLICT','','Published head does not match the proposed precondition.');
 if(previousAudience)need(canonical(previousAudience)===canonical(p.audience),'CONFLICT','/audience','Set audience is immutable in this family.');
 need(p.expectedVersion<LIMITS.version,'LIMIT','/expectedVersion','Version space exhausted.');
 const from=p.release.activation.kind==='on-publication'?now:p.release.activation.at;
 need(p.release.activation.kind==='on-publication'||from>now,'CONFLICT','/release/activation','Scheduled start must still be future at publication.');
 need(previous===null||from>previous.effectiveFrom,'CONFLICT','/release/activation','Effective starts must strictly increase.');interval(from,p.release.validUntil,'/release');
 const out:PublishedBundle={formatVersion:1,kind:'reference-code-list',setId:p.setId,version:p.expectedVersion+1,labels:p.release.labels,ownerId:p.release.ownerId,status:p.release.status,publishedAt:now,effectiveFrom:from,validUntil:p.release.validUntil,values:p.release.values};
 return take(parsePublishedBundle(out));
 });}
const digest=(text:string)=>createHash('sha256').update(text,'utf8').digest('hex');
export const publicationHash=(input:unknown):Result<string>=>run(()=>digest(canonical(take(parsePublishedBundle(input)))));

/** Pure complete-history oracle for native-test expectations. Production should
 * use indexed release headers and recheck the selected bundle, not load every
 * historical payload. Missing, unsorted or over-budget histories fail closed. */
export function selectEffective(input:unknown,asOf:unknown,now:unknown):Result<EffectiveSelection>{return run(()=>{
 const time=instant(snapshot(now,128),'/now'),atTime=asOf===undefined?time:instant(snapshot(asOf,128),'/asOf');need(atTime<=time,'FORMAT','/asOf','Future as-of queries are not historical reads.');
 need(input!==null&&typeof input==='object'&&!nodeTypes.isProxy(input)&&Array.isArray(input)&&Object.getPrototypeOf(input)===Array.prototype,'INVALID_JSON','','Expected a complete release history.');
 const length=Object.getOwnPropertyDescriptor(input,'length')?.value;need(Number.isInteger(length)&&length>=0&&length<=LIMITS.historyVersions,'LIMIT','','History oracle bound exceeded.');
 need(Reflect.ownKeys(input).length===length+1,'INVALID_JSON','','Invalid history array.');
 const history:PublishedBundle[]=[];
 for(let i=0;i<length;i++){
  const d=Object.getOwnPropertyDescriptor(input,String(i));need(d?.enumerable&&Object.hasOwn(d,'value'),'INVALID_JSON',at('',i),'History entries must be data fields.');
  const row=take(parsePublishedBundle(d.value)),prior=history[i-1];
  need(row.version===i+1&&row.publishedAt<=time&&(!prior||row.setId===prior.setId&&row.publishedAt>=prior.publishedAt&&row.effectiveFrom>prior.effectiveFrom),'CONFLICT',at('',i),'History must be a complete monotonic single-set prefix.');history.push(row);
 }
 const known=history.filter(row=>row.publishedAt<=atTime),selected=known.filter(row=>row.effectiveFrom<=atTime).at(-1);
 if(!selected)return freeze({asOf:atTime,phase:'NOT_EFFECTIVE',version:null,publicationHash:null,effectiveFrom:null,effectiveUntil:null,values:[]});
 // Only a successor known at the requested instant can close this read's interval.
 const next=known.find(row=>row.version===selected.version+1),until=[selected.validUntil,next?.effectiveFrom].filter((v):v is string=>typeof v==='string').sort(compare)[0]??null;
 const expired=until!==null&&atTime>=until;
 return freeze({asOf:atTime,phase:expired?'EXPIRED':selected.status==='deprecated'?'DEPRECATED':'EFFECTIVE',version:selected.version,publicationHash:digest(canonical(selected)),effectiveFrom:selected.effectiveFrom,effectiveUntil:until,
  values:expired?[]:selected.values.filter(row=>(row.validFrom===null||row.validFrom<=atTime)&&(row.validUntil===null||atTime<row.validUntil))});
 });}
export const CSV_COLUMNS=Object.freeze(['format_version','kind','set_id','version','set_labels_json','set_owner_id','set_status','published_at','effective_from','set_valid_until','code','value_labels_json','value_owner_id','value_status','value_valid_from','value_valid_until']);
const csvCell=(value:string)=>/[",\r\n]/.test(value)?'"'+value.replaceAll('"','""')+'"':value;
export function serializeBundle(input:unknown,format:unknown):Result<Download>{return run(()=>{
 need(format==='json'||format==='csv','FORMAT','/format','Unsupported download format.');const b=take(parsePublishedBundle(input));let body:string;
 if(format==='json')body=canonical(b)+'\n';
 else{
  const header=[String(b.formatVersion),b.kind,b.setId,String(b.version),canonical(b.labels),b.ownerId,b.status,b.publishedAt,b.effectiveFrom,b.validUntil??''];
  body=CSV_COLUMNS.join(',')+'\r\n'+b.values.map(row=>[...header,row.code,canonical(row.labels),row.ownerId,row.status,row.validFrom??'',row.validUntil??''].map(csvCell).join(',')).join('\r\n')+'\r\n';
 }
 const bytes=Buffer.byteLength(body,'utf8');need(bytes<=LIMITS.downloadBytes,'LIMIT','','Complete download budget exceeded.');
 return Object.freeze({body,contentType:format==='json'?'application/json; charset=utf-8':'text/csv; charset=utf-8',etag:'"'+digest(`gc-reference-${format}-v1\0${body}`)+'"',byteLength:bytes});
 });}

/** Validate immutable worker receipts without granting authority to their fields. */
export function parsePublicationResult(input:unknown):Result<PublicationResult>{return run(()=>{
 const v=fields(snapshot(input,4096),'',['binding','setId','version','publicationHash','publishedAt','effectiveFrom']);
 need(v.binding==='reference.publish','FORMAT','/binding','Unknown publication binding.');
 need(typeof v.publicationHash==='string'&&/^[0-9a-f]{64}$/.test(v.publicationHash),'FORMAT','/publicationHash','Expected a publication hash.');
 const publishedAt=instant(v.publishedAt,'/publishedAt'),effectiveFrom=instant(v.effectiveFrom,'/effectiveFrom');
 need(effectiveFrom>=publishedAt,'INTERVAL','/effectiveFrom','A publication cannot be backdated.');
 return freeze({binding:'reference.publish',setId:uuid(v.setId,'/setId'),version:integer(v.version,'/version'),publicationHash:v.publicationHash,publishedAt,effectiveFrom});
 });}
