// SPDX-License-Identifier: Apache-2.0
// PRIVATE PURE PROTOTYPE: no authorization, persistence, publication or runtime is established here.
import {createHash} from 'node:crypto';
import {types as nodeTypes} from 'node:util';
import {parseBoundedJSONEnvelope} from './model.ts';
import type {Issue,Result,Labels,LocalizedLabel,WorkflowPin,Download} from './reference-data-contracts.ts';
import {STRUCTURE_LIMITS as LIMITS,STRUCTURE_CSV_COLUMNS,
 type ReferenceReleasePin,type Interval,type StructureDefinition,type HierarchyDefinition,type CrosswalkDefinition,
 type HierarchyEdge,type CrosswalkMapping,type MappingConfidence,type StructureProposal,type StructureApprovalPayload,
 type StructureProposalDigestPreimage,type PublishedStructure,type StructurePublicationResult,
 type StructurePublicationContext,type EndpointValidationContext} from './reference-structure-contracts.ts';
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
   const out:Json[]|Fields=array?[]:Object.create(null);
   for(const key of names){
    need(typeof key==='string'&&key.length<=256&&!reserved.has(key),'INVALID_JSON',path,'Reserved or invalid property key.');
    const d=Object.getOwnPropertyDescriptor(value,key),child=at(path,key);
    need(d?.enumerable&&Object.hasOwn(d,'value'),'INVALID_JSON',child,'Only enumerable data properties are supported.');
    if(!array){string(key,child);charge(1,child);}
    const next=copy(d.value,child,depth+1);
    if(array)(out as Json[]).push(next);else (out as Fields)[key]=next;
   }
   return out;
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
function freeze<T>(value:T):T{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
/** Only owned, descriptor-checked or constructed data reaches this encoder. */
function canonical(value:unknown):string {
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort(compare).map(key=>JSON.stringify(key)+':'+canonical((value as Record<string,unknown>)[key])).join(',')+'}';
}
function budget(value:unknown,maximum:number,path:string){need(Buffer.byteLength(canonical(value),'utf8')<=maximum,'LIMIT',path,'Canonical JSON byte budget exceeded.');}
const digest=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
function hash(value:Json,path:string):string{need(typeof value==='string'&&/^[a-f0-9]{64}$/.test(value),'FORMAT',path,'Expected a lowercase SHA256.');return value;}
function code(value:Json,path:string):string{need(typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value),'FORMAT',path,'Expected an exact code identifier.');return value;}
function pin(value:Json,path:string):ReferenceReleasePin{const v=fields(value,path,['setId','version','publicationHash']);return {setId:uuid(v.setId,at(path,'setId')),version:integer(v.version,at(path,'version')),publicationHash:hash(v.publicationHash,at(path,'publicationHash'))};}
function rowInterval(value:Fields,path:string):Interval{const validFrom=bound(value.validFrom,at(path,'validFrom')),validUntil=bound(value.validUntil,at(path,'validUntil'));interval(validFrom,validUntil,path);return {validFrom,validUntil};}
const lower=(v:string|null)=>v??'';
const upper=(v:string|null)=>v??'\uffff';
const intervalCompare=(a:Interval,b:Interval)=>compare(lower(a.validFrom),lower(b.validFrom))||compare(upper(a.validUntil),upper(b.validUntil));
function hierarchyEdges(value:Json,path:string):HierarchyEdge[]{
 return list(value,path,LIMITS.hierarchyEdges).map((row,i)=>{const p=at(path,i),v=fields(row,p,['parentCode','childCode','validFrom','validUntil']);
  const parentCode=code(v.parentCode,at(p,'parentCode')),childCode=code(v.childCode,at(p,'childCode'));need(parentCode!==childCode,'CONFLICT',p,'A hierarchy cannot contain a self edge.');return {parentCode,childCode,...rowInterval(v,p)};
 }).sort((a,b)=>compare(a.parentCode,b.parentCode)||compare(a.childCode,b.childCode)||intervalCompare(a,b));
}
function confidence(value:Json,path:string):MappingConfidence{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value),'FIELDS',path,'Expected confidence metadata.');
 if(value.kind==='not-assessed'){fields(value,path,['kind']);return {kind:'not-assessed'};}
 const v=fields(value,path,['kind','basisPoints','basis']);need(v.kind==='declared','FORMAT',path,'Unknown confidence mode.');
 need(typeof v.basisPoints==='number'&&Number.isInteger(v.basisPoints)&&v.basisPoints>=0&&v.basisPoints<=10000,'FORMAT',at(path,'basisPoints'),'Expected declared basis points from zero to10000.');
 return {kind:'declared',basisPoints:v.basisPoints,basis:text(v.basis,at(path,'basis'),LIMITS.confidenceBasis,true)};
}
function mappings(value:Json,path:string):CrosswalkMapping[]{
 return list(value,path,LIMITS.crosswalkMappings).map<CrosswalkMapping>((row,i)=>{const p=at(path,i),v=fields(row,p,['sourceCode','targetCode','relation','method','methodDetails','transformationNotes','confidence','validFrom','validUntil']);
  need(v.relation==='equivalent'||v.relation==='source-broader'||v.relation==='source-narrower'||v.relation==='related','FORMAT',at(p,'relation'),'Unknown mapping relation.');
  need(v.method==='steward-asserted'||v.method==='source-reported'||v.method==='rule-described','FORMAT',at(p,'method'),'Unknown mapping method.');
  return {sourceCode:code(v.sourceCode,at(p,'sourceCode')),targetCode:code(v.targetCode,at(p,'targetCode')),relation:v.relation,method:v.method,
   methodDetails:text(v.methodDetails,at(p,'methodDetails'),LIMITS.methodDetails,true),transformationNotes:text(v.transformationNotes,at(p,'transformationNotes'),LIMITS.transformationNotes,true),confidence:confidence(v.confidence,at(p,'confidence')),...rowInterval(v,p)};
 }).sort((a,b)=>compare(a.sourceCode,b.sourceCode)||compare(a.targetCode,b.targetCode)||intervalCompare(a,b));
}
function definition(value:Json,path:string):StructureDefinition{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value),'FIELDS',path,'Expected structure definition.');
 const hierarchy=value.kind==='reference-hierarchy';need(hierarchy||value.kind==='reference-crosswalk','FORMAT',at(path,'kind'),'Unknown structure kind.');
 const common=['formatVersion','kind','labels','ownerId','status','activation','validUntil'];
 const v=fields(value,path,[...common,...(hierarchy?['reference','multiParent','edges']:['source','target','cardinality','overlapPolicy','mappings'])]);
 need(v.formatVersion===1,'FORMAT',path,'Unknown structure format.');const a=v.activation;
 need(a!==null&&typeof a==='object'&&!Array.isArray(a),'FIELDS',at(path,'activation'),'Expected activation metadata.');
 let activation:StructureDefinition['activation'];
 if(a.kind==='on-publication'){fields(a,at(path,'activation'),['kind']);activation={kind:'on-publication'};}
 else{fields(a,at(path,'activation'),['kind','at']);need(a.kind==='at','FORMAT',at(path,'activation'),'Unknown activation mode.');activation={kind:'at',at:instant(a.at,at(at(path,'activation'),'at'))};}
 const base={formatVersion:1 as const,labels:labels(v.labels,at(path,'labels')),ownerId:uuid(v.ownerId,at(path,'ownerId')),status:status(v.status,at(path,'status')),activation,validUntil:bound(v.validUntil,at(path,'validUntil'))};
 if(activation.kind==='at')interval(activation.at,base.validUntil,path);
 let result:StructureDefinition;
 if(hierarchy){need(v.multiParent==='forbid'||v.multiParent==='allow','FORMAT',at(path,'multiParent'),'Declare the multi-parent policy.');result={...base,kind:'reference-hierarchy',reference:pin(v.reference,at(path,'reference')),multiParent:v.multiParent,edges:hierarchyEdges(v.edges,at(path,'edges'))};}
 else{need(v.cardinality==='many-to-many'&&v.overlapPolicy==='reject-overlapping-pair','FORMAT',path,'Declare the supported crosswalk policies.');const source=pin(v.source,at(path,'source')),target=pin(v.target,at(path,'target'));need(source.setId!==target.setId,'FORMAT',path,'A crosswalk connects distinct sets.');result={...base,kind:'reference-crosswalk',source,target,cardinality:'many-to-many',overlapPolicy:'reject-overlapping-pair',mappings:mappings(v.mappings,at(path,'mappings'))};}
 // Resolve relative starts against a stable lower bound for syntax-only overlap checks.
 // Publication repeats validation with its canonical effectiveFrom and endpoint windows.
 validateGraph(result,activation.kind==='at'?activation.at:'0001-01-01T00:00:00.000Z',false);
 budget(result,LIMITS.releaseBytes,path);return result;
}
function payload(value:Json,path:string):StructureApprovalPayload{
 const v=fields(value,path,['formatVersion','kind','structureId','expectedVersion','release']);need(v.formatVersion===1&&v.kind==='reference-structure-publication','FORMAT',path,'Unknown publication format.');
 const expectedVersion=integer(v.expectedVersion,at(path,'expectedVersion'),true);need(expectedVersion<=LIMITS.expectedVersion,'LIMIT',at(path,'expectedVersion'),'No successor version remains.');
 const out:StructureApprovalPayload={formatVersion:1,kind:'reference-structure-publication',structureId:uuid(v.structureId,at(path,'structureId')),expectedVersion,release:definition(v.release,at(path,'release'))};budget(out,LIMITS.payloadBytes,path);return out;
}
export const parseRelease=(input:unknown):Result<StructureDefinition>=>run(()=>freeze(definition(snapshot(input,LIMITS.releaseBytes),'')));
export const parseApprovalPayload=(input:unknown):Result<StructureApprovalPayload>=>run(()=>freeze(payload(snapshot(input,LIMITS.payloadBytes),'')));
export function parseProposal(input:unknown,requesterId:unknown):Result<StructureProposal>{return run(()=>{
 const v=fields(snapshot(input,LIMITS.envelopeBytes),'',['id','structureId','expectedVersion','release','workflow','assignments','expiresAt']);
 const p=payload({formatVersion:1,kind:'reference-structure-publication',structureId:v.structureId,expectedVersion:v.expectedVersion,release:v.release},'');
 const w=fields(v.workflow,'/workflow',['id','version','definitionHash']);need(typeof w.id==='string'&&KEY.test(w.id)&&!reserved.has(w.id),'FORMAT','/workflow/id','Expected a workflow key.');
 const workflow:WorkflowPin={id:w.id,version:integer(w.version,'/workflow/version'),definitionHash:hash(w.definitionHash,'/workflow/definitionHash')};
 const a=v.assignments;need(a!==null&&typeof a==='object'&&!Array.isArray(a),'FIELDS','/assignments','Expected assignment keys.');const keys=Object.keys(a).sort(compare);need(keys.length>0&&keys.length<=LIMITS.assignments,'LIMIT','/assignments','Assignment count is outside its bound.');
 const requester=uuid(snapshot(requesterId,128),'/requesterId'),assignments:Record<string,string>=Object.create(null),reviewers=new Set<string>();
 for(const key of keys){need(KEY.test(key)&&!reserved.has(key),'FORMAT',at('/assignments',key),'Invalid assignment key.');const value=uuid(a[key],at('/assignments',key));need(value!==requester&&!reviewers.has(value),'FORMAT',at('/assignments',key),'Reviewers must be distinct and not requester.');assignments[key]=value;reviewers.add(value);}
 return freeze({id:uuid(v.id,'/id'),structureId:p.structureId,expectedVersion:p.expectedVersion,release:p.release,workflow,assignments,expiresAt:instant(v.expiresAt,'/expiresAt')});
});}
export function parseProposalJSON(input:unknown,requesterId:unknown):Result<StructureProposal>{return run(()=>{
 need(typeof input==='string'&&input.length<=LIMITS.envelopeBytes&&Buffer.byteLength(input,'utf8')<=LIMITS.envelopeBytes,'LIMIT','','Raw JSON budget exceeded.');
 const parsed=parseBoundedJSONEnvelope(input);need(parsed.ok,'INVALID_JSON','','Malformed or duplicate-key JSON.');return take(parseProposal(parsed.value,requesterId));
});}
export function approvalDigestPreimage(input:unknown,requesterId:unknown):Result<StructureProposalDigestPreimage>{return run(()=>{
 const p=take(parseProposal(input,requesterId));return freeze({id:p.id,binding:'reference.structure.publish',payload:{formatVersion:1,kind:'reference-structure-publication',structureId:p.structureId,expectedVersion:p.expectedVersion,release:p.release},workflow:p.workflow,assignments:p.assignments,expiresAt:p.expiresAt});
});}
export const proposalDigest=(input:unknown,requesterId:unknown):Result<string>=>run(()=>digest(canonical(take(approvalDigestPreimage(input,requesterId)))));
function endpointPins(value:StructureDefinition|PublishedStructure):ReferenceReleasePin[]{return value.kind==='reference-hierarchy'?[value.reference]:[value.source,value.target];}
function identity(value:StructureDefinition|PublishedStructure):string{return canonical({kind:value.kind,setIds:endpointPins(value).map(p=>p.setId)});}
type Resolved<T extends Interval>={row:T;from:string;until:string|null};
function resolve<T extends Interval>(row:T,from:string,until:string|null,path:string,contain:boolean):Resolved<T>{
 const start=row.validFrom??from,end=row.validUntil??until;interval(start,end,path);
 if(contain)need(start>=from&&(until===null||end!==null&&end<=until),'INTERVAL',path,'Entry interval must be inside the structure interval.');return {row,from:start,until:end};
}
function validateGraph(value:StructureDefinition|PublishedStructure,from:string,contain=true):void{
 const rows=value.kind==='reference-hierarchy'?value.edges:value.mappings;
 const resolved=rows.map((row,i)=>resolve(row,from,value.validUntil,at('/entries',i),contain));
 const lastByPair=new Map<string,Resolved<Interval>>();
 for(const item of resolved){const row=item.row,pair='parentCode' in row?[row.parentCode,row.childCode]:[row.sourceCode,row.targetCode],key=canonical(pair),previous=lastByPair.get(key);
  need(!previous||upper(previous.until)<=item.from,'CONFLICT','/entries','Overlapping intervals for the same ordered code pair are not permitted.');lastByPair.set(key,item);
 }
 if(value.kind!=='reference-hierarchy')return;
 need(new Set(value.edges.flatMap(row=>[row.parentCode,row.childCode])).size<=LIMITS.endpointCodes,'LIMIT','/edges','Hierarchy nodes exceed the endpoint code bound.');
 const edges=resolved as Resolved<HierarchyEdge>[];const points=[...new Set([from,...edges.flatMap(row=>[row.from,...(row.until===null?[]:[row.until])]),...(value.validUntil===null?[]:[value.validUntil])])].sort(compare);
 need(points.length<=LIMITS.temporalBoundaryPoints,'LIMIT','/edges','Too many temporal graph boundaries.');
 for(const point of points){if(point<from||value.validUntil!==null&&point>=value.validUntil)continue;
  const active=edges.filter(row=>row.from<=point&&(row.until===null||point<row.until));const outgoing=new Map<string,string[]>(),indegree=new Map<string,number>();
  for(const {row} of active){if(!indegree.has(row.parentCode))indegree.set(row.parentCode,0);indegree.set(row.childCode,(indegree.get(row.childCode)??0)+1);outgoing.set(row.parentCode,[...(outgoing.get(row.parentCode)??[]),row.childCode]);}
  if(value.multiParent==='forbid')need([...indegree.values()].every(count=>count<=1),'CONFLICT','/edges','Multiple active parents violate the declared policy.');
  const queue=[...indegree].filter(([,count])=>count===0).map(([node])=>node),depth=new Map(queue.map(node=>[node,1]));let visited=0;
  for(let i=0;i<queue.length;i++){const node=queue[i];visited++;need((depth.get(node)??1)<=LIMITS.hierarchyDepth,'LIMIT','/edges','Hierarchy depth exceeds its bound.');
   for(const child of outgoing.get(node)??[]){depth.set(child,Math.max(depth.get(child)??1,(depth.get(node)??1)+1));const count=indegree.get(child)!-1;indegree.set(child,count);if(count===0)queue.push(child);}}
  need(visited===indegree.size,'CONFLICT','/edges','An active hierarchy cycle is not permitted.');
 }
}
function bundle(value:Json,path:string):PublishedStructure{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value),'FIELDS',path,'Expected a published structure.');
 const common=['formatVersion','kind','structureId','version','labels','ownerId','status','publishedAt','effectiveFrom','validUntil'];
 const v=fields(value,path,[...common,...(value.kind==='reference-hierarchy'?['reference','multiParent','edges']:['source','target','cardinality','overlapPolicy','mappings'])]);
 const {structureId,version,publishedAt,effectiveFrom,...rest}=v;
 const published=instant(publishedAt,at(path,'publishedAt')),effective=instant(effectiveFrom,at(path,'effectiveFrom'));need(effective>=published,'INTERVAL',path,'A publication cannot be backdated.');
 // Preserve the original definition byte budget: a scheduled activation has
 // a timestamp while an immediate activation does not.
 const d=definition({...rest,activation:effective===published?{kind:'on-publication'}:{kind:'at',at:effective}},path);interval(effective,d.validUntil,path);
 const {activation,...remaining}=d;const out:PublishedStructure={...remaining,structureId:uuid(structureId,at(path,'structureId')),version:integer(version,at(path,'version')),publishedAt:published,effectiveFrom:effective};
 validateGraph(out,effective);budget(out,LIMITS.payloadBytes,path);need(canonical(v)===canonical(out),'NON_CANONICAL',path,'Stored bundles must already be normalized and sorted.');return out;
}
export const parsePublishedBundle=(input:unknown):Result<PublishedStructure>=>run(()=>freeze(bundle(snapshot(input,LIMITS.payloadBytes),'')));
function contextFields(value:unknown,keys:readonly string[]):Record<string,unknown>{
 need(value!==null&&typeof value==='object'&&!nodeTypes.isProxy(value),'INVALID_JSON','','Expected plain context.');const proto=Object.getPrototypeOf(value);need(proto===null||proto===Object.prototype,'INVALID_JSON','','Expected plain context.');
 const actual=Reflect.ownKeys(value);need(actual.length===keys.length&&keys.every(key=>actual.includes(key)),'FIELDS','','Provide exactly the context fields.');const result:Record<string,unknown>=Object.create(null);
 for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);need(d?.enumerable&&Object.hasOwn(d,'value'),'INVALID_JSON',at('',key),'Context must use data fields.');result[key]=d.value;}return result;
}
function endpoint(value:Json,path:string):EndpointValidationContext{
 const v=fields(value,path,['pin','releaseStatus','publishedAt','effectiveFrom','declaredValidUntil','nextKnownEffectiveFrom','codes']);const publishedAt=instant(v.publishedAt,at(path,'publishedAt')),effectiveFrom=instant(v.effectiveFrom,at(path,'effectiveFrom'));
 need(effectiveFrom>=publishedAt,'INTERVAL',path,'Endpoint publication cannot be backdated.');const declaredValidUntil=bound(v.declaredValidUntil,at(path,'declaredValidUntil')),nextKnownEffectiveFrom=bound(v.nextKnownEffectiveFrom,at(path,'nextKnownEffectiveFrom'));interval(effectiveFrom,declaredValidUntil,path);interval(effectiveFrom,nextKnownEffectiveFrom,path);
 const seen=new Set<string>(),codes=list(v.codes,at(path,'codes'),LIMITS.endpointCodes,1).map((row,i)=>{const p=at(at(path,'codes'),i),item=fields(row,p,['code','status','validFrom','validUntil']),key=code(item.code,at(p,'code'));need(!seen.has(key),'DUPLICATE',p,'Duplicate endpoint code.');seen.add(key);return {code:key,status:status(item.status,at(p,'status')),...rowInterval(item,p)};});
 return {pin:pin(v.pin,at(path,'pin')),releaseStatus:status(v.releaseStatus,at(path,'releaseStatus')),publishedAt,effectiveFrom,declaredValidUntil,nextKnownEffectiveFrom,codes};
}
function minimum(...values:(string|null)[]):string|null{return values.filter((v):v is string=>v!==null).sort(compare)[0]??null;}
function contained(from:string,until:string|null,lowerBound:string,upperBound:string|null,path:string){need(from>=lowerBound&&(upperBound===null||until!==null&&until<=upperBound),'INTERVAL',path,'The complete interval must be inside the pinned endpoint validity.');}
/** Authorized services must verify actual immutable reference bundles/hashes before deriving
 * these bounded endpoint contexts. This pure function cannot establish database truth. */
export function publish(input:StructurePublicationContext):Result<PublishedStructure>{return run(()=>{
 const c=contextFields(input,['payload','publishedAt','previous','endpoints']);const p=take(parseApprovalPayload(c.payload)),now=instant(snapshot(c.publishedAt,128),'/publishedAt'),previous=c.previous===null?null:take(parsePublishedBundle(c.previous));
 need(previous===null?p.expectedVersion===0:previous.structureId===p.structureId&&previous.version===p.expectedVersion&&previous.publishedAt<=now&&identity(previous)===identity(p.release),'CONFLICT','','Head version or fixed endpoint identity changed.');
 const from=p.release.activation.kind==='on-publication'?now:p.release.activation.at;need(p.release.activation.kind==='on-publication'||from>now,'CONFLICT','/activation','A scheduled start must still be future.');need(previous===null||from>previous.effectiveFrom,'CONFLICT','/activation','Effective starts must strictly increase.');interval(from,p.release.validUntil,'/release');
 const pins=endpointPins(p.release),contexts=list(snapshot(c.endpoints,LIMITS.payloadBytes),'/endpoints',2,1).map((v,i)=>endpoint(v,at('/endpoints',i)));
 need(contexts.length===pins.length&&new Set(contexts.map(v=>v.pin.setId)).size===contexts.length,'CONFLICT','/endpoints','Provide exactly the distinct pinned endpoint contexts.');
 for(const expected of pins){const actual=contexts.find(c=>c.pin.setId===expected.setId);need(actual&&canonical(actual.pin)===canonical(expected),'CONFLICT','/endpoints','Endpoint pin mismatch.');need(actual.publishedAt<=now&&actual.releaseStatus==='active','CONFLICT','/endpoints','Endpoint is not a published active release.');contained(from,p.release.validUntil,actual.effectiveFrom,minimum(actual.declaredValidUntil,actual.nextKnownEffectiveFrom),'/release');}
 const rows=p.release.kind==='reference-hierarchy'?p.release.edges:p.release.mappings;
 for(const [i,row] of rows.entries()){const resolved=resolve(row,from,p.release.validUntil,at('/entries',i),true),codes='parentCode'in row?[row.parentCode,row.childCode]:[row.sourceCode,row.targetCode];
  for(let n=0;n<codes.length;n++){const pinIndex=p.release.kind==='reference-hierarchy'?0:n,context=contexts.find(c=>c.pin.setId===pins[pinIndex].setId)!,value=context.codes.find(c=>c.code===codes[n]);need(value&&value.status==='active','CONFLICT',at('/entries',i),'An endpoint code is missing or deprecated.');
   const first=[context.effectiveFrom,value.validFrom??context.effectiveFrom].sort(compare).at(-1)!;contained(resolved.from,resolved.until,first,minimum(context.declaredValidUntil,context.nextKnownEffectiveFrom,value.validUntil),at('/entries',i));}}
 const {activation,...rest}=p.release;return take(parsePublishedBundle({...rest,structureId:p.structureId,version:p.expectedVersion+1,publishedAt:now,effectiveFrom:from}));
});}
export const publicationHash=(input:unknown):Result<string>=>run(()=>digest(canonical(take(parsePublishedBundle(input)))));
export function parsePublicationResult(input:unknown):Result<StructurePublicationResult>{return run(()=>{
 const v=fields(snapshot(input,4096),'',['binding','structureId','version','publicationHash','publishedAt','effectiveFrom']);need(v.binding==='reference.structure.publish','FORMAT','/binding','Unknown publication binding.');
 const publishedAt=instant(v.publishedAt,'/publishedAt'),effectiveFrom=instant(v.effectiveFrom,'/effectiveFrom');need(effectiveFrom>=publishedAt,'INTERVAL','/effectiveFrom','A publication cannot be backdated.');return freeze({binding:'reference.structure.publish',structureId:uuid(v.structureId,'/structureId'),version:integer(v.version,'/version'),publicationHash:hash(v.publicationHash,'/publicationHash'),publishedAt,effectiveFrom});
});}
const csvCell=(value:string)=>/[",\r\n]/.test(value)?'"'+value.replaceAll('"','""')+'"':value;
function csvRows(b:PublishedStructure):string[][]{
 const fixed={schemaVersion:'1',structureKind:b.kind,structureId:b.structureId,version:String(b.version),publicationHash:digest(canonical(b))};
 const row=(fields:Record<string,string>)=>STRUCTURE_CSV_COLUMNS.map(name=>fields[name]??'');
 const meta={...fixed,recordType:'release',labelsJson:canonical(b.labels),ownerId:b.ownerId,status:b.status,publishedAt:b.publishedAt,effectiveFrom:b.effectiveFrom,validUntil:b.validUntil??'',
  ...(b.kind==='reference-hierarchy'?{referencePinJson:canonical(b.reference),multiParent:b.multiParent}:{sourcePinJson:canonical(b.source),targetPinJson:canonical(b.target),cardinality:b.cardinality,overlapPolicy:b.overlapPolicy})};
 const entries=b.kind==='reference-hierarchy'?b.edges.map(e=>row({...fixed,recordType:'hierarchy-edge',parentCode:e.parentCode,childCode:e.childCode,entryValidFrom:e.validFrom??'',entryValidUntil:e.validUntil??''})):
  b.mappings.map(e=>row({...fixed,recordType:'crosswalk-mapping',sourceCode:e.sourceCode,targetCode:e.targetCode,entryValidFrom:e.validFrom??'',entryValidUntil:e.validUntil??'',relation:e.relation,method:e.method,methodDetails:e.methodDetails,transformationNotes:e.transformationNotes,confidenceJson:canonical(e.confidence)}));
 return [[...STRUCTURE_CSV_COLUMNS],row(meta),...entries];
}
export function serializeBundle(input:unknown,format:'json'|'csv'):Result<Download>{return run(()=>{
 need(format==='json'||format==='csv','FORMAT','/format','Unsupported download format.');const b=take(parsePublishedBundle(input));const body=format==='json'?canonical(b)+'\n':csvRows(b).map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
 const byteLength=Buffer.byteLength(body,'utf8');need(byteLength<=LIMITS.downloadBytes,'LIMIT','','Complete download exceeds its bound.');return Object.freeze({body,byteLength,contentType:format==='json'?'application/json; charset=utf-8':'text/csv; charset=utf-8',etag:'"'+digest(`gc-reference-structure-${format}-v1\0${body}`)+'"'});
});}
function parseCSV(input:unknown):string[][]{
 need(typeof input==='string'&&input.length<=LIMITS.downloadBytes&&Buffer.byteLength(input,'utf8')<=LIMITS.downloadBytes&&!malformed.test(input),'LIMIT','','CSV input is invalid or too large.');
 const rows:string[][]=[],record:string[]=[];let field='',mode:'start'|'plain'|'quoted'|'closed'='start';
 function finishField(){need(record.length<STRUCTURE_CSV_COLUMNS.length,'FIELDS','','Too many CSV columns.');record.push(field);field='';mode='start';}
 function finishRow(){finishField();need(record.length===STRUCTURE_CSV_COLUMNS.length,'FIELDS','','Wrong CSV column count.');rows.push(record.splice(0));need(rows.length<=LIMITS.crosswalkMappings+2,'LIMIT','','Too many CSV rows.');}
 for(let i=0;i<input.length;i++){const c=input[i];if(mode==='quoted'){if(c==='"'){if(input[i+1]==='"'){field+='"';i++;}else mode='closed';}else field+=c;continue;}
  if(c===','){finishField();continue;}if(c==='\r'&&input[i+1]==='\n'){finishRow();i++;continue;}
  need(c!=='\r'&&c!=='\n'&&mode!=='closed','FORMAT','','CSV must use exact RFC4180 records.');
  if(c==='"'){need(mode==='start','FORMAT','','Unexpected CSV quote.');mode='quoted';}else{mode='plain';field+=c;}}
 need(mode==='start'&&record.length===0&&field===''&&rows.length>=2,'FORMAT','','CSV must end with a complete metadata record and CRLF.');
 need(canonical(rows[0])===canonical(STRUCTURE_CSV_COLUMNS),'FIELDS','','Unknown CSV column schema.');return rows;
}
/** Exact approved representation parser only; this does not provide governed bulk import. */
export function parseBundleCSV(input:unknown):Result<PublishedStructure>{return run(()=>{
 const rows=parseCSV(input),record=(values:string[])=>Object.fromEntries(STRUCTURE_CSV_COLUMNS.map((name,i)=>[name,values[i]])),m=record(rows[1]);
 need(m.recordType==='release'&&m.schemaVersion==='1','FORMAT','','Expected one v1 release metadata record.');
 const json=(value:string):Json=>{const parsed=parseBoundedJSONEnvelope(value);need(parsed.ok,'INVALID_JSON','','Malformed or duplicate JSON cell.');return snapshot(parsed.value,LIMITS.payloadBytes);};
 const rest={formatVersion:1,kind:m.structureKind,structureId:m.structureId,version:Number(m.version),labels:json(m.labelsJson),ownerId:m.ownerId,status:m.status,publishedAt:m.publishedAt,effectiveFrom:m.effectiveFrom,validUntil:m.validUntil||null};
 let candidate:unknown;
 if(m.structureKind==='reference-hierarchy')candidate={...rest,reference:json(m.referencePinJson),multiParent:m.multiParent,edges:rows.slice(2).map(v=>{const e=record(v);need(e.recordType==='hierarchy-edge','FORMAT','','Expected hierarchy records.');return {parentCode:e.parentCode,childCode:e.childCode,validFrom:e.entryValidFrom||null,validUntil:e.entryValidUntil||null};})};
 else{need(m.structureKind==='reference-crosswalk','FORMAT','','Unknown structure kind.');candidate={...rest,source:json(m.sourcePinJson),target:json(m.targetPinJson),cardinality:m.cardinality,overlapPolicy:m.overlapPolicy,mappings:rows.slice(2).map(v=>{const e=record(v);need(e.recordType==='crosswalk-mapping','FORMAT','','Expected crosswalk records.');return {sourceCode:e.sourceCode,targetCode:e.targetCode,relation:e.relation,method:e.method,methodDetails:e.methodDetails,transformationNotes:e.transformationNotes,confidence:json(e.confidenceJson),validFrom:e.entryValidFrom||null,validUntil:e.entryValidUntil||null};})};}
 const result=take(parsePublishedBundle(candidate));need(digest(canonical(result))===m.publicationHash,'CONFLICT','','CSV publication hash mismatch.');
 // Exact reserialization closes non-applicable cells, repeated coordinates, row ordering,
 // numeric spelling and duplicate metadata without permissive per-field fallbacks.
 need(take(serializeBundle(result,'csv')).body===input,'NON_CANONICAL','','CSV must be the complete canonical release representation.');return result;
});}
