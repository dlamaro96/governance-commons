// SPDX-License-Identifier: Apache-2.0
/** Immutable structure reads and proposal commands. Protected SQL owns current
 * authority, complete principal locks, approval and atomic publication. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {signedCursor} from './cursor.ts';
import {parseProposal,parsePublishedBundle,publicationHash,serializeBundle,parsePublicationResult} from './reference-structure.ts';
import {STRUCTURE_LIMITS as L,type StructureIdentity,type StructureReleaseSummary,type StructureReleaseView,type StructureAuthoringContext,type StructurePage,type StructurePageQuery,type StructureListQuery,type StructureEffectiveQuery,type EffectiveStructureView,type EndpointGap,type ReferenceReleasePin,type StructureProposalReceipt,type StructurePublicationResult,type PublishedStructure} from './reference-structure-contracts.ts';
import type {Download,Labels} from './reference-data-contracts.ts';

const UUID=/^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export const structureInvalid=()=>new Problem(400,'REFERENCE_STRUCTURE_INPUT_INVALID','Provide exactly the declared structure fields and values.');
const unavailable=()=>new Problem(404,'REFERENCE_STRUCTURE_UNAVAILABLE','The structure or release is unavailable.');
const integrity=()=>new Problem(500,'REFERENCE_STRUCTURE_STORAGE_INVALID','The structure operation could not be verified.');
const retry=()=>new Problem(503,'REFERENCE_STRUCTURE_RETRY','A stable execution window was unavailable. Retry with the same idempotency key.');
const pageInvalid=()=>new Problem(400,'REFERENCE_STRUCTURE_PAGE_INVALID','This structure page is invalid. Start a new listing.');
const limit=()=>new Problem(422,'REFERENCE_STRUCTURE_LIMIT','This structure operation exceeds its supported bounds.');
const deadlines=new WeakMap<Tx,number>();
/** A dedicated budget: nested calls cannot renew the original wall deadline. */
export async function structureQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let end=deadlines.get(tx);if(end===undefined){end=performance.now()+L.commandDeadlineMs;deadlines.set(tx,end);}
 const remaining=Math.floor(end-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(Math.min(L.statementDeadlineMs,remaining))},true),set_config('lock_timeout',${String(Math.min(L.lockDeadlineMs,remaining))},true)`.execute(tx);
 if(performance.now()>=end)throw retry();const value=await work();if(performance.now()>=end)throw retry();return value;
}
export function structureFailure(error:unknown):Problem{
 if(error instanceof Problem)return error;
 const e=error as {code?:unknown;message?:unknown}|null,c=e?.code,m=e?.message;
 if(['55P03','40P01','57014'].includes(String(c)))return retry();
 if(c==='P0002'&&m==='reference structure resource not found')return unavailable();
 if(c==='42501'&&m==='reference structure forbidden')return new Problem(403,'REFERENCE_STRUCTURE_FORBIDDEN','Your current permissions do not allow this structure operation.');
 if(c==='40001'){
  const codes:Record<string,string>={'reference structure version conflict':'VERSION_CONFLICT','reference structure schedule stale':'REFERENCE_STRUCTURE_SCHEDULE_STALE','reference structure endpoint changed':'REFERENCE_STRUCTURE_ENDPOINT_CHANGED','reference structure approval expired':'REFERENCE_STRUCTURE_EXPIRED','IDEMPOTENCY_CONFLICT':'IDEMPOTENCY_CONFLICT','WORKFLOW_PIN_STALE':'WORKFLOW_PIN_STALE'};
  return typeof m==='string'&&Object.hasOwn(codes,m)?new Problem(409,codes[m],'The structure state changed. Reload before continuing.'):retry();
 }
 if(c==='22023'&&m==='reference structure request invalid')return new Problem(422,'REFERENCE_STRUCTURE_DEFINITION_INVALID','Correct the structure release and review assignments.');
 if(c==='54000'&&m==='reference structure limit')return limit();return integrity();
}
export function structureObject(input:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 try{
  if(!input||typeof input!=='object'||types.isProxy(input)||Array.isArray(input)||![null,Object.prototype].includes(Object.getPrototypeOf(input)))throw 0;
  const keys=Reflect.ownKeys(input);if(keys.length>required.length+optional.length||required.some(k=>!keys.includes(k)))throw 0;
  return Object.fromEntries(keys.map(k=>{if(typeof k!=='string'||![...required,...optional].includes(k))throw 0;const d=Object.getOwnPropertyDescriptor(input,k);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;return [k,d.value];}));
 }catch{throw structureInvalid();}
}
function id(v:unknown):asserts v is string{if(typeof v!=='string'||!UUID.test(v))throw structureInvalid();}
function integer(v:unknown,min:number=1,max:number=L.version):asserts v is number{if(typeof v!=='number'||!Number.isInteger(v)||Object.is(v,-0)||v<min||v>max)throw structureInvalid();}
function stamp(v:unknown):asserts v is string{if(typeof v!=='string'||v.startsWith('0000')||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)throw structureInvalid();}
function digest(v:unknown):asserts v is string{if(typeof v!=='string'||!HASH.test(v))throw structureInvalid();}
function stored<T>(work:()=>T):T{try{return work();}catch{throw integrity();}}
function bounded<T>(value:T):T{if(Buffer.byteLength(JSON.stringify(value))>L.responseBytes)throw limit();return value;}
function text(v:unknown,max:number,multiline=false):asserts v is string{if(typeof v!=='string'||!v.length||v.length>max||malformed.test(v)||v!==v.normalize('NFC').trim()||(multiline?/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/:/[\u0000-\u001f\u007f-\u009f]/).test(v))throw structureInvalid();}
function labels(v:unknown):Labels{const x=structureObject(v,['en','ar']);return Object.fromEntries(['en','ar'].map(k=>{const a=structureObject(x[k],['label','description']);text(a.label,L.label);text(a.description,L.description,true);return [k,a];})) as unknown as Labels;}
function identity(v:unknown):StructureIdentity{
 const base=structureObject(v,['kind'],['referenceSetId','sourceSetId','targetSetId']);
 if(base.kind==='reference-hierarchy'){const a=structureObject(v,['kind','referenceSetId']);id(a.referenceSetId);return {kind:'reference-hierarchy',referenceSetId:a.referenceSetId};}
 if(base.kind==='reference-crosswalk'){const a=structureObject(v,['kind','sourceSetId','targetSetId']);id(a.sourceSetId);id(a.targetSetId);if(a.sourceSetId===a.targetSetId)throw structureInvalid();return {kind:'reference-crosswalk',sourceSetId:a.sourceSetId,targetSetId:a.targetSetId};}throw structureInvalid();
}
function summary(v:unknown):StructureReleaseSummary{
 const a=structureObject(v,['structureId','version','publishedAt','effectiveFrom','identity','labels','ownerId','status','validUntil','publicationHash','entryCount']);
 id(a.structureId);id(a.ownerId);integer(a.version);stamp(a.publishedAt);stamp(a.effectiveFrom);digest(a.publicationHash);integer(a.entryCount,0,L.array);
 if(a.validUntil!==null)stamp(a.validUntil);if(!['active','deprecated'].includes(String(a.status))||a.effectiveFrom<a.publishedAt||a.validUntil!==null&&a.validUntil<=a.effectiveFrom)throw structureInvalid();
 return {...a,identity:identity(a.identity),labels:labels(a.labels)} as unknown as StructureReleaseSummary;
}
function identityOf(release:PublishedStructure):StructureIdentity{return release.kind==='reference-hierarchy'?{kind:release.kind,referenceSetId:release.reference.setId}:{kind:release.kind,sourceSetId:release.source.setId,targetSetId:release.target.setId};}
function summaryOf(view:StructureReleaseView):StructureReleaseSummary{const r=view.release;return {structureId:r.structureId,version:r.version,publishedAt:r.publishedAt,effectiveFrom:r.effectiveFrom,identity:identityOf(r),labels:r.labels,ownerId:r.ownerId,status:r.status,validUntil:r.validUntil,publicationHash:view.publicationHash,entryCount:r.kind==='reference-hierarchy'?r.edges.length:r.mappings.length};}
export function parseStructurePublicationResult(input:unknown):StructurePublicationResult{const result=parsePublicationResult(input);if(!result.ok)throw structureInvalid();return result.value;}
async function authorize(tx:Tx,p:Principal,write=false){await structureQuery(tx,()=>sql`select public.gc_reference_structure_authorize(${p.id}::uuid,${write}::boolean)`.execute(tx));}
async function visible(tx:Tx,p:Principal,structureId:string){const row=(await structureQuery(tx,()=>sql`select h.id from public.reference_structure_heads h where h.tenant_id=${p.tenantId}::uuid and h.id=${structureId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid)`.execute(tx))).rows[0];if(!row)throw unavailable();}
async function authorized(tx:Tx,p:Principal,structureId:string,write=false){await authorize(tx,p,write);await visible(tx,p,structureId);}
async function clock(tx:Tx){const value=(await structureQuery(tx,()=>sql<{value:unknown}>`select public.gc_relation_utc(clock_timestamp()) as value`.execute(tx))).rows[0]?.value;return stored(()=>{stamp(value);return value;});}
function paging(p:Principal,collection:string,structureId:string|null,input:unknown,extra:readonly string[]=[]){
 const q=structureObject(input,[],['limit','cursor',...extra]),size=q.limit??L.pageDefault;integer(size,1,L.pageMaximum);
 const search=q.q??'';if(typeof search!=='string'||search.length>L.search||malformed.test(search)||/[\u0000-\u001f\u007f-\u009f]/.test(search))throw structureInvalid();const normalized=search.normalize('NFC').trim();
 if(q.kind!==undefined&&q.kind!=='reference-hierarchy'&&q.kind!=='reference-crosswalk')throw structureInvalid();if(q.setId!==undefined)id(q.setId);if(q.asOf!==undefined)stamp(q.asOf);
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,collection,structureId,size,normalized,q.kind??null,q.setId??null,q.asOf??null])).digest('hex');
 const codec=signedCursor(process.env.SESSION_KEY,'reference-structures-'+collection+'-v1');let cursor:unknown[]|null=null;
 if(q.cursor!==undefined)try{if(typeof q.cursor!=='string'||!q.cursor||q.cursor.length>L.cursor)throw 0;const value=codec.decode(q.cursor);if(!Array.isArray(value)||value.length!==4||value[0]!==1||value[1]!==binding)throw 0;cursor=value;}catch{throw pageInvalid();}
 return {limit:size,q:normalized,kind:q.kind as StructureIdentity['kind']|undefined,setId:q.setId as string|undefined,asOf:q.asOf as string|undefined,cursor,next:(last:unknown,pin:unknown)=>codec.encode([1,binding,last,pin])};
}
function identitySQL(){return sql`case when h.kind='reference-hierarchy' then jsonb_build_object('kind',h.kind,'referenceSetId',h.reference_set_id) else jsonb_build_object('kind',h.kind,'sourceSetId',h.source_set_id,'targetSetId',h.target_set_id) end`;}
function summarySQL(){return sql`jsonb_build_object('structureId',h.id,'version',r.version,'publishedAt',public.gc_relation_utc(r.published_at),'effectiveFrom',public.gc_relation_utc(r.effective_from),'identity',${identitySQL()},'labels',r.published_bundle->'labels','ownerId',r.owner_id,'status',r.status,'validUntil',case when r.valid_until is null then null else public.gc_relation_utc(r.valid_until) end,'publicationHash',r.publication_hash,'entryCount',jsonb_array_length(case when h.kind='reference-hierarchy' then r.published_bundle->'edges' else r.published_bundle->'mappings' end))`;}
async function parsedSummaries(tx:Tx,p:Principal,rows:readonly {value:unknown}[],structureId?:string){await authorize(tx,p);if(structureId)await visible(tx,p,structureId);const items=rows.map(row=>stored(()=>summary(row.value)));for(const item of items)await visible(tx,p,item.structureId);return items;}
export async function listReferenceStructures(tx:Tx,p:Principal,input:StructureListQuery={}):Promise<StructurePage<StructureReleaseSummary>>{
 const page=paging(p,'structures',null,input,['q','kind','setId']);let after:string|null=null;if(page.cursor)try{id(page.cursor[2]);if(page.cursor[3]!==null)throw 0;after=page.cursor[2];}catch{throw pageInvalid();}
 await authorize(tx,p);const search='%'+page.q.replaceAll('\\','\\\\').replaceAll('%','\\%').replaceAll('_','\\_')+'%';
 const rows=(await structureQuery(tx,()=>sql<{value:unknown}>`with authorized as materialized (select h.* from public.reference_structure_heads h where h.tenant_id=${p.tenantId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid)) select ${summarySQL()} as value from authorized h join public.reference_structure_releases r on r.tenant_id=h.tenant_id and r.structure_id=h.id and r.version=h.current_version where ${after===null?sql`true`:sql`h.id>${after}::uuid`} and ${page.kind?sql`h.kind=${page.kind}`:sql`true`} and ${page.setId?sql`(h.reference_set_id=${page.setId}::uuid or h.source_set_id=${page.setId}::uuid or h.target_set_id=${page.setId}::uuid)`:sql`true`} and ${page.q?sql`(r.published_bundle#>>'{labels,en,label}' ilike ${search} escape '\\' or r.published_bundle#>>'{labels,ar,label}' ilike ${search} escape '\\')`:sql`true`} order by h.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=(await parsedSummaries(tx,p,rows)).slice(0,page.limit);return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.structureId,null):null});
}
export async function listStructureReleases(tx:Tx,p:Principal,structureId:string,input:StructurePageQuery={}):Promise<StructurePage<StructureReleaseSummary>>{
 id(structureId);const page=paging(p,'releases',structureId,input);let after=0;if(page.cursor)try{integer(page.cursor[2]);if(page.cursor[3]!==null)throw 0;after=page.cursor[2];}catch{throw pageInvalid();}
 await authorized(tx,p,structureId);const rows=(await structureQuery(tx,()=>sql<{value:unknown}>`select ${summarySQL()} as value from public.reference_structure_heads h join public.reference_structure_releases r on r.tenant_id=h.tenant_id and r.structure_id=h.id where h.tenant_id=${p.tenantId}::uuid and h.id=${structureId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid) and r.version>${after} order by r.version limit ${page.limit+1}`.execute(tx))).rows;
 const items=(await parsedSummaries(tx,p,rows,structureId)).slice(0,page.limit);if(items.some(x=>x.structureId!==structureId))throw integrity();return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.version,null):null});
}
async function release(tx:Tx,p:Principal,structureId:string,version:number):Promise<StructureReleaseView>{
 const meta=(await structureQuery(tx,()=>sql<{body_bytes:number;publication_hash:string;identity:unknown}>`with permitted as materialized (select h.* from public.reference_structure_heads h where h.tenant_id=${p.tenantId}::uuid and h.id=${structureId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid)) select octet_length(r.published_bundle::text) as body_bytes,r.publication_hash,${identitySQL()} as identity from permitted h join public.reference_structure_releases r on r.tenant_id=h.tenant_id and r.structure_id=h.id where r.version=${version}`.execute(tx))).rows[0];
 await authorized(tx,p,structureId);if(!meta)throw unavailable();if(!Number.isInteger(meta.body_bytes)||meta.body_bytes<1||meta.body_bytes>L.payloadBytes*2||!HASH.test(meta.publication_hash))throw integrity();
 const raw=(await structureQuery(tx,()=>sql<{value:unknown}>`select r.published_bundle as value from public.reference_structure_releases r where r.tenant_id=${p.tenantId}::uuid and r.structure_id=${structureId}::uuid and r.version=${version} and public.gc_reference_structure_visible(r.structure_id,${p.id}::uuid)`.execute(tx))).rows[0]?.value;
 await authorized(tx,p,structureId);return stored(()=>{const parsed=parsePublishedBundle(raw);if(!parsed.ok||parsed.value.structureId!==structureId||parsed.value.version!==version)throw 0;const value=publicationHash(parsed.value);if(!value.ok||value.value!==meta.publication_hash||JSON.stringify(identity(meta.identity))!==JSON.stringify(identityOf(parsed.value)))throw 0;return {release:parsed.value,publicationHash:value.value};});
}
export async function getStructureRelease(tx:Tx,p:Principal,structureId:string,version:number):Promise<StructureReleaseView>{id(structureId);integer(version);await authorized(tx,p,structureId);return bounded(await release(tx,p,structureId,version));}
export async function getStructureAuthoringContext(tx:Tx,p:Principal,structureId:string):Promise<StructureAuthoringContext>{
 id(structureId);await authorized(tx,p,structureId,true);const row=(await structureQuery(tx,()=>sql<{version:number}>`select h.current_version as version from public.reference_structure_heads h where h.tenant_id=${p.tenantId}::uuid and h.id=${structureId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid)`.execute(tx))).rows[0];
 await authorized(tx,p,structureId,true);if(!row)throw unavailable();stored(()=>integer(row.version));const selected=await release(tx,p,structureId,row.version);await authorized(tx,p,structureId,true);return bounded({...selected,identity:identityOf(selected.release),latestPublishedVersion:row.version,audiencePolicy:'intersection-of-current-endpoint-audiences' as const});
}
interface Selection{version:number;publicationHash:string;effectiveFrom:string;effectiveUntil:string|null;status:'active'|'deprecated'}
function selection(v:unknown):Selection{const a=structureObject(v,['version','publicationHash','effectiveFrom','effectiveUntil','status']);integer(a.version);digest(a.publicationHash);stamp(a.effectiveFrom);if(a.effectiveUntil!==null)stamp(a.effectiveUntil);if(!['active','deprecated'].includes(String(a.status))||a.effectiveUntil!==null&&a.effectiveUntil<=a.effectiveFrom)throw structureInvalid();return a as unknown as Selection;}
async function selectedAt(tx:Tx,p:Principal,structureId:string,asOf:string):Promise<Selection|null>{
 const row=(await structureQuery(tx,()=>sql<{value:unknown}>`select jsonb_build_object('version',r.version,'publicationHash',r.publication_hash,'effectiveFrom',public.gc_relation_utc(r.effective_from),'effectiveUntil',case when least(r.valid_until,n.effective_from) is null then null else public.gc_relation_utc(least(r.valid_until,n.effective_from)) end,'status',r.status) as value from public.reference_structure_releases r left join lateral(select min(s.effective_from) as effective_from from public.reference_structure_releases s where s.tenant_id=r.tenant_id and s.structure_id=r.structure_id and s.version>r.version and s.published_at<=${asOf}::timestamptz) n on true where r.tenant_id=${p.tenantId}::uuid and r.structure_id=${structureId}::uuid and public.gc_reference_structure_visible(r.structure_id,${p.id}::uuid) and r.published_at<=${asOf}::timestamptz and r.effective_from<=${asOf}::timestamptz order by r.effective_from desc,r.version desc limit 1`.execute(tx))).rows[0];
 await authorized(tx,p,structureId);return row?stored(()=>selection(row.value)):null;
}
function endpoints(r:PublishedStructure):readonly {endpoint:EndpointGap['endpoint'];pin:ReferenceReleasePin}[]{return r.kind==='reference-hierarchy'?[{endpoint:'reference',pin:r.reference}]:[{endpoint:'source',pin:r.source},{endpoint:'target',pin:r.target}];}
async function endpointGaps(tx:Tx,p:Principal,r:PublishedStructure,asOf:string):Promise<EndpointGap[]>{
 const gaps:EndpointGap[]=[];
 for(const e of endpoints(r)){
  const row=(await structureQuery(tx,()=>sql<{value:unknown}>`select jsonb_build_object('version',v.version,'publicationHash',v.publication_hash,'effectiveFrom',public.gc_relation_utc(v.effective_from),'effectiveUntil',case when least(v.valid_until,n.effective_from) is null then null else public.gc_relation_utc(least(v.valid_until,n.effective_from)) end,'status',v.status) as value from public.reference_releases v left join lateral(select min(s.effective_from) as effective_from from public.reference_releases s where s.tenant_id=v.tenant_id and s.set_id=v.set_id and s.version>v.version and s.published_at<=${asOf}::timestamptz) n on true where v.tenant_id=${p.tenantId}::uuid and v.set_id=${e.pin.setId}::uuid and public.gc_reference_visible(v.set_id,${p.id}::uuid) and v.published_at<=${asOf}::timestamptz and v.effective_from<=${asOf}::timestamptz order by v.effective_from desc,v.version desc limit 1`.execute(tx))).rows[0];
  await authorized(tx,p,r.structureId);if(!row){gaps.push({endpoint:e.endpoint,reason:'NOT_EFFECTIVE'});continue;}const a=stored(()=>selection(row.value));
  if(a.effectiveUntil!==null&&asOf>=a.effectiveUntil)gaps.push({endpoint:e.endpoint,reason:'EXPIRED'});else if(a.status==='deprecated')gaps.push({endpoint:e.endpoint,reason:'DEPRECATED'});else if(a.version!==e.pin.version||a.publicationHash!==e.pin.publicationHash)gaps.push({endpoint:e.endpoint,reason:'PIN_SUPERSEDED'});
 }return gaps;
}
export async function getStructureEffective(tx:Tx,p:Principal,structureId:string,input:StructureEffectiveQuery={}):Promise<EffectiveStructureView>{
 id(structureId);const page=paging(p,'effective',structureId,input,['asOf']);let after=-1,pin:{asOf:string;version:number;publicationHash:string;endpointPinsHash:string}|null=null;
 if(page.cursor)try{integer(page.cursor[2],0,L.array-1);after=page.cursor[2];const a=structureObject(page.cursor[3],['asOf','version','publicationHash','endpointPinsHash']);stamp(a.asOf);integer(a.version);digest(a.publicationHash);digest(a.endpointPinsHash);if(page.asOf!==undefined&&page.asOf!==a.asOf)throw 0;pin=a as {asOf:string;version:number;publicationHash:string;endpointPinsHash:string};}catch{throw pageInvalid();}
 await authorized(tx,p,structureId);const now=await clock(tx),asOf=pin?.asOf??page.asOf??now;if(asOf>now)throw structureInvalid();const chosen=await selectedAt(tx,p,structureId,asOf);
 if(pin&&(!chosen||chosen.version!==pin.version||chosen.publicationHash!==pin.publicationHash))throw pageInvalid();
 if(!chosen){const latest=await getStructureAuthoringRead(tx,p,structureId);await authorized(tx,p,structureId);return {structure:summaryOf(latest),selection:{phase:'NOT_EFFECTIVE',asOf,version:null,publicationHash:null,effectiveFrom:null,effectiveUntil:null,gaps:[]},items:[],nextCursor:null};}
 const view=await release(tx,p,structureId,chosen.version),r=view.release;if(view.publicationHash!==chosen.publicationHash||r.effectiveFrom!==chosen.effectiveFrom||r.status!==chosen.status||r.validUntil!==null&&(chosen.effectiveUntil===null||chosen.effectiveUntil>r.validUntil))throw integrity();
 const structure=summaryOf(view),selected={asOf,version:chosen.version,publicationHash:chosen.publicationHash,effectiveFrom:chosen.effectiveFrom,effectiveUntil:chosen.effectiveUntil};
 const endpointPinsHash=createHash('sha256').update(JSON.stringify(endpoints(r))).digest('hex');if(pin&&pin.endpointPinsHash!==endpointPinsHash)throw pageInvalid();
 if(chosen.effectiveUntil!==null&&asOf>=chosen.effectiveUntil||chosen.status==='deprecated'){if(pin)throw pageInvalid();await authorized(tx,p,structureId);return {structure,selection:{...selected,phase:chosen.effectiveUntil!==null&&asOf>=chosen.effectiveUntil?'EXPIRED':'DEPRECATED',gaps:[]},items:[],nextCursor:null};}
 const gaps=await endpointGaps(tx,p,r,asOf);if(gaps.length){if(pin)throw pageInvalid();await authorized(tx,p,structureId);return {structure,selection:{...selected,phase:'ENDPOINT_PIN_NOT_EFFECTIVE',gaps},items:[],nextCursor:null};}
 const rows=(r.kind==='reference-hierarchy'?r.edges:r.mappings).map((value,index)=>({value,index})).filter(({value,index})=>index>after&&(value.validFrom===null||value.validFrom<=asOf)&&(value.validUntil===null||asOf<value.validUntil));
 if(pin){const entries=r.kind==='reference-hierarchy'?r.edges:r.mappings,previous=entries[after];if(!previous||(previous.validFrom!==null&&previous.validFrom>asOf)||(previous.validUntil!==null&&previous.validUntil<=asOf))throw pageInvalid();}
 const visibleRows=rows.slice(0,page.limit),nextCursor=rows.length>page.limit?page.next(visibleRows.at(-1)!.index,{asOf,version:chosen.version,publicationHash:chosen.publicationHash,endpointPinsHash}):null;
 await authorized(tx,p,structureId);const selection={...selected,phase:'EFFECTIVE' as const,gaps:[] as const};
 return bounded(r.kind==='reference-hierarchy'?{structure,selection,kind:r.kind,reference:r.reference,multiParent:r.multiParent,items:visibleRows.map(v=>v.value) as typeof r.edges,nextCursor}:{structure,selection,kind:r.kind,source:r.source,target:r.target,cardinality:r.cardinality,overlapPolicy:r.overlapPolicy,items:visibleRows.map(v=>v.value) as typeof r.mappings,nextCursor});
}
async function getStructureAuthoringRead(tx:Tx,p:Principal,structureId:string):Promise<StructureReleaseView>{
 const row=(await structureQuery(tx,()=>sql<{version:number}>`select h.current_version as version from public.reference_structure_heads h where h.tenant_id=${p.tenantId}::uuid and h.id=${structureId}::uuid and public.gc_reference_structure_visible(h.id,${p.id}::uuid)`.execute(tx))).rows[0];await authorized(tx,p,structureId);if(!row)throw unavailable();stored(()=>integer(row.version));return release(tx,p,structureId,row.version);
}
export async function downloadStructureRelease(tx:Tx,p:Principal,structureId:string,version:number,format:'json'|'csv'):Promise<Download>{
 if(format!=='json'&&format!=='csv')throw structureInvalid();const selected=await getStructureRelease(tx,p,structureId,version);const result=serializeBundle(selected.release,format);if(!result.ok||result.value.byteLength>L.downloadBytes)throw integrity();await authorized(tx,p,structureId);return result.value;
}
export async function proposeReferenceStructure(tx:Tx,p:Principal,input:unknown,key:string,correlation:string):Promise<StructureProposalReceipt>{
 const parsed=parseProposal(input,p.id);if(!parsed.ok)throw new Problem(422,'REFERENCE_STRUCTURE_DEFINITION_INVALID','Correct the structure release and review assignments.');
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw structureInvalid();
 // The protected command authorizes retained receipts before NEW head/schedule
 // checks. A retry never reselects a release or bypasses endpoint visibility.
 const raw=(await structureQuery(tx,()=>sql<{value:unknown}>`select public.gc_reference_structure_command('reference.structure.propose',${key},${JSON.stringify(parsed.value)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 return stored(()=>{const a=structureObject(raw,['instance']),instance=structureObject(a.instance,['id']);if(instance.id!==parsed.value.id)throw 0;return {instance:{id:parsed.value.id}};});
}
