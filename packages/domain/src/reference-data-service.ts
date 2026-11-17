// SPDX-License-Identifier: Apache-2.0
/** Governed code-list reads and proposal commands. SQL owns publication,
 * current authority, lock ordering and retained command receipts. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {sql,type Tx} from '../../db/src/index.ts';
import type {RawBuilder} from 'kysely';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {parseProposal,parsePublishedBundle,publicationHash,serializeBundle,parsePublicationResult} from './reference-data.ts';
import {LIMITS,type Audience,type Download,type Labels,type PublicationResult,type ReferenceAuthoringContext,type ReferenceEffectiveQuery,type ReferenceEffectiveState,type ReferenceEffectiveView,type ReferencePage,type ReferencePageQuery,type ReferenceProposalReceipt,type ReferenceReleaseSummary,type ReferenceReleaseView,type ReferenceSetQuery,type ReferenceSetSummary,type ReferenceValue} from './reference-data-contracts.ts';

const uuid=/^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash=/^[a-f0-9]{64}$/;
const code=/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export const referenceInvalid=()=>new Problem(400,'REFERENCE_INPUT_INVALID','Provide exactly the declared reference-data fields and values.');
const unavailable=()=>new Problem(404,'REFERENCE_UNAVAILABLE','The reference set or release is unavailable.');
const integrity=()=>new Problem(500,'REFERENCE_STORAGE_INVALID','The reference-data operation could not be verified.');
const retry=()=>new Problem(503,'REFERENCE_RETRY','A stable execution window was unavailable. Retry with the same idempotency key.');
const pageInvalid=()=>new Problem(400,'REFERENCE_PAGE_INVALID','This reference-data page is invalid. Start a new listing.');
const deadlines=new WeakMap<Tx,number>();
export async function referenceQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let end=deadlines.get(tx);if(end===undefined){end=performance.now()+30000;deadlines.set(tx,end);}
 const remaining=Math.floor(end-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(remaining)},true),set_config('lock_timeout',${String(Math.min(5000,remaining))},true)`.execute(tx);
 const result=await work();if(performance.now()>=end)throw retry();return result;
}
export function referenceFailure(error:unknown):Problem{
 if(error instanceof Problem)return error;
 const e=error as {code?:unknown;message?:unknown}|null,c=e?.code,m=e?.message;
 if(['55P03','40P01','57014'].includes(String(c)))return retry();
 if(c==='P0002'&&m==='reference resource not found')return unavailable();
 if(c==='42501'&&(m==='reference forbidden'||m==='Current membership does not permit this relation operation'||m==='Asserted relations require an authenticated member'))return new Problem(403,'REFERENCE_FORBIDDEN','Your current permissions do not allow this reference-data operation.');
 if(c==='40001'){
  const codes:Record<string,string>={'reference version conflict':'VERSION_CONFLICT','reference schedule stale':'REFERENCE_SCHEDULE_STALE','IDEMPOTENCY_CONFLICT':'IDEMPOTENCY_CONFLICT','WORKFLOW_PIN_STALE':'WORKFLOW_PIN_STALE'};
  return typeof m==='string'&&Object.hasOwn(codes,m)?new Problem(409,codes[m],'The reference-data state changed. Reload before continuing.'):retry();
 }
 if(c==='22023'&&m==='reference request invalid')return new Problem(422,'REFERENCE_DEFINITION_INVALID','Correct the reference release and review assignments.');
 if(c==='54000'&&m==='reference limit')return new Problem(422,'REFERENCE_LIMIT','This reference-data operation exceeds its supported bounds.');
 return integrity();
}
/** No accessors, symbols, custom prototypes or proxy reflection at the service boundary. */
export function referenceObject(input:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 try{
  if(!input||typeof input!=='object'||types.isProxy(input)||Array.isArray(input)||![null,Object.prototype].includes(Object.getPrototypeOf(input)))throw 0;
  const keys=Reflect.ownKeys(input);if(keys.length>required.length+optional.length||required.some(k=>!keys.includes(k)))throw 0;
  return Object.fromEntries(keys.map(k=>{if(typeof k!=='string'||![...required,...optional].includes(k))throw 0;const d=Object.getOwnPropertyDescriptor(input,k);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;return [k,d.value];}));
 }catch{throw referenceInvalid();}
}
function id(v:unknown):asserts v is string{if(typeof v!=='string'||!uuid.test(v))throw referenceInvalid();}
function integer(v:unknown,min:number=1,max:number=LIMITS.version):asserts v is number{if(typeof v!=='number'||!Number.isInteger(v)||Object.is(v,-0)||v<min||v>max)throw referenceInvalid();}
function stamp(v:unknown):asserts v is string{if(typeof v!=='string'||v.startsWith('0000')||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)throw referenceInvalid();}
function digest(v:unknown):asserts v is string{if(typeof v!=='string'||!hash.test(v))throw referenceInvalid();}
function stored<T>(work:()=>T):T{try{return work();}catch{throw integrity();}}
function bounded<T>(v:T):T{if(Buffer.byteLength(JSON.stringify(v))>1048576)throw new Problem(422,'REFERENCE_LIMIT','This reference-data response exceeds its supported bounds.');return v;}
function normalizedText(v:unknown,max:number,multiline=false):asserts v is string{
 if(typeof v!=='string'||!v.length||v.length>max||malformed.test(v)||v!==v.normalize('NFC').trim()||(multiline?/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/:/[\u0000-\u001f\u007f-\u009f]/).test(v))throw referenceInvalid();
}
function labels(input:unknown):Labels{
 const x=referenceObject(input,['en','ar']);return Object.fromEntries(['en','ar'].map(locale=>{const v=referenceObject(x[locale],['label','description']);normalizedText(v.label,LIMITS.label);normalizedText(v.description,LIMITS.description,true);return [locale,v];})) as unknown as Labels;
}
function summary(input:unknown):ReferenceReleaseSummary{
 const v=referenceObject(input,['setId','version','labels','ownerId','status','publishedAt','effectiveFrom','validUntil','publicationHash','valueCount']);
 id(v.setId);id(v.ownerId);integer(v.version);integer(v.valueCount,1,LIMITS.values);digest(v.publicationHash);stamp(v.publishedAt);stamp(v.effectiveFrom);
 if(v.validUntil!==null)stamp(v.validUntil);if((v.status!=='active'&&v.status!=='deprecated')||v.effectiveFrom<v.publishedAt||v.validUntil!==null&&v.validUntil<=v.effectiveFrom)throw referenceInvalid();
 return {...v,labels:labels(v.labels)} as unknown as ReferenceReleaseSummary;
}
function state(input:unknown):ReferenceEffectiveState{
 const v=referenceObject(input,['asOf','phase','version','publicationHash','effectiveFrom','effectiveUntil']);stamp(v.asOf);
 if(v.phase==='NOT_EFFECTIVE'){if([v.version,v.publicationHash,v.effectiveFrom,v.effectiveUntil].some(x=>x!==null))throw referenceInvalid();}
 else{if((v.phase!=='EFFECTIVE'&&v.phase!=='DEPRECATED'&&v.phase!=='EXPIRED'))throw referenceInvalid();integer(v.version);digest(v.publicationHash);stamp(v.effectiveFrom);if(v.effectiveUntil!==null)stamp(v.effectiveUntil);
  if(v.effectiveFrom>v.asOf||v.effectiveUntil!==null&&v.effectiveUntil<=v.effectiveFrom||(v.phase==='EXPIRED')!==(v.effectiveUntil!==null&&v.effectiveUntil<=v.asOf))throw referenceInvalid();}
 return v as unknown as ReferenceEffectiveState;
}
function setSummary(input:unknown):ReferenceSetSummary{
 const v=referenceObject(input,['id','latest','effective']);id(v.id);const latest=summary(v.latest),effective=state(v.effective);if(latest.setId!==v.id||effective.version!==null&&effective.version>latest.version)throw referenceInvalid();return {id:v.id,latest,effective};
}
export function parseReferencePublicationResult(input:unknown):PublicationResult{
 const result=parsePublicationResult(input);if(!result.ok)throw referenceInvalid();return result.value;
}
const actions=['catalog:read','reference:read'];
async function authorize(tx:Tx,p:Principal,write=false){await referenceQuery(tx,()=>modelPersistence.authorize(tx,p,write?[...actions,'reference:write']:actions));}
async function visible(tx:Tx,p:Principal,setId:string){
 const row=(await referenceQuery(tx,()=>sql`select s.id from public.reference_sets s where s.tenant_id=${p.tenantId}::uuid and s.id=${setId}::uuid and public.gc_reference_visible(s.id,${p.id}::uuid)`.execute(tx))).rows[0];if(!row)throw unavailable();
}
async function clock(tx:Tx):Promise<string>{
 const value=(await referenceQuery(tx,()=>sql<{value:unknown}>`select public.gc_relation_utc(clock_timestamp()) as value`.execute(tx))).rows[0]?.value;return stored(()=>{stamp(value);return value;});
}
function paging(p:Principal,kind:string,setId:string|null,input:unknown,extra:readonly string[]=[]){
 const q=referenceObject(input,[],['limit','cursor',...extra]),limit=q.limit??25;integer(limit,1,100);
 const term=q.q===undefined?'':q.q; if(typeof term!=='string'||term.length>200||malformed.test(term)||/[\u0000-\u001f\u007f-\u009f]/.test(term))throw referenceInvalid();const normalized=term.normalize('NFC').trim();
 if(q.asOf!==undefined)stamp(q.asOf);
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,kind,setId,limit,normalized,q.asOf??null])).digest('hex');
 const codec=signedCursor(process.env.SESSION_KEY,'reference-data-'+kind+'-v1');let cursor:unknown[]|null=null;
 if(q.cursor!==undefined)try{if(typeof q.cursor!=='string'||!q.cursor||q.cursor.length>1024)throw 0;const raw=codec.decode(q.cursor);if(!Array.isArray(raw)||raw.length!==4||raw[0]!==1||raw[1]!==binding)throw 0;cursor=raw;}catch{throw pageInvalid();}
 return {limit,q:normalized,asOf:q.asOf as string|undefined,cursor,next:(last:unknown,pin:unknown)=>codec.encode([1,binding,last,pin])};
}
function summarySQL(alias:'r'|'latest'):RawBuilder<unknown>{const a=sql.ref(alias);return sql`jsonb_build_object('setId',${a}.set_id,'version',${a}.version,'labels',${a}.published_bundle->'labels','ownerId',${a}.owner_id,'status',${a}.status,'publishedAt',public.gc_relation_utc(${a}.published_at),'effectiveFrom',public.gc_relation_utc(${a}.effective_from),'validUntil',case when ${a}.valid_until is null then null else public.gc_relation_utc(${a}.valid_until) end,'publicationHash',${a}.publication_hash,'valueCount',jsonb_array_length(${a}.published_bundle->'values'))`;}
function effectiveSQL(asOf:string):RawBuilder<unknown>{return sql`jsonb_build_object('asOf',${asOf}::text,'phase',case when chosen.version is null then 'NOT_EFFECTIVE' when chosen.valid_until<=${asOf}::timestamptz then 'EXPIRED' when chosen.status='deprecated' then 'DEPRECATED' else 'EFFECTIVE' end,'version',chosen.version,'publicationHash',chosen.publication_hash,'effectiveFrom',case when chosen.effective_from is null then null else public.gc_relation_utc(chosen.effective_from) end,'effectiveUntil',case when least(chosen.valid_until,successor.effective_from) is null then null else public.gc_relation_utc(least(chosen.valid_until,successor.effective_from)) end)`;}
function effectiveJoins(asOf:string){return sql`left join lateral (select e.version,e.publication_hash,e.effective_from,e.valid_until,e.status from public.reference_releases e where e.tenant_id=s.tenant_id and e.set_id=s.id and e.published_at<=${asOf}::timestamptz and e.effective_from<=${asOf}::timestamptz order by e.effective_from desc,e.version desc limit 1) chosen on true left join lateral (select n.effective_from from public.reference_releases n where n.tenant_id=s.tenant_id and n.set_id=s.id and n.version>chosen.version and n.published_at<=${asOf}::timestamptz order by n.version limit 1) successor on true`;}
async function setAt(tx:Tx,p:Principal,setId:string,asOf:string):Promise<ReferenceSetSummary>{
 const value=(await referenceQuery(tx,()=>sql<{value:unknown}>`select jsonb_build_object('id',s.id,'latest',${summarySQL('latest')},'effective',${effectiveSQL(asOf)}) as value from public.reference_sets s join public.reference_releases latest on latest.tenant_id=s.tenant_id and latest.set_id=s.id and latest.version=s.current_version ${effectiveJoins(asOf)} where s.tenant_id=${p.tenantId}::uuid and s.id=${setId}::uuid and public.gc_reference_visible(s.id,${p.id}::uuid)`.execute(tx))).rows[0]?.value;
 if(value===undefined)throw unavailable();return stored(()=>setSummary(value));
}
export async function listReferenceSets(tx:Tx,p:Principal,query:ReferenceSetQuery={}):Promise<ReferencePage<ReferenceSetSummary>>{
 const page=paging(p,'sets',null,query,['q']);let after:string|null=null,asOf:string|undefined;
 if(page.cursor)try{id(page.cursor[2]);stamp(page.cursor[3]);after=page.cursor[2];asOf=page.cursor[3];}catch{throw pageInvalid();}
 await authorize(tx,p);const now=await clock(tx);asOf=asOf??now;if(asOf>now)throw pageInvalid();
 const search='%'+page.q.replaceAll('\\','\\\\').replaceAll('%','\\%').replaceAll('_','\\_')+'%';
 const rows=(await referenceQuery(tx,()=>sql<{value:unknown}>`select jsonb_build_object('id',s.id,'latest',${summarySQL('latest')},'effective',${effectiveSQL(asOf)}) as value from public.reference_sets s join public.reference_releases latest on latest.tenant_id=s.tenant_id and latest.set_id=s.id and latest.version=s.current_version ${effectiveJoins(asOf)} where s.tenant_id=${p.tenantId}::uuid and public.gc_reference_visible(s.id,${p.id}::uuid) and ${after===null?sql`true`:sql`s.id>${after}::uuid`} and ${page.q?sql`(latest.published_bundle#>>'{labels,en,label}' ilike ${search} escape '\\' or latest.published_bundle#>>'{labels,ar,label}' ilike ${search} escape '\\')`:sql`true`} order by s.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>stored(()=>setSummary(r.value)));await authorize(tx,p);
 return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.id,asOf):null});
}
export async function listReferenceReleases(tx:Tx,p:Principal,setId:string,query:ReferencePageQuery={}):Promise<ReferencePage<ReferenceReleaseSummary>>{
 id(setId);const page=paging(p,'releases',setId,query);let after=0;if(page.cursor)try{integer(page.cursor[2]);if(page.cursor[3]!==null)throw 0;after=page.cursor[2];}catch{throw pageInvalid();}
 await authorize(tx,p);await visible(tx,p,setId);
 const rows=(await referenceQuery(tx,()=>sql<{value:unknown}>`select ${summarySQL('r')} as value from public.reference_releases r where r.tenant_id=${p.tenantId}::uuid and r.set_id=${setId}::uuid and r.version>${after} order by r.version limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>stored(()=>summary(r.value)));if(items.some(r=>r.setId!==setId))throw integrity();await authorize(tx,p);await visible(tx,p,setId);
 return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.version,null):null});
}
async function release(tx:Tx,p:Principal,setId:string,version:number):Promise<ReferenceReleaseView>{
 const metadata=(await referenceQuery(tx,()=>sql<{body_bytes:number;publication_hash:string}>`select octet_length(r.published_bundle::text) as body_bytes,r.publication_hash from public.reference_releases r where r.tenant_id=${p.tenantId}::uuid and r.set_id=${setId}::uuid and r.version=${version}`.execute(tx))).rows[0];
 if(!metadata)throw unavailable();if(!Number.isInteger(metadata.body_bytes)||metadata.body_bytes<1||metadata.body_bytes>524288||!hash.test(metadata.publication_hash))throw integrity();
 const raw=(await referenceQuery(tx,()=>sql<{value:unknown}>`select r.published_bundle as value from public.reference_releases r where r.tenant_id=${p.tenantId}::uuid and r.set_id=${setId}::uuid and r.version=${version}`.execute(tx))).rows[0]?.value;
 return stored(()=>{const parsed=parsePublishedBundle(raw);if(!parsed.ok||parsed.value.setId!==setId||parsed.value.version!==version)throw 0;const hash=publicationHash(parsed.value);if(!hash.ok||hash.value!==metadata.publication_hash)throw 0;return {release:parsed.value,publicationHash:hash.value};});
}
export async function getReferenceRelease(tx:Tx,p:Principal,setId:string,version:number):Promise<ReferenceReleaseView>{
 id(setId);integer(version);await authorize(tx,p);await visible(tx,p,setId);const value=await release(tx,p,setId,version);await authorize(tx,p);await visible(tx,p,setId);return value;
}
export async function getReferenceAuthoringContext(tx:Tx,p:Principal,setId:string):Promise<ReferenceAuthoringContext>{
 id(setId);await authorize(tx,p,true);await visible(tx,p,setId);
 const row=(await referenceQuery(tx,()=>sql<{version:number;audience:unknown}>`select s.current_version as version,jsonb_build_object('visibility',s.visibility,'allowedIdentityIds',s.allowed_identities) as audience from public.reference_sets s where s.tenant_id=${p.tenantId}::uuid and s.id=${setId}::uuid and public.gc_reference_visible(s.id,${p.id}::uuid)`.execute(tx))).rows[0];if(!row)throw unavailable();
 const audience=stored(()=>{integer(row.version);const a=referenceObject(row.audience,['visibility','allowedIdentityIds']);if((a.visibility!=='tenant'&&a.visibility!=='restricted')||!Array.isArray(a.allowedIdentityIds)||a.allowedIdentityIds.length>LIMITS.principals)throw 0;
  let previous='';for(const member of a.allowedIdentityIds){id(member);if(member<=previous)throw 0;previous=member;}if((a.visibility==='tenant')!==(a.allowedIdentityIds.length===0))throw 0;return a as unknown as Audience;});
 const selected=await release(tx,p,setId,row.version);await authorize(tx,p,true);await visible(tx,p,setId);return {...selected,setId,latestPublishedVersion:row.version,audience};
}
export async function getReferenceEffective(tx:Tx,p:Principal,setId:string,query:ReferenceEffectiveQuery={}):Promise<ReferenceEffectiveView>{
 id(setId);const page=paging(p,'effective',setId,query,['asOf']);let after:string|null=null,pin:{asOf:string;version:number;publicationHash:string}|null=null;
 if(page.cursor)try{if(typeof page.cursor[2]!=='string'||!code.test(page.cursor[2]))throw 0;after=page.cursor[2];const v=referenceObject(page.cursor[3],['asOf','version','publicationHash']);stamp(v.asOf);integer(v.version);digest(v.publicationHash);if(page.asOf!==undefined&&page.asOf!==v.asOf)throw 0;pin=v as {asOf:string;version:number;publicationHash:string};}catch{throw pageInvalid();}
 await authorize(tx,p);await visible(tx,p,setId);const now=await clock(tx),asOf=pin?.asOf??page.asOf??now;if(asOf>now)throw referenceInvalid();
 const set=await setAt(tx,p,setId,asOf),selection=set.effective;
 if(pin&&(pin.version!==selection.version||pin.publicationHash!==selection.publicationHash))throw pageInvalid();
 if(selection.phase==='NOT_EFFECTIVE'||selection.phase==='EXPIRED'){if(pin)throw pageInvalid();await authorize(tx,p);await visible(tx,p,setId);return {set,selection,items:[],nextCursor:null};}
 // The immutable full bundle is capped independently. Value pagination never
 // loads history and never interprets a scheduled/new head as this selected pin.
 const selected=await release(tx,p,setId,selection.version!);if(selected.publicationHash!==selection.publicationHash)throw integrity();
 const candidates=selected.release.values.filter(v=>(v.validFrom===null||v.validFrom<=asOf)&&(v.validUntil===null||asOf<v.validUntil)&&(after===null||v.code>after));
 const items=candidates.slice(0,page.limit);await authorize(tx,p);await visible(tx,p,setId);
 return bounded({set,selection,items,nextCursor:candidates.length>page.limit?page.next(items.at(-1)!.code,{asOf,version:selection.version,publicationHash:selection.publicationHash}):null});
}
export async function downloadReferenceRelease(tx:Tx,p:Principal,setId:string,version:number,format:'json'|'csv'):Promise<Download>{
 if(format!=='json'&&format!=='csv')throw referenceInvalid();const selected=await getReferenceRelease(tx,p,setId,version);const result=serializeBundle(selected.release,format);if(!result.ok)throw integrity();return result.value;
}
export async function proposeReferenceRelease(tx:Tx,p:Principal,input:unknown,key:string,correlation:string):Promise<ReferenceProposalReceipt>{
 const parsed=parseProposal(input,p.id);if(!parsed.ok)throw new Problem(422,'REFERENCE_DEFINITION_INVALID','Correct the reference release and review assignments.',parsed.issues);
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw referenceInvalid();
 await authorize(tx,p,true);
 // Do not pre-reject current head/schedule drift here: the protected command
 // authenticates first and resolves a retained exact receipt before NEW checks.
 const raw=(await referenceQuery(tx,()=>sql<{value:unknown}>`select public.gc_reference_command('reference.propose',${key},${JSON.stringify(parsed.value)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 return stored(()=>{const v=referenceObject(raw,['instance']),instance=referenceObject(v.instance,['id']);if(instance.id!==parsed.value.id)throw 0;return {instance:{id:parsed.value.id}};});
}
