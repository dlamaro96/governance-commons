// SPDX-License-Identifier: Apache-2.0
import {performance} from 'node:perf_hooks';
import {types as utilTypes} from 'node:util';
import {AUTHORITY_ADMISSION_LIMITS as L} from '../../authority/src/admission.ts';
import {canonicalDecisionJSON,decisionHash,decisionShapes} from '../../authority/src/decision-schema.ts';
import type {Counter,Digest,UUID,Version} from '../../authority/src/types.ts';
import {parseHumanAssetContext,type HumanAssetContext} from '../../authority-runtime/src/asset-context.ts';
import {parseVersionedHumanAssetContext,type VersionedHumanAssetContext} from '../../authority-runtime/src/versioned-asset-context.ts';
import {AuthorityFoundationError,type AuthorityFoundationErrorCode,type AuthorityHumanClosure,type ClosureSelectors,type NativeOwnerConnection,type NativeOwnerPool} from './contracts.ts';
import {parseAuthorityHumanClosure,parseClosureSelectors} from './loader.ts';
import {admitted,digest,row,shape,uuid,version,literal,nullable,counter} from './shape.ts';
export type {NativeOwnerConnection,NativeOwnerPool} from './contracts.ts';
const codes:Record<string,AuthorityFoundationErrorCode>={'22023':'AUTHORITY_FOUNDATION_INPUT_INVALID','42501':'AUTHORITY_FOUNDATION_EXECUTOR_REJECTED','28000':'AUTHORITY_FOUNDATION_SESSION_REJECTED','40001':'AUTHORITY_FOUNDATION_VERSION_CONFLICT','54000':'AUTHORITY_FOUNDATION_PROFILE_LIMIT','23514':'AUTHORITY_FOUNDATION_INTEGRITY','57014':'AUTHORITY_FOUNDATION_DEADLINE','55P03':'AUTHORITY_FOUNDATION_DEADLINE'};
function safeError(e:unknown):AuthorityFoundationError{
 if(e!==null&&typeof e==='object'&&utilTypes.isProxy(e))return new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
 if(e instanceof AuthorityFoundationError)return e;
 if(e!==null&&typeof e==='object'&&!utilTypes.isProxy(e)){const code=Object.getOwnPropertyDescriptor(e,'code');if(code&&'value'in code&&typeof code.value==='string'&&Object.hasOwn(codes,code.value))return new AuthorityFoundationError(codes[code.value]!);}
 return new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
}
function one(result:{rows:unknown[]}):Record<string,unknown>{
 if(!Array.isArray(result.rows)||result.rows.length!==1)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
 const value=result.rows[0];if(value===null||typeof value!=='object'||Array.isArray(value)||utilTypes.isProxy(value))throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
 const keys=Reflect.ownKeys(value);if(keys.length>8)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
 return Object.fromEntries(keys.map(key=>{const d=Object.getOwnPropertyDescriptor(value,key);if(typeof key!=='string'||!d||!('value'in d)||!d.enumerable)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');return [key,d.value];}));
}
const rootQuery=`SELECT (session_user = current_user AND r.owner_role_oid = session_user::regrole::oid
 AND r.owner_role_name = session_user AND r.database_oid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
 AND r.mode = 'inactive' AND current_setting('transaction_isolation') = 'repeatable read'
 AND current_setting('transaction_read_only') = 'on') AS native_owner
 FROM gc_authority.foundation_root r JOIN gc_authn.installation_root a USING (database_oid,owner_role_oid,owner_role_name)
 WHERE r.singleton AND a.singleton`;
const registryMeasureQuery=`SELECT octet_length(registry_document)::text AS raw_bytes,canonical_bytes::text AS canonical_bytes,json_nodes::text AS json_nodes
 FROM gc_authority.registries WHERE id=$1::uuid AND version=$2::integer AND digest=$3::text`;
const registryBodyQuery=`SELECT registry_document FROM gc_authority.registries WHERE id=$1::uuid AND version=$2::integer AND digest=$3::text`;
function measure(v:unknown,max:number):number{if(typeof v!=='string'||!/^[1-9][0-9]{0,18}$/.test(v)||BigInt(v)>BigInt(max))throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');return Number(v);}
type Query=(text:string,values?:unknown[])=>Promise<{rows:unknown[]}>;
type AssetInput={sessionHash:Digest;assetId:UUID;expectedVersion:Version};
type AssetContent=Pick<HumanAssetContext,'asset'|'placement'|'domainPath'|'domainEpoch'|'unavailableFacts'>;
const sessionQuery=`SELECT jsonb_build_object('formatVersion',1,'sessionId',s.session_id,'sessionVersion',s.session_version,
 'identityId',s.identity_id,'tenantId',s.tenant_id,'generation',s.generation::text,'authnFenceEpoch',s.authn_fence_epoch::text,
 'issuingRegistrationId',s.issuing_registration_id,'issuerRegistrationId',s.issuer_registration_id,'identityBindingId',s.identity_binding_id,
 'authenticatedAt',gc_authority.utc(s.authenticated_at),'issuedAt',gc_authority.utc(s.issued_at),'expiresAt',gc_authority.utc(s.expires_at)) AS session
 FROM gc_authn.foundation_session_v1($1::text) s`;
const zeroDigest='0'.repeat(64) as Digest;
function integrity():never{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');}
function optional(result:{rows:unknown[]}):Record<string,unknown>|null{
 if(!Array.isArray(result.rows)||result.rows.length>1)integrity();return result.rows.length?one(result):null;
}
/** Fixed canonical reads only. The native owner/session admission precedes this
 * helper; its output remains inactive provenance, never an effect capability. */
async function assetContent(query:Query,input:AssetInput,session:Record<string,unknown>):Promise<AssetContent>{
 const tenant=uuid(session.tenantId,''),actor=uuid(session.identityId,'');
 await query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,actor]);
 // Legacy assets do not constrain ACL shape or positive versions. Admit scalar
 // size/count before loading the complete ACL; never truncate hidden identities.
 const pre=optional(await query(`SELECT version,status IN ('active','retired','unavailable') AS status_valid,
  visibility IN ('tenant','restricted') AS visibility_valid,jsonb_typeof(allowed_identities) AS acl_type,
  octet_length(allowed_identities::text)::text AS acl_bytes,
  CASE WHEN jsonb_typeof(allowed_identities)='array' THEN jsonb_array_length(allowed_identities)::text ELSE NULL END AS acl_count
  FROM public.assets WHERE tenant_id=$1::uuid AND id=$2::uuid`,[tenant,input.assetId]));
 if(!pre)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_VERSION_CONFLICT');
 version(pre.version,'');
 if(pre.version!==input.expectedVersion)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_VERSION_CONFLICT');
 if(pre.status_valid!==true||pre.visibility_valid!==true||pre.acl_type!=='array')integrity();
 measure(pre.acl_bytes,262144);
 if(typeof pre.acl_count!=='string'||!/^(0|[1-9][0-9]{0,9})$/.test(pre.acl_count)||Number(pre.acl_count)>4096)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');
 const asset=one(await query(`SELECT tenant_id::text AS "tenantId",id::text,version,status,visibility,
  allowed_identities AS "allowedIdentities" FROM public.assets WHERE tenant_id=$1::uuid AND id=$2::uuid`,[tenant,input.assetId]));
 const detached=row(admitted(asset).data);
 if(!Array.isArray(detached.allowedIdentities)||detached.allowedIdentities.length!==Number(pre.acl_count))integrity();
 const identities=detached.allowedIdentities.map(x=>uuid(x,'') as UUID).sort();
 if(new Set(identities).size!==identities.length)integrity();
 const parsedAsset=shape({tenantId:uuid,id:uuid,version,status:literal('active','retired','unavailable'),visibility:literal('tenant','restricted'),allowedIdentities:v=>v})({...detached,allowedIdentities:identities},'') as AssetContent['asset'];
 if(parsedAsset.tenantId!==tenant||parsedAsset.id!==input.assetId||parsedAsset.version!==input.expectedVersion)integrity();
 const rawPlacement=optional(await query(`SELECT version,domain_id::text AS "domainId",recorded_asset_version AS "recordedAssetVersion",
  recorded_domain_version AS "recordedDomainVersion" FROM public.asset_domain_placements WHERE tenant_id=$1::uuid AND asset_id=$2::uuid`,[tenant,input.assetId]));
 const placement=rawPlacement===null?null:shape({version,domainId:nullable(uuid),recordedAssetVersion:version,recordedDomainVersion:nullable(version)})(admitted(rawPlacement).data,'') as AssetContent['placement'];
 const domains:HumanAssetContext['domainPath'][number][]=[],seen=new Set<string>();let next=placement?.domainId??null;
 while(next!==null){
  if(seen.has(next))integrity();
  // SQL011 permits32 total stored nodes. The pure authority DTO's33 entries
  // are not permission to accept a corrupt business-domain hierarchy.
  if(domains.length>=32)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');
  seen.add(next);
  const current=optional(await query(`SELECT id::text,version,parent_id::text AS "parentId",type_id::text AS "typeId",type_version AS "typeVersion",
   CASE WHEN status IN ('active','retired') THEN status ELSE NULL END AS status FROM public.domains WHERE tenant_id=$1::uuid AND id=$2::uuid`,[tenant,next]));
  if(!current)integrity();
  const domain=shape({id:uuid,version,parentId:nullable(uuid),typeId:uuid,typeVersion:version,status:literal('active','retired')})(admitted(current).data,'') as HumanAssetContext['domainPath'][number];
  if(domain.id!==next)integrity();domains.push(domain);next=domain.parentId;
 }
 const epoch=one(await query("SELECT coalesce((SELECT epoch::text FROM public.domain_scope_state WHERE tenant_id=$1::uuid),'0') AS epoch",[tenant]));
 if(epoch.epoch!=='0')counter(epoch.epoch,'');
 if(Object.keys(epoch).length!==1)integrity();
 return {asset:parsedAsset,placement,domainPath:domains,domainEpoch:epoch.epoch as HumanAssetContext['domainEpoch'],unavailableFacts:['classification','approved-tags','purpose','environment']};
}
/** Fresh native-owner connections only. No database singleton, role switching,
 * retries, reused snapshots, authority decision, or runtime activation. */
export function createAuthorityFoundationRepository(pool:NativeOwnerPool):{loadHumanClosure(input:{sessionHash:Digest;selectors:ClosureSelectors}):Promise<AuthorityHumanClosure>;loadHumanAssetContext(input:AssetInput):Promise<HumanAssetContext>;loadVersionedHumanAssetContext(input:AssetInput):Promise<VersionedHumanAssetContext>}{
 async function read(input:unknown,kind:'closure'|'asset'|'versioned-asset'):Promise<AuthorityHumanClosure|HumanAssetContext|VersionedHumanAssetContext>{
  const started=performance.now();let expired=false,client:NativeOwnerConnection|undefined,released=false,inTransaction=false;
  const deadlineError=()=>new AuthorityFoundationError('AUTHORITY_FOUNDATION_DEADLINE');
  const release=(destroy:boolean)=>{if(client&&!released){released=true;try{client.release(destroy);}catch{/* A broken owner connection is never returned as success. */}}};
  let rejectDeadline!:(error:AuthorityFoundationError)=>void;
  const deadline=new Promise<never>((_,reject)=>{rejectDeadline=reject;});
  // Suppress an unhandled rejection while synchronous bounded validation runs.
  void deadline.catch(()=>{});
  const timer=setTimeout(()=>{expired=true;release(true);rejectDeadline(deadlineError());},30000);
  const check=()=>{if(expired||performance.now()-started>=30000){expired=true;release(true);throw deadlineError();}};
  const query=async(text:string,values?:unknown[])=>{check();if(!client||released)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');const pending=client.query(text,values);const result=await Promise.race([pending,deadline]);check();return result;};
  try{
   let envelope:Record<string,unknown>;
   try{envelope=(kind==='closure'?shape({sessionHash:digest,selectors:v=>v}):shape({sessionHash:digest,assetId:uuid,expectedVersion:version}))(admitted(input).data,'') as Record<string,unknown>;}catch{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INPUT_INVALID');}
   let selectors:ClosureSelectors|undefined;
   if(kind==='closure'){const parsed=parseClosureSelectors(envelope.selectors);if(!parsed.ok)throw new AuthorityFoundationError(parsed.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INPUT_INVALID');selectors=parsed.value;}check();
   // A pool acquisition completing after expiry is destroyed without any SQL.
   const connecting=pool.connect().then(c=>{if(expired){try{c.release(true);}catch{}throw deadlineError();}client=c;return c;});
   client=await Promise.race([connecting,deadline]);check();
   await query("SET statement_timeout = '25s'");await query("SET lock_timeout = '2s'");await query("SET idle_in_transaction_session_timeout = '5s'");
   await query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');inTransaction=true;
   const root=one(await query(rootQuery));if(Object.keys(root).length!==1||root.native_owner!==true)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_EXECUTOR_REJECTED');
   let content:AssetContent|undefined,initialSession:Record<string,unknown>|undefined,previousContext:Record<string,unknown>|undefined,securityRevision:Counter|undefined;
   if(kind!=='closure'){
    const sessionResult=one(await query(sessionQuery,[envelope.sessionHash]));if(Object.keys(sessionResult).length!==1)integrity();initialSession=row(admitted(sessionResult.session).data);
    previousContext=one(await query("SELECT current_setting('gc.tenant_id',true) AS tenant,current_setting('gc.actor_id',true) AS actor"));
    if(Object.keys(previousContext).sort().join(',')!=='actor,tenant'||Object.values(previousContext).some(v=>v!==null&&(typeof v!=='string'||Buffer.byteLength(v)>128)))integrity();
    content=await assetContent(query,envelope as AssetInput,initialSession);
    if(kind==='versioned-asset'){
     const head=one(await query('SELECT revision::text FROM gc_authority.content_security_heads WHERE tenant_id=$1::uuid',[content.asset.tenantId]));
     if(Object.keys(head).length!==1)integrity();
     securityRevision=counter(head.revision,'') as Counter;
    }
    selectors={formatVersion:1,requests:[{action:'asset:metadata.read',resource:{tenantId:content.asset.tenantId,kind:'asset',id:content.asset.id},revision:content.asset.version,field:null}]};
   }
   if(!selectors)integrity();
   const loaded=one(await query('SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure',[envelope.sessionHash,canonicalDecisionJSON(selectors)]));
   if(Object.keys(loaded).length!==1)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const physical=admitted(loaded.closure),closureRow=row(physical.data),snapshot=row(closureRow.snapshot);
   // Read only the strictly scalar registry pin before full graph validation.
   const pin=shape({registryId:uuid,registryVersion:version,registryDigest:digest})({registryId:snapshot.registryId,registryVersion:snapshot.registryVersion,registryDigest:snapshot.registryDigest},'') as Record<string,unknown>;
   const params=[pin.registryId,pin.registryVersion,pin.registryDigest];
   const meta=one(await query(registryMeasureQuery,params));if(Object.keys(meta).sort().join(',')!=='canonical_bytes,json_nodes,raw_bytes')throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const rawBytes=measure(meta.raw_bytes,L.rawBytes),canonicalBytes=measure(meta.canonical_bytes,L.canonicalBytes),nodes=measure(meta.json_nodes,L.jsonNodes);
   const retainedContext=content?{formatVersion:1,kind:'inactive-human-asset-context',contentAuthority:false,closure:physical.data,registry:null,...content,contextDigest:zeroDigest}:undefined;
   const retained=retainedContext?admitted(kind==='versioned-asset'?{formatVersion:1,kind:'inactive-versioned-asset-context',contentAuthority:false,context:retainedContext,securityRevision,contextDigest:zeroDigest}:retainedContext):physical;
   if(retained.metrics.canonicalBytes+canonicalBytes>L.canonicalBytes||retained.metrics.canonicalBytes+rawBytes>L.rawBytes||retained.metrics.nodes+nodes>L.jsonNodes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');
   const body=one(await query(registryBodyQuery,params));if(Object.keys(body).length!==1||typeof body.registry_document!=='string'||Buffer.byteLength(body.registry_document)!==rawBytes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const registry=admitted(body.registry_document);if(registry.metrics.canonicalBytes!==canonicalBytes||registry.metrics.nodes!==nodes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const parsed=parseAuthorityHumanClosure(physical.data,body.registry_document);if(!parsed.ok)throw new AuthorityFoundationError(parsed.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INTEGRITY');
   if(canonicalDecisionJSON(parsed.value.selectors)!==canonicalDecisionJSON(selectors.requests))throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');check();
   let result:AuthorityHumanClosure|HumanAssetContext|VersionedHumanAssetContext=parsed.value;
   if(content){
    if(canonicalDecisionJSON(parsed.value.session)!==canonicalDecisionJSON(initialSession))integrity();
    // The registered raw document may retain unsorted sets. The closure parser
    // validates its pin and semantics; expose the canonical registry DTO before
    // hashing the composed envelope, as required by the context parser.
    const canonicalRegistry=decisionShapes.registry(registry.data,'/registry');
    const value={formatVersion:1,kind:'inactive-human-asset-context',contentAuthority:false,closure:parsed.value,registry:canonicalRegistry,...content,contextDigest:zeroDigest};
    // Whole-envelope admission precedes hashing; registry and context cannot
    // each reset the original physical budget.
    admitted(value);value.contextDigest=decisionHash(value);
    const context=parseHumanAssetContext(value);if(!context.ok)throw new AuthorityFoundationError(context.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INTEGRITY');
    result=context.value;
    if(kind==='versioned-asset'){
     const wrapped={formatVersion:1,kind:'inactive-versioned-asset-context',contentAuthority:false,context:context.value,securityRevision,contextDigest:zeroDigest};
     admitted(wrapped);wrapped.contextDigest=decisionHash(wrapped);
     const versioned=parseVersionedHumanAssetContext(wrapped);if(!versioned.ok)throw new AuthorityFoundationError(versioned.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INTEGRITY');
     result=versioned.value;
    }
    await query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[previousContext!.tenant??'',previousContext!.actor??'']);
   }
   await query('COMMIT');inTransaction=false;check();release(false);return result;
  }catch(error){
   const failure=expired||performance.now()-started>=30000?deadlineError():safeError(error);
   if(inTransaction&&!released&&!expired){try{await query('ROLLBACK');}catch{release(true);}}
   release(true);throw failure;
  }finally{clearTimeout(timer);}
 }
 return Object.freeze({loadHumanClosure:(input:{sessionHash:Digest;selectors:ClosureSelectors})=>read(input,'closure') as Promise<AuthorityHumanClosure>,loadHumanAssetContext:(input:AssetInput)=>read(input,'asset') as Promise<HumanAssetContext>,loadVersionedHumanAssetContext:(input:AssetInput)=>read(input,'versioned-asset') as Promise<VersionedHumanAssetContext>});
}
