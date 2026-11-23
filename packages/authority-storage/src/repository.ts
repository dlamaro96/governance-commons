// SPDX-License-Identifier: Apache-2.0
import {performance} from 'node:perf_hooks';
import {types as utilTypes} from 'node:util';
import {AUTHORITY_ADMISSION_LIMITS as L} from '../../authority/src/admission.ts';
import {canonicalDecisionJSON} from '../../authority/src/decision-schema.ts';
import type {Digest} from '../../authority/src/types.ts';
import {AuthorityFoundationError,type AuthorityFoundationErrorCode,type AuthorityHumanClosure,type ClosureSelectors,type NativeOwnerConnection,type NativeOwnerPool} from './contracts.ts';
import {parseAuthorityHumanClosure,parseClosureSelectors} from './loader.ts';
import {admitted,digest,row,shape,uuid,version} from './shape.ts';
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
/** Fresh native-owner connections only. No database singleton, role switching,
 * retries, reused snapshots, authority decision, or runtime activation. */
export function createAuthorityFoundationRepository(pool:NativeOwnerPool):{loadHumanClosure(input:{sessionHash:Digest;selectors:ClosureSelectors}):Promise<AuthorityHumanClosure>}{
 return Object.freeze({async loadHumanClosure(input:{sessionHash:Digest;selectors:ClosureSelectors}):Promise<AuthorityHumanClosure>{
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
   try{envelope=shape({sessionHash:digest,selectors:v=>v})(admitted(input).data,'') as Record<string,unknown>;}catch{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INPUT_INVALID');}
   const selectors=parseClosureSelectors(envelope.selectors);if(!selectors.ok)throw new AuthorityFoundationError(selectors.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INPUT_INVALID');check();
   // A pool acquisition completing after expiry is destroyed without any SQL.
   const connecting=pool.connect().then(c=>{if(expired){try{c.release(true);}catch{}throw deadlineError();}client=c;return c;});
   client=await Promise.race([connecting,deadline]);check();
   await query("SET statement_timeout = '25s'");await query("SET lock_timeout = '2s'");await query("SET idle_in_transaction_session_timeout = '5s'");
   await query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');inTransaction=true;
   const root=one(await query(rootQuery));if(Object.keys(root).length!==1||root.native_owner!==true)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_EXECUTOR_REJECTED');
   const loaded=one(await query('SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure',[envelope.sessionHash,canonicalDecisionJSON(selectors.value)]));
   if(Object.keys(loaded).length!==1)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const physical=admitted(loaded.closure),closureRow=row(physical.data),snapshot=row(closureRow.snapshot);
   // Read only the strictly scalar registry pin before full graph validation.
   const pin=shape({registryId:uuid,registryVersion:version,registryDigest:digest})({registryId:snapshot.registryId,registryVersion:snapshot.registryVersion,registryDigest:snapshot.registryDigest},'') as Record<string,unknown>;
   const params=[pin.registryId,pin.registryVersion,pin.registryDigest];
   const meta=one(await query(registryMeasureQuery,params));if(Object.keys(meta).sort().join(',')!=='canonical_bytes,json_nodes,raw_bytes')throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const rawBytes=measure(meta.raw_bytes,L.rawBytes),canonicalBytes=measure(meta.canonical_bytes,L.canonicalBytes),nodes=measure(meta.json_nodes,L.jsonNodes);
   if(physical.metrics.canonicalBytes+canonicalBytes>L.canonicalBytes||physical.metrics.canonicalBytes+rawBytes>L.rawBytes||physical.metrics.nodes+nodes>L.jsonNodes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');
   const body=one(await query(registryBodyQuery,params));if(Object.keys(body).length!==1||typeof body.registry_document!=='string'||Buffer.byteLength(body.registry_document)!==rawBytes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const registry=admitted(body.registry_document);if(registry.metrics.canonicalBytes!==canonicalBytes||registry.metrics.nodes!==nodes)throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');
   const parsed=parseAuthorityHumanClosure(physical.data,body.registry_document);if(!parsed.ok)throw new AuthorityFoundationError(parsed.issues.some(i=>i.code==='limit')?'AUTHORITY_FOUNDATION_PROFILE_LIMIT':'AUTHORITY_FOUNDATION_INTEGRITY');
   if(canonicalDecisionJSON(parsed.value.selectors)!==canonicalDecisionJSON(selectors.value.requests))throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');check();
   await query('COMMIT');inTransaction=false;check();release(false);return parsed.value;
  }catch(error){
   const failure=expired||performance.now()-started>=30000?deadlineError():safeError(error);
   if(inTransaction&&!released&&!expired){try{await query('ROLLBACK');}catch{release(true);}}
   release(true);throw failure;
  }finally{clearTimeout(timer);}
 }});
}
