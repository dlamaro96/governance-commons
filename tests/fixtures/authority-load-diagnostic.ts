// SPDX-License-Identifier: Apache-2.0
// Test-only bounded timing observation; never changes SQL, deadlines or outcomes.
import {performance} from 'node:perf_hooks';
import type {NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
export type LoadPhase='connect'|'statement-limit'|'lock-limit'|'idle-limit'|'begin'|'owner-check'|'closure'|'registry-measure'|'registry-body'|'commit'|'rollback'|'unclassified';
export interface LoadObservation {phase:LoadPhase;startedMs:number;elapsedMs:number;outcome:'fulfilled'|'rejected'}
function phase(text:string):LoadPhase{
 if(text==="SET statement_timeout = '25s'")return 'statement-limit';
 if(text==="SET lock_timeout = '2s'")return 'lock-limit';
 if(text==="SET idle_in_transaction_session_timeout = '5s'")return 'idle-limit';
 if(text==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')return 'begin';
 if(text==='COMMIT')return 'commit';if(text==='ROLLBACK')return 'rollback';
 if(text==='SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure')return 'closure';
 if(text.startsWith('SELECT (session_user = current_user AND r.owner_role_oid'))return 'owner-check';
 if(text.startsWith('SELECT octet_length(registry_document)::text AS raw_bytes,'))return 'registry-measure';
 if(text.startsWith('SELECT registry_document FROM gc_authority.registries WHERE'))return 'registry-body';
 return 'unclassified';
}
const ms=(n:number)=>Number.isFinite(n)?Math.max(0,Math.min(3600000,Math.round(n))):3600000;
export function observeOwnerPool(pool:NativeOwnerPool,clock:()=>number=performance.now.bind(performance)){
 const started=clock(),observations:LoadObservation[]=[];
 const observed=async<T>(step:LoadPhase,work:()=>Promise<T>):Promise<T>=>{
  const from=clock();let outcome:'fulfilled'|'rejected'='rejected';
  try{const result=await work();outcome='fulfilled';return result;}
  finally{if(observations.length<32)observations.push({phase:step,startedMs:ms(from-started),elapsedMs:ms(clock()-from),outcome});}
 };
 const wrapped:NativeOwnerPool={async connect(){const client=await observed('connect',()=>pool.connect());return {
  query:(text,values)=>observed(phase(text),()=>client.query(text,values)),
  release:error=>client.release(error),
 };}};
 return {pool:wrapped,snapshot:()=>({elapsedMs:ms(clock()-started),phases:observations.map(row=>({...row}))})};
}
