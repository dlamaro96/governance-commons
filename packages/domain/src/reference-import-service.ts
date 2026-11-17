// SPDX-License-Identifier: Apache-2.0
import {sql, type Tx} from '../../db/src/index.ts';
import {Problem, type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {getReferenceAuthoringContext, referenceInvalid, referenceObject, referenceQuery} from './reference-data-service.ts';
import {parseImportRows, reconcileImport} from './reference-import.ts';
import {IMPORT_LIMITS, type ImportBase, type ImportFormat, type ImportMode, type ImportPreview} from './reference-import-contracts.ts';
import type {ReferenceValue} from './reference-data-contracts.ts';

const uuid=/^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash=/^[a-f0-9]{64}$/;
const actions=['catalog:read','reference:read','reference:write'];
const stale=()=>new Problem(409,'REFERENCE_IMPORT_STALE','The reference set changed. Reload its current version before previewing this import.');
const unavailable=()=>new Problem(404,'REFERENCE_UNAVAILABLE','The reference set or release is unavailable.');
export function importBase(input:unknown):ImportBase {
 const v=referenceObject(input,['setId','expectedVersion','publicationHash']);
 if(typeof v.setId!=='string'||!uuid.test(v.setId)||typeof v.expectedVersion!=='number'||!Number.isInteger(v.expectedVersion)||Object.is(v.expectedVersion,-0)||v.expectedVersion<0||v.expectedVersion>=2147483647)throw referenceInvalid();
 if(v.expectedVersion===0?v.publicationHash!==null:typeof v.publicationHash!=='string'||!hash.test(v.publicationHash))throw referenceInvalid();
 return {setId:v.setId,expectedVersion:v.expectedVersion,publicationHash:v.publicationHash as string|null};
}
async function authorize(tx:Tx,p:Principal){await referenceQuery(tx,()=>modelPersistence.authorize(tx,p,actions));}
async function baseline(tx:Tx,p:Principal,base:ImportBase):Promise<readonly ReferenceValue[]>{
 await authorize(tx,p);
 if(base.expectedVersion===0){
  const exists=(await referenceQuery(tx,()=>sql`select id from public.reference_sets where tenant_id=${p.tenantId}::uuid and id=${base.setId}::uuid`.execute(tx))).rows.length;
  if(exists)throw unavailable();
  return [];
 }
 const current=await getReferenceAuthoringContext(tx,p,base.setId);
 if(current.latestPublishedVersion!==base.expectedVersion||current.publicationHash!==base.publicationHash)throw stale();
 return current.release.values;
}
async function owners(tx:Tx,p:Principal,values:readonly ReferenceValue[]){
 const ids=[...new Set(values.map(v=>v.ownerId))].sort();
 const rows=(await referenceQuery(tx,()=>sql<{id:string}>`select m.identity_id::text as id from public.memberships m join public.identities i on i.id=m.identity_id where m.tenant_id=${p.tenantId}::uuid and m.identity_id=any(${ids}::uuid[]) and m.active and i.active order by m.identity_id`.execute(tx))).rows;
 if(rows.length!==ids.length||rows.some((r,i)=>r.id!==ids[i]))throw new Problem(422,'REFERENCE_IMPORT_OWNER_UNAVAILABLE','Every proposed code owner must be a current member of this tenant.');
}
/** Advisory only. No receipt, audit, canonical row or publication is written.
 * The original bounded transaction is reused for all checks; submission and
 * publication independently enforce their complete current authority. */
export async function previewReferenceImport(tx:Tx,p:Principal,input:unknown,format:ImportFormat,mode:ImportMode,raw:Uint8Array):Promise<ImportPreview>{
 const base=importBase(input);
 if((format!=='json'&&format!=='csv')||(mode!=='merge'&&mode!=='replace'))throw referenceInvalid();
 const before=await baseline(tx,p,base);
 const parsed=parseImportRows(raw,format);
 let result:ImportPreview;
 if(parsed.state==='invalid')result=parsed;
 else {
  result=reconcileImport(base,before,mode,parsed);
  if(result.state==='ready')await owners(tx,p,result.values);
 }
 // Recheck the current authored pin and audience even for invalid previews;
 // changed or revoked authority never returns old values or change counts.
 await baseline(tx,p,base);
 if(result.state==='ready')await owners(tx,p,result.values);
 await authorize(tx,p);
 if(Buffer.byteLength(JSON.stringify(result),'utf8')>IMPORT_LIMITS.responseBytes)throw new Problem(422,'REFERENCE_LIMIT','This reference-data response exceeds its supported bounds.');
 return result;
}
