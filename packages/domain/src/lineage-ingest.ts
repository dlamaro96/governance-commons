// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {Problem} from '../../authz/src/index.ts';
import {sql,type Tx} from '../../db/src/index.ts';
import {LINEAGE_GAPS,LINEAGE_LIMITS,type PgViewLineage} from './lineage-contracts.ts';
export interface LineageRecord {externalId:string;type:string;metadata:Record<string,unknown>;parentExternalId?:string|null}
const invalid=()=>new Problem(422,'LINEAGE_INVALID','The source dependency observation is invalid.');
function fail(value:unknown):asserts value{if(!value)throw invalid();}
function object(value:unknown,keys:string[]):asserts value is Record<string,unknown>{
 fail(value&&typeof value==='object'&&!Array.isArray(value));
 fail(Object.keys(value).sort().join('|')===[...keys].sort().join('|'));
}
function oid(value:unknown):value is string{return typeof value==='string'&&/^[1-9]\d{0,9}$/.test(value)&&BigInt(value)<=4294967295n;}
function relation(value:unknown):{database:string;relation:string}{
 fail(typeof value==='string');const parts=value.split(':');fail(parts.length===4&&parts[0]==='pg'&&parts[2]==='relation'&&oid(parts[1])&&oid(parts[3]));
 return {database:parts[1],relation:parts[3]};
}
export function lineageCanonical(value:unknown):string{
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(lineageCanonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+lineageCanonical((value as Record<string,unknown>)[k])).join(',')+'}';
}
export const lineageHash=(value:unknown)=>createHash('sha256').update(lineageCanonical(value)).digest('hex');
/** No older catalog fallback. Every view and endpoint is in this exact successful observation. */
export function validateLineage(value:unknown,records:readonly LineageRecord[],connector:string):PgViewLineage|undefined{
 if(value===undefined)return undefined;
 fail(connector==='postgresql');object(value,['formatVersion','kind','adapterVersion','queryTemplate','views']);
 fail(value.formatVersion===1&&value.kind==='postgresql-view-dependencies'&&value.adapterVersion==='1'&&value.queryTemplate==='postgresql-view-dependencies-v1');
 fail(Array.isArray(value.views)&&value.views.length<=LINEAGE_LIMITS.views&&Buffer.byteLength(JSON.stringify(value))<=LINEAGE_LIMITS.bytes);
 const byId=new Map<string,LineageRecord>(),expected:string[]=[];let database:string|undefined;
 for(const row of records){
  fail(!byId.has(row.externalId));byId.set(row.externalId,row);
  if(row.type==='table'||row.type==='view'){
   const parsed=relation(row.externalId);database??=parsed.database;fail(database===parsed.database&&row.metadata.oid===parsed.relation);
   fail(row.type==='view'?['v','m'].includes(String(row.metadata.relationKind)):['r','p','f'].includes(String(row.metadata.relationKind)));
   if(row.type==='view')expected.push(row.externalId);
  }
 }
 expected.sort();fail(value.views.length===expected.length);
 let edges=0,witnesses=0;const rewriteIds=new Set<string>();
 for(let index=0;index<value.views.length;index++){
  const view=value.views[index];object(view,['viewExternalId','rewriteOid','dependencies','gaps']);
  fail(view.viewExternalId===expected[index]&&oid(view.rewriteOid)&&Array.isArray(view.dependencies)&&Array.isArray(view.gaps));
  fail(!rewriteIds.has(String(view.rewriteOid)));rewriteIds.add(String(view.rewriteOid));
  const gaps=view.gaps;fail(gaps.length<=LINEAGE_GAPS.length&&gaps.every((g,i)=>typeof g==='string'&&(LINEAGE_GAPS as readonly string[]).includes(g)&&(i===0||String(gaps[i-1])<g)));
  let last='';
  for(const dependency of view.dependencies){
   object(dependency,['referencedExternalId','referencedAttributeNumbers']);const ref=dependency.referencedExternalId;
   fail(typeof ref==='string'&&ref>last);last=ref;const parsed=relation(ref),target=byId.get(ref);
   fail(parsed.database===database&&target&&['table','view'].includes(target.type));
   const attributes=dependency.referencedAttributeNumbers;fail(Array.isArray(attributes)&&attributes.length>0);
   fail(attributes.every((n,i)=>Number.isInteger(n)&&n>=0&&n<=32767&&(i===0||attributes[i-1]<n)));
   for(const n of attributes){if(n===0)continue;const column=byId.get(ref+':column:'+n);fail(column?.type==='column'&&column.parentExternalId===ref&&column.metadata.ordinalPosition===n);}
   edges++;witnesses+=attributes.length;fail(edges<=LINEAGE_LIMITS.edges&&witnesses<=LINEAGE_LIMITS.witnesses);
  }
 }
 return value as unknown as PgViewLineage;
}
/** Caller holds the tenant ledger, job and source locks, in that order. */
export async function claimScanGeneration(tx:Tx,job:{id:string;source_id:string;scan_generation:string|null},source:{next_scan_generation:string}):Promise<string>{
 if(job.scan_generation!==null)return job.scan_generation;
 const generation=String(source.next_scan_generation);
 if(!/^[1-9]\d{0,18}$/.test(generation)||BigInt(generation)>=9223372036854775807n)throw new Problem(409,'SCAN_GENERATION_EXHAUSTED','This source cannot accept another scan.');
 await tx.updateTable('sources').set({next_scan_generation:sql`next_scan_generation+1`}).where('id','=',job.source_id).execute();
 await tx.updateTable('jobs').set({scan_generation:generation}).where('id','=',job.id).execute();return generation;
}
export function scanIsSuperseded(generation:string|null,accepted:string):boolean{
 if(generation===null)throw new Problem(409,'SCAN_CLAIM_REQUIRED','Claim this scan before submitting an observation.');
 return BigInt(generation)<BigInt(accepted);
}
export async function storeLineage(tx:Tx,input:{tenantId:string;jobId:string;sourceId:string;generation:string;sourceVersion:string;observedAt:string;lineage:PgViewLineage;assets:Map<string,{id:string;version:number}>}):Promise<void>{
 const {tenantId,jobId,sourceId,generation,sourceVersion,observedAt,lineage,assets}=input;
 await tx.insertInto('lineage_observations').values({tenant_id:tenantId,id:jobId,source_id:sourceId,scan_generation:generation,payload:JSON.stringify(lineage),payload_hash:lineageHash(lineage),source_version:sourceVersion,observed_at:new Date(observedAt)}).execute();
 const edges=[];
 for(const view of lineage.views){
  const downstream=assets.get(view.viewExternalId);fail(downstream);
  for(const dependency of view.dependencies){
   const upstream=assets.get(dependency.referencedExternalId);fail(upstream);
   const evidence={viewExternalId:view.viewExternalId,rewriteOid:view.rewriteOid,...dependency};
   edges.push({tenant_id:tenantId,id:lineageHash({jobId,upstream:upstream.id,downstream:downstream.id}),observation_id:jobId,source_id:sourceId,
    upstream_asset_id:upstream.id,upstream_version:upstream.version,downstream_asset_id:downstream.id,downstream_version:downstream.version,
    referenced_attribute_numbers:dependency.referencedAttributeNumbers,evidence_hash:lineageHash(evidence)});
  }
 }
 for(let i=0;i<edges.length;i+=200)await tx.insertInto('lineage_edge_observations').values(edges.slice(i,i+200)).execute();
}
export async function verifyLineageReplay(tx:Tx,jobId:string,value:PgViewLineage|undefined,provenance:{sourceVersion:string;observedAt:string}):Promise<void>{
 const prior=await tx.selectFrom('lineage_observations').select(['payload_hash','source_version','observed_at']).where('id','=',jobId).executeTakeFirst();
 if((prior?.payload_hash??null)!==(value===undefined?null:lineageHash(value))||(prior&&(prior.source_version!==provenance.sourceVersion||new Date(prior.observed_at).getTime()!==new Date(provenance.observedAt).getTime())))throw new Problem(409,'SCAN_REPLAY_CONFLICT','Completed scan evidence differs from this submission.');
}
