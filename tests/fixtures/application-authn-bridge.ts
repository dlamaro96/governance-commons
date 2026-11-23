// SPDX-License-Identifier: Apache-2.0
/** Real native PostgreSQL bridge fixtures. Requires the isolated authn harness;
 * it never selects a shared database or impersonates an application connection. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {TestContext} from 'node:test';
import type pg from 'pg';
import {parseApplicationBridgeManifest,type ApplicationBridgeManifest} from '../../packages/authn/src/application-installation.ts';
import {fixture,config,connect,query,scalar,tx,uuid,iso,type Fixture,type Row} from './authority-authn-foundation.ts';

export const bridgeSQL='SELECT * FROM public.gc_app_protected_session_v1($1,$2)';
export type BridgeOperation='application-bridge-install'|'application-bridge-revoke';
export interface BridgeRequest {operation:BridgeOperation;sql:string;values:unknown[]}
export interface BridgeEntry extends BridgeRequest {row:Row}
export interface BridgeFixture extends Fixture {activeBridge?:BridgeEntry}
const commonFields=['request_id','release_ref','operator_ref','expected_db_oid','expected_owner_oid','predecessor_hash'];
const commonKinds=['U','S','S','I','I','S'];
const shapes={
 'application-bridge-install':{function:'install_application_bridge_v1',fields:['bridge_id','expected_app_oid','api_registration_id','bridge_generation','authn_generation','expires_at'],kinds:['U','I','U','I','I','T']},
 'application-bridge-revoke':{function:'revoke_application_bridge_v1',fields:['bridge_id','expected_manifest_hash'],kinds:['U','S']},
} as const;
const stringScalar=(value:string)=>`S${Buffer.byteLength(value,'utf8')}:${value}`;
/** Independent bytes: no call to gc_authn.scalar/field or the product codec. */
export function bridgeEncoding(request:BridgeRequest):Buffer{
 const shape=shapes[request.operation],fields=[...commonFields,...shape.fields],kinds=[...commonKinds,...shape.kinds];
 assert.equal(request.values.length,fields.length);
 let text='gc-app-authn-install/v1;'+stringScalar(request.operation);
 fields.forEach((field,index)=>{const value=request.values[index];text+=stringScalar(field);text+=value===null?'N;':kinds[index]==='U'?`U${value};`:kinds[index]==='I'?`I${value};`:kinds[index]==='T'?`T${iso(value)};`:stringScalar(String(value));});
 return Buffer.from(text,'utf8');
}
export function bridgeManifest(request:BridgeRequest):ApplicationBridgeManifest {
 const v=request.values;
 const operation=request.operation==='application-bridge-install'
  ?{type:request.operation,bridgeId:v[6],expectedAppRoleOid:v[7],apiRegistrationId:v[8],bridgeGeneration:v[9],authenticationGeneration:v[10],expiresAt:iso(v[11])}
  :{type:request.operation,bridgeId:v[6],expectedManifestHash:v[7]};
 const parsed=parseApplicationBridgeManifest({formatVersion:1,requestId:v[0],releaseReference:v[1],deploymentOperatorReference:v[2],expectedDatabaseOid:v[3],expectedOwnerRoleOid:v[4],predecessorManifestHash:v[5],operation});
 assert.ok(parsed.ok);return parsed.value;
}
export async function bridgeState(owner:pg.Client):Promise<Row>{
 return scalar(owner,`SELECT
 (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY sequence),'[]'::jsonb) FROM gc_authn.application_bridge_receipts r) receipts,
 (SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY bridge_generation),'[]'::jsonb) FROM gc_authn.application_bridge_installations b) installations`);
}
export async function bridgeChain(owner:pg.Client):Promise<{predecessor:string|null;generation:number}>{
 const row=await scalar(owner,`SELECT
 (SELECT manifest_hash FROM gc_authn.application_bridge_receipts ORDER BY sequence DESC LIMIT 1) predecessor,
 (SELECT coalesce(max(bridge_generation),0)::int+1 FROM gc_authn.application_bridge_installations) generation`);
 return {predecessor:row.predecessor as string|null,generation:Number(row.generation)};
}
async function request(owner:pg.Client,operation:BridgeOperation,args:unknown[],options:{requestId?:string;predecessor?:string|null}={}):Promise<BridgeRequest>{
 const identity=await scalar(owner,`SELECT (SELECT oid::int8 FROM pg_database WHERE datname=current_database()) db,(SELECT oid::int8 FROM pg_roles WHERE rolname=session_user) owner`);
 const chain=await bridgeChain(owner),values=[options.requestId??uuid(),'synthetic-bridge-release','synthetic-bridge-operator',Number(identity.db),Number(identity.owner),options.predecessor===undefined?chain.predecessor:options.predecessor,...args];
 return {operation,values,sql:`SELECT * FROM gc_authn.${shapes[operation].function}(${values.map((_,i)=>'$'+(i+1)).join(',')})`};
}
export async function prepareBridge(f:Fixture,options:{bridgeId?:string;appOid?:number;apiId?:string;generation?:number;authnGeneration?:number;expiresAt?:string;requestId?:string;predecessor?:string|null}={}):Promise<BridgeRequest>{
 const chain=await bridgeChain(f.owner),app=await scalar(f.legacy,'SELECT session_user::text original,current_user::text effective,session_user::regrole::oid::int8 oid');
 assert.equal(app.original,'gc_app');assert.equal(app.effective,'gc_app');
 return request(f.owner,'application-bridge-install',[options.bridgeId??uuid(),options.appOid??Number(app.oid),options.apiId??f.apiId,options.generation??chain.generation,options.authnGeneration??1,options.expiresAt??f.expiry],options);
}
export async function prepareRevoke(owner:pg.Client,entry:BridgeEntry,options:{requestId?:string;predecessor?:string|null}={}):Promise<BridgeRequest>{
 return request(owner,'application-bridge-revoke',[entry.row.target_id,entry.row.manifest_hash],options);
}
export async function verifyBridgeReceipt(owner:pg.Client,entry:BridgeEntry):Promise<void>{
 const encoding=bridgeEncoding(entry),hash=createHash('sha256').update(encoding).digest('hex');
 assert.deepEqual(Object.keys(entry.row).sort(),['installation_id','manifest_hash','target_id','recorded_at'].sort());
 assert.equal(entry.row.target_id,entry.values[6]);assert.equal(entry.row.manifest_hash,hash);
 const saved=await scalar(owner,'SELECT * FROM gc_authn.application_bridge_receipts WHERE id=$1',[entry.row.installation_id]);
 assert.ok(Buffer.isBuffer(saved.manifest_encoding)&&saved.manifest_encoding.equals(encoding),'Retained independent bridge receipt bytes differ');
 assert.equal(saved.request_id,entry.values[0]);assert.equal(saved.operation,entry.operation);assert.equal(saved.target_id,entry.row.target_id);
 assert.equal(saved.manifest_hash,hash);assert.equal(saved.predecessor_hash,entry.values[5]);assert.equal(saved.release_reference,entry.values[1]);assert.equal(saved.operator_reference,entry.values[2]);
 assert.equal(Number(saved.database_oid),entry.values[3]);assert.equal(Number(saved.owner_role_oid),entry.values[4]);assert.equal(iso(saved.recorded_at),iso(entry.row.recorded_at));
}
export async function installBridge(f:BridgeFixture,prepared?:BridgeRequest):Promise<BridgeEntry>{
 const requested=prepared??await prepareBridge(f),entry={...requested,row:await scalar(f.owner,requested.sql,requested.values)};
 // Track the owned effect before assertion work, so a failed codec assertion
 // cannot leave a live global bridge for a subsequent test.
 f.activeBridge=entry;await verifyBridgeReceipt(f.owner,entry);return entry;
}
export async function revokeBridge(f:BridgeFixture,client:pg.Client=f.owner):Promise<BridgeEntry>{
 assert.ok(f.activeBridge,'No fixture-owned bridge to revoke');const requested=await prepareRevoke(client,f.activeBridge);
 const entry={...requested,row:await scalar(client,requested.sql,requested.values)};f.activeBridge=undefined;await verifyBridgeReceipt(client,entry);return entry;
}
export async function bridgeFixture(t:TestContext,options:{install?:boolean;expiryMs?:number}={}):Promise<BridgeFixture>{
 const f:BridgeFixture=await fixture(t,{expiryMs:options.expiryMs});
 t.after(async()=>{
  if(!f.activeBridge)return;
  // Original fixture connections have their own teardown. This cleanup uses a
  // fresh native owner and works independently of hook execution order.
  const cleanup=await connect(config.owner);
  try{await revokeBridge(f,cleanup);}finally{await cleanup.end();}
 });
 if(options.install!==false)await installBridge(f);return f;
}
export async function applicationSession(client:pg.Client,hash:unknown,csrf:unknown=null):Promise<Row>{
 return tx(client,()=>scalar(client,bridgeSQL,[hash,csrf]),'REPEATABLE READ READ ONLY');
}
export async function denyRequest(owner:pg.Client,request:BridgeRequest,predicate:(error:unknown)=>boolean):Promise<void>{
 await query(owner,'BEGIN');
 try{await assert.rejects(query(owner,request.sql,request.values),predicate);}finally{await query(owner,'ROLLBACK');}
}
