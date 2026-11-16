// SPDX-License-Identifier: Apache-2.0
/** Isolated, synthetic PostgreSQL authentication fixtures. No core URLs, bearer
 * material, SET ROLE impersonation, or privilege assertions through the owner. */
import assert from 'node:assert/strict';
import {randomBytes, randomUUID, createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {TestContext} from 'node:test';
import pg from 'pg';

export type Row = Record<string, any>;
export interface Role {name:string; url:string}
interface Slot {login:Role; api:Role; nextLogin:Role; nextApi:Role}
interface Config {owner:string; admin:string; legacy:string; unregistered:Role; slots:Slot[]; suiteOffset:number}
const configPath=process.env.AUTHN_FOUNDATION_CONFIG;
if(!configPath)throw Error('AUTHN_FOUNDATION_CONFIG is required; no shared runtime fallback');
export const config=JSON.parse(readFileSync(configPath,'utf8')) as Config;
assert.ok(config.slots.length>=48 && Number.isSafeInteger(config.suiteOffset));
for(const role of [config.unregistered,...config.slots.flatMap(slot=>[slot.login,slot.api,slot.nextLogin,slot.nextApi])])assert.match(role.name,/^gc_af_[a-z0-9_]+$/);
let nextSlot=config.suiteOffset;
export const uuid=()=>randomUUID();
export const digest=()=>createHash('sha256').update(randomBytes(32)).digest('hex');
export const iso=(value:unknown)=>new Date(value as string).toISOString();
export class SqlFailure extends Error {constructor(readonly code:string){super(`PostgreSQL rejected qualification operation (${code})`);}}
export async function query(client:pg.Client,sql:string,values:unknown[]=[]):Promise<pg.QueryResult<Row>>{
 try{return await client.query(sql,values);}catch(error){throw new SqlFailure(typeof(error as {code?:unknown}).code==='string'?(error as {code:string}).code:'CONNECTION_FAILURE');}
}
export const rejected=(...codes:string[])=>(error:unknown)=>error instanceof SqlFailure&&codes.includes(error.code);
export async function connect(url:string):Promise<pg.Client>{
 const client=new pg.Client({connectionString:url,connectionTimeoutMillis:5000,application_name:'gc-authn-foundation-qualification'});
 try{await client.connect();await query(client,"SET statement_timeout='8s'; SET lock_timeout='5s'");return client;}
 catch(error){await client.end().catch(()=>{});throw error instanceof SqlFailure?error:new SqlFailure('CONNECTION_FAILURE');}
}
export async function tx<T>(client:pg.Client,fn:()=>Promise<T>,mode='READ COMMITTED'):Promise<T>{
 await query(client,`BEGIN ISOLATION LEVEL ${mode}`);
 try{const result=await fn();await query(client,'COMMIT');return result;}catch(error){await query(client,'ROLLBACK');throw error;}
}
export async function inspect(client:pg.Client,hash:string):Promise<Row>{return tx(client,async()=>(await query(client,'SELECT * FROM public.gc_authn_session_inspect($1)',[hash])).rows[0]!,'REPEATABLE READ READ ONLY');}
export async function scalar(client:pg.Client,sql:string,values:unknown[]=[]):Promise<Row>{const r=await query(client,sql,values);assert.equal(r.rowCount,1);return r.rows[0]!;}
export async function dbNow(client:pg.Client):Promise<string>{return iso((await scalar(client,"SELECT date_trunc('milliseconds',clock_timestamp()) t")).t);}
export async function counts(client:pg.Client):Promise<Row>{return scalar(client,`SELECT
 (SELECT count(*)::int FROM gc_authn.sessions) sessions,
 (SELECT count(*)::int FROM gc_authn.session_provenance) provenance,
 (SELECT count(*)::int FROM gc_authn.session_events) events,
 (SELECT count(*)::int FROM public.sessions) legacy`);}

const functions={
 'register-executor':{name:'provision_executor',fields:['registration_id','channel_id','role_name','expected_role_oid','kind','generation','expires_at'],kinds:['uuid','uuid','text','oid','text','integer','time']},
 'advance-generation':{name:'advance_generation',fields:['kind','channel_id','registration_id','expected_previous_registration_id','expected_head_version'],kinds:['text','uuid','uuid','uuid','integer']},
 'register-issuer':{name:'provision_issuer',fields:['issuer_id','registration_id','generation','issuer','client_id','redirect_uri','environment','expires_at'],kinds:['uuid','uuid','integer','text','text','text','text','time']},
 'bind-identity':{name:'bind_identity',fields:['binding_id','issuer_id','identity_id','expected_issuer','expected_subject','expires_at'],kinds:['uuid','uuid','uuid','text','text','time']},
 'initialize-tenant':{name:'initialize_tenant',fields:['tenant_id','generation'],kinds:['uuid','integer']},
 'advance-tenant-generation':{name:'advance_tenant_generation',fields:['tenant_id','expected_generation','expected_epoch','generation'],kinds:['uuid','integer','integer','integer']},
 'revoke-executor':{name:'revoke_executor',fields:['registration_id'],kinds:['uuid']},
 'revoke-issuer':{name:'revoke_issuer',fields:['issuer_id'],kinds:['uuid']},
 'revoke-binding':{name:'revoke_binding',fields:['binding_id'],kinds:['uuid']},
} as const;
export type InstallOperation=keyof typeof functions;
const commonFields=['request_id','release_ref','operator_ref','expected_db_oid','expected_owner_oid','predecessor_hash'];
const commonKinds=['uuid','text','text','oid','oid','text'];
const stringScalar=(s:string)=>`S${Buffer.byteLength(s,'utf8')}:${s}`;
/** Independent contract codec; it does not call the product codec or trust SQL's digest. */
export function installEncoding(operation:InstallOperation,values:unknown[]):Buffer{
 const shape=functions[operation],fields=[...commonFields,...shape.fields],kinds=[...commonKinds,...shape.kinds];assert.equal(fields.length,values.length);
 let result='gc-authn-install/v1;'+stringScalar(operation);
 fields.forEach((field,i)=>{const value=values[i];result+=stringScalar(field);result+=value===null?'N;':kinds[i]==='uuid'?`U${value};`:kinds[i]==='integer'||kinds[i]==='oid'?`I${value};`:kinds[i]==='time'?`T${iso(value)};`:stringScalar(String(value));});
 return Buffer.from(result,'utf8');
}
export async function install(client:pg.Client,operation:InstallOperation,args:unknown[],requestId:string=uuid(),predecessor:string|null=null):Promise<{row:Row;values:unknown[];sql:string}>{
 const identity=await scalar(client,"SELECT (SELECT oid::int8 FROM pg_database WHERE datname=current_database()) db, (SELECT oid::int8 FROM pg_roles WHERE rolname=session_user) owner");
 const shape=functions[operation],values=[requestId,'synthetic-release','synthetic-operator',Number(identity.db),Number(identity.owner),predecessor,...args];
 const sql=`SELECT * FROM gc_authn.${shape.name}(${values.map((_,i)=>'$'+(i+1)).join(',')})`;
 const row=await scalar(client,sql,values);const encoding=installEncoding(operation,values);
 assert.ok(row.manifest_hash===createHash('sha256').update(encoding).digest('hex'),'SQL and independent typed installation codec disagree');
 const saved=await scalar(client,'SELECT manifest_encoding,manifest_hash FROM gc_authn.installation_receipts WHERE id=$1',[row.installation_id]);
 assert.ok(Buffer.isBuffer(saved.manifest_encoding)&&saved.manifest_encoding.equals(encoding),'Retained receipt encoding differs');
 assert.ok(saved.manifest_hash===row.manifest_hash);return {row,values,sql};
}
export interface Fixture {owner:pg.Client;admin:pg.Client;legacy:pg.Client;login:pg.Client;api:pg.Client;roles:Slot;tenant:string;otherTenant:string;identity:string;issuer:string;subject:string;issuerId:string;bindingId:string;loginId:string;apiId:string;loginChannel:string;apiChannel:string;expiry:string;clients:pg.Client[]}
export async function fixture(t:TestContext,options:{expiryMs?:number}={}):Promise<Fixture>{
 const slot=config.slots[nextSlot++];assert.ok(slot,'Native fixture role pool exhausted');const clients:pg.Client[]=[];
 t.after(async()=>{const failures=await Promise.allSettled(clients.map(c=>c.end()));assert.ok(failures.every(x=>x.status==='fulfilled'),'Native connections did not close');});
 const open=async(url:string)=>{const c=await connect(url);clients.push(c);return c;};
 const owner=await open(config.owner),admin=await open(config.admin),legacy=await open(config.legacy),login=await open(slot.login.url),api=await open(slot.api.url);
 const tenants=[uuid(),uuid()].sort();const f:Fixture={owner,admin,legacy,login,api,roles:slot,tenant:tenants[0]!,otherTenant:tenants[1]!,identity:uuid(),issuer:'https://synthetic-authn.example/'+uuid(),subject:'synthetic-'+uuid(),issuerId:uuid(),bindingId:uuid(),loginId:uuid(),apiId:uuid(),loginChannel:uuid(),apiChannel:uuid(),expiry:new Date(Date.parse(await dbNow(owner))+(options.expiryMs??3600000)).toISOString(),clients};
 await query(owner,'INSERT INTO public.tenants(id,name) VALUES($1,$3),($2,$3)',[f.tenant,f.otherTenant,'Synthetic authn qualification']);
 await query(owner,'INSERT INTO public.identities(id,issuer,subject,name) VALUES($1,$2,$3,$4)',[f.identity,f.issuer,f.subject,'Synthetic authn subject']);
 for(const tenant of tenants)await tx(owner,async()=>{await query(owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,f.identity]);await query(owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic','[]')",[tenant,f.identity]);});
 for(const [kind,role,registration,channel] of [['login',slot.login,f.loginId,f.loginChannel],['api',slot.api,f.apiId,f.apiChannel]] as const){
  const oid=Number((await scalar(owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);
  await install(owner,'register-executor',[registration,channel,role.name,oid,kind,1,f.expiry]);await install(owner,'advance-generation',[kind,channel,registration,null,null]);
 }
 await install(owner,'register-issuer',[f.issuerId,f.loginId,1,f.issuer,'synthetic-client','http://127.0.0.1:4310/auth/callback','isolated-test',f.expiry]);
 await install(owner,'bind-identity',[f.bindingId,f.issuerId,f.identity,f.issuer,f.subject,f.expiry]);
 for(const tenant of tenants)await install(owner,'initialize-tenant',[tenant,1]);
 return f;
}
export async function extra(f:Fixture,role:'login'|'api'|'nextLogin'|'nextApi'|'unregistered'|'owner'|'admin'):Promise<pg.Client>{
 const url=role==='owner'?config.owner:role==='admin'?config.admin:role==='unregistered'?config.unregistered.url:f.roles[role].url;
 const c=await connect(url);f.clients.push(c);return c;
}
export interface Attempt {id:string;state:string;nonce:string;verifier:string;expires:string}
export async function begin(f:Fixture,client=f.login):Promise<Attempt>{
 const state=digest(),nonce=digest(),verifier=randomBytes(48).toString('base64url');const row=await scalar(client,'SELECT * FROM public.gc_authn_attempt_begin($1,$2,$3)',[state,verifier,nonce]);
 assert.deepEqual(Object.keys(row).sort(),['format_version','attempt_id','expires_at'].sort());assert.equal(row.format_version,1);
 return {id:row.attempt_id,state,nonce,verifier,expires:iso(row.expires_at)};
}
export async function consume(f:Fixture,a:Attempt,client=f.login):Promise<Row>{return scalar(client,'SELECT * FROM public.gc_authn_attempt_consume($1,$2)',[a.id,a.state]);}
export async function issueArgs(f:Fixture,a:Attempt):Promise<unknown[]>{
 const now=await dbNow(f.owner);return [a.id,f.issuer,f.subject,'synthetic-client',a.nonce,digest(),now,now,new Date(Date.parse(now)+600000).toISOString(),digest(),digest()];
}
export const issueSQL='SELECT * FROM public.gc_authn_session_issue($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)';
export async function session(f:Fixture):Promise<{row:Row;hash:string;csrf:string;attempt:Attempt;args:unknown[]}>{
 const a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);const row=await scalar(f.login,issueSQL,args);return {row,hash:args[9] as string,csrf:args[10] as string,attempt:a,args};
}
export async function setMembership(f:Fixture,client:pg.Client,tenant:string,active:boolean):Promise<void>{
 await query(client,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,f.identity]);
 const r=await query(client,'UPDATE public.memberships SET active=$3 WHERE tenant_id=$1 AND identity_id=$2',[tenant,f.identity,active]);assert.equal(r.rowCount,1);
}
export async function waitBlocked(observer:pg.Client,blocked:pg.Client,blocker:pg.Client):Promise<void>{
 const waiter=Number((blocked as unknown as {processID:number}).processID),owner=Number((blocker as unknown as {processID:number}).processID);assert.ok(waiter>0&&owner>0);
 const deadline=performance.now()+3500;
 while(performance.now()<deadline){const row=await scalar(observer,'SELECT $2::int=ANY(pg_blocking_pids($1)) blocked',[waiter,owner]);if(row.blocked)return;await new Promise(r=>setTimeout(r,15));}
 assert.fail('Expected native PostgreSQL lock dependency was not observed');
}
