// SPDX-License-Identifier: Apache-2.0
/** Actual Fastify/authentication/SQL compilation against a controlled local client.
 * No network, PostgreSQL, OIDC exchange, source scan or Temporal qualification. */
import assert from 'node:assert/strict';
import {test,type TestContext} from 'node:test';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import {pool} from '../../packages/db/src/index.ts';
import {monitorDefinitionHash} from '../../packages/domain/src/quality-monitoring.ts';
import type {QualityMonitorDefinition} from '../../packages/domain/src/quality-monitoring-contracts.ts';
import {installQualityMonitoring} from '../../apps/api/src/quality-monitoring.ts';
import {sha256} from '../../packages/authn/src/transport.ts';
const id=(n:number)=>`20000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const tenant=id(1),actor=id(2),monitorId=id(3),ruleId=id(4),stamp='2026-11-17T00:00:00.000Z';
const definition:QualityMonitorDefinition={formatVersion:1,name:'Synthetic monitor',purpose:'Current aggregate observation',rule:{id:ruleId,version:1,definitionHash:'a'.repeat(64)},executorId:actor,authorizationExpiresAt:'2026-11-18T00:00:00.000Z',schedule:{kind:'fixed-interval',timeZone:'UTC',startsAt:stamp,endsAt:null,intervalSeconds:60,lateGraceSeconds:10,missedSlots:'skip',overlap:'skip'},maintenance:[],silences:[],routing:{channel:'in-app',ownerId:actor,recipientIds:[actor]},issue:{category:'data-quality',acknowledgeWithinSeconds:60,resolveWithinSeconds:120},recoveryMaximumAgeSeconds:600,retry:{policy:'quality-run-v1'}};
const origin='http://127.0.0.1:4310',sessionToken='A'.repeat(43),csrfToken='B'.repeat(43);
const headers={cookie:`gc_authn_session=${sessionToken}; gc_authn_csrf=${csrfToken}`,'x-csrf-token':csrfToken,origin,'idempotency-key':'synthetic-monitor-command','content-type':'application/json'};
async function fixture(t:TestContext){
 const authKeys=['AUTHN_ENVIRONMENT','PUBLIC_AUTHN_ORIGIN','PUBLIC_URL'] as const,authBefore=Object.fromEntries(authKeys.map(key=>[key,process.env[key]]));
 process.env.AUTHN_ENVIRONMENT='isolated-test';process.env.PUBLIC_AUTHN_ORIGIN=origin;process.env.PUBLIC_URL=origin;
 t.after(()=>{for(const key of authKeys){if(authBefore[key]===undefined)delete process.env[key];else process.env[key]=authBefore[key];}});
 const calls:{text:string;values:readonly unknown[]}[]=[],state={privateOutput:false,memberActive:true};
 const client={release(){},async query(text:string,values:readonly unknown[]=[]){calls.push({text,values});
  if(text.includes('gc_app_protected_session_v1')){
   if(!state.memberActive)throw Object.assign(new Error('AUTHN_REJECTED'),{code:'28000'});
   return {rows:[{format_version:1,session_id:id(50),session_version:1,identity_id:actor,selected_tenant_id:tenant,
    issuer_id:id(51),identity_binding_id:id(52),authenticated_at:new Date(Date.now()-60_000).toISOString(),
    expires_at:new Date(Date.now()+60_000).toISOString(),generation:1,tenant_fence_epoch:1,authority_mode:'inactive',content_authority:false}]};
  }
  if(text.includes('from "identities"'))return {rows:[{name:'Synthetic author'}]};
  if(text.includes('AS within_profile'))return {rows:[{live:true,within_profile:true}]};
  if(text.includes('from "memberships"'))return {rows:state.memberActive?[{id:tenant,name:'Synthetic tenant',role:'steward',permissions:['catalog:read','quality:read','quality:write','quality:execute']}]:[]};
  if(text.includes('gc_quality_monitor_command')){const body=JSON.parse(values[2] as string),monitor={id:body.id,revision:body.expectedRevision+1,definitionVersion:1,definitionHash:monitorDefinitionHash(body.definition),definition:body.definition,state:'enabled',blocked:null,nextSlotAt:stamp,lastAdmittedOrdinal:0,lastProjectedOrdinal:0,currentObservation:{state:'unobserved'},lastConclusive:null,createdAt:stamp,createdBy:actor};return {rows:[{value:{monitor:{...monitor,...(state.privateOutput?{source:{secretRef:'synthetic-private-token'}}:{})}}}]};}
  if(text.endsWith(' as visible'))return {rows:[{visible:true}]};
  if(['begin','start transaction isolation level repeatable read read only','commit','rollback'].includes(text)||text.includes('set_config'))return {rows:[],command:text.toUpperCase()};
  throw new Error('Unexpected compiled query in host fixture');
 }};
 t.mock.method(pool,'connect',async()=>client as any);
 const app=Fastify({logger:false});await app.register(cookie);await installQualityMonitoring(app);await app.ready();
 return {app,calls,state,commands:()=>calls.filter(x=>x.text.includes('gc_quality_monitor_command'))};
}
test('human mutation uses actual session, current membership and CSRF before protected command routing',async t=>{
 const f=await fixture(t),payload={id:monitorId,expectedRevision:0,definition};try{
  const accepted=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers,payload});assert.equal(accepted.statusCode,201,accepted.body);assert.equal(accepted.json().monitor.id,monitorId);assert.equal(f.commands().length,1);assert.deepEqual(f.commands()[0].values.slice(0,3),['quality.monitor.publish',headers['idempotency-key'],JSON.stringify(payload)]);
  const scope=f.calls.filter(x=>x.text.includes("set_config('gc.tenant_id'"));assert.ok(scope.length>=2);for(const q of scope)assert.deepEqual(q.values,[tenant,actor]);
  const {cookie:omittedCookie,...withoutCookie}=headers;assert.ok(omittedCookie);
  const bridge=f.calls.find(q=>q.text.includes('gc_app_protected_session_v1'))!;assert.deepEqual(bridge.values,[sha256(sessionToken),sha256(csrfToken)]);
  assert.ok(f.calls.some(q=>q.text==='start transaction isolation level repeatable read read only'));assert.equal(f.calls.some(q=>q.text.includes('from \"sessions\"')),false);
  for(const changed of [withoutCookie,{...headers,'x-csrf-token':'wrong'},{...headers,origin:'https://foreign.example.invalid'}]){const r=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers:changed,payload});assert.ok([401,403].includes(r.statusCode),r.body);assert.equal(f.commands().length,1);}
  f.state.memberActive=false;const revoked=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers,payload});assert.equal(revoked.statusCode,401);assert.equal(revoked.json().code,'SESSION_EXPIRED');assert.equal(f.commands().length,1);
 }finally{await f.app.close();}
});
test('installed human routes refuse duplicate keys, unknown fields, substituted path IDs and ambiguous idempotency',async t=>{
 const f=await fixture(t),payload={id:monitorId,expectedRevision:0,definition};try{
  const raw=JSON.stringify(payload);
  for(const candidate of [raw.replace('"expectedRevision":0','"expectedRevision":0,"expectedRevision":1'),raw.replace('"expectedRevision":0','"expectedRevision":"0"'),JSON.stringify({...payload,tenantId:tenant}),JSON.stringify({...payload,definition:{...definition,sourceSql:'synthetic-private-sql'}}),' '.repeat(32769)+raw]){const r=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers,payload:candidate});assert.equal(r.statusCode,400,r.body);assert.equal(r.json().code,'MONITOR_INPUT_INVALID');assert.equal(r.body.includes('synthetic-private'),false);}
  const {'idempotency-key':omitted,...withoutKey}=headers;assert.ok(omitted);
  for(const changed of [withoutKey,{...headers,'idempotency-key':'short'},{...headers,'idempotency-key':['synthetic-one-key','synthetic-two-key']}]){const r=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers:changed,payload});assert.equal(r.statusCode,400,r.body);assert.equal(r.json().code,'IDEMPOTENCY_REQUIRED');}
  const mismatch=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors/'+id(20)+'/definitions',headers,payload:{...payload,expectedRevision:1}});assert.equal(mismatch.statusCode,400);assert.equal(mismatch.json().code,'MONITOR_INPUT_INVALID');assert.equal(f.commands().length,0);
 }finally{await f.app.close();}
});
test('installed human query transport refuses ambiguous filters and output corruption stays redacted',async t=>{
 const f=await fixture(t);try{
  for(const url of ['/api/v1/quality/monitors?limit=01','/api/v1/quality/monitors?limit=1&%6cimit=2','/api/v1/quality/issues?assignedToMe=1','/api/v1/quality/issues?assignedToMe=false&assignedToMe=true','/api/v1/quality/notifications?tenantId='+tenant]){const r=await f.app.inject({url,headers:{cookie:headers.cookie}});assert.equal(r.statusCode,400,r.body);assert.equal(r.json().code,'MONITOR_INPUT_INVALID');}
  f.state.privateOutput=true;const result=await f.app.inject({method:'POST',url:'/api/v1/quality/monitors',headers,payload:{id:monitorId,expectedRevision:0,definition}});assert.equal(result.statusCode,500,result.body);assert.equal(result.json().code,'MONITOR_STORAGE_INVALID');assert.equal(result.body.includes('synthetic-private-token'),false);assert.equal(result.body.includes('source'),false);assert.ok(f.calls.some(q=>q.text==='rollback'));assert.equal(f.commands().length,1);
 }finally{await f.app.close();}
});
