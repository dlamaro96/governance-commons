// SPDX-License-Identifier: Apache-2.0
import {test,after} from 'node:test';import assert from 'node:assert/strict';import {randomUUID,createHash} from 'node:crypto';
import {db,scope,sql} from '../../packages/db/src/index.ts';
const A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward='10000000-0000-4000-8000-000000000001',consumer='10000000-0000-4000-8000-000000000003';
const base=process.env.TEST_BASE_URL??'http://api:4310',origin=process.env.PUBLIC_URL??'http://localhost:4310';
async function session(user=steward,tenant=A){const raw=randomUUID()+randomUUID(),csrf=randomUUID();await db.insertInto('sessions').values({id_hash:createHash('sha256').update(raw).digest('hex'),identity_id:user,tenant_id:tenant,csrf,expires_at:new Date(Date.now()+60000)}).execute();return {'Cookie':`gc_session=${raw}`,'X-CSRF-Token':csrf,'Origin':origin,'Content-Type':'application/json'};}
const sourceBody={name:'Integration source',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'};
test('runtime role cannot bypass RLS and pool context resets',async()=>{
 const role=await sql<any>`SELECT rolname,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`.execute(db);assert.equal(role.rows[0].rolsuper,false);assert.equal(role.rows[0].rolbypassrls,false);assert.equal(role.rows[0].rolname,'gc_app');
 const id=randomUUID();await scope(A,steward,async tx=>{await tx.insertInto('sources').values({tenant_id:A,id,name:'RLS fixture',host:'source-postgres',port:5432,database_name:'harbor',schema_name:'public',secret_ref:'demo-postgres'}).execute();});
 assert.equal((await scope(B,steward,tx=>tx.selectFrom('sources').selectAll().where('id','=',id).execute())).length,0);
 assert.equal((await db.selectFrom('sources').selectAll().where('id','=',id).execute()).length,0);
 await assert.rejects(()=>scope(A,steward,tx=>tx.insertInto('jobs').values({tenant_id:B,id:randomUUID(),source_id:id,actor_id:steward}).execute()));
 await assert.rejects(()=>scope(B,steward,tx=>tx.insertInto('jobs').values({tenant_id:B,id:randomUUID(),source_id:id,actor_id:steward}).execute()));
 await scope(A,steward,tx=>tx.deleteFrom('sources').where('id','=',id).execute());
});
test('API denies unauthenticated access, CSRF, role escalation and tenant tampering',async()=>{
 assert.equal((await fetch(base+'/api/v1/assets')).status,401);
 const headers=await session();const me=await fetch(base+'/api/v1/me',{headers});assert.equal(me.status,200);assert.equal((await me.json() as any).tenant.id,A);
 assert.equal((await fetch(base+'/api/v1/session/tenant',{method:'POST',headers,body:JSON.stringify({tenantId:B})})).status,403);
 assert.equal((await fetch(base+'/api/v1/sources',{method:'POST',headers:{...headers,Origin:'https://evil.invalid','Idempotency-Key':randomUUID()},body:JSON.stringify(sourceBody)})).status,403);
 const limited=await session(consumer);assert.equal((await fetch(base+'/api/v1/sources',{method:'POST',headers:{...limited,'Idempotency-Key':randomUUID()},body:JSON.stringify(sourceBody)})).status,403);
 assert.equal((await fetch(base+'/api/v1/sources',{method:'POST',headers:{...headers,'Idempotency-Key':randomUUID()},body:JSON.stringify({...sourceBody,host:'169.254.169.254'})})).status,400);
});
test('source creation idempotency binds request and atomic audit; audit is immutable',async()=>{
 const headers={...await session(),'Idempotency-Key':randomUUID()};const send=(body:object)=>fetch(base+'/api/v1/sources',{method:'POST',headers,body:JSON.stringify(body)});
 const first=await send(sourceBody);assert.equal(first.status,201);const source=(await first.json() as any).source;
 const second=await send(sourceBody);assert.equal((await second.json() as any).source.id,source.id);
 assert.equal((await send({...sourceBody,name:'Changed request'})).status,409);
 const audits=await scope(A,steward,tx=>tx.selectFrom('audit').selectAll().where('resource_id','=',source.id).execute());assert.equal(audits.length,1);assert.equal(audits[0].action,'source.created');
 await assert.rejects(()=>scope(A,steward,tx=>tx.updateTable('audit').set({action:'forged'}).where('id','=',audits[0].id).execute()));
 await assert.rejects(()=>scope(A,steward,tx=>tx.deleteFrom('audit').where('id','=',audits[0].id).execute()));
});
test('restricted asset denied through direct detail and stale projection search',async()=>{
 const id=randomUUID(),name='hidden-canary-'+randomUUID();await scope(A,steward,tx=>tx.insertInto('assets').values({tenant_id:A,id,external_id:id,name,qualified_name:name,type:'dataset',observed_at:new Date(),visibility:'restricted',allowed_identities:JSON.stringify([steward])}).execute());
 const indexResponse=await fetch((process.env.OPENSEARCH_URL??'http://opensearch:9200')+'/gc-assets-v1/_doc/'+id+'?refresh=true',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenantId:A,id,name,qualifiedName:name,type:'dataset',description:'',status:'active',version:1})});assert.equal(indexResponse.ok,true);
 const headers=await session(consumer);assert.equal((await fetch(base+'/api/v1/assets/'+id,{headers})).status,404);
 const result=await fetch(base+'/api/v1/assets?q='+encodeURIComponent(name),{headers});assert.equal(result.status,200);const body=await result.json() as any;assert.equal(body.total,0);assert.deepEqual(body.facets,[]);assert.equal(JSON.stringify(body).includes(name),false);
 const summit=await session('10000000-0000-4000-8000-000000000005',B);assert.equal((await fetch(base+'/api/v1/assets/'+id,{headers:summit})).status,404);
 await scope(A,steward,tx=>tx.deleteFrom('assets').where('id','=',id).execute());
});
after(async()=>{await db.destroy();});
