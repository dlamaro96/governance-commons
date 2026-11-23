// SPDX-License-Identifier: Apache-2.0
/** Real SQL032 regressions. Owner-only predicate fixtures/function instrumentation
 * always roll back. Original26 retain ordinary writes and journals; the added race uses real independent connections. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {assetView,record} from '../../apps/api/src/repository.ts';
import {sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {createRelation} from '../../packages/domain/src/relation-service.ts';
import {fixture,asset,plainType,type Fixture} from '../fixtures/relation-candidate.ts';
const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
const original=readFileSync('packages/db/migrations/018_glossary_nominal_candidates.sql','utf8');
const current=readFileSync('packages/db/migrations/032_relation_candidate_validation.sql','utf8');
const declaration='CREATE OR REPLACE FUNCTION public.gc_relation_check_type';
function expression(source:string,kind:'count'|'missing'){
 const body=source.slice(source.indexOf(declaration));
 const start=kind==='count'?(body.indexOf(' OR (SELECT count(*) FROM public.gc_relation_nominal_candidates')>=0?body.indexOf(' OR (SELECT count(*) FROM public.gc_relation_nominal_candidates'):body.indexOf(' OR (WITH candidates'))+5:body.indexOf('IF side_min>0 AND EXISTS(')+'IF side_min>0 AND EXISTS('.length;
 const end=kind==='count'?body.indexOf(')>2000 THEN'):body.indexOf(" THEN\n   RAISE EXCEPTION 'RELATION_PARTICIPATION_REQUIRED'")-1;
 assert.ok(start>0&&end>start);return body.slice(start,end).replace(/\bhead_definition\b/g,'$2::jsonb').replace(/\btype_identity\b/g,'$4::uuid').replace(/\bselected_side\b/g,'$3::text').replace(/(?<![.\w])tenant\b/g,'$1::uuid');
}
const oldCount=expression(original,'count'),newCount=expression(current,'count'),oldMissing=expression(original,'missing'),newMissing=expression(current,'missing');
async function safe(t:TestContext,work:()=>Promise<void>){try{await work();}catch(e){if(e instanceof assert.AssertionError)throw e;const code=(e as {code?:unknown})?.code;t.diagnostic(JSON.stringify({sqlstate:typeof code==='string'&&/^[A-Z0-9]{5}$/.test(code)?code:null}));throw Error('Native candidate regression failed; see finite SQLSTATE.');}}
async function owned<T>(f:Fixture,work:(c:pg.Client)=>Promise<T>,actor=f.author):Promise<T>{await f.owner.query('BEGIN');try{await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('statement_timeout','30000ms',true)",[f.tenant,actor]);return await work(f.owner);}finally{await f.owner.query('ROLLBACK');}}
const code=(c:string,message?:string)=>(e:unknown)=>!!e&&typeof e==='object'&&(e as any).code===c&&(message===undefined||(e as any).message===message);
async function refusal(c:pg.Client,statement:string,args:unknown[],expected:string,message?:string){await c.query('SAVEPOINT refused');try{await assert.rejects(()=>c.query(statement,args),code(expected,message));}finally{await c.query('ROLLBACK TO SAVEPOINT refused');await c.query('RELEASE SAVEPOINT refused');}}
async function seed(c:pg.Client,f:Fixture,model:{id:string;version:number},count:number,state='active'){
 const rows=(await c.query(`INSERT INTO public.assets(tenant_id,id,external_id,name,qualified_name,type,owner_id,observed_at,model_id,model_version,type_state)
 SELECT $1,gen_random_uuid(),'candidate-'||gen_random_uuid(),'Synthetic candidate','synthetic.candidate.'||n,'dataset',$2,clock_timestamp(),$3,$4,$5 FROM generate_series(1,$6) n RETURNING *`,[f.tenant,f.author,model.id,model.version,state,count])).rows;
 await c.query(`INSERT INTO public.asset_revisions(tenant_id,asset_id,version,snapshot) SELECT $1,x.id,x.version,x.snapshot FROM jsonb_to_recordset($2::jsonb) x(id uuid,version integer,snapshot jsonb)`,[f.tenant,JSON.stringify(rows.map(r=>({id:r.id,version:r.version,snapshot:assetView(r)})))]);return rows.map(r=>r.id as string);
}
async function scalar(c:pg.Client,query:string,args:unknown[]){return(await c.query(`SELECT (${query}) AS value`,args)).rows[0].value;}
async function missing(c:pg.Client,query:string,args:unknown[]){return(await c.query(`SELECT EXISTS(${query}) AS value`,args)).rows[0].value;}
async function graph(f:Fixture){const model=await f.type(plainType('candidate_'+randomUUID().replaceAll('-',''))),r=await f.relation({sourceTypes:[{typeId:model.typeId,includeDescendants:true}],targetTypes:[{typeId:model.typeId,includeDescendants:true}]});return{model,r};}
async function definition(c:pg.Client,f:Fixture,id:string){return(await c.query('SELECT definition FROM public.relation_type_versions WHERE tenant_id=$1 AND relation_type_id=$2 AND version=1',[f.tenant,id])).rows[0].definition;}
async function functionShape(c:pg.Client){return(await c.query("SELECT pg_get_functiondef('public.gc_relation_endpoint_eligible(uuid,uuid,jsonb,text)'::regprocedure) AS definition")).rows[0].definition as string;}

test('candidate fence preserves nominal and exhaustive counts for inheritance states and duplicate paths',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f),child=await f.type({...plainType('child_'+randomUUID().replaceAll('-','')),parents:[{id:model.id,version:1}],lifecycle:null}),noise=await f.type(plainType('noise_'+randomUUID().replaceAll('-','')));
 await owned(f,async c=>{await seed(c,f,model,2);await seed(c,f,model,1,'inactive');await seed(c,f,child,2);await seed(c,f,noise,5);const d=await definition(c,f,r.relationTypeId);
  for(const descendants of [false,true])for(const states of [null,['active'],['inactive']]){
   const v={...d,sourceTypes:[{typeId:model.typeId,includeDescendants:descendants}],targetTypes:[{typeId:model.typeId,includeDescendants:descendants}],sourceStates:states,targetStates:states},args=[f.tenant,JSON.stringify(v)];
   const all=await scalar(c,"SELECT count(*) FROM public.assets a WHERE a.tenant_id=$1::uuid AND (public.gc_relation_endpoint_eligible($1::uuid,a.id,$2::jsonb,'source') OR public.gc_relation_endpoint_eligible($1::uuid,a.id,$2::jsonb,'target'))",args);
   assert.equal(await scalar(c,oldCount,args),all);assert.equal(await scalar(c,newCount,args),all);assert.equal(Number(all),states?.[0]==='inactive'?1:descendants?(states===null?5:4):(states===null?3:2));
  }
 });
}));

test('candidate participation predicate preserves directed incident side and active binding distinctions',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f);await owned(f,async c=>{
  const [id]=await seed(c,f,model,1),d=await definition(c,f,r.relationTypeId);
  // Read-predicate witnesses only; guards and rows restore by transaction rollback.
  await c.query('ALTER TABLE public.relation_participations DISABLE TRIGGER USER');
  for(const selected of ['source','target','incident']){
   const args=[f.tenant,JSON.stringify(d),selected,r.relationTypeId];assert.equal(await missing(c,oldMissing,args),true);assert.equal(await missing(c,newMissing,args),true);
   const row=randomUUID();await c.query("INSERT INTO relation_participations(tenant_id,id,relation_type_id,relation_type_version,asset_id,asset_version,side,status,version,created_by,updated_by) VALUES($1,$2,$3,1,$4,1,$5,'released',1,$6,$6)",[f.tenant,row,r.relationTypeId,id,selected,f.author]);
   assert.equal(await missing(c,newMissing,args),true);await c.query("UPDATE relation_participations SET status='active' WHERE tenant_id=$1 AND id=$2",[f.tenant,row]);
   assert.equal(await missing(c,newMissing,args),false);assert.equal(await missing(c,oldMissing,args),false);
   for(const other of ['source','target','incident'].filter(x=>x!==selected)){const otherArgs=[f.tenant,JSON.stringify(d),other,r.relationTypeId];assert.equal(await missing(c,newMissing,otherArgs),true);assert.equal(await missing(c,oldMissing,otherArgs),true);}
   await c.query('DELETE FROM relation_participations WHERE tenant_id=$1 AND id=$2',[f.tenant,row]);
  }
 });assert.equal((await f.owner.query("SELECT bool_and(tgenabled='O') AS ok FROM pg_trigger WHERE tgrelid='public.relation_participations'::regclass AND NOT tgisinternal")).rows[0].ok,true);
}));

test('candidate full validator retains exact two-thousand endpoint boundary and rollback of overflow',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f),before=await f.state();await owned(f,async c=>{
  await seed(c,f,model,2000);assert.equal(await scalar(c,newCount,[f.tenant,JSON.stringify(await definition(c,f,r.relationTypeId))]),'2000');
  await c.query('SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId]);await seed(c,f,model,1);await refusal(c,'SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId],'54000','RELATION_PROFILE_LIMIT');
 });assert.deepEqual(await f.state(),before);
}));

test('candidate full validator retains tenant and runtime execute denials',async t=>safe(t,async()=>{
 const f=await fixture(t),foreign=await fixture(t),{model,r}=await graph(f),local=await asset(f,model),before=await f.state();
 await owned(foreign,async c=>{await c.query(`INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,owner_id,observed_at) VALUES($1,$2::uuid,$2::uuid::text,'Foreign collision','synthetic.foreign','dataset',$3,clock_timestamp())`,[foreign.tenant,local.id,foreign.author]);assert.equal((await c.query('SELECT count(*)::integer AS n FROM assets WHERE tenant_id=$1 AND id=$2',[foreign.tenant,local.id])).rows[0].n,1);
  const d=await f.as(async tx=>(await sql<{definition:unknown}>`SELECT definition FROM relation_type_versions WHERE tenant_id=${f.tenant} AND relation_type_id=${r.relationTypeId} AND version=1`.execute(tx)).rows[0]!.definition);assert.equal(await scalar(c,newCount,[foreign.tenant,JSON.stringify(d)]),'0');assert.equal(await scalar(c,oldCount,[foreign.tenant,JSON.stringify(d)]),'0');assert.equal((await c.query('SELECT count(*)::integer AS n FROM assets WHERE tenant_id=$1 AND id=$2',[f.tenant,local.id])).rows[0].n,0);
 });await owned(f,async c=>{assert.equal(await scalar(c,newCount,[f.tenant,JSON.stringify(await definition(c,f,r.relationTypeId))]),'1');await refusal(c,'SELECT public.gc_relation_check_type($1,$2)',[randomUUID(),r.relationTypeId],'42501','Untrusted graph tenant');assert.equal(await scalar(c,newCount,[randomUUID(),JSON.stringify(await definition(c,f,r.relationTypeId))]),'0');});
 const runtime=new pg.Client({connectionString:config.legacy});await runtime.connect();try{await runtime.query('BEGIN');await runtime.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.author]);await assert.rejects(()=>runtime.query('SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId]),code('42501'));await runtime.query('ROLLBACK');}finally{await runtime.end();}assert.deepEqual(await f.state(),before);
}));

test('candidate full validator keeps hidden eligible scope refusal ahead of size diagnostics',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f);await asset(f,model,f.author,true);const before=await f.state();await owned(f,async c=>{await seed(c,f,model,2001);await refusal(c,'SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId],'42501','RELATION_SCOPE_UNAVAILABLE');},f.reader);assert.deepEqual(await f.state(),before);
}));

test('candidate and immutable SQL018 complete validator agree on same-snapshot valid and overflow states',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f);await owned(f,async c=>{
  const old=original.slice(original.indexOf(declaration),original.indexOf('\nREVOKE ALL ON FUNCTION public.gc_relation_check_type',original.indexOf(declaration))).replace(declaration,'CREATE FUNCTION public.gc_candidate_old_check');await c.query(old);await c.query('REVOKE ALL ON FUNCTION public.gc_candidate_old_check(uuid,uuid) FROM PUBLIC,gc_app');
  async function outcome(fn:string){await c.query('SAVEPOINT compared');try{await c.query(`SELECT public.${fn}($1,$2)`,[f.tenant,r.relationTypeId]);return'OK';}catch(e){assert.ok(code('54000','RELATION_PROFILE_LIMIT')(e));return(e as any).code;}finally{await c.query('ROLLBACK TO SAVEPOINT compared');await c.query('RELEASE SAVEPOINT compared');}}
  await seed(c,f,model,2);assert.equal(await outcome('gc_relation_check_type'),'OK');assert.equal(await outcome('gc_candidate_old_check'),'OK');await seed(c,f,model,1999);assert.equal(await outcome('gc_relation_check_type'),'54000');assert.equal(await outcome('gc_candidate_old_check'),'54000');
 });assert.equal((await f.owner.query("SELECT to_regprocedure('public.gc_candidate_old_check(uuid,uuid)') AS value")).rows[0].value,null);
}));

test('candidate expensive helper calls stay bounded by joined candidates under generic and custom plans',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f),noise=await f.type(plainType('noise_'+randomUUID().replaceAll('-',''))),before=await functionShape(f.owner);
 await owned(f,async c=>{await seed(c,f,model,2);await seed(c,f,noise,1024);const d=JSON.stringify(await definition(c,f,r.relationTypeId));await c.query('CREATE TEMP TABLE candidate_calls(n integer) ON COMMIT DROP');assert.ok(before.includes('\nBEGIN\n'));await c.query(before.replace('\nBEGIN\n','\nBEGIN\n INSERT INTO pg_temp.candidate_calls VALUES(1);\n'));await c.query(`PREPARE candidate_count(uuid,jsonb) AS ${newCount}`);await c.query(`PREPARE candidate_missing(uuid,jsonb,text,uuid) AS SELECT EXISTS(${newMissing}) AS value`);const literal=(s:string)=>"'"+s.replaceAll("'","''")+"'";
  for(const mode of ['force_generic_plan','force_custom_plan']){await c.query("SELECT set_config('plan_cache_mode',$1,true)",[mode]);await c.query('TRUNCATE candidate_calls');const plan=(await c.query(`EXPLAIN (ANALYZE,FORMAT JSON) EXECUTE candidate_count(${literal(f.tenant)}::uuid,${literal(d)}::jsonb)`)).rows[0]['QUERY PLAN'][0].Plan;const nodes:any[]=[];function visit(n:any){nodes.push(n);for(const p of n.Plans??[])visit(p);}visit(plan);assert.ok(nodes.some(n=>n['Node Type']==='CTE Scan'));assert.ok(nodes.every(n=>n['Relation Name']!=='assets'||!String(n.Filter??'').includes('gc_relation_endpoint_eligible')));const count=Number((await c.query('SELECT count(*) AS value FROM candidate_calls')).rows[0].value);assert.ok(count>=2&&count<=4);
   await c.query('TRUNCATE candidate_calls');const minPlan=(await c.query(`EXPLAIN (ANALYZE,FORMAT JSON) EXECUTE candidate_missing(${literal(f.tenant)}::uuid,${literal(d)}::jsonb,'source',${literal(r.relationTypeId)}::uuid)`)).rows[0]['QUERY PLAN'][0].Plan;nodes.length=0;visit(minPlan);assert.ok(nodes.some(n=>n['Node Type']==='CTE Scan'));assert.ok(nodes.every(n=>n['Relation Name']!=='assets'||!String(n.Filter??'').includes('gc_relation_endpoint_eligible')));const minCount=Number((await c.query('SELECT count(*) AS value FROM candidate_calls')).rows[0].value);assert.ok(minCount>=1&&minCount<=2,'Positive minimum stops only after an eligible missing candidate');
   await c.query('TRUNCATE candidate_calls');await c.query('SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId]);const fullCount=Number((await c.query('SELECT count(*) AS value FROM candidate_calls')).rows[0].value);assert.ok(fullCount>=2&&fullCount<=4,'Fixture has no restricted assets, bindings or edges; only replaced count expression calls eligibility');
  }await c.query('DEALLOCATE candidate_count');await c.query('DEALLOCATE candidate_missing');
 });assert.equal(await functionShape(f.owner),before);
}));

test('candidate validation retains original graph deadline refusal without mutation',async t=>safe(t,async()=>{const f=await fixture(t),before=await f.state();await owned(f,async c=>{await refusal(c,"SELECT public.gc_relation_graph_budget(clock_timestamp()-interval '31 seconds')",[],'57014','Graph operation deadline exceeded');});assert.deepEqual(await f.state(),before);}));


test('candidate complete validator retains four-thousand active participation limit independently of eligible endpoint count',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f),before=await f.state();await owned(f,async c=>{
  const ids=await seed(c,f,model,2000);await c.query('ALTER TABLE relation_participations DISABLE TRIGGER USER');
  await c.query(`INSERT INTO relation_participations(tenant_id,id,relation_type_id,relation_type_version,asset_id,asset_version,side,status,version,created_by,updated_by)
   SELECT $1,gen_random_uuid(),$2,1,asset_id,1,side,'active',1,$3,$3 FROM unnest($4::uuid[]) asset_id CROSS JOIN unnest(ARRAY['source','target']) side`,[f.tenant,r.relationTypeId,f.author,ids]);
  assert.equal((await c.query('SELECT count(*)::integer AS n FROM relation_participations WHERE tenant_id=$1 AND relation_type_id=$2 AND status=\'active\'',[f.tenant,r.relationTypeId])).rows[0].n,4000);
  await c.query('SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId]);
  await c.query(`INSERT INTO relation_participations(tenant_id,id,relation_type_id,relation_type_version,asset_id,asset_version,side,status,version,created_by,updated_by) VALUES($1,gen_random_uuid(),$2,1,$3,1,'incident','active',1,$4,$4)`,[f.tenant,r.relationTypeId,ids[0],f.author]);
  assert.equal((await c.query('SELECT count(*)::integer AS n FROM relation_participations WHERE tenant_id=$1 AND relation_type_id=$2',[f.tenant,r.relationTypeId])).rows[0].n,4001);
  await refusal(c,'SELECT public.gc_relation_check_type($1,$2)',[f.tenant,r.relationTypeId],'54000','RELATION_PROFILE_LIMIT');
 });assert.deepEqual(await f.state(),before);assert.equal((await f.owner.query("SELECT bool_and(tgenabled='O') AS ok FROM pg_trigger WHERE tgrelid='public.relation_participations'::regclass AND NOT tgisinternal")).rows[0].ok,true);
}));

test('candidate production mutation observes principal wait then refuses committed revocation without graph or journal writes',async t=>safe(t,async()=>{
 const f=await fixture(t),{model,r}=await graph(f),a=await asset(f,model),b=await asset(f,model),before=await f.state();let waiter=0;let pending:Promise<unknown>|undefined;
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('statement_timeout','30000ms',true)",[f.tenant,f.author]);
  assert.equal((await f.owner.query("UPDATE memberships SET permissions='[\"catalog:read\",\"models:read\"]'::jsonb WHERE tenant_id=$1 AND identity_id=$2",[f.tenant,f.author])).rowCount,1);
  const blocker=(await f.owner.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  pending=f.as(async tx=>{waiter=(await sql<{pid:number}>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0]!.pid;return createRelation(tx,f.principal(),randomUUID(),{relationTypeId:r.relationTypeId,relationTypeVersion:1,sourceAssetId:a.id,sourceAssetVersion:a.version,targetAssetId:b.id,targetAssetVersion:b.version,attributes:{},ownerId:f.author,validFrom:null,validTo:null,visibility:'tenant',allowedIdentityIds:[]},{record});}).then(()=>({unexpected:true}),error=>error);
  const end=performance.now()+2500;let observed=false;while(performance.now()<end){if(waiter&&(await f.owner.query('SELECT $2::integer=ANY(pg_blocking_pids($1::integer)) AS waiting',[waiter,blocker])).rows[0].waiting){observed=true;break;}await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(observed,true,'Actual contender must be observed blocked by this transaction');await f.owner.query('COMMIT');
  const error=await pending;assert.ok(error instanceof Problem&&error.status===403&&error.code==='FORBIDDEN');assert.deepEqual(await f.state(),before);
 }finally{await f.owner.query('ROLLBACK');await pending;}
}));
