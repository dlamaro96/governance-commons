// SPDX-License-Identifier: Apache-2.0
/** Real PostgreSQL classification/approval qualification in an owned disposable
 * database. Scan completions are authored metadata fixtures, not source-worker
 * execution or source-value sampling. All history remains until DB teardown. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {claimSourceScan,completeSourceScan,failSourceScan} from '../../apps/api/src/source-scans.ts';
import {parseClassificationTaxonomy,parseMetadataClassificationRule,classificationDefinitionHash,classificationInputDigest,evaluateMetadataClassification} from '../../packages/domain/src/classification.ts';
import {getClassificationTaxonomy,listClassificationTaxonomies,listClassificationAssignments,listClassificationSuggestions,parseClassificationAssignmentView} from '../../packages/domain/src/classification-service.ts';
import type {ClassificationAssetInput,ClassificationPin,ClassificationTaxonomy,MetadataClassificationRule,ClassificationEvaluationView} from '../../packages/domain/src/classification-contracts.ts';

const file=process.env.AUTHN_FOUNDATION_CONFIG;
assert.ok(file,'AUTHN_FOUNDATION_CONFIG is required; no shared runtime fallback');
const config=JSON.parse(readFileSync(file,'utf8')) as {owner:string;legacy:string};
assert.equal(typeof config.owner,'string');assert.equal(typeof config.legacy,'string');
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','classification:read','classification:write','classification:approve','sources:read','sources:write','audit:read'];
const tables=['classification_taxonomies','classification_taxonomy_versions','classification_rules','classification_rule_versions','classification_evaluations','classification_assignments','classification_assignment_revisions'] as const;
const snapshots=[...tables,'assets','asset_revisions','sources','jobs','approval_requests','approval_tasks','approval_decisions','approval_dispatch','workflow_definitions','workflow_definition_versions','audit','outbox','idempotency'] as const;
const code=(expected:string)=>(error:unknown)=>!!error&&typeof error==='object'&&'code'in error&&error.code===expected;
const problem=(status:number)=>(error:unknown)=>error instanceof Problem&&error.status===status;
const exactInvalid=(error:unknown)=>code('22023')(error)&&error instanceof Error&&error.message==='classification request invalid';
function canonical(value:any):string{
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(value instanceof Date)return JSON.stringify(value.toISOString());
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
const hash=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
const textHash=(value:string)=>createHash('sha256').update(value).digest('hex');
const taxonomy=():ClassificationTaxonomy=>({formatVersion:1,name:'Metadata sensitivity',description:'Synthetic metadata-only labels.',labels:[{key:'contact',name:'Contact metadata',description:'Requires independent review.',status:'active'}]});
const rule=(ownerId:string,label:ClassificationPin):MetadataClassificationRule=>({formatVersion:1,kind:'metadata-literal',name:'Email-name rule',purpose:'Suggest from the canonical metadata name only.',ownerId,status:'active',assetTypes:['column'],label:{taxonomy:label,labelKey:'contact'},all:[{field:'name',operator:'contains',comparison:'ascii-insensitive',literal:'email'}]});
const pin=(id:string,definition:unknown,version=1):ClassificationPin=>({id,version,definitionHash:classificationDefinitionHash(definition)});

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await database.destroy();await owner.end();});await owner.connect();
 await owner.query("SET statement_timeout='15s'; SET lock_timeout='2s'");
 const tenant=randomUUID(),foreign=randomUUID(),actor=randomUUID(),reviewer=randomUUID(),second=randomUUID(),reader=randomUUID(),outsider=randomUUID(),sourceId=randomUUID();
 const ownerTx=async<T>(work:()=>Promise<T>,scope=tenant,who=actor)=>{await owner.query('BEGIN');try{
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),pg_advisory_xact_lock(hashtextextended($1,0))",[scope,who]);
  const value=await work();await owner.query('COMMIT');return value;
 }catch(error){await owner.query('ROLLBACK');throw error;}};
 await owner.query('INSERT INTO tenants(id,name) VALUES($1,$3),($2,$3)',[tenant,foreign,'Synthetic classification qualification']);
 for(const who of [actor,reviewer,second,reader,outsider])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[who,'https://classification-fixture.invalid/owned','Synthetic classification participant']);
 for(const [scope,ids]of [[tenant,[actor,reviewer,second,reader]],[foreign,[outsider]]] as const)await ownerTx(async()=>{
  for(const who of ids)await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[scope,who,'synthetic',JSON.stringify(who===reader?['catalog:read','classification:read']:permissions)]);
 },scope,ids[0]);
 await ownerTx(()=>owner.query('INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',[tenant,sourceId,'Synthetic classification source','classification-source.invalid','synthetic','owned','synthetic-unused','postgresql']));
 const principal=(who=actor,scope=tenant):Principal=>({id:who,tenantId:scope,name:'Synthetic classification participant',permissions});
 const as=<T>(work:(tx:Tx)=>Promise<T>,who:string=actor,scope:string=tenant)=>database.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${scope},true),set_config('gc.actor_id',${who},true)`.execute(tx);await configureRelationTransaction(tx);await lockTenantLedger(tx,scope);return work(tx);
 });
 const command=(operation:string,body:unknown,key=randomUUID(),who=actor)=>as(async tx=>(await sql<{value:any}>`select public.gc_classification_command(${operation},${key},${JSON.stringify(body)}::jsonb,'classification-native') as value`.execute(tx)).rows[0].value,who);
 const approval=(operation:string,body:unknown,key=randomUUID(),who=actor)=>as(async tx=>(await sql<{value:any}>`select public.gc_approval_command(${operation},${key},${JSON.stringify(body)}::jsonb,'classification-native') as value`.execute(tx)).rows[0].value,who);
 const observe=async(name='email_address',dataType='text',fail=false)=>{
  const jobId=randomUUID();await as(tx=>tx.insertInto('jobs').values({tenant_id:tenant,id:jobId,source_id:sourceId,actor_id:actor,status:'queued'}).execute());
  await as(tx=>claimSourceScan(tx,tenant,jobId,'classification-native'),'site:local');
  if(fail){await as(tx=>failSourceScan(tx,tenant,jobId,'SOURCE_DATABASE_ERROR','classification-native'),'site:local');return;}
  await as(tx=>completeSourceScan(tx,tenant,jobId,{observedAt:new Date().toISOString(),sourceVersion:'17 synthetic fixture',permissionFingerprint:'owned-metadata-fixture',complete:true,records:[
   {externalId:'pg:42:schema:10',name:'owned',qualifiedName:'synthetic.owned',type:'schema',metadata:{oid:'10',provenance:'source-observed'}},
   {externalId:'pg:42:relation:101',name:'contacts',qualifiedName:'synthetic.owned.contacts',type:'table',parentExternalId:'pg:42:schema:10',metadata:{oid:'101',relationKind:'r',schema:'owned',table:'contacts',provenance:'source-observed'}},
   {externalId:'pg:42:relation:101:column:1',name,qualifiedName:'synthetic.owned.contacts.'+name,type:'column',parentExternalId:'pg:42:relation:101',metadata:{dataType,ordinalPosition:1,nullable:true,provenance:'source-observed'}}]},'classification-native'),'site:local');
 };
 await observe();
 const assetId=(await as(tx=>tx.selectFrom('assets').select('id').where('source_id','=',sourceId).where('type','=','column').executeTakeFirstOrThrow())).id as string;
 const asset=()=>as(async tx=>{const a=await tx.selectFrom('assets').selectAll().where('id','=',assetId).executeTakeFirstOrThrow();return {id:a.id,version:a.version,type:a.type,name:a.name,qualifiedName:a.qualified_name,dataType:a.metadata.dataType??null} as ClassificationAssetInput;});
 const publishTaxonomy=(definition=taxonomy(),id=randomUUID(),expectedVersion=0,key=randomUUID())=>command('classification.taxonomy.publish',{id,expectedVersion,definition},key);
 const publishRule=(definition:MetadataClassificationRule,id=randomUUID(),expectedVersion=0,key=randomUUID())=>command('classification.rule.publish',{id,expectedVersion,definition},key);
 const setup=async()=>{const a=(await publishTaxonomy()).taxonomy,b=(await publishRule(rule(actor,{id:a.id,version:a.version,definitionHash:a.definitionHash}))).rule;return {taxonomy:a,rule:b};};
 const evaluate=async(selected:ClassificationPin,id=randomUUID(),key=randomUUID(),who=actor)=>{const input=await asset();return command('classification.evaluate',{id,assetId,expectedAssetVersion:input.version,rule:{id:selected.id,version:selected.version,definitionHash:selected.definitionHash}},key,who);};
 const workflowId='classification_'+randomUUID().replaceAll('-','');
 const workflowDefinition=(version=1)=>({formatVersion:1,id:workflowId,version,name:'Independent metadata classification review',separationOfDuties:true,stages:[{id:'review',name:'Independent review',assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'}]});
 const workflow=async()=>{const value=await approval('approval.definition.publish',{definition:workflowDefinition(),expectedVersion:0});return {id:workflowId,version:1,definitionHash:value.definitionHash};};
 const propose=(evaluation:ClassificationEvaluationView,w:ClassificationPin,expectedAssignmentVersion=0,key=randomUUID(),extra:Record<string,unknown>={})=>{
  const body={id:randomUUID(),change:{kind:'apply',suggestionId:evaluation.id,expectedAssignmentVersion},workflow:w,assignments:{steward:reviewer,owner:second},expiresAt:new Date(Date.now()+3600000).toISOString(),...extra};return {body,key,run:()=>command('classification.propose',body,key)};
 };
 const request=(id:string)=>as(async tx=>({row:await tx.selectFrom('approval_requests').selectAll().where('id','=',id).executeTakeFirstOrThrow(),tasks:await tx.selectFrom('approval_tasks').selectAll().where('request_id','=',id).orderBy('assignment').execute()}));
 const decide=async(id:string,who=reviewer,decision='approve',key=randomUUID())=>{const current=await request(id),task=current.tasks.find(r=>r.assigned_identity_id===who);assert.ok(task);
  return approval('approval.decide',{requestId:id,proposalDigest:current.row.proposal_digest,taskId:task.id,taskVersion:task.version,decision,reason:'Reviewed metadata evidence independently'},key,who);};
 const tick=(id:string)=>as(async tx=>(await sql<{value:any}>`select public.gc_approval_tick(${id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const publish=(id:string,who=actor)=>as(async tx=>(await sql<{value:any}>`select public.gc_classification_publish(${id}::uuid) as value`.execute(tx)).rows[0].value,who);
 const ready=async(id:string)=>{await decide(id);await decide(id,second);const result=await tick(id);assert.equal(result.status,'ready');return result;};
 const state=()=>ownerTx(async()=>{const result:Record<string,unknown[]>={};for(const table of snapshots)result[table]=(await owner.query('SELECT * FROM public."'+table+'" WHERE tenant_id=$1',[tenant])).rows.sort((a,b)=>canonical(a).localeCompare(canonical(b)));return result;});
 const unchanged=async(work:()=>Promise<unknown>,predicate:(error:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal leaves canonical data/history/approval/journals/idempotency unchanged');};
 const revoke=(who:string,grants:string[])=>ownerTx(()=>owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,who,JSON.stringify(grants)]));
 const restrict=(allowed:string[])=>ownerTx(()=>owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[tenant,assetId,JSON.stringify(allowed)]));
 return {owner,ownerTx,tenant,foreign,actor,reviewer,second,reader,outsider,sourceId,assetId,as,principal,command,approval,observe,asset,publishTaxonomy,publishRule,setup,evaluate,workflow,workflowDefinition,propose,request,decide,tick,publish,ready,state,unchanged,revoke,restrict};
}

test('classification SQL definition normalization and hashes match pure Unicode, closed fields and exact limits',async t=>{
 const f=await fixture(t),base=taxonomy(),selected=pin(randomUUID(),base),r=rule(f.actor,selected);
 const cases:[string,unknown,boolean][]=[['taxonomy',base,true],['taxonomy',{...base,name:'\uFEFF Cafe\u0301 \u00a0'},true],['taxonomy',{...base,labels:[base.labels[0],base.labels[0]]},false],['taxonomy',{...base,extra:true},false],['taxonomy',{...base,name:'\u0001 Name'},false],['taxonomy',{...base,name:'😀'.repeat(120)},true],['taxonomy',{...base,name:'😀'.repeat(121)},false],['taxonomy',null,false],
  ['rule',r,true],['rule',{...r,all:[{...r.all[0],literal:' \u0065\u0301 '}]},true],['rule',{...r,all:[{...r.all[0],literal:'  '}]},true],['rule',{...r,all:[]},false],['rule',{...r,assetTypes:['column','column']},false],['rule',{...r,label:{...r.label,taxonomy:{...selected,version:0}}},false],['rule',{...r,all:[{...r.all[0],literal:'a\nb'}]},false],['rule',{...r,all:[{...r.all[0],literal:'x'.repeat(257)}]},false]];
 for(const [kind,input,valid]of cases){const parsed=kind==='taxonomy'?parseClassificationTaxonomy(input):parseMetadataClassificationRule(input);assert.equal(parsed.ok,valid);
  const name=kind==='taxonomy'?'taxonomy':'rule',result=(await f.owner.query('SELECT public.gc_classification_'+name+'_valid($1::jsonb) AS valid,public.gc_classification_'+name+'_normalize($1::jsonb) AS normalized',[JSON.stringify(input)])).rows[0];assert.equal(result.valid,valid);
  if(parsed.ok){assert.deepEqual(result.normalized,parsed.value);const stored=(await f.owner.query('SELECT public.gc_type_migration_hash($1::jsonb) AS value',[JSON.stringify(result.normalized)])).rows[0].value;assert.equal(stored,hash(parsed.value));assert.equal(stored,classificationDefinitionHash(parsed.value));}else assert.equal(result.normalized,null);
 }
 // JSONB retains 1.0 spelling; the JS numeric value is still the safe integer 1.
 const float=JSON.stringify(r).replace('"version":1,','"version":1.0,');assert.notEqual(float,JSON.stringify(r));assert.equal((await f.owner.query('SELECT public.gc_classification_rule_valid($1::jsonb) AS valid',[float])).rows[0].valid,true);
});

test('classification SQL evaluation has literal Unicode and ASCII-only semantics with exact observed evidence and digest',async t=>{
 const f=await fixture(t),a=await f.asset(),label=pin(randomUUID(),taxonomy()),base=rule(f.actor,label),at='2026-11-17T00:00:00.000Z';
 const vectors:[MetadataClassificationRule,ClassificationAssetInput,string][]=[
  [base,{...a,name:'EMAIL'},'matched'],[base,{...a,name:'other'},'not_matched'],
  [{...base,all:[{field:'name',operator:'equals',comparison:'exact',literal:'é'}]},{...a,name:'e\u0301'},'matched'],
  [{...base,all:[{field:'name',operator:'equals',comparison:'ascii-insensitive',literal:'Ä'}]},{...a,name:'ä'},'not_matched'],
  [{...base,all:[{field:'name',operator:'contains',comparison:'exact',literal:'.*'}]},{...a,name:'a.*b'},'matched'],
  [{...base,all:[{field:'name',operator:'starts-with',comparison:'exact',literal:' email'}]},{...a,name:' email '},'matched'],
  [{...base,all:[{field:'name',operator:'ends-with',comparison:'exact',literal:'mail '}]},{...a,name:' email '},'matched'],
  [{...base,all:[base.all[0],{field:'dataType',operator:'equals',comparison:'exact',literal:'text'}]},{...a,dataType:null},'not_matched'],
  [base,{...a,type:'metric'},'unsupported'],[{...base,status:'retired'},a,'matched'],
  [{...base,all:[base.all[0],base.all[0]]},a,'matched']];
 for(const [definition,input,outcome]of vectors){const selected=pin(randomUUID(),definition),pure=evaluateMetadataClassification(definition,selected,input,at);assert.equal(pure.ok,true);if(!pure.ok)throw Error('Expected valid pure vector');assert.equal(pure.value.outcome,outcome);
  const actual=(await f.owner.query('SELECT public.gc_classification_evaluate($1::jsonb,$2::jsonb,$3::jsonb,$4::timestamptz) AS value,public.gc_classification_input_digest($1::jsonb,$3::jsonb) AS digest',[JSON.stringify(definition),JSON.stringify(selected),JSON.stringify(input),at])).rows[0];
  assert.deepEqual(actual.value,pure.value);assert.equal(actual.digest,classificationInputDigest(definition,input));
  const fields=Object.fromEntries([...new Set(definition.all.map(p=>p.field))].map(field=>[field,input[field]]));assert.equal(actual.digest,hash({formatVersion:1,assetId:input.id,assetType:input.type,fields}));
  for(const m of actual.value.evidence.matches){assert.equal(m.value,input[m.field as 'name']);assert.equal(m.valueHash,textHash(m.value));}
 }
 assert.equal(classificationInputDigest(base,a),classificationInputDigest(base,{...a,version:a.version+1,dataType:'changed unselected'}));
 assert.notEqual(classificationInputDigest(base,a),classificationInputDigest(base,{...a,name:'different'}));
 const selected=pin(randomUUID(),base),params=[JSON.stringify(base),JSON.stringify(selected),JSON.stringify(a),at];
 for(const overrides of [[1,JSON.stringify({...selected,definitionHash:'0'.repeat(64)})],[2,JSON.stringify({...a,extra:true})],[2,JSON.stringify({...a,name:'bad\nvalue'})],[3,'2026-11-17T00:00:00.000001Z']] as const){const changed=[...params];changed[overrides[0]]=overrides[1];await assert.rejects(()=>f.owner.query('SELECT public.gc_classification_evaluate($1::jsonb,$2::jsonb,$3::jsonb,$4::timestamptz)',changed),exactInvalid);}
 const large={...base,all:Array.from({length:8},()=>({field:'name' as const,operator:'contains' as const,comparison:'exact' as const,literal:'é'}))},largeAsset={...a,name:'é'.repeat(2048)};
 assert.equal(evaluateMetadataClassification(large,pin(randomUUID(),large),largeAsset,at).ok,false);
 await assert.rejects(()=>f.owner.query('SELECT public.gc_classification_evaluate($1::jsonb,$2::jsonb,$3::jsonb,$4::timestamptz)',[JSON.stringify(large),JSON.stringify(pin(randomUUID(),large)),JSON.stringify(largeAsset),at]),exactInvalid);
});

test('classification storage forces tenant RLS and finite writers, protects history and reserved journals',async t=>{
 const f=await fixture(t),s=await f.setup();await f.evaluate(s.rule);
 const flags=(await f.owner.query("SELECT relname,relrowsecurity,relforcerowsecurity,relowner='gc_app'::regrole AS owned,has_table_privilege('gc_app',oid,'INSERT,UPDATE,DELETE,TRUNCATE') AS write FROM pg_class WHERE oid=ANY($1::regclass[]) ORDER BY relname",[tables.map(x=>'public.'+x)])).rows;
 assert.equal(flags.length,tables.length);for(const r of flags){assert.equal(r.relrowsecurity,true);assert.equal(r.relforcerowsecurity,true);assert.equal(r.owned,false);assert.equal(r.write,false);}
 const native=(await f.as(tx=>sql<{rolsuper:boolean;rolbypassrls:boolean}>`select rolsuper,rolbypassrls from pg_roles where rolname=session_user`.execute(tx))).rows[0];assert.deepEqual(native,{rolsuper:false,rolbypassrls:false});
 for(const signature of ['gc_classification_propose(jsonb,text)','gc_classification_asset_input(uuid)','gc_classification_lock_review(uuid)','gc_approval_command_glossary_legacy(text,text,jsonb,text)','gc_approval_tick_glossary_legacy(uuid)'])
  assert.equal((await f.owner.query("SELECT has_function_privilege('gc_app',$1,'EXECUTE') AS allowed",['public.'+signature])).rows[0].allowed,false);
 for(const table of tables){assert.equal((await f.as(tx=>sql`select * from ${sql.table(table)}`.execute(tx),f.outsider,f.foreign)).rows.length,0);
  await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(table)} where tenant_id=${f.tenant}::uuid`.execute(tx)),code('42501'));}
 await f.unchanged(()=>f.as(tx=>sql`insert into public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) values(${f.tenant}::uuid,${f.actor},'classification.evaluate','fabricated-native',${'0'.repeat(64)},'{}'::jsonb)`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.as(tx=>sql`insert into public.outbox(tenant_id,id,event_type,resource_id,resource_version,payload) values(${f.tenant}::uuid,${randomUUID()}::uuid,'classification.applied',${f.assetId},1,'{}'::jsonb)`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE classification_taxonomy_versions SET definition=definition WHERE tenant_id=$1',[f.tenant])),error=>code('P0001')(error)&&error instanceof Error&&error.message==='audit is append only');
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE classification_rules SET current_version=current_version+2 WHERE tenant_id=$1',[f.tenant])),code('42501'));
 const foreignRule=randomUUID();await f.unchanged(()=>f.ownerTx(async()=>{
  await f.owner.query('INSERT INTO classification_rules VALUES($1,$2,1,$3,clock_timestamp())',[f.foreign,foreignRule,f.outsider]);
  // Otherwise valid foreign-owned definition cannot reference a taxonomy pin
  // from the primary tenant; this is a real composite FK, not an API check.
  await f.owner.query('INSERT INTO classification_rule_versions VALUES($1,$2,1,$3::jsonb,$4,$5,1,$6,$7,$7,clock_timestamp())',[f.foreign,foreignRule,JSON.stringify({...s.rule.definition,ownerId:f.outsider}),classificationDefinitionHash({...s.rule.definition,ownerId:f.outsider}),s.taxonomy.id,s.taxonomy.definitionHash,f.outsider]);
 },f.foreign,f.outsider),code('23503'));
 assert.equal((await f.ownerTx(()=>f.owner.query('SELECT id FROM classification_rules WHERE tenant_id=$1 AND id=$2',[f.foreign,foreignRule]),f.foreign,f.outsider)).rows.length,0);
});

test('classification definition versions and exact replay retain immutable pins and paired audit/outbox',async t=>{
 const f=await fixture(t),id=randomUUID(),key=randomUUID(),body={id,expectedVersion:0,definition:taxonomy()},first=await f.command('classification.taxonomy.publish',body,key),before=await f.state();
 assert.deepEqual(await f.command('classification.taxonomy.publish',body,key),first);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.command('classification.taxonomy.publish',{...body,definition:{...taxonomy(),name:'Changed'}},key),code('40001'));
 const second=await f.publishTaxonomy({...taxonomy(),name:'Second publication'},id,1);assert.equal(second.taxonomy.version,2);
 const prior=await f.as(tx=>getClassificationTaxonomy(tx,f.principal(),id,1));assert.equal(prior.currentVersion,2);assert.deepEqual(prior.definition,first.taxonomy.definition);assert.equal(prior.definitionHash,first.taxonomy.definitionHash);
 const state=await f.state(),audit=(state.audit as any[]).filter(x=>x.action.startsWith('classification.')),outbox=(state.outbox as any[]).filter(x=>x.event_type.startsWith('classification.'));
 assert.equal(audit.length,2);assert.deepEqual(audit.map(x=>x.id).sort(),outbox.map(x=>x.id).sort());assert.equal(state.classification_taxonomy_versions.length,2);
});

test('classification suggestions require independent quorum and only protected finalization applies or withdraws labels',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();
 assert.equal((await f.state()).classification_assignments.length,0);await f.unchanged(()=>f.publish(p.body.id),code('40001'));
 await f.decide(p.body.id);assert.equal((await f.tick(p.body.id)).status,'pending');assert.equal((await f.state()).classification_assignments.length,0);
 await f.decide(p.body.id,f.second);assert.equal((await f.tick(p.body.id)).status,'ready');await f.unchanged(()=>f.publish(p.body.id,f.reviewer),code('42501'));
 const applied=await f.publish(p.body.id);assert.equal(applied.binding,'classification.review');assert.equal(applied.status,'active');assert.equal(applied.assignmentVersion,1);assert.equal(applied.assetId,f.assetId);
 const before=await f.state();assert.deepEqual(await f.publish(p.body.id),applied);assert.deepEqual(await f.state(),before);
 const view=await f.as(tx=>listClassificationAssignments(tx,f.principal(),f.assetId));assert.equal(view.items.length,1);assert.equal(view.items[0].reason,'');assert.equal(view.items[0].evidenceCurrent,true);assert.deepEqual(parseClassificationAssignmentView(view.items[0]),view.items[0]);
 // Retiring the detector must not trap an already reviewed assignment: a new
 // independently reviewed withdrawal retains its original evidence/pin.
 await f.publishRule({...s.rule.definition,status:'retired'},s.rule.id,1);
 const withdrawal={id:randomUUID(),change:{kind:'withdraw',assignmentId:applied.assignmentId,expectedAssignmentVersion:1,reason:'Retire after independent review'},workflow:w,assignments:{steward:f.reviewer,owner:f.second},expiresAt:new Date(Date.now()+3600000).toISOString()};
 await f.command('classification.propose',withdrawal);await f.ready(withdrawal.id);const removed=await f.publish(withdrawal.id);assert.equal(removed.assignmentVersion,2);assert.equal(removed.status,'withdrawn');
 assert.equal((await f.request(p.body.id)).row.status,'succeeded');assert.equal((await f.request(withdrawal.id)).row.status,'succeeded');
 const state=await f.state();assert.equal(state.classification_assignments.length,1);assert.equal(state.classification_assignment_revisions.length,2);assert.equal((state.classification_assignment_revisions[0] as any).status==='active'||(state.classification_assignment_revisions[1] as any).status==='active',true);
});

test('classification self-review, duplicate reviewers, rejection and cancellation never produce an assignment',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule);
 for(const assignments of [{steward:f.actor,owner:f.second},{steward:f.reviewer,owner:f.reviewer}]){const p=f.propose(evaluation,w,0,randomUUID(),{assignments});await f.unchanged(p.run,code('42501'));}
 const rejected=f.propose(evaluation,w);await rejected.run();await f.decide(rejected.body.id,f.reviewer,'reject');assert.equal((await f.tick(rejected.body.id)).status,'rejected');await f.unchanged(()=>f.publish(rejected.body.id),code('40001'));
 const cancelled=f.propose(evaluation,w);await cancelled.run();const current=(await f.request(cancelled.body.id)).row;
 await f.approval('approval.cancel',{requestId:current.id,proposalDigest:current.proposal_digest,reason:'No longer required'});assert.equal((await f.tick(current.id)).status,'cancelled');await f.unchanged(()=>f.publish(current.id),code('40001'));
 assert.equal((await f.state()).classification_assignments.length,0);
});

test('classification current permissions and ACL govern reads, new commands and successful replay',async t=>{
 const f=await fixture(t),s=await f.setup(),a=await f.asset(),id=randomUUID(),key=randomUUID(),body={id,assetId:f.assetId,expectedAssetVersion:a.version,rule:{id:s.rule.id,version:s.rule.version,definitionHash:s.rule.definitionHash}};
 const first=await f.command('classification.evaluate',body,key);assert.equal(first.evaluation.outcome,'matched');
 await f.restrict([f.reviewer,f.second]);await f.unchanged(()=>f.command('classification.evaluate',body,key),code('P0002'));
 await f.unchanged(()=>f.as(tx=>listClassificationSuggestions(tx,f.principal(),f.assetId)),problem(404));
 await f.restrict([f.actor,f.reviewer,f.second]);await f.revoke(f.actor,['catalog:read','classification:read']);
 await f.unchanged(()=>f.command('classification.evaluate',body,key),code('42501'));
 await f.unchanged(()=>f.evaluate(s.rule,randomUUID(),randomUUID(),f.reader),code('42501'));
 await f.unchanged(()=>f.as(tx=>listClassificationSuggestions(tx,f.principal(f.outsider,f.foreign),f.assetId),f.outsider,f.foreign),problem(404));
});

test('classification selected metadata drift blocks proposal and final effect; harmless rescans retain the reviewed label',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();await f.ready(p.body.id);
 await f.observe('email_address','varchar');const refreshed=await f.asset();assert.ok(refreshed.version>evaluation.evidence.observedAssetVersion);
 const same=await f.as(tx=>listClassificationSuggestions(tx,f.principal(),f.assetId));assert.equal(same.items[0].evidenceCurrent,true);const applied=await f.publish(p.body.id);
 await f.observe('email_address','integer',true);assert.equal((await f.as(tx=>listClassificationAssignments(tx,f.principal(),f.assetId))).items[0].id,applied.assignmentId);
 await f.observe('phone_number');const stale=await f.as(tx=>listClassificationAssignments(tx,f.principal(),f.assetId));assert.equal(stale.items[0].status,'active');assert.equal(stale.items[0].evidenceCurrent,false);
 const proposal=f.propose(evaluation,w,1);await f.unchanged(proposal.run,code('40001'));
 const newest=await f.evaluate(s.rule);assert.equal(newest.evaluation.outcome,'not_matched');assert.equal(newest.evaluation.suggestionId,null);
});

test('classification final effect rechecks selected input, taxonomy pin and rule pin',async t=>{
 for(const changed of ['input','taxonomy','rule'] as const){const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();await f.ready(p.body.id);
  if(changed==='input')await f.observe('phone_number');
  if(changed==='taxonomy')await f.publishTaxonomy({...taxonomy(),labels:[{...taxonomy().labels[0],status:'deprecated'}]},s.taxonomy.id,1);
  if(changed==='rule')await f.publishRule({...s.rule.definition,status:'retired'},s.rule.id,1);
  await f.unchanged(()=>f.publish(p.body.id),code('40001'));assert.equal((await f.state()).classification_assignments.length,0);
 }
});

test('classification request executes its immutable workflow version after the definition head changes',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();
 const pinned=await f.request(p.body.id),next={...f.workflowDefinition(2),stages:[{...f.workflowDefinition(2).stages[0],quorum:1}]};
 await f.approval('approval.definition.publish',{definition:next,expectedVersion:1});
 await f.decide(p.body.id);assert.equal((await f.tick(p.body.id)).status,'pending','Pinned v1 still requires both reviewers');
 await f.decide(p.body.id,f.second);assert.equal((await f.tick(p.body.id)).status,'ready');assert.equal((await f.publish(p.body.id)).status,'active');
 const retained=await f.request(p.body.id);assert.equal(retained.row.workflow_version,1);assert.equal(retained.row.workflow_hash,w.definitionHash);
 assert.deepEqual(retained.tasks.map(t=>[t.id,t.assignment,t.assigned_identity_id,t.stage_index]),pinned.tasks.map(t=>[t.id,t.assignment,t.assigned_identity_id,t.stage_index]));
});

test('classification final effect rechecks requester, reviewers and current target visibility',async t=>{
 for(const changed of ['requester','reviewer','acl'] as const){const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();await f.ready(p.body.id);
  if(changed==='requester')await f.revoke(f.actor,['catalog:read','classification:read']);
  if(changed==='reviewer')await f.revoke(f.reviewer,['catalog:read','classification:read']);
  if(changed==='acl')await f.restrict([f.actor,f.second]);
  await f.unchanged(()=>f.publish(p.body.id),code('42501'));assert.equal((await f.state()).classification_assignments.length,0);
 }
});

test('classification two reviewed proposals cannot both consume one assignment version',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),one=f.propose(evaluation,w),two=f.propose(evaluation,w);
 await one.run();await two.run();await f.ready(one.body.id);await f.ready(two.body.id);await f.publish(one.body.id);
 await f.unchanged(()=>f.publish(two.body.id),code('40001'));const state=await f.state();assert.equal(state.classification_assignments.length,1);assert.equal(state.classification_assignment_revisions.length,1);
});

test('classification paging binds actor tenant and collection while filtering hidden targets before exposure',async t=>{
 const f=await fixture(t);await f.publishTaxonomy();await f.publishTaxonomy();
 const first=await f.as(tx=>listClassificationTaxonomies(tx,f.principal(),{limit:1}));assert.equal(first.items.length,1);assert.ok(first.nextCursor);
 const next=await f.as(tx=>listClassificationTaxonomies(tx,f.principal(),{limit:1,cursor:first.nextCursor!}));assert.equal(next.items.length,1);assert.notEqual(next.items[0].id,first.items[0].id);assert.equal(next.nextCursor,null);
 await f.unchanged(()=>f.as(tx=>listClassificationTaxonomies(tx,f.principal(f.reader),{limit:1,cursor:first.nextCursor!}),f.reader),problem(400));
 await f.unchanged(()=>f.as(tx=>listClassificationTaxonomies(tx,f.principal(),{limit:2,cursor:first.nextCursor!})),problem(400));
 const s=await f.setup();await f.evaluate(s.rule);await f.restrict([f.actor]);
 await f.unchanged(()=>f.as(tx=>listClassificationSuggestions(tx,f.principal(f.reader),f.assetId),f.reader),problem(404));
 await f.unchanged(()=>f.as(tx=>listClassificationAssignments(tx,f.principal(f.reader),f.assetId),f.reader),problem(404));
});

test('classification transaction rollback preserves canonical assignment and paired approval audit/outbox',async t=>{
 const f=await fixture(t),s=await f.setup(),w=await f.workflow(),{evaluation}=await f.evaluate(s.rule),p=f.propose(evaluation,w);await p.run();await f.ready(p.body.id);
 const marker=new Error('Synthetic rollback after protected finalization');
 await f.unchanged(()=>f.as(async tx=>{const value=(await sql<{value:any}>`select public.gc_classification_publish(${p.body.id}::uuid) as value`.execute(tx)).rows[0].value;assert.equal(value.status,'active');throw marker;}),error=>error===marker);
 await f.publish(p.body.id);const state=await f.state(),request=(await f.request(p.body.id)).row;assert.equal(request.status,'succeeded');assert.equal(state.classification_assignment_revisions.length,1);
 const audit=(state.audit as any[]).filter(r=>r.action.startsWith('classification.')||r.action.startsWith('approval.'));
 const outbox=(state.outbox as any[]).filter(r=>r.event_type.startsWith('classification.')||r.event_type.startsWith('approval.'));
 assert.deepEqual(audit.map(r=>r.id).sort(),outbox.map(r=>r.id).sort());
});
