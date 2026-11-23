// SPDX-License-Identifier: Apache-2.0
/** Real reviewed classification facts assembled under the native owner snapshot.
 * Returned contexts remain inactive provenance, not an effect capability. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import pg from 'pg';
import {fixture,closeDefaultDb,apply,asset,bind,revokeProducer,read,readInput,heads,snapshot,labelId,taxonomy,rule,pin,publishTaxonomy,publishRule,setup,evaluate,workflow,propose,request,decide,tick,ready,publish,withdraw,observe,reviseDescription,producerLookup,query,scalar,tx,scope,uuid,dbNow,config,failure,decisionHash,canonicalDecisionJSON,zero,approval,preBaselineFixtureMarker,adoptPreBaselineFixture} from '../fixtures/reviewed-classification-facts.ts';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import type {NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import {parseInactiveClassifiedAssetContext} from '../../packages/authority-runtime/src/classified-asset-context.ts';
import type {Digest,UUID,Version} from '../../packages/authority/src/types.ts';

after(closeDefaultDb);
type Fixture=Awaited<ReturnType<typeof fixture>>;
type Context=Awaited<ReturnType<typeof read>>;
function empty(value:Context){assert.deepEqual(value.classifications,{status:'known',value:[]});assert.deepEqual(value.approvedFacts,[]);assert.ok(value.producerBinding&&value.producerBinding.operation==='bind');}
function unavailable(value:Context){assert.deepEqual(value.classifications,{status:'unavailable'});assert.deepEqual(value.approvedFacts,[]);}
function context(value:Context,f:Fixture,version=1){
 assert.equal(value.formatVersion,1);assert.equal(value.kind,'inactive-classified-asset-context');assert.equal(value.contentAuthority,false);assert.equal(value.context.contentAuthority,false);
 assert.equal(value.context.context.asset.tenantId,f.tenant);assert.equal(value.context.context.asset.id,f.assetId);assert.equal(value.context.context.asset.version,version);assert.equal(value.context.context.registry.digest,f.registry.digest);
 assert.equal(value.context.context.closure.snapshot.registryId,f.registryId);assert.equal(value.contextDigest,decisionHash({...value,contextDigest:zero}));assert.equal(value.context.contextDigest,decisionHash({...value.context,contextDigest:zero}));
 const parsed=parseInactiveClassifiedAssetContext(value);assert.equal(parsed.ok,true);if(parsed.ok)assert.deepEqual(parsed.value,value);
}
async function heldRead(f:Fixture,change:()=>Promise<unknown>,version=1){
 const pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000}),statements:string[]=[];let changed=false;
 const observed:NativeOwnerPool={async connect(){const client=await pool.connect();return {async query(text,values){statements.push(text);const result=await client.query(text,values);if(text.includes('AS native_owner')){assert.equal(changed,false);await change();changed=true;}return result;},release(error){client.release(error);}};}};
 try{const result=await read(f,version,observed);assert.equal(changed,true);assert.equal(statements.filter(text=>text==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY').length,1);assert.equal(statements.filter(text=>text==='COMMIT').length,1);assert.equal(statements.filter(text=>text.includes('load_human_closure_v1')).length,1);assert.equal(statements.filter(text=>text.includes('load_reviewed_classification_producer_v1')).length,1);return result;}finally{await pool.end();assert.equal(pool.totalCount,0);}
}

test('real reviewed publication produces exact assignment provenance and stable label UUID without writing or activating authority',async t=>{
 const f=await fixture(t),applied=await apply(f),before=await snapshot(f),value=await read(f),id=await labelId(f,applied.taxonomy!.id,'contact');context(value,f);
 assert.deepEqual(value.classifications,{status:'known',value:[{id:applied.result.assignmentId,version:1}]});assert.equal(value.approvedFacts.length,1);
 const fact=value.approvedFacts[0]!,revision=await scalar(f.admin,'SELECT public.gc_relation_utc(created_at) stamp FROM public.classification_assignment_revisions WHERE tenant_id=$1 AND assignment_id=$2 AND version=1',[f.tenant,applied.result.assignmentId]);
 assert.deepEqual(fact,{ref:{id:applied.result.assignmentId,version:1},kind:'classifications',provenance:{producer:f.producers.primary.ref,tenantId:f.tenant,registryDigest:f.registry.digest,sourceRecordId:applied.result.assignmentId,sourceRecordVersion:1},resource:{tenantId:f.tenant,kind:'asset',id:f.assetId},revision:1,fieldId:null,securityRevision:value.context.securityRevision,state:'approved',validity:{notBefore:revision.stamp,expiresAt:null},values:[id]});
 assert.notEqual(id,applied.taxonomy!.id);assert.notEqual(id,applied.result.assignmentId);assert.deepEqual(await snapshot(f),before);assert.equal((await scalar(f.admin,'SELECT mode FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).mode,'inactive');
});

test('complete empty discovery is known only after explicit producer installation',async t=>{
 const f=await fixture(t,{bind:false}),before=await read(f);context(before,f);unavailable(before);assert.equal(before.producerBinding,null);
 await bind(f);const current=await read(f);empty(current);assert.equal(BigInt(current.context.context.closure.snapshot.authorityEpoch),BigInt(before.context.context.closure.snapshot.authorityEpoch)+1n);assert.equal(current.context.securityRevision,before.context.securityRevision);
});

test('suggestions pending ready and rejected reviews do not become approved classification facts',async t=>{
 const f=await fixture(t),definitions=await setup(f),w=await workflow(f),evaluation=await evaluate(f,definitions.rule);empty(await read(f));
 const first=await propose(f,evaluation,w);empty(await read(f));await ready(f,first,w);empty(await read(f));
 const second=await propose(f,evaluation,w);await decide(f,second,f.reviewers[0]!,'reject');assert.equal((await tick(f,second)).status,'rejected');empty(await read(f));
 await publish(f,first);assert.equal((await read(f)).approvedFacts.length,1);
});

test('complete independently reviewed withdrawal is known empty even after its historic rule retires',async t=>{
 const f=await fixture(t),applied=await apply(f);await publishRule(f,{...applied.rule.definition,status:'retired'},applied.rule.id,1);unavailable(await read(f));
 const withdrawn=await withdraw(f,applied.result,applied.workflow);assert.equal(withdrawn.result.assignmentVersion,2);empty(await read(f));
 assert.equal((await request(f,applied.requestId)).row.status,'succeeded');assert.equal((await request(f,withdrawn.requestId)).row.status,'succeeded');assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM public.classification_assignment_revisions WHERE tenant_id=$1',[f.tenant])).n,2);
});

test('multiple reviewed labels yield complete unique facts and canonical sorted reference coverage',async t=>{
 const f=await fixture(t),tax=await publishTaxonomy(f,taxonomy(['contact','restricted'])),w=await workflow(f),first=await apply(f,{workflow:w,selected:await publishRule(f,rule(f,tax,'contact'))}),second=await apply(f,{workflow:w,selected:await publishRule(f,rule(f,tax,'restricted'))}),value=await read(f);
 assert.equal(value.classifications.status,'known');if(value.classifications.status!=='known')assert.fail('Expected known complete partition');
 const refs=[{id:first.result.assignmentId,version:1},{id:second.result.assignmentId,version:1}].sort((a,b)=>a.id.localeCompare(b.id));assert.deepEqual(value.classifications.value,refs);assert.deepEqual(value.approvedFacts.map(fact=>fact.ref),refs);
 assert.deepEqual(new Set(value.approvedFacts.flatMap(fact=>fact.values)),new Set([await labelId(f,tax.id,'contact'),await labelId(f,tax.id,'restricted')]));assert.equal(new Set(value.approvedFacts.map(fact=>fact.provenance.sourceRecordId)).size,2);
});

test('multi-stage quorum admits cancelled unanswered tasks and the exact incremented decision versions',async t=>{
 const f=await fixture(t),w=await workflow(f,{stages:3,assignments:3,quorum:1}),applied=await apply(f,{workflow:w}),stored=await request(f,applied.requestId);assert.equal(stored.tasks.length,9);assert.equal(stored.decisions.length,3);
 assert.equal(stored.tasks.filter(row=>row.status==='cancelled').length,6);assert.equal(stored.tasks.filter(row=>row.status==='decided').length,3);
 for(const decision of stored.decisions){const task=stored.tasks.find(row=>row.id===decision.task_id)!;assert.equal(task.version,decision.task_version+1);assert.equal(decision.task_version,task.stage_index===0?1:2);}
 const value=await read(f);assert.equal(value.approvedFacts.length,1);assert.equal(value.approvedFacts[0]!.ref.id,applied.result.assignmentId);
});

test('description-only current asset revision keeps reviewed selected-field evidence and binds the new revision',async t=>{
 const f=await fixture(t),applied=await apply(f),before=await read(f),next=await reviseDescription(f),value=await read(f,next.version);context(value,f,next.version);
 assert.equal(value.approvedFacts.length,1);assert.equal(value.approvedFacts[0]!.revision,next.version);assert.equal(value.approvedFacts[0]!.provenance.sourceRecordVersion,1);assert.deepEqual(value.approvedFacts[0]!.values,before.approvedFacts[0]!.values);assert.equal(value.approvedFacts[0]!.ref.id,applied.result.assignmentId);assert.ok(BigInt(value.context.securityRevision)>BigInt(before.context.securityRevision));
});

test('a real rescan of selected metadata makes the complete classification partition unavailable',async t=>{
 const f=await fixture(t),applied=await apply(f);await observe(f,'phone_number');const current=await asset(f),value=await read(f,current.version);unavailable(value);
 assert.equal((await scalar(f.admin,'SELECT status FROM public.classification_assignments WHERE tenant_id=$1 AND id=$2',[f.tenant,applied.result.assignmentId])).status,'active','Product history remains present when authority evidence becomes stale');
});

test('retiring a current detector leaves its reviewed assignment unavailable',async t=>{
 const f=await fixture(t),applied=await apply(f);await publishRule(f,{...applied.rule.definition,status:'retired'},applied.rule.id,1);unavailable(await read(f));assert.equal((await producerLookup(f)).binding!.operation,'bind');
});

test('taxonomy display repin preserves label identity but requires a new reviewed current rule and assignment revision',async t=>{
 const f=await fixture(t),applied=await apply(f),before=await read(f),tax=applied.taxonomy!,updated=await publishTaxonomy(f,{...tax.definition,name:'Renamed synthetic taxonomy'},tax.id,1);unavailable(await read(f));
 assert.equal(await labelId(f,tax.id,'contact'),before.approvedFacts[0]!.values[0]);const currentRule=await publishRule(f,{...applied.rule.definition,label:{...applied.rule.definition.label,taxonomy:pin(updated)}},applied.rule.id,1),next=await apply(f,{selected:currentRule,workflow:applied.workflow,expectedAssignmentVersion:1}),value=await read(f);
 assert.equal(next.result.assignmentId,applied.result.assignmentId);assert.equal(value.approvedFacts[0]!.ref.version,2);assert.equal(value.approvedFacts[0]!.provenance.sourceRecordVersion,2);assert.deepEqual(value.approvedFacts[0]!.values,before.approvedFacts[0]!.values);
});

test('deprecating a canonical label invalidates active authority facts without recycling its stable UUID',async t=>{
 const f=await fixture(t),applied=await apply(f),tax=applied.taxonomy!,id=await labelId(f,tax.id,'contact');await publishTaxonomy(f,{...tax.definition,labels:tax.definition.labels.map(label=>({...label,status:'deprecated'}))},tax.id,1);unavailable(await read(f));assert.equal(await labelId(f,tax.id,'contact'),id);assert.equal((await scalar(f.admin,'SELECT retired_at_version FROM gc_authority.classification_label_identities WHERE tenant_id=$1 AND id=$2',[f.tenant,id])).retired_at_version,2);
});

test('one stale active assignment refuses the entire partition instead of returning the other valid fact',async t=>{
 const f=await fixture(t),a=await apply(f,{key:'contact'});await apply(f,{key:'other_contact'});assert.equal((await read(f)).approvedFacts.length,2);await publishRule(f,{...a.rule.definition,status:'retired'},a.rule.id,1);unavailable(await read(f));
});

test('revoked producer refuses both an active partition and a previously valid known-empty partition',async t=>{
 const f=await fixture(t);empty(await read(f));const applied=await apply(f);await revokeProducer(f);unavailable(await read(f));await bind(f);assert.equal((await read(f)).approvedFacts.length,1);await withdraw(f,applied.result,applied.workflow);empty(await read(f));await revokeProducer(f);const unavailableEmpty=await read(f);unavailable(unavailableEmpty);assert.equal(unavailableEmpty.producerBinding!.operation,'revoke');
});

test('producer expiry is checked even for zero active assignments and does not prevent an explicit revoke',async t=>{
 const f=await fixture(t,{producerLifetimeMs:12000}),expiry=Date.parse(f.producers.primary.validity.expiresAt!);empty(await read(f));const deadline=performance.now()+15000;
 while(Date.parse(await dbNow(f.owner))<=expiry){assert.ok(performance.now()<deadline,'Synthetic producer did not expire inside the bounded test interval');await new Promise(resolve=>setTimeout(resolve,100));}
 unavailable(await read(f));await revokeProducer(f);assert.equal((await producerLookup(f)).binding!.operation,'revoke');
});

test('a held reader cannot combine an earlier empty snapshot with a concurrent reviewed application',async t=>{
 const f=await fixture(t),before=await read(f),held=await heldRead(f,()=>apply(f));empty(held);assert.equal(held.context.securityRevision,before.context.securityRevision);assert.equal(held.context.context.closure.snapshot.authorityEpoch,before.context.context.closure.snapshot.authorityEpoch);
 const fresh=await read(f);assert.equal(fresh.approvedFacts.length,1);assert.ok(BigInt(fresh.context.securityRevision)>BigInt(held.context.securityRevision));
});

test('a held reader retains the full reviewed fact while a concurrent withdrawal becomes visible only in a fresh snapshot',async t=>{
 const f=await fixture(t),applied=await apply(f),before=await read(f),held=await heldRead(f,()=>withdraw(f,applied.result,applied.workflow));assert.deepEqual(held.approvedFacts,before.approvedFacts);assert.deepEqual(held.classifications,before.classifications);assert.equal(held.context.securityRevision,before.context.securityRevision);
 const fresh=await read(f);empty(fresh);assert.ok(BigInt(fresh.context.securityRevision)>BigInt(held.context.securityRevision));
});

test('producer revocation is atomic with the authority epoch for held and fresh classified readers',async t=>{
 const f=await fixture(t);await apply(f);const before=await read(f),held=await heldRead(f,()=>revokeProducer(f));assert.deepEqual(held.producerBinding,before.producerBinding);assert.deepEqual(held.approvedFacts,before.approvedFacts);
 const fresh=await read(f);unavailable(fresh);assert.equal(fresh.context.securityRevision,held.context.securityRevision);assert.equal(BigInt(fresh.context.context.closure.snapshot.authorityEpoch),BigInt(held.context.context.closure.snapshot.authorityEpoch)+1n);
});

test('classified repository rejects missing foreign and stale assets without weakening exact target admission',async t=>{
 const f=await fixture(t),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000}),foreign=uuid();
 await tx(f.owner,async()=>{await scope(f.owner,f,f.otherTenant);await query(f.owner,"INSERT INTO public.assets(tenant_id,id,external_id,name,qualified_name,type,observed_at) VALUES($1::uuid,$2::uuid,$2::uuid::text,'Synthetic foreign asset',$2::uuid::text,'column',clock_timestamp())",[f.otherTenant,foreign]);});
 const before=await snapshot(f);try{for(const input of [{...readInput(f),assetId:uuid() as UUID},{...readInput(f),assetId:foreign as UUID},{...readInput(f),expectedVersion:2 as Version}])await assert.rejects(createAuthorityFoundationRepository(pool).loadClassifiedHumanAssetContext(input),failure('VERSION_CONFLICT'));}finally{await pool.end();}assert.deepEqual(await snapshot(f),before);
});

test('all runtime credentials refuse the classified owner repository despite forged tenant actor and owner GUCs',async t=>{
 const f=await fixture(t);await apply(f);const before=await snapshot(f);
 for(const url of [config.legacy,f.roles.login.url,f.roles.api.url,f.roles.nextLogin.url,f.roles.nextApi.url,config.unregistered.url]){
  const pool=new pg.Pool({connectionString:url,max:1,connectionTimeoutMillis:5000});try{const client=await pool.connect();await client.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false),set_config('gc.authn_owner','gc_owner',false)",[f.tenant,f.identity]);client.release();await assert.rejects(createAuthorityFoundationRepository(pool).loadClassifiedHumanAssetContext(readInput(f)),failure('EXECUTOR_REJECTED'));}finally{await pool.end();assert.equal(pool.totalCount,0);}
 }
 assert.deepEqual(await snapshot(f),before);
});

test('classified reads restore prior pooled context and revoked sessions cannot reuse their earlier evidence',async t=>{
 const f=await fixture(t),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000}),actor=uuid();let client=await pool.connect();await client.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.otherTenant,actor]);client.release();
 try{empty(await read(f,1,pool));client=await pool.connect();assert.deepEqual((await client.query("SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('transaction_read_only') readonly")).rows,[{tenant:f.otherTenant,actor,readonly:'off'}]);client.release();await query(f.api,'SELECT * FROM public.gc_authn_session_revoke($1,$2,1)',[f.hash,f.csrf]);await assert.rejects(read(f,1,pool),failure('SESSION_REJECTED'));}finally{await pool.end();assert.equal(pool.totalCount,0);}
});

test('existing context methods keep their prior unavailable-fact contract after the new classified reader is added',async t=>{
 const f=await fixture(t);await apply(f);const pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000});try{const repository=createAuthorityFoundationRepository(pool),old=await repository.loadHumanAssetContext(readInput(f)),versioned=await repository.loadVersionedHumanAssetContext(readInput(f));assert.deepEqual(old.unavailableFacts,['classification','approved-tags','purpose','environment']);assert.deepEqual(versioned.context.unavailableFacts,old.unavailableFacts);assert.equal(Object.hasOwn(old,'approvedFacts'),false);assert.equal(Object.hasOwn(versioned,'approvedFacts'),false);assert.equal(old.contentAuthority,false);assert.equal(versioned.contentAuthority,false);}finally{await pool.end();}
});

test('complete canonical discovery admits 256 heads to byte preflight and refuses the 257th before measuring or loading proofs',async t=>{
 const f=await fixture(t),w=await workflow(f,{assignments:1,quorum:1}),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000});
 const phases:string[]=[],countRows:Record<string,unknown>[]=[],measureRows:Record<string,unknown>[]=[];
 const observed:NativeOwnerPool={async connect(){const client=await pool.connect();return {async query(text,values){
  const result=await client.query(text,values);
  for(const phase of ['counts','measure','bodies'])if(text.includes('reviewed-classification:'+phase)){phases.push(phase);if(phase==='counts')countRows.push(result.rows[0]);if(phase==='measure')measureRows.push(result.rows[0]);}
  return result;
 },release(error){client.release(error);}};}};
 try{
  for(let i=0;i<256;i++)await apply(f,{workflow:w});
  // This legitimate256-head inventory exceeds the independent2MiB proof cap.
  // The real measure query proves that256 passed the count guard; no body is
  // read and no claim is made that this full inventory fits the byte profile.
  let before=await snapshot(f);await assert.rejects(read(f,1,observed),failure('PROFILE_LIMIT'));assert.deepEqual(await snapshot(f),before);
  assert.deepEqual(phases,['counts','measure']);assert.equal(countRows.length,1);assert.equal(measureRows.length,1);
  const counts=countRows[0]!,measured=measureRows[0]!;
  assert.deepEqual(Object.fromEntries(Object.entries(counts).map(([key,value])=>[key,Number(value)])),{assignments:256,tasks:256,max_tasks:1,decisions:256,max_decisions:1});
  assert.equal(Number(measured.assignments),256);assert.equal(measured.dependencies_complete,true);assert.equal(measured.component_bounds,true);
  assert.ok(Number(measured.canonical_bytes)+257>2097152||Number(measured.raw_bytes)+257>2097152);
  await apply(f,{workflow:w});phases.length=0;countRows.length=0;measureRows.length=0;
  before=await snapshot(f);await assert.rejects(read(f,1,observed),failure('PROFILE_LIMIT'));assert.deepEqual(await snapshot(f),before);
  assert.deepEqual(phases,['counts']);assert.equal(countRows.length,1);assert.equal(Number(countRows[0]!.assignments),257);assert.equal(measureRows.length,0);
  assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM public.classification_assignments WHERE tenant_id=$1 AND asset_id=$2',[f.tenant,f.assetId])).n,257);
 }finally{await pool.end();assert.equal(pool.totalCount,0);}
});

test('a preserved pre034 reviewed assignment remains unavailable when its historical taxonomy pin has no baseline binding',async t=>{
 const marker=preBaselineFixtureMarker(),f=await adoptPreBaselineFixture(t,marker);
 const stored=await scalar(f.admin,`SELECT a.status,a.version,a.asset_id,a.taxonomy_id,a.label_key,
  ar.suggestion_id,ar.approval_request_id,e.asset_version,e.rule_id,e.rule_version,
  rv.taxonomy_version,rv.taxonomy_hash,r.requester_id,r.status request_status,r.workflow_version,w.current_version workflow_head_version,
  (SELECT count(*)::int FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id AND t.status='decided') decided_tasks,
  (SELECT count(*)::int FROM public.approval_decisions d WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND d.decision='approve') approvals
  FROM public.classification_assignments a
  JOIN public.classification_assignment_revisions ar ON (ar.tenant_id,ar.assignment_id,ar.version)=(a.tenant_id,a.id,a.version)
  JOIN public.classification_evaluations e ON (e.tenant_id,e.id)=(ar.tenant_id,ar.suggestion_id)
  JOIN public.classification_rule_versions rv ON (rv.tenant_id,rv.rule_id,rv.version)=(e.tenant_id,e.rule_id,e.rule_version)
  JOIN public.approval_requests r ON (r.tenant_id,r.id)=(ar.tenant_id,ar.approval_request_id)
  JOIN public.workflow_definitions w ON (w.tenant_id,w.id)=(r.tenant_id,r.workflow_id)
  WHERE a.tenant_id=$1 AND a.id=$2`,[f.tenant,marker.assignmentId]);
 assert.deepEqual(stored,{status:'active',version:marker.assignmentVersion,asset_id:marker.assetId,taxonomy_id:marker.taxonomyId,label_key:marker.labelKey,
  suggestion_id:marker.suggestionId,approval_request_id:marker.approvalRequestId,asset_version:marker.assetVersion,rule_id:marker.ruleId,rule_version:marker.ruleVersion,
  taxonomy_version:marker.historicalTaxonomyVersion,taxonomy_hash:marker.historicalTaxonomyHash,requester_id:marker.requesterId,request_status:'succeeded',workflow_version:1,workflow_head_version:2,decided_tasks:2,approvals:2});
 assert.notEqual(f.identity,marker.requesterId);
 const baseline=await scalar(f.admin,`SELECT b.baseline_version,b.baseline_hash,i.id,i.first_registered_version,i.retired_at_version,
  v.taxonomy_version,v.label_status,v.label_id,
  (SELECT count(*)::int FROM gc_authority.classification_label_version_bindings old WHERE old.tenant_id=b.tenant_id AND old.taxonomy_id=b.taxonomy_id AND old.taxonomy_version=$4 AND old.label_key=$3) historical_bindings
  FROM gc_authority.classification_label_baselines b JOIN gc_authority.classification_label_identities i
  ON (i.tenant_id,i.taxonomy_id)=(b.tenant_id,b.taxonomy_id) AND i.label_key=$3
  JOIN gc_authority.classification_label_version_bindings v ON (v.tenant_id,v.taxonomy_id,v.taxonomy_version,v.label_key)=(b.tenant_id,b.taxonomy_id,b.baseline_version,i.label_key)
  WHERE b.tenant_id=$1 AND b.taxonomy_id=$2`,[f.tenant,marker.taxonomyId,marker.labelKey,marker.historicalTaxonomyVersion]);
 assert.equal(baseline.baseline_version,marker.baselineVersion);assert.equal(baseline.baseline_hash,marker.baselineHash);assert.equal(baseline.first_registered_version,marker.baselineVersion);assert.equal(baseline.retired_at_version,null);
 assert.equal(baseline.taxonomy_version,marker.baselineVersion);assert.equal(baseline.label_status,'active');assert.equal(baseline.label_id,baseline.id);assert.equal(baseline.historical_bindings,0);
 assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM public.classification_assignments WHERE tenant_id=$1 AND asset_id=$2',[f.tenant,f.assetId])).n,1);
 const before=await snapshot(f),value=await read(f,marker.assetVersion);context(value,f,marker.assetVersion);unavailable(value);
 assert.equal(value.producerBinding!.operation,'bind');assert.deepEqual(value.producerBinding!.producer,f.producers.primary.ref);assert.deepEqual(await snapshot(f),before);
});

test('held taxonomy publication preserves complete old facts while the fresh snapshot sees the stale pin and new content revision',async t=>{
 const f=await fixture(t),applied=await apply(f),tax=applied.taxonomy!,before=await read(f),id=await labelId(f,tax.id,'contact');
 const held=await heldRead(f,()=>publishTaxonomy(f,{...tax.definition,name:'Synthetic concurrent taxonomy publication'},tax.id,1));
 assert.deepEqual(held.approvedFacts,before.approvedFacts);assert.deepEqual(held.classifications,before.classifications);assert.equal(held.context.securityRevision,before.context.securityRevision);
 assert.equal(held.context.context.closure.snapshot.authorityEpoch,before.context.context.closure.snapshot.authorityEpoch);
 const fresh=await read(f);unavailable(fresh);assert.ok(BigInt(fresh.context.securityRevision)>BigInt(held.context.securityRevision));assert.equal(fresh.context.context.closure.snapshot.authorityEpoch,held.context.context.closure.snapshot.authorityEpoch);
 assert.equal(await labelId(f,tax.id,'contact'),id);assert.equal((await scalar(f.admin,'SELECT version,status FROM public.classification_assignments WHERE tenant_id=$1 AND id=$2',[f.tenant,applied.result.assignmentId])).version,1);
});

test('adjacent real reviewed inventories cross the source-proof byte cap before any body retrieval or assignment-count limit',async t=>{
 const proofLimit=2097152,maxHeads=64,f=await fixture(t),keys=Array.from({length:maxHeads},(_,i)=>'label_'+String(i).padStart(2,'0'));
 const definition=taxonomy(keys);for(const label of definition.labels)label.description='Synthetic bounded metadata. '+ 'x'.repeat(800);
 const definitionBytes=Buffer.byteLength(canonicalDecisionJSON(definition));assert.ok(definitionBytes>50000&&definitionBytes<=65536);
 const tax=await publishTaxonomy(f,definition),w=await workflow(f,{assignments:1,quorum:1}),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000});
 const phases:string[]=[],measureRows:Record<string,unknown>[]=[],countRows:Record<string,unknown>[]=[];let previousCount=0,previousCanonical=0,previousRaw=0,refused=false;
 const observed:NativeOwnerPool={async connect(){const client=await pool.connect();return {async query(text,values){
  const result=await client.query(text,values);
  for(const phase of ['counts','measure','bodies'])if(text.includes('reviewed-classification:'+phase)){phases.push(phase);if(phase==='counts')countRows.push(result.rows[0]);if(phase==='measure')measureRows.push(result.rows[0]);}
  return result;
 },release(error){client.release(error);}};}};
 try{
  for(let index=0;index<maxHeads;index++){
   await apply(f,{selected:await publishRule(f,rule(f,tax,keys[index]!)),workflow:w});
   phases.length=0;measureRows.length=0;countRows.length=0;const before=await snapshot(f);let value:Context|undefined,error:unknown;
   try{value=await read(f,1,observed);}catch(e){error=e;}
   assert.deepEqual(await snapshot(f),before);assert.equal(countRows.length,1);assert.equal(measureRows.length,1);const counts=countRows[0]!,measured=measureRows[0]!;
   const count=Number(counts.assignments),canonicalBytes=Number(measured.canonical_bytes)+count+1,rawBytes=Number(measured.raw_bytes)+count+1;
   assert.equal(count,index+1);assert.equal(Number(measured.assignments),count);assert.equal(Number(counts.tasks),count);assert.equal(Number(counts.decisions),count);
   assert.equal(Number(counts.max_tasks),1);assert.equal(Number(counts.max_decisions),1);assert.ok(count<256&&Number(counts.tasks)<4096&&Number(counts.decisions)<4096);
   assert.equal(measured.component_bounds,true);assert.equal(measured.dependencies_complete,true);
   if(error!==undefined){
    assert.ok(failure('PROFILE_LIMIT')(error),'Only the actual source-proof byte limit may refuse this inventory');assert.deepEqual(phases,['counts','measure']);
    assert.ok(canonicalBytes>proofLimit||rawBytes>proofLimit);assert.equal(previousCount,count-1);assert.ok(previousCount>0&&previousCanonical<=proofLimit&&previousRaw<=proofLimit);refused=true;break;
   }
   assert.ok(value);context(value,f);assert.equal(value.classifications.status,'known');assert.equal(value.approvedFacts.length,count);assert.deepEqual(phases,['counts','measure','bodies']);
   assert.ok(canonicalBytes<=proofLimit&&rawBytes<=proofLimit);previousCount=count;previousCanonical=canonicalBytes;previousRaw=rawBytes;
  }
  assert.equal(refused,true,'Bounded legitimate taxonomy copies must cross the2MiB proof profile within64 actual assignments');
 }finally{await pool.end();assert.equal(pool.totalCount,0);}
});
