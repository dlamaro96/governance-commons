// SPDX-License-Identifier: Apache-2.0
/** SQL024 candidate. Real PostgreSQL only; not run until the owned upgrade gate is launched.
 * Actual approval service decisions and protected SQL tick/publication are used. No HTTP, Temporal, browser or external-source claim. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {structureFixture,hierarchy,crosswalk,structureTables,stateCode,problem,guarded,good,hash,labels} from '../fixtures/reference-structure.ts';
import {parseRelease,parseProposal,proposalDigest,publish,publicationHash,parseBundleCSV} from '../../packages/domain/src/reference-structure.ts';
import {proposeReferenceStructure,getStructureRelease,getStructureEffective,listReferenceStructures,listStructureReleases,getStructureAuthoringContext,downloadStructureRelease} from '../../packages/domain/src/reference-structure-service.ts';
import type {HierarchyDefinition,CrosswalkDefinition,StructureProposal} from '../../packages/domain/src/reference-structure-contracts.ts';
const conflict=stateCode('40001');
const offset=(at:string,ms:number)=>new Date(Date.parse(at)+ms).toISOString();
async function completed(f:Awaited<ReturnType<typeof structureFixture>>,p:StructureProposal){await f.structureReady(p);const result=await f.structurePublish(p.id);const view=await f.as(tx=>getStructureRelease(tx,f.principal(),p.structureId,p.expectedVersion+1));return {p,result,view};}

// This parser is independent of the production CSV reader and checks exact RFC4180 framing.
function csvRows(body:string){const rows:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false;
 for(let i=0;i<body.length;i++){const c=body[i];if(quoted){if(c==='"'){if(body[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;continue;}
 if(c==='"'){assert.equal(cell,'');assert.equal(closed,false);quoted=true;}else if(c===','){row.push(cell);cell='';closed=false;}else if(c==='\r'){assert.equal(body[++i],'\n');row.push(cell);rows.push(row);row=[];cell='';closed=false;}else{assert.equal(closed,false);assert.notEqual(c,'\n');cell+=c;}}
 assert.equal(quoted,false);assert.equal(cell,'');assert.deepEqual(row,[]);return rows;}

test('structure SQL normalization matches bounded pure definitions and retains exact code and confidence semantics',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),other=await f.endpoint(),base=hierarchy(f.actor,e.pin),mapped=crosswalk(f.actor,e.pin,other.pin);
 const vectors:unknown[]=[base,{...base,labels:{...base.labels,en:{label:' \ufeff Cafe\u0301 \u00a0',description:'Line\nSecond'}}},{...base,labels:{...base.labels,en:{label:'A\tB',description:''}}},{...base,extra:true},{...base,edges:[{...base.edges[0],parentCode:' A'}]},mapped,{...mapped,mappings:[{...mapped.mappings[0],confidence:{kind:'declared',basisPoints:10000,basis:'Steward comparison'}}]},{...mapped,mappings:[{...mapped.mappings[0],confidence:{kind:'declared',basisPoints:10001,basis:'Out of range'}}]}];
 for(const input of vectors){const parsed=parseRelease(input),actual=(await f.owner.query('SELECT public.gc_reference_structure_release_normalize($1::jsonb) AS value',[JSON.stringify(input)])).rows[0].value;
 if(parsed.ok)assert.deepEqual(actual,JSON.parse(JSON.stringify(parsed.value)));else assert.equal(actual,null);}
 const p=f.structureProposal(base);await f.structureCommand(p);assert.equal((await f.request(p.id)).row.proposal_digest,good(proposalDigest(good(parseProposal(p,f.actor)),f.actor)));
});

test('structure four tables force tenant RLS and deny runtime DML and receipt namespace forgery',async t=>{
 const f=await structureFixture(t),e=await f.endpoint();await completed(f,f.structureProposal(hierarchy(f.actor,e.pin)));
 const flags=(await f.owner.query("SELECT relname,relrowsecurity,relforcerowsecurity,has_table_privilege('gc_app',oid,'INSERT,UPDATE,DELETE,TRUNCATE') AS write FROM pg_class WHERE oid=ANY($1::regclass[]) ORDER BY relname",[structureTables.map(x=>'public.'+x)])).rows;
 assert.equal(flags.length,4);for(const r of flags)assert.deepEqual([r.relrowsecurity,r.relforcerowsecurity,r.write],[true,true,false]);
 for(const name of structureTables){assert.equal((await f.as(tx=>sql`select * from ${sql.table(name)}`.execute(tx),f.outsider,f.foreign)).rows.length,0);await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(name)} where tenant_id=${f.tenant}::uuid`.execute(tx)),stateCode('42501'));}
 await f.unchanged(()=>f.as(tx=>sql`insert into public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) values(${f.tenant}::uuid,${f.actor},'reference.structure.propose','forged-structure-key',${'0'.repeat(64)},'{}'::jsonb)`.execute(tx)),stateCode('42501'));
});

test('structure hierarchy publishes only after independent quorum with exact immutable bytes, projections and paired journals',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));
 await f.as(tx=>proposeReferenceStructure(tx,f.principal(),p,randomUUID(),'structure-native'));await f.unchanged(()=>f.structurePublish(p.id),conflict);
 await f.decide(p.id);assert.equal((await f.tick(p.id)).status,'pending');assert.equal((await f.state()).reference_structure_releases.length,0);
 await f.decide(p.id,f.second);assert.equal((await f.tick(p.id)).status,'ready');await f.unchanged(()=>f.structurePublish(p.id,f.reviewer),stateCode('42501'));
 const result=await f.structurePublish(p.id),view=await f.as(tx=>getStructureRelease(tx,f.principal(),p.structureId,1)),normalized=good(parseProposal(p,f.actor));
 const expected=good(publish({payload:{formatVersion:1,kind:'reference-structure-publication',structureId:p.structureId,expectedVersion:0,release:normalized.release},publishedAt:result.publishedAt,previous:null,endpoints:[{pin:e.pin,releaseStatus:e.view.release.status,publishedAt:e.view.release.publishedAt,effectiveFrom:e.view.release.effectiveFrom,declaredValidUntil:null,nextKnownEffectiveFrom:null,codes:e.view.release.values.map(({code,status,validFrom,validUntil})=>({code,status,validFrom,validUntil}))}]}));
 assert.deepEqual(view.release,JSON.parse(JSON.stringify(expected)));assert.equal(view.publicationHash,hash(expected));assert.equal(view.publicationHash,good(publicationHash(view.release)));assert.deepEqual((await f.request(p.id)).row.result,result);
 const s=await f.state();assert.equal(s.reference_structure_heads.length,1);assert.equal(s.reference_hierarchy_edges.length,1);assert.equal(s.reference_crosswalk_mappings.length,0);
 assert.deepEqual(s.reference_hierarchy_edges.map(x=>[x.entry_index,x.parent_code,x.child_code,x.reference_version]),[[0,'A','a',1]]);
 const a=s.audit.filter(x=>x.action==='reference.structure_published'),o=s.outbox.filter(x=>x.event_type==='reference.structure_published');assert.equal(a.length,1);assert.deepEqual(a.map(x=>x.id),o.map(x=>x.id));assert.equal(a[0].changes.publicationHash,result.publicationHash);
});

test('structure crosswalk publishes many-to-many provenance and JSON/CSV preserve the same version and hash',async t=>{
 const f=await structureFixture(t),a=await f.endpoint(),b=await f.endpoint(),d=crosswalk(f.actor,a.pin,b.pin);
 const mapping={...d.mappings[0],methodDetails:'Reviewed, "literal" mapping\nSecond line',confidence:{kind:'declared' as const,basisPoints:8750,basis:'Authored assessment'}};
 const p=f.structureProposal({...d,mappings:[mapping,{...mapping,targetCode:'001',relation:'related'}]}),done=await completed(f,p);
 const json=await f.as(tx=>downloadStructureRelease(tx,f.principal(),p.structureId,1,'json')),csv=await f.as(tx=>downloadStructureRelease(tx,f.principal(),p.structureId,1,'csv'));
 assert.deepEqual(JSON.parse(json.body),done.view.release);assert.deepEqual(good(parseBundleCSV(csv.body)),done.view.release);assert.notEqual(json.etag,csv.etag);
 const rows=csvRows(csv.body);assert.equal(rows.length,4);assert.equal(rows[1][0],'release');assert.deepEqual(rows.slice(2).map(r=>r[0]),['crosswalk-mapping','crosswalk-mapping']);assert.equal(rows[1][5],done.view.publicationHash);assert.equal((await f.state()).reference_crosswalk_mappings.length,2);
});

test('structure self review, repeated reviewers and rejected or cancelled requests cannot publish',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),d=hierarchy(f.actor,e.pin);
 for(const assignments of [{first:f.actor,second:f.second},{first:f.reviewer,second:f.reviewer}])await f.unchanged(()=>f.structureCommand(f.structureProposal(d,{assignments})),stateCode('42501'));
 const rejected=f.structureProposal(d);await f.structureCommand(rejected);await f.decide(rejected.id,f.reviewer,'reject');assert.equal((await f.tick(rejected.id)).status,'rejected');await f.unchanged(()=>f.structurePublish(rejected.id),conflict);
 const cancelled=f.structureProposal(d);await f.structureCommand(cancelled);await f.approval('approval.cancel',{requestId:cancelled.id,proposalDigest:(await f.request(cancelled.id)).row.proposal_digest,reason:'Withdraw structure proposal'});assert.equal((await f.tick(cancelled.id)).status,'cancelled');await f.unchanged(()=>f.structurePublish(cancelled.id),conflict);
});

test('structure temporal DAG rejects real cycles but accepts a reversal at a half-open boundary',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),d=hierarchy(f.actor,e.pin),start=offset(await f.now(),60000),boundary=offset(start,10000);
 await f.unchanged(()=>f.structureCommand(f.structureProposal({...d,edges:[d.edges[0],{parentCode:'a',childCode:'A',validFrom:null,validUntil:null}]})),conflict);
 const legal:HierarchyDefinition={...d,activation:{kind:'at',at:start},edges:[{parentCode:'A',childCode:'a',validFrom:null,validUntil:boundary},{parentCode:'a',childCode:'A',validFrom:boundary,validUntil:null}]};
 const done=await completed(f,f.structureProposal(legal));assert.equal(done.view.release.effectiveFrom,start);assert.equal((await f.state()).reference_hierarchy_edges.length,2);
});

test('structure multi-parent policy is temporal and explicit, while allow still rejects a cycle',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),d=hierarchy(f.actor,e.pin),two=[d.edges[0],{parentCode:'001',childCode:'a',validFrom:null,validUntil:null}];
 await f.unchanged(()=>f.structureCommand(f.structureProposal({...d,edges:two})),conflict);
 await completed(f,f.structureProposal({...d,multiParent:'allow',edges:two}));
 await f.unchanged(()=>f.structureCommand(f.structureProposal({...d,multiParent:'allow',edges:[...two,{parentCode:'a',childCode:'001',validFrom:null,validUntil:null}]})),conflict);
 const start=offset(await f.now(),60000),boundary=offset(start,10000);await completed(f,f.structureProposal({...d,activation:{kind:'at',at:start},edges:[{...two[0],validUntil:boundary},{...two[1],validFrom:boundary}]}));
});

test('structure crosswalk refuses overlapping ordered pairs regardless of relation and accepts touching intervals',async t=>{
 const f=await structureFixture(t),a=await f.endpoint(),b=await f.endpoint(),d=crosswalk(f.actor,a.pin,b.pin),m=d.mappings[0];
 await f.unchanged(()=>f.structureCommand(f.structureProposal({...d,mappings:[m,{...m,relation:'related'}]})),conflict);
 const start=offset(await f.now(),60000),boundary=offset(start,10000);await completed(f,f.structureProposal({...d,activation:{kind:'at',at:start},mappings:[{...m,validUntil:boundary},{...m,validFrom:boundary,relation:'related'}]}));
});

test('structure exact endpoint codes and full validity windows refuse absent, deprecated and out-of-window members',async t=>{
 const f=await structureFixture(t),p=f.proposal(),future=offset(await f.now(),60000);const endpointRelease={...p.release,values:p.release.values.map(x=>x.code==='a'?{...x,validFrom:future}:x.code==='001'?{...x,status:'deprecated' as const}:x)};
 const e=await f.endpoint({...p,release:endpointRelease}),d=hierarchy(f.actor,e.pin);
 for(const childCode of ['missing','001','a'])await f.unchanged(()=>f.structureCommand(f.structureProposal({...d,edges:[{...d.edges[0],childCode}]})),conflict);
 await completed(f,f.structureProposal({...d,activation:{kind:'at',at:future}}));
});

test('structure endpoint successor between approval and effect refuses publication without any partial effects',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);
 await f.complete(f.proposal({setId:e.pin.setId,expectedVersion:1,release:{...e.proposal.release,labels:labels('New endpoint')}}));await f.unchanged(()=>f.structurePublish(p.id),conflict);assert.equal((await f.request(p.id)).row.status,'ready');
});

test('structure later endpoint successor exposes a pin gap with zero rows while exact history stays unchanged',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),done=await completed(f,f.structureProposal(hierarchy(f.actor,e.pin)));
 const before=await f.as(tx=>getStructureEffective(tx,f.principal(),done.p.structureId,{}));assert.equal(before.selection.phase,'EFFECTIVE');
 await f.complete(f.proposal({setId:e.pin.setId,expectedVersion:1,release:e.proposal.release}));
 const after=await f.as(tx=>getStructureEffective(tx,f.principal(),done.p.structureId,{}));assert.equal(after.selection.phase,'ENDPOINT_PIN_NOT_EFFECTIVE');assert.deepEqual(after.items,[]);assert.equal(after.nextCursor,null);assert.deepEqual(after.selection.gaps,[{endpoint:'reference',reason:'PIN_SUPERSEDED'}]);
 assert.deepEqual(await f.as(tx=>getStructureRelease(tx,f.principal(),done.p.structureId,1)),done.view);
});

test('structure scheduled successor preserves selected summary and an empty replacement takes effect without fallback',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),first=await completed(f,f.structureProposal(hierarchy(f.actor,e.pin))),start=offset(await f.now(),5000);
 const next=f.structureProposal({...hierarchy(f.actor,e.pin),activation:{kind:'at',at:start},edges:[]},{structureId:first.p.structureId,expectedVersion:1});await completed(f,next);
 const earlier=await f.as(tx=>getStructureEffective(tx,f.principal(),next.structureId,{asOf:first.result.publishedAt}));assert.equal(earlier.structure.version,1);assert.equal(earlier.items.length,1);
 await f.waitUntil(start);const after=await f.as(tx=>getStructureEffective(tx,f.principal(),next.structureId,{asOf:start}));assert.equal(after.structure.version,2);assert.equal(after.selection.phase,'EFFECTIVE');assert.deepEqual(after.items,[]);
 const history=await f.as(tx=>listStructureReleases(tx,f.principal(),next.structureId,{}));assert.deepEqual(history.items.map(x=>x.version),[1,2]);assert.equal((await f.as(tx=>getStructureAuthoringContext(tx,f.principal(),next.structureId))).latestPublishedVersion,2);
});

test('structure current audience intersection hides both details and list candidates before pagination',async t=>{
 const f=await structureFixture(t),a=await f.endpoint(),b=await f.endpoint({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.second]}}),hidden=await completed(f,f.structureProposal(crosswalk(f.actor,a.pin,b.pin))),visible=await completed(f,f.structureProposal(hierarchy(f.actor,a.pin)));
 const list=await f.as(tx=>listReferenceStructures(tx,f.principal(f.reader),{limit:1}),f.reader);assert.deepEqual(list.items.map(x=>x.structureId),[visible.p.structureId]);assert.equal(list.nextCursor,null);
 for(const id of [hidden.p.structureId,randomUUID()])await assert.rejects(()=>f.as(tx=>getStructureRelease(tx,f.principal(f.reader),id,1),f.reader),problem(404));
 await assert.rejects(()=>f.as(tx=>getStructureRelease(tx,f.principal(f.outsider,f.foreign),visible.p.structureId,1),f.outsider,f.foreign),problem(404));
});

test('structure current owner, reviewer and requester revocation blocks final effects and retained replay',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal({...hierarchy(f.actor,e.pin),ownerId:f.reader}),key=randomUUID();await f.structureCommand(p,key);await f.decide(p.id);await f.decide(p.id,f.second);await f.tick(p.id);
 await f.revoke(f.reader,['catalog:read']);await f.unchanged(()=>f.structurePublish(p.id),stateCode('42501'));await f.revoke(f.reader,['catalog:read','reference:read']);
 await f.revoke(f.reviewer,['catalog:read','reference:read']);await f.unchanged(()=>f.structurePublish(p.id),stateCode('42501'));
 await f.revoke(f.actor,['catalog:read','reference:read']);await f.unchanged(()=>f.structureCommand(p,key),stateCode('42501'));assert.equal((await f.request(p.id)).row.status,'ready');
});

test('structure exact proposal and publication replay survive head drift but preserve request hash and live access',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin)),key=randomUUID(),receipt=await f.structureCommand(p,key);
 await f.decide(p.id);await f.decide(p.id,f.second);await f.tick(p.id);const published=await f.structurePublish(p.id);
 await completed(f,f.structureProposal({...hierarchy(f.actor,e.pin),edges:[]},{structureId:p.structureId,expectedVersion:1}));const before=await f.state();assert.deepEqual(await f.structureCommand(p,key),receipt);assert.deepEqual(await f.structurePublish(p.id),published);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.structureCommand({...p,expiresAt:offset(p.expiresAt,1)},key),conflict);
});

test('structure kind and ordered endpoint identity cannot be rebound by a later release',async t=>{
 const f=await structureFixture(t),a=await f.endpoint(),b=await f.endpoint(),first=await completed(f,f.structureProposal(hierarchy(f.actor,a.pin)));
 for(const release of [hierarchy(f.actor,b.pin),crosswalk(f.actor,a.pin,b.pin)])await f.unchanged(()=>f.structureCommand(f.structureProposal(release,{structureId:first.p.structureId,expectedVersion:1})),conflict);
});

test('structure effective cursor retains omitted-asOf clock and rejects changed actor, query or signature',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),d=hierarchy(f.actor,e.pin),done=await completed(f,f.structureProposal({...d,edges:[d.edges[0],{parentCode:'A',childCode:'001',validFrom:null,validUntil:null}]}));
 const page=await f.as(tx=>getStructureEffective(tx,f.principal(),done.p.structureId,{limit:1}));assert.ok(page.nextCursor);const continuation=page.nextCursor;
 const next=await f.as(tx=>getStructureEffective(tx,f.principal(),done.p.structureId,{limit:1,cursor:continuation}));assert.equal(next.selection.asOf,page.selection.asOf);assert.equal(next.items.length,1);assert.notDeepEqual(next.items,page.items);assert.equal(next.nextCursor,null);
 for(const query of [{limit:2,cursor:continuation},{limit:1,cursor:continuation,asOf:page.selection.asOf},{limit:1,cursor:continuation.slice(0,-4)+'AAAA'}])await assert.rejects(()=>f.as(tx=>getStructureEffective(tx,f.principal(),done.p.structureId,query)),problem(400));
 await assert.rejects(()=>f.as(tx=>getStructureEffective(tx,f.principal(f.reader),done.p.structureId,{limit:1,cursor:continuation}),f.reader),problem(400));
});

test('structure forced rollback after successful sealed publication restores every canonical and journal row',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);const stop=new Error('Synthetic after-seal rollback');let sealed=false;
 await f.unchanged(()=>f.as(async tx=>{const r=(await sql<{value:any}>`select public.gc_reference_structure_publish(${p.id}::uuid) as value`.execute(tx)).rows[0].value;assert.equal(r.version,1);await sql`set constraints all immediate`.execute(tx);sealed=true;throw stop;}),x=>x===stop);assert.equal(sealed,true);assert.equal((await f.request(p.id)).row.status,'ready');
});

test('structure deferred seal catches a missing projected row even when publication reaches its success result',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);let returned=false;
 await f.unchanged(()=>f.ownerTx(async()=>{
  await f.owner.query("CREATE FUNCTION pg_temp.suppress_owned_structure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER a_owned_structure_suppression BEFORE INSERT ON reference_hierarchy_edges FOR EACH ROW EXECUTE FUNCTION pg_temp.suppress_owned_structure()");
  const r=(await f.owner.query('SELECT public.gc_reference_structure_publish($1::uuid) AS value',[p.id])).rows[0].value;assert.equal(r.version,1);returned=true;
  await f.owner.query('DROP TRIGGER a_owned_structure_suppression ON reference_hierarchy_edges; SET CONSTRAINTS ALL IMMEDIATE');
 }),stateCode('23514'));assert.equal(returned,true,'Must reach completed protected effect before testing deferred completeness');
});

test('structure early flush rejects late entries and committed history remains immutable even to owner',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);let sealed=false;
 await f.unchanged(()=>f.ownerTx(async()=>{await f.owner.query('SELECT public.gc_reference_structure_publish($1::uuid)',[p.id]);await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');sealed=true;await f.owner.query("INSERT INTO reference_hierarchy_edges VALUES($1,$2,1,1,$3,1,'A','001',NULL,NULL)",[f.tenant,p.structureId,e.pin.setId]);}),guarded);assert.equal(sealed,true);
 await f.structurePublish(p.id);await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE reference_hierarchy_edges SET parent_code=parent_code WHERE tenant_id=$1 AND structure_id=$2',[f.tenant,p.structureId])),stateCode('P0001'));
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query("INSERT INTO reference_hierarchy_edges VALUES($1,$2,1,1,$3,1,'A','001',NULL,NULL)",[f.tenant,p.structureId,e.pin.setId])),guarded);
});

test('structure failed effect recording requires exact ready version, site identity and closed failure code',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin)),ready=await f.structureReady(p);
 const fail=(who:string,version:number,code:string|null)=>f.as(tx=>sql`select public.gc_reference_structure_fail(${p.id}::uuid,${version},${code})`.execute(tx),who);
 for(const [who,code] of [[f.actor,'REFERENCE_STRUCTURE_EXPIRED'],['site:local','anything'],['site:local',null]] as const)await f.unchanged(()=>fail(who,ready.version,code),stateCode('42501'));
 const before=await f.state();await fail('site:local',ready.version-1,'REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED');assert.deepEqual(await f.state(),before);
 await fail('site:local',ready.version,'REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED');const row=(await f.request(p.id)).row;assert.equal(row.status,'failed');assert.equal(row.error_code,'REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED');assert.equal((await f.state()).reference_structure_releases.length,0);
});

test('structure deferred seal refuses a missing paired journal after protected publication returns',async t=>{
 const f=await structureFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);let returned=false;
 await f.unchanged(()=>f.ownerTx(async()=>{
  await f.owner.query("CREATE FUNCTION pg_temp.suppress_owned_structure_journal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='reference.structure_published' THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER a_owned_structure_journal BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION pg_temp.suppress_owned_structure_journal()");
  const r=(await f.owner.query('SELECT public.gc_reference_structure_publish($1::uuid) AS value',[p.id])).rows[0].value;assert.equal(r.version,1);returned=true;
  await f.owner.query('DROP TRIGGER a_owned_structure_journal ON audit; SET CONSTRAINTS ALL IMMEDIATE');
 }),stateCode('23514'));assert.equal(returned,true,'Must reach protected success result before checking missing paired journal');
});
