// SPDX-License-Identifier: Apache-2.0
/** SQL011 storage qualification; every test uses actual forced-RLS PostgreSQL. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import {randomUUID} from 'node:crypto';
import {db,scope,sql} from '../../packages/db/src/index.ts';
import {typeHash} from '../../packages/domain/src/asset-type-policy.ts';
import type {DomainMutationRequest} from '../../packages/domain/src/business-domain-service-contracts.ts';
import type {DomainTypeView,DomainView} from '../../packages/domain/src/business-domain-contracts.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {actor,tenant,ownerId,principal,reason,correlation,digest,definition,fixture,execute,begin,project,persist,seal,snapshot,migrationPlan,sqlCode,typeView,domainView} from '../fixtures/business-domains.ts';
if(!process.env.DATABASE_URL)throw Error('Disposable real PostgreSQL DATABASE_URL required; no SQL011 tests ran.');
const foreign='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',other='10000000-0000-4000-8000-000000000005';
const edit=(d:DomainView):DomainMutationRequest=>({kind:'domain.update',domainId:d.id,expectedVersion:d.version,name:d.name+' revised',description:d.description,attributes:d.attributes,ownerId:d.ownerId,reason});
const assign=(f:Awaited<ReturnType<typeof fixture>>):DomainMutationRequest=>({kind:'domain.placement',assetId:f.asset.id,expectedPlacementVersion:0,assetVersion:f.asset.version,domainId:f.domains[0]!.id,domainVersion:f.domains[0]!.version,reason});

test('all public/private domain tables force tenant RLS and runtime has only narrow helper and mutation privileges',async()=>{
 const f=await fixture();
 await scope(tenant,actor,async tx=>{
  const rows=await sql<{name:string;forced:boolean;owner:string}>`SELECT c.relname name,c.relrowsecurity AND c.relforcerowsecurity forced,r.rolname owner FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind='r' AND (c.relname LIKE 'domain_%' OR c.relname LIKE 'asset_domain_%')`.execute(tx);
  assert.equal(rows.rows.length,19);for(const row of rows.rows){assert.equal(row.forced,true);assert.notEqual(row.owner,'gc_app');}
  const functions=await sql<{name:string}>`SELECT p.proname name FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'gc_domain_%' AND has_function_privilege('gc_app',p.oid,'EXECUTE') ORDER BY p.proname`.execute(tx);
  assert.deepEqual(functions.rows.map(r=>r.name),['gc_domain_replay_authorize','gc_domain_scope_epoch','gc_domain_type_migration_begin','gc_domain_type_migration_seal','gc_domain_write_begin','gc_domain_write_seal']);
 });
 for(const table of ['domain_operation_contexts','domain_transaction_bindings','domain_scope_state','domain_operation_policies','domain_operation_scope_members','domain_migration_operations','domain_operation_domain_claims','domain_operation_journal_claims'])
  await assert.rejects(()=>scope(tenant,actor,tx=>tx.selectFrom(table).selectAll().execute()),sqlCode('42501'));
 for(const table of ['domain_type_dependencies','domain_type_migrations','domain_type_migration_domains'])await assert.rejects(()=>scope(tenant,actor,tx=>tx.deleteFrom(table).execute()),sqlCode('42501'));
 assert.deepEqual(await scope(foreign,other,tx=>tx.selectFrom('domains').selectAll().where('id','=',f.domains[0]!.id).execute()),[]);
});

test('type inheritance independently resolves exact transitive diamonds and rejects conflicting pins, spoofed resolution and root cycles',async()=>{
 const root=(await execute({kind:'domain-type.create',definition:definition({attributes:{code:{type:'text'}},requiredOwner:true}),reason})).type as DomainTypeView;
 const left=(await execute({kind:'domain-type.create',definition:definition({parents:[{typeId:root.typeId,version:1}],lifecycle:null}),reason})).type as DomainTypeView;
 const right=(await execute({kind:'domain-type.create',definition:definition({parents:[{typeId:root.typeId,version:1}],lifecycle:null}),reason})).type as DomainTypeView;
 const leaf=(await execute({kind:'domain-type.create',definition:definition({parents:[{typeId:right.typeId,version:1},{typeId:left.typeId,version:1}],lifecycle:null}),reason})).type as DomainTypeView;
 assert.equal(leaf.resolved.dependencies.length,3);assert.equal(leaf.resolved.requiredOwner,true);
 const closure=await scope(tenant,actor,tx=>tx.selectFrom('domain_type_dependencies').selectAll().where('type_id','=',leaf.typeId).execute());assert.equal(closure.length,3);
 await assert.rejects(()=>execute({kind:'domain-type.create',definition:definition(),reason},{alterRow:row=>{row.resolved=JSON.stringify({...JSON.parse(row.resolved),requiredOwner:true});}}),sqlCode('23514'));
 await assert.rejects(()=>execute({kind:'domain-type.publish',typeId:root.typeId,expectedHeadVersion:1,definition:{...root.definition,version:2,parents:[{typeId:leaf.typeId,version:1}]},previewDigest:digest,reason}),sqlCode('23514'));
});

test('actual domain revisions preserve identity, creation attribution, typed values, lifecycle and full revision envelope',async()=>{
 const f=await fixture({definition:{attributes:{amount:{type:'decimal',required:true}},requiredOwner:true},attributes:{amount:'12345678901234567890.123456789'},ownerId});
 const original=f.domains[0]!,updated=(await execute(edit(original))).domain as DomainView;
 const active=(await execute({kind:'domain.state',domainId:updated.id,expectedVersion:updated.version,state:'active',reason})).domain as DomainView;
 assert.equal(active.createdAt,original.createdAt);assert.equal(active.createdBy,actor);assert.equal(active.version,3);assert.deepEqual(active.attributes,original.attributes);
 const revisions=await scope(tenant,actor,tx=>tx.selectFrom('domain_revisions').select('snapshot').where('domain_id','=',original.id).orderBy('version').execute());
 assert.deepEqual(revisions.map(r=>r.snapshot.action),['created','updated','state-changed']);assert.deepEqual(revisions[0]!.snapshot.domain,original);
 for(const r of revisions){assert.equal(r.snapshot.formatVersion,1);assert.equal(r.snapshot.reason,reason);assert.equal(r.snapshot.correlationId,correlation);}
 await assert.rejects(()=>execute({kind:'domain.state',domainId:active.id,expectedVersion:3,state:'active',reason}),sqlCode('23514'));
});

test('placement zero is absent, assignment and unassignment retain real history and never alter canonical asset or asset revisions',async()=>{
 const f=await fixture();const before=await scope(tenant,actor,async tx=>({asset:await tx.selectFrom('assets').selectAll().where('id','=',f.asset.id).executeTakeFirstOrThrow(),history:await tx.selectFrom('asset_revisions').selectAll().where('asset_id','=',f.asset.id).execute()}));
 assert.deepEqual(await scope(tenant,actor,tx=>tx.selectFrom('asset_domain_placements').selectAll().where('asset_id','=',f.asset.id).execute()),[]);
 const placed=await execute(assign(f));assert.equal(placed.placement.version,1);assert.equal(placed.placement.recordedAssetVersion,1);
 await assert.rejects(()=>execute({...assign(f),expectedPlacementVersion:1} as DomainMutationRequest),sqlCode('23514'));
 const unassigned=await execute({kind:'domain.placement',assetId:f.asset.id,expectedPlacementVersion:1,assetVersion:1,domainId:null,domainVersion:null,reason});
 assert.equal(unassigned.placement.version,2);assert.equal(unassigned.placement.domainId,null);assert.equal(unassigned.placement.recordedAssetVersion,1);
 await scope(tenant,actor,async tx=>{
  assert.deepEqual(await tx.selectFrom('assets').selectAll().where('id','=',f.asset.id).executeTakeFirstOrThrow(),before.asset);
  assert.deepEqual(await tx.selectFrom('asset_revisions').selectAll().where('asset_id','=',f.asset.id).execute(),before.history);
  const histories=await tx.selectFrom('asset_domain_placement_revisions').select('snapshot').where('asset_id','=',f.asset.id).orderBy('version').execute();
  assert.deepEqual(histories.map(r=>r.snapshot.placement.version),[1,2]);assert.deepEqual(histories[0]!.snapshot.placement,placed.placement);
 });
});

test('direct DML, fabricated GUC claims, forged reserved success and early constraints cannot authorize a write',async()=>{
 const f=await fixture(),before=await snapshot();
 await assert.rejects(()=>scope(tenant,actor,async tx=>{await sql`SELECT set_config('gc.domain_operation',${randomUUID()},true)`.execute(tx);await tx.updateTable('domains').set({name:'Forged'}).where('id','=',f.domains[0]!.id).execute();}),sqlCode('23514'));
 await assert.rejects(()=>scope(tenant,actor,tx=>tx.insertInto('idempotency').values({tenant_id:tenant,actor_id:actor,operation:'domain.update',key:randomUUID(),request_hash:'0'.repeat(64),response:'{}'}).execute()),sqlCode('23514'));
 await assert.rejects(()=>execute(edit(f.domains[0]!),{afterBegin:async tx=>{await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx);}}),sqlCode('23514'));
 await assert.rejects(()=>scope(tenant,actor,tx=>begin(tx,edit(f.domains[0]!))),sqlCode('23514'));
 assert.deepEqual(await snapshot(),before);
});

test('missing and forged revisions, journal values and idempotency response roll back canonical rows and scope epoch',async()=>{
 const f=await fixture(),before=await snapshot();
 for(const fault of [{skipRevision:true},{skipJournal:true},{alterRevision:(r:any)=>{r.reason='Unclaimed reason';}},
  {alterRow:(r:any)=>{r.name='Unclaimed name';}},{alterEvent:(e:any)=>{e.payload.resourceKind='domain-type';}},
  {alterSuccess:(response:any)=>({...response,unexpected:true})}]){
  await assert.rejects(()=>execute(edit(f.domains[0]!),fault),sqlCode('23514'));assert.deepEqual(await snapshot(),before);
 }
});

test('exact audit and outbox pair accepts either member first and binds resource kind, revision hash, protected time and actor name',async()=>{
 const f=await fixture(),result=await execute(edit(f.domains[0]!),{outboxFirst:true});
 await scope(tenant,actor,async tx=>{
  const audit=await tx.selectFrom('audit').selectAll().where('resource_id','=',f.domains[0]!.id).where('action','=','domain.updated').executeTakeFirstOrThrow();
  const event=await tx.selectFrom('outbox').selectAll().where('id','=',audit.id).executeTakeFirstOrThrow();
  const revision=await tx.selectFrom('domain_revisions').select('snapshot').where('domain_id','=',f.domains[0]!.id).where('version','=',2).executeTakeFirstOrThrow();
  assert.equal(audit.hash,typeHash(audit.envelope));assert.deepEqual(audit.envelope.changes,audit.changes);assert.equal(audit.changes.revisionHash,typeHash(revision.snapshot));
  assert.equal(event.payload.resourceKind,'domain');assert.equal(event.payload.resourceVersion,2);assert.equal(event.payload.time,result.domain.updatedAt);assert.equal(event.payload.data.reason,undefined);
  assert.equal(audit.actor_name,(await tx.selectFrom('identities').select('name').where('id','=',actor).executeTakeFirstOrThrow()).name);
  await tx.updateTable('outbox').set({attempts:1,processed_at:new Date()}).where('id','=',event.id).execute();
 });
});

test('duplicate begin or seal, actor/tenant switching, reused row claims and post-seal/finalization legacy mutations are rejected',async()=>{
 const f=await fixture(),request=edit(f.domains[0]!),before=await snapshot();
 for(const options of [
  {afterBegin:async(tx:any)=>{await begin(tx,request);}},
  {afterBegin:async(tx:any,s:any)=>{await sql`SELECT set_config('gc.actor_id',${ownerId},true)`.execute(tx);await seal(tx,request,s.operationId);}},
  {afterBegin:async(tx:any,s:any)=>{await sql`SELECT set_config('gc.tenant_id',${foreign},true)`.execute(tx);await seal(tx,request,s.operationId);}},
  {beforeSeal:async(tx:any)=>{await tx.updateTable('domains').set({name:'extra'}).where('id','=',f.domains[0]!.id).execute();}},
  {afterSeal:async(tx:any,s:any)=>{await seal(tx,request,s.operationId);}},
  {afterSeal:async(tx:any)=>{await sql`UPDATE assets SET name=name WHERE false`.execute(tx);}},
  {afterSuccess:async(tx:any)=>{await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx);await sql`UPDATE assets SET name=name WHERE false`.execute(tx);}},
 ]){await assert.rejects(()=>execute(request,options),sqlCode('23514'));assert.deepEqual(await snapshot(),before);}
});

test('protected legacy marker rejects both mutation orderings and scanner service actor remains compatible outside domain operations',async()=>{
 const f=await fixture(),request=edit(f.domains[0]!);
 await assert.rejects(()=>execute(request,{beforeBegin:async tx=>{await sql`UPDATE assets SET name=name WHERE false`.execute(tx);}}),sqlCode('23514'));
 await assert.rejects(()=>execute(request,{afterBegin:async tx=>{await sql`UPDATE governance_models SET current_version=current_version WHERE false`.execute(tx);}}),sqlCode('23514'));
 await scope(tenant,'site:local',async tx=>{
  const row=await tx.updateTable('assets').set({name:'Synthetic scanner refresh',version:f.asset.version+1,observed_at:new Date(),updated_at:new Date()}).where('id','=',f.asset.id).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:row.id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
 });
 const edited=(await execute(request)).domain;assert.equal(edited.version,2);
});

test('hierarchy rejects cycles, simultaneous concealed moves, active-child/placement retirement and retired ordinary edits',async()=>{
 const f=await fixture(),root=f.domains[0]!;
 const child=(await execute({kind:'domain.create',name:'Synthetic child',description:'',parentId:root.id,type:root.type,attributes:{},ownerId:null,reason})).domain as DomainView;
 const hierarchy=(d:DomainView,kind:'move'|'retire'|'restore',parentId:string|null):DomainMutationRequest=>({kind:'domain.hierarchy',change:{kind,domainId:d.id,expectedVersion:d.version,parentId,reason},previewDigest:digest});
 await assert.rejects(()=>execute(hierarchy(root,'move',child.id)),sqlCode('23514'));
 await assert.rejects(()=>execute(hierarchy(root,'retire',null)),sqlCode('23514'));
 await assert.rejects(()=>execute(hierarchy(child,'retire',null)),sqlCode('23514'));
 const retired=(await execute(hierarchy(child,'retire',root.id))).domain as DomainView;
 await assert.rejects(()=>execute(edit(retired)),sqlCode('23514'));
 const restored=(await execute(hierarchy(retired,'restore',root.id))).domain as DomainView;assert.equal(restored.status,'active');
 await execute(assign(f));await assert.rejects(()=>execute(hierarchy(root,'retire',null)),sqlCode('23514'));
});

test('compatible publication preserves all exact pins and complete mixed-version retired migration yields real normalized outcomes',async()=>{
 const f=await fixture(),first=f.domains[0]!;
 const published=(await execute({kind:'domain-type.publish',typeId:f.type.typeId,expectedHeadVersion:1,definition:{...f.type.definition,version:2,label:'Synthetic published label'},previewDigest:digest,reason})).type as DomainTypeView;
 const second=(await execute({kind:'domain.create',name:'Synthetic version two',description:'',parentId:null,type:{typeId:published.typeId,version:2},attributes:{},ownerId:null,reason})).domain as DomainView;
 const retired=(await execute({kind:'domain.hierarchy',change:{kind:'retire',domainId:first.id,expectedVersion:1,parentId:null,reason},previewDigest:digest})).domain as DomainView;
 const plan=migrationPlan(published,[1,2]);
 const request:DomainMutationRequest={kind:'domain-type-migration.execute',typeId:f.type.typeId,expectedHeadVersion:2,definition:{...published.definition,version:3,label:'Synthetic migrated label'},plan,previewDigest:digest,reason};
 const before=await snapshot();await assert.rejects(()=>execute(request,{omitDomain:second.id}),sqlCode('23514'));assert.deepEqual(await snapshot(),before);
 const result=await execute(request),receipt=result.receipt;
 assert.equal(receipt.outcomes.length,2);assert.deepEqual(receipt.sourcePolicies.map((s:any)=>s.pin.version),[1,2]);
 await scope(tenant,actor,async tx=>{
  const members=await tx.selectFrom('domain_type_migration_domains').selectAll().where('migration_id','=',receipt.id).orderBy('domain_id').execute();assert.equal(members.length,2);
  for(const member of members){const outcome=receipt.outcomes.find((o:any)=>o.domainId===member.domain_id);assert.equal(member.before_tuple_hash,typeHash(outcome.before));assert.equal(member.after_tuple_hash,typeHash(outcome.after));
   const history=await tx.selectFrom('domain_revisions').select('snapshot').where('domain_id','=',member.domain_id).where('version','=',member.from_version).executeTakeFirstOrThrow();
   assert.equal(history.snapshot.domain.type.version,member.domain_id===first.id?1:2);
  }
  const current=domainView(await tx.selectFrom('domains').selectAll().where('id','=',first.id).executeTakeFirstOrThrow());assert.equal(current.status,'retired');assert.equal(current.parentId,retired.parentId);assert.equal(current.createdAt,first.createdAt);assert.equal(current.type.version,3);
 });
});

test('empty complete migration creates only target type and receipt journals with no fabricated member or domain history',async()=>{
 const f=await fixture({count:0}),before=await snapshot(),plan=migrationPlan(f.type,[]);
 const result=await execute({kind:'domain-type-migration.execute',typeId:f.type.typeId,expectedHeadVersion:1,definition:{...f.type.definition,version:2},plan,previewDigest:digest,reason});
 assert.deepEqual(result.receipt.outcomes,[]);const afterState=await snapshot();assert.deepEqual(afterState.domain_revisions,before.domain_revisions);
 assert.equal(afterState.audit.length-before.audit.length,2);assert.equal(BigInt(afterState.epoch)-BigInt(before.epoch),1n);
 assert.deepEqual(await scope(tenant,actor,tx=>tx.selectFrom('domain_type_migration_domains').selectAll().where('migration_id','=',result.receipt.id).execute()),[]);
});

test('missing/foreign pins, domain references and owners never satisfy tenant-scoped canonical foreign keys',async()=>{
 const f=await fixture(),before=await snapshot();
 for(const request of [
  {kind:'domain.create',name:'Foreign owner',description:'',parentId:null,type:{typeId:f.type.typeId,version:1},attributes:{},ownerId:other,reason},
  {kind:'domain.create',name:'Missing pin',description:'',parentId:null,type:{typeId:randomUUID(),version:1},attributes:{},ownerId:null,reason},
  {kind:'domain.create',name:'Missing parent',description:'',parentId:randomUUID(),type:{typeId:f.type.typeId,version:1},attributes:{},ownerId:null,reason},
 ] as DomainMutationRequest[])await assert.rejects(()=>execute(request),sqlCode('23514'));
 assert.deepEqual(await snapshot(),before);
});

test('authorized physical JSONB expansion and aggregate retained copies are bounded before canonical serialization',async()=>{
 const f=await fixture({definition:{attributes:{value:{type:'number'}}}}),request=edit(f.domains[0]!),before=await snapshot();
 await assert.rejects(()=>scope(tenant,actor,tx=>sql`SELECT gc_domain_write_begin(${randomUUID()}::uuid,${randomUUID()},${JSON.stringify(request).replace('"attributes":{}','"attributes":{'+Array.from({length:8},(_,i)=>'"value'+i+'":1e100000').join(',')+'}')}::jsonb,${correlation})`.execute(tx)),sqlCode('54000'));
 const large={...definition(),attributes:{a:{type:'text' as const,label:'a'.repeat(256)}}};
 const requestLarge={kind:'domain-type.create',definition:large,reason} as const;
 await assert.rejects(()=>execute(requestLarge,{alterRow:row=>{row.definition=JSON.stringify({...large,label:'x'.repeat(300000)});}}),sqlCode('23514'));
 assert.deepEqual(await snapshot(),before);
});

test('current original-scope replay helper never grants new writes or returns private context material',async()=>{
 const f=await fixture(),key=randomUUID(),request=edit(f.domains[0]!);await execute(request,{key});
 await scope(tenant,actor,async tx=>{
  const result=await sql<{value:boolean}>`SELECT gc_domain_replay_authorize('domain.update',${key}) value`.execute(tx);assert.equal(result.rows[0]!.value,true);
  assert.equal((await sql<{value:boolean}>`SELECT gc_domain_replay_authorize('domain.update',${randomUUID()}) value`.execute(tx)).rows[0]!.value,false);
 });
 assert.equal((await scope(tenant,ownerId,tx=>sql<{value:boolean}>`SELECT gc_domain_replay_authorize('domain.update',${key}) value`.execute(tx))).rows[0]!.value,false);
});


test('committed protected outbox cannot be renamed into a legacy family or have payload identity rewritten',async()=>{
 const f=await fixture();
 const event=await scope(tenant,actor,tx=>tx.selectFrom('outbox').selectAll().where('resource_id','=',f.domains[0]!.id).where('event_type','=','domain.created').executeTakeFirstOrThrow());
 for(const patch of [{event_type:'legacy.synthetic'},{event_type:'legacy.synthetic',payload:JSON.stringify({...event.payload,type:'legacy.synthetic'})},{resource_id:randomUUID()}])
  await assert.rejects(()=>scope(tenant,actor,tx=>tx.updateTable('outbox').set(patch).where('id','=',event.id).execute()),sqlCode('23514'));
 assert.deepEqual(await scope(tenant,actor,tx=>tx.selectFrom('outbox').selectAll().where('id','=',event.id).executeTakeFirstOrThrow()),event);
});


test('direct unavailable placement asset remains indistinguishable404 instead of disclosing complete-scope denial',async()=>{
 const f=await fixture();
 for(const assetId of [randomUUID(),'30000000-0000-4000-8000-000000000099'])
  await assert.rejects(()=>execute({kind:'domain.placement',assetId,expectedPlacementVersion:0,assetVersion:1,domainId:f.domains[0]!.id,domainVersion:1,reason}),
   (error:any)=>error.code==='23514'&&error.message==='ASSET_NOT_FOUND');
 await scope(tenant,actor,async tx=>{
  const row=await tx.updateTable('assets').set({visibility:'restricted',allowed_identities:JSON.stringify([ownerId]),version:2,updated_at:new Date()}).where('id','=',f.asset.id).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:row.id,version:2,snapshot:JSON.stringify(assetView(row))}).execute();
 });
 await assert.rejects(()=>execute({kind:'domain.placement',assetId:f.asset.id,expectedPlacementVersion:0,assetVersion:2,domainId:f.domains[0]!.id,domainVersion:1,reason}),
  (error:any)=>error.code==='23514'&&error.message==='ASSET_NOT_FOUND');
});


test('placement retains opaque legacy metadata keys without applying domain definition key grammar',async()=>{
 const f=await fixture();const metadata={'source column/name':{'漢字':'Synthetic retained value'},constructor:'ordinary synthetic metadata'};
 const row=await scope(tenant,actor,async tx=>{const row=await tx.updateTable('assets').set({metadata:JSON.stringify(metadata),version:2,updated_at:new Date()}).where('id','=',f.asset.id).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:row.id,version:2,snapshot:JSON.stringify(assetView(row))}).execute();return row;});
 const before=await scope(tenant,actor,tx=>tx.selectFrom('asset_revisions').select('snapshot').where('asset_id','=',row.id).where('version','=',2).executeTakeFirstOrThrow());
 await execute({kind:'domain.placement',assetId:row.id,expectedPlacementVersion:0,assetVersion:2,domainId:f.domains[0]!.id,domainVersion:1,reason});
 assert.deepEqual(await scope(tenant,actor,tx=>tx.selectFrom('asset_revisions').select('snapshot').where('asset_id','=',row.id).where('version','=',2).executeTakeFirstOrThrow()),before);
});

after(()=>db.destroy());
