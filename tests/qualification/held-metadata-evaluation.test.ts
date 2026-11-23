// SPDX-License-Identifier: Apache-2.0
/** Isolated native-owner qualification. Every query reaches PostgreSQL and all
 * policies, grants and reviewed assignments use canonical protected writers.
 * Query observation never substitutes rows, evaluator results or permissions. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import pg from 'pg';
import {fixture,closeDefaultDb,apply,asset,bind,revokeProducer,readInput,heads,snapshot,labelId,taxonomy,rule,publishTaxonomy,publishRule,setup,evaluate,workflow,propose,ready,publish,withdraw,query,scalar,tx,scope,uuid,config,failure,canonicalDecisionJSON,type Fixture} from '../fixtures/held-metadata-evaluation.ts';
import {mutate,addPolicy,addRole,addGrant,setMembership,uid,version} from '../fixtures/authority-foundation.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {createAuthorityFoundationRepository,type InactiveHeldHumanAssetMetadataEvaluation} from '../../packages/authority-storage/src/repository.ts';
import {AuthorityFoundationError,type NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import type {Digest,UUID,Version,PolicyDefinition} from '../../packages/authority/src/types.ts';

after(closeDefaultDb);
type Seen={text:string;values?:unknown[];rows:Record<string,any>[]};
type Observation={before?:(client:pg.PoolClient,text:string,values:unknown[]|undefined)=>Promise<void>;after?:(client:pg.PoolClient,row:Seen)=>Promise<void>};
function ownerPool(options:Observation={}){
 const pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000}),seen:Seen[]=[],releases:boolean[]=[];let connections=0;
 const observed:NativeOwnerPool={async connect(){connections++;const client=await pool.connect();return {async query(text,values){
  await options.before?.(client,text,values);const result=await client.query(text,values),row={text,values,rows:result.rows};seen.push(row);await options.after?.(client,row);return result;
 },release(destroy){releases.push(destroy??false);client.release(destroy);}};}};
 return {pool,observed,seen,releases,connections:()=>connections,close:async()=>{await pool.end();assert.equal(pool.totalCount,0);}};
}
async function run(f:Fixture,expectedVersion=1,options:Observation={}){
 const p=ownerPool(options);try{const result=await createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f,expectedVersion));return {result,seen:p.seen,releases:p.releases};}finally{await p.close();}
}
function inert(value:InactiveHeldHumanAssetMetadataEvaluation,allowed:boolean,reason?:string){
 assert.deepEqual(Object.keys(value).sort(),['contentAuthority','contextDigest','formatVersion','kind','result']);assert.equal(value.formatVersion,1);assert.equal(value.kind,'inactive-held-human-asset-metadata-evaluation');assert.equal(value.contentAuthority,false);assert.match(value.contextDigest,/^[0-9a-f]{64}$/);
 assert.equal(value.result.outcome,'evaluated');assert.equal(value.result.root?.allowed,allowed);if(reason!==undefined)assert.equal(value.result.root?.reason,reason);assert.deepEqual(value.result.issues,[]);assert.ok(Object.isFrozen(value)&&Object.isFrozen(value.result));
 assert.equal('sourceProof'in value,false);assert.equal('composition'in value,false);assert.equal('allowToken'in value,false);assert.equal('sessionHash'in value,false);
}
function successfulProtocol(value:Awaited<ReturnType<typeof run>>){
 const texts=value.seen.map(row=>row.text);assert.equal(texts.filter(s=>s==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY').length,1);assert.equal(texts.filter(s=>s.includes('load_human_closure_v1')).length,1);assert.equal(texts.filter(s=>s.includes('load_reviewed_classification_producer_v1')).length,1);
 assert.equal(texts.filter(s=>s.includes('FROM gc_authn.foundation_session_v1')).length,2);assert.equal(texts.at(-1),'COMMIT');assert.equal(texts.includes('ROLLBACK'),false);assert.deepEqual(value.releases,[false]);
 const finalSession=texts.reduce((last,s,index)=>s.includes('FROM gc_authn.foundation_session_v1')?index:last,-1);assert.equal(finalSession,texts.length-3);assert.ok(texts.findIndex(s=>s.includes('load_reviewed_classification_producer_v1'))<finalSession);
}
async function ordinaryAllow(f:Fixture){return mutate(f,async()=>addGrant(f,await addRole(f,[await addPolicy(f)])));}
async function classificationAllow(f:Fixture,id:UUID){
 const document:PolicyDefinition={formatVersion:1,id:uid(),version,rules:[{id:uid(),effect:'allow',actions:['asset:metadata.read'],fields:null,when:{op:'classification-any',ids:[id]}}]};
 return mutate(f,async()=>{const policy=await addPolicy(f,{document}),grant=await addGrant(f,await addRole(f,[policy]));return {policy,grant,document};});
}
async function visibility(f:Fixture,allowed:string[]=[]){
 return tx(f.owner,async()=>{await scope(f.owner,f);const row=await scalar(f.owner,"UPDATE public.assets SET visibility='restricted',allowed_identities=$3::jsonb,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING *",[f.tenant,f.assetId,JSON.stringify(allowed)]);await query(f.owner,'INSERT INTO public.asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.assetId,row.version,JSON.stringify(assetView(row))]);return row;});
}
async function held(f:Fixture,change:()=>Promise<unknown>,expectedVersion=1){
 let changed=false;const value=await run(f,expectedVersion,{after:async(_client,row)=>{if(row.text.includes(' AS native_owner')){assert.equal(changed,false);await change();changed=true;}}});assert.equal(changed,true);successfulProtocol(value);return value;
}
const security=(seen:Seen[])=>seen.find(s=>s.text.includes('FROM gc_authority.content_security_heads'))!.rows[0]!.revision as string;
const closure=(seen:Seen[])=>seen.find(s=>s.text.includes(' AS closure'))!.rows[0]!.closure;
const producer=(seen:Seen[])=>seen.find(s=>s.text.includes('load_reviewed_classification_producer_v1'))!.rows[0]!.producer;
function denied(error:unknown,code:string){assert.ok(error instanceof AuthorityFoundationError);assert.equal(error.code,'AUTHORITY_FOUNDATION_'+code);assert.equal(error.message,error.code);assert.equal('detail'in error,false);return true;}

test('native held evaluation keeps complete producer-backed empty discovery inert and denies without an allow grant',async t=>{
 const f=await fixture(t),before=await snapshot(f),value=await run(f);inert(value.result,false,'no_allow');successfulProtocol(value);
 assert.equal(producer(value.seen).binding.operation,'bind');assert.equal(value.seen.find(s=>s.text.includes('reviewed-classification:counts'))!.rows[0]!.assignments,'0');assert.equal(value.seen.some(s=>s.text.includes('reviewed-classification:bodies')),false);
 assert.equal(closure(value.seen).snapshot.registryId,f.registryId);assert.equal(closure(value.seen).snapshot.registryDigest,f.registry.digest);assert.deepEqual(await snapshot(f),before);assert.equal((await scalar(f.admin,'SELECT mode FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).mode,'inactive');
});

test('native held evaluation uses a canonical ordinary grant and the exact installed visibility profile',async t=>{
 const f=await fixture(t),grant=await ordinaryAllow(f),before=await snapshot(f),value=await run(f);inert(value.result,true,'allowed');successfulProtocol(value);
 for(const adapter of f.registry.adapters){assert.equal(adapter.containment,'asset-placement');assert.equal(adapter.dependencyElevation,'forbidden');assert.deepEqual(adapter.ceilings,[{slot:'canonical-visibility',kind:'visibility'}]);}
 assert.ok(value.result.result.root!.matched.some(witness=>witness.grant.id===grant.ref.id&&witness.effect==='allow'));assert.deepEqual(await snapshot(f),before);
});

test('native canonical restricted visibility overrides an ordinary allow and admits only the current ACL identity',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);const blocked=await visibility(f),first=await run(f,blocked.version);inert(first.result,false,'ceiling_denied');successfulProtocol(first);
 const admitted=await visibility(f,[f.identity]),second=await run(f,admitted.version);inert(second.result,true,'allowed');successfulProtocol(second);assert.ok(BigInt(security(second.seen))>BigInt(security(first.seen)));
});

test('native classification policy treats an uninstalled producer as unknown and an installed empty partition as false',async t=>{
 const f=await fixture(t,{bind:false}),definitions=await setup(f);await classificationAllow(f,await labelId(f,definitions.taxonomy.id,'contact') as UUID);
 const unknown=await run(f);inert(unknown.result,false,'indeterminate');assert.equal(producer(unknown.seen).binding,null);assert.equal(unknown.seen.some(row=>row.text.includes('reviewed-classification:counts')),false);
 await bind(f);const known=await run(f);inert(known.result,false,'no_allow');successfulProtocol(known);assert.equal(BigInt(closure(known.seen).snapshot.authorityEpoch),BigInt(closure(unknown.seen).snapshot.authorityEpoch)+1n);
});

test('native real classification policy ignores suggestions and ready approval then allows only the exact published reviewed fact',async t=>{
 const f=await fixture(t),definitions=await setup(f),id=await labelId(f,definitions.taxonomy.id,'contact') as UUID,policy=await classificationAllow(f,id),suggestion=await evaluate(f,definitions.rule),w=await workflow(f);
 inert((await run(f)).result,false,'no_allow');const requestId=await propose(f,suggestion,w);await ready(f,requestId,w);inert((await run(f)).result,false,'no_allow');const applied=await publish(f,requestId),before=await snapshot(f),value=await run(f);
 inert(value.result,true,'allowed');successfulProtocol(value);const bodies=value.seen.find(row=>row.text.includes('reviewed-classification:bodies'))!.rows;assert.equal(bodies.length,1);
 assert.ok(value.result.result.root!.matched.some(witness=>witness.grant.id===policy.grant.ref.id&&witness.policy.policyId===policy.policy.policyId&&witness.effect==='allow'));
 assert.equal((await scalar(f.admin,'SELECT status FROM public.approval_requests WHERE tenant_id=$1 AND id=$2',[f.tenant,requestId])).status,'succeeded');assert.equal((await scalar(f.admin,'SELECT version FROM public.classification_assignments WHERE tenant_id=$1 AND id=$2',[f.tenant,applied.assignmentId])).version,1);
 assert.equal(canonicalDecisionJSON(value.result).includes('Reviewed synthetic metadata evidence independently'),false);assert.deepEqual(await snapshot(f),before);
});

test('native held asset visibility and content revision stay coherent across a concurrent canonical ACL change',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);const before=await heads(f),value=await held(f,()=>visibility(f));inert(value.result,true,'allowed');assert.equal(security(value.seen),before.content);assert.equal(closure(value.seen).selectors[0].revision,1);
 const current=await asset(f),fresh=await run(f,current.version);inert(fresh.result,false,'ceiling_denied');assert.ok(BigInt(security(fresh.seen))>BigInt(security(value.seen)));assert.equal(closure(fresh.seen).selectors[0].revision,2);
 await assert.rejects(run(f),failure('VERSION_CONFLICT'));
});

test('native held reviewed policy allow survives concurrent withdrawal only in its original snapshot',async t=>{
 const f=await fixture(t),applied=await apply(f);await classificationAllow(f,await labelId(f,applied.taxonomy!.id,'contact') as UUID);const before=await heads(f),value=await held(f,()=>withdraw(f,applied.result,applied.workflow));inert(value.result,true,'allowed');assert.equal(security(value.seen),before.content);
 const fresh=await run(f);inert(fresh.result,false,'no_allow');assert.ok(BigInt(security(fresh.seen))>BigInt(security(value.seen)));assert.equal(closure(fresh.seen).snapshot.authorityEpoch,closure(value.seen).snapshot.authorityEpoch);
});

test('native held producer and authority epoch stay atomic while a concurrent revoke makes fresh classification evaluation indeterminate',async t=>{
 const f=await fixture(t),applied=await apply(f);await classificationAllow(f,await labelId(f,applied.taxonomy!.id,'contact') as UUID);const value=await held(f,()=>revokeProducer(f));inert(value.result,true,'allowed');assert.equal(producer(value.seen).binding.operation,'bind');
 const fresh=await run(f);inert(fresh.result,false,'indeterminate');assert.equal(producer(fresh.seen).binding.operation,'revoke');assert.equal(security(fresh.seen),security(value.seen));assert.equal(BigInt(closure(fresh.seen).snapshot.authorityEpoch),BigInt(closure(value.seen).snapshot.authorityEpoch)+1n);
});

test('native held taxonomy facts remain exact while a concurrent current-pin publication makes the fresh policy indeterminate',async t=>{
 const f=await fixture(t),applied=await apply(f),tax=applied.taxonomy!;await classificationAllow(f,await labelId(f,tax.id,'contact') as UUID);const value=await held(f,()=>publishTaxonomy(f,{...tax.definition,name:'Synthetic concurrent taxonomy name'},tax.id,1));inert(value.result,true,'allowed');
 const fresh=await run(f);inert(fresh.result,false,'indeterminate');assert.ok(BigInt(security(fresh.seen))>BigInt(security(value.seen)));assert.equal(closure(fresh.seen).snapshot.authorityEpoch,closure(value.seen).snapshot.authorityEpoch);
});

test('native held evaluation rejects current inactive tenant membership before producing a result',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);inert((await run(f)).result,true,'allowed');await tx(f.owner,()=>setMembership(f,f.owner,f.tenant,false));const before=await snapshot(f),p=ownerPool();
 try{await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f)),error=>denied(error,'SESSION_REJECTED'));assert.equal(p.seen.some(row=>row.text==='COMMIT'),false);assert.equal(p.seen.at(-1)?.text,'ROLLBACK');assert.deepEqual(p.releases,[true]);}finally{await p.close();}assert.deepEqual(await snapshot(f),before);
});

test('native held evaluation restores pooled context and refuses a canonically revoked session on a fresh read',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);const p=ownerPool(),actor=uuid();let client=await p.pool.connect();await client.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.otherTenant,actor]);client.release();
 try{
  inert(await createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f)),true,'allowed');client=await p.pool.connect();assert.deepEqual((await client.query("SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('transaction_read_only') readonly")).rows,[{tenant:f.otherTenant,actor,readonly:'off'}]);client.release();
  await query(f.api,'SELECT * FROM public.gc_authn_session_revoke($1,$2,1)',[f.hash,f.csrf]);await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f)),error=>denied(error,'SESSION_REJECTED'));assert.deepEqual(p.releases,[false,true]);assert.equal(p.seen.filter(row=>row.text==='COMMIT').length,1);
 }finally{await p.close();}
});

test('native final protected recheck refuses real wall-clock expiry and returns no evaluated envelope',async t=>{
 const f=await fixture(t,{authnExpiryMs:20000});await ordinaryAllow(f);let sessionReads=0,waited=false;
 const p=ownerPool({before:async(client,text)=>{if(!text.includes('FROM gc_authn.foundation_session_v1'))return;if(++sessionReads!==2)return;
  const remaining=Number((await client.query('SELECT extract(epoch FROM $1::timestamptz-clock_timestamp()) remaining',[f.expiry])).rows[0]!.remaining);assert.ok(remaining>0&&remaining<=20,'The initial session and evaluation must precede actual bounded expiry');
  // Active SQL keeps the transaction alive; this is an actual PostgreSQL wait,
  // not an injected SQLSTATE, mocked result, fake clock or concurrent row swap.
  await client.query('SELECT pg_sleep(greatest(0,extract(epoch FROM $1::timestamptz-clock_timestamp()))+0.05)',[f.expiry]);waited=true;
 }});
 try{await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f)),error=>denied(error,'SESSION_REJECTED'));assert.equal(waited,true);assert.equal(sessionReads,2);assert.equal(p.seen.filter(row=>row.text.includes('FROM gc_authn.foundation_session_v1')).length,1);assert.equal(p.seen.at(-1)?.text,'ROLLBACK');assert.equal(p.seen.some(row=>row.text==='COMMIT'),false);assert.deepEqual(p.releases,[true]);}finally{await p.close();}
});

test('fixed held metadata input rejects caller-selected subject adapter action time producer registry and proof before native connection',async()=>{
 const p=ownerPool(),input={sessionHash:'a'.repeat(64) as Digest,assetId:uuid() as UUID,expectedVersion:1 as Version};
 try{for(const extra of [{subject:{kind:'human',id:uuid()}},{adapterId:'asset.read'},{action:'asset:metadata.read'},{now:new Date().toISOString()},{producer:{id:uuid(),version:1}},{registry:{}},{sourceProof:[]},{contentAuthority:true}])await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata({...input,...extra}),error=>denied(error,'INPUT_INVALID'));assert.equal(p.connections(),0);assert.deepEqual(p.seen,[]);assert.deepEqual(p.releases,[]);}finally{await p.close();}
});

test('all runtime credentials refuse native held evaluation even with forged tenant actor and owner settings',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);const before=await snapshot(f);
 for(const url of [config.legacy,f.roles.login.url,f.roles.api.url,f.roles.nextLogin.url,f.roles.nextApi.url,config.unregistered.url]){
  const pool=new pg.Pool({connectionString:url,max:1,connectionTimeoutMillis:5000});try{const client=await pool.connect();await client.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false),set_config('gc.authn_owner','gc_owner',false)",[f.tenant,f.identity]);client.release();await assert.rejects(createAuthorityFoundationRepository(pool).evaluateHeldHumanAssetMetadata(readInput(f)),error=>denied(error,'EXECUTOR_REJECTED'));}finally{await pool.end();assert.equal(pool.totalCount,0);}
 }assert.deepEqual(await snapshot(f),before);
});

test('canonically installed unsupported held adapter profile fails closed before final recheck and commit',async t=>{
 const f=await fixture(t,{unsupportedProfile:true});await ordinaryAllow(f);const before=await snapshot(f),p=ownerPool();
 try{await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f)),error=>denied(error,'UNSUPPORTED'));assert.equal(p.seen.filter(row=>row.text.includes('FROM gc_authn.foundation_session_v1')).length,1);assert.equal(p.seen.some(row=>row.text==='COMMIT'),false);assert.equal(p.seen.at(-1)?.text,'ROLLBACK');assert.deepEqual(p.releases,[true]);}finally{await p.close();}assert.deepEqual(await snapshot(f),before);
});

test('native held evaluation rejects missing foreign and stale asset selectors without writes',async t=>{
 const f=await fixture(t);await ordinaryAllow(f);const foreign=uuid();await tx(f.owner,async()=>{await scope(f.owner,f,f.otherTenant);await query(f.owner,"INSERT INTO public.assets(tenant_id,id,external_id,name,qualified_name,type,observed_at) VALUES($1::uuid,$2::uuid,$2::uuid::text,'Synthetic foreign asset',$2::uuid::text,'column',clock_timestamp())",[f.otherTenant,foreign]);});const before=await snapshot(f),p=ownerPool();
 try{for(const input of [{...readInput(f),assetId:uuid() as UUID},{...readInput(f),assetId:foreign as UUID},{...readInput(f),expectedVersion:2 as Version}])await assert.rejects(createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(input),error=>denied(error,'VERSION_CONFLICT'));assert.equal(p.seen.some(row=>row.text==='COMMIT'),false);assert.deepEqual(p.releases,[true,true,true]);}finally{await p.close();}assert.deepEqual(await snapshot(f),before);
});

test('native held evaluation enforces the real reviewed source-proof byte cap before body retrieval and evaluation',async t=>{
 const proofLimit=2097152,maxHeads=64,f=await fixture(t),keys=Array.from({length:maxHeads},(_,i)=>'label_'+String(i).padStart(2,'0'));await ordinaryAllow(f);
 const definition=taxonomy(keys);for(const label of definition.labels)label.description='Synthetic bounded metadata. '+'x'.repeat(800);const definitionBytes=Buffer.byteLength(canonicalDecisionJSON(definition));assert.ok(definitionBytes>50000&&definitionBytes<=65536);
 const tax=await publishTaxonomy(f,definition),w=await workflow(f,{assignments:1,quorum:1});let adjacent=0,priorCanonical=0,priorRaw=0,refused=false;
 for(let index=0;index<maxHeads;index++){
  await apply(f,{selected:await publishRule(f,rule(f,tax,keys[index]!)),workflow:w});const p=ownerPool(),before=await snapshot(f);let value:InactiveHeldHumanAssetMetadataEvaluation|undefined,error:unknown;
  try{try{value=await createAuthorityFoundationRepository(p.observed).evaluateHeldHumanAssetMetadata(readInput(f));}catch(e){error=e;}
   const phases=p.seen.filter(row=>row.text.includes('reviewed-classification:')).map(row=>row.text.match(/reviewed-classification:(counts|measure|bodies)/)![1]);
   const countRow=p.seen.find(row=>row.text.includes('reviewed-classification:counts'))!.rows[0]!,measure=p.seen.find(row=>row.text.includes('reviewed-classification:measure'))!.rows[0]!,count=Number(countRow.assignments),canonicalBytes=Number(measure.canonical_bytes)+count+1,rawBytes=Number(measure.raw_bytes)+count+1;
   assert.equal(count,index+1);assert.equal(Number(measure.assignments),count);assert.equal(Number(countRow.tasks),count);assert.equal(Number(countRow.decisions),count);assert.equal(Number(countRow.max_tasks),1);assert.equal(Number(countRow.max_decisions),1);assert.ok(count<256&&Number(countRow.tasks)<4096&&Number(countRow.decisions)<4096);assert.equal(measure.component_bounds,true);assert.equal(measure.dependencies_complete,true);
   if(error!==undefined){denied(error,'PROFILE_LIMIT');assert.deepEqual(phases,['counts','measure']);assert.ok(canonicalBytes>proofLimit||rawBytes>proofLimit);assert.equal(adjacent,count-1);assert.ok(adjacent>0&&priorCanonical<=proofLimit&&priorRaw<=proofLimit);assert.equal(p.seen.filter(row=>row.text.includes('FROM gc_authn.foundation_session_v1')).length,1);assert.equal(p.seen.at(-1)?.text,'ROLLBACK');assert.deepEqual(p.releases,[true]);refused=true;}
   else{assert.ok(value);inert(value,true,'allowed');assert.deepEqual(phases,['counts','measure','bodies']);assert.ok(canonicalBytes<=proofLimit&&rawBytes<=proofLimit);assert.equal(p.seen.at(-1)?.text,'COMMIT');assert.deepEqual(p.releases,[false]);adjacent=count;priorCanonical=canonicalBytes;priorRaw=rawBytes;}
  }finally{await p.close();}assert.deepEqual(await snapshot(f),before);if(refused)break;
 }
 assert.equal(refused,true,'Actual complete reviewed inventories must cross the source-proof byte cap within64 bounded assignments');
});
