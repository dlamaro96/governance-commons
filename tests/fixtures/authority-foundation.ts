// SPDX-License-Identifier: Apache-2.0
/** Synthetic owner-only integrity fixtures. Nothing here is administered access,
 * installation consent, production containment, or a runtime authority adapter. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {TestContext} from 'node:test';
import pg from 'pg';
import * as authn from './authority-authn-foundation.ts';
import {canonicalDecisionJSON, decisionHash} from '../../packages/authority/src/decision-schema.ts';
import type {ActionId} from '../../packages/authority/src/actions.ts';
import {policyHash, parsePolicyFile} from '../../packages/authority/src/policy.ts';
import {makeDecisionFixture, parsed, sealDecisionFixture, zero, type Mutable} from '../unit/fixtures/authority-decision.ts';
import type {Counter, Digest, PolicyDefinition, PolicyExpr, PolicyPin, Scope, UTC, UUID, Validity, Version} from '../../packages/authority/src/types.ts';
import type {AtomicRequest, AuthorityDecisionRegistry, AuthorityGrant, DelegableCeiling, EffectCeiling, GrantRef, PolicyEvidence, DefinitionEvidence} from '../../packages/authority/src/decision-types.ts';
import type {AuthorityHumanClosure, ClosureSelectors, ElevationUseRecord} from '../../packages/authority-storage/src/contracts.ts';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import {parseAuthorityHumanClosure} from '../../packages/authority-storage/src/loader.ts';
export {query,scalar,tx,extra,rejected,SqlFailure,uuid,digest,dbNow,waitBlocked,install,session,setMembership} from './authority-authn-foundation.ts';
const {query,scalar,tx,uuid,dbNow}=authn;
export const version=1 as Version;
export const forever:Validity={notBefore:null,expiresAt:null};
export const uid=()=>uuid() as UUID;
export type HumanGrant=Exclude<AuthorityGrant,{kind:'service'}>;
type Family='definition'|'group-membership'|'grant'|'elevation-use';
type DefinitionKind='policy'|'role'|'responsibility-type'|'group';
interface Pending {family:Family;id:string;kind:DefinitionKind|null;version:number;head:number;actor:string;rawBytes?:number;subId?:string|null}
export interface FoundationFixture extends authn.Fixture {
 hash:string;csrf:string;protectedSession:authn.Row;registry:Mutable<AuthorityDecisionRegistry>;registryId:string;
 request:AtomicRequest;now:UTC;pending:Pending[];people:Set<UUID>;model:{grants:HumanGrant[];policies:PolicyEvidence[];definitions:DefinitionEvidence[];memberships:Array<{id:string;groupId:string;identityId:string;state:'active'|'revoked';validity:Validity}>;parents:Map<string,{parent:GrantRef;via:string|null}>;uses:Mutable<ElevationUseRecord>[]};
}
export const selectors=(f:FoundationFixture):ClosureSelectors=>({formatVersion:1,requests:[f.request]});
export async function rawLoad(f:FoundationFixture,client=f.owner,text=JSON.stringify(selectors(f))):Promise<AuthorityHumanClosure>{
 return tx(client,async()=>(await scalar(client,'SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure',[f.hash,text])).closure as AuthorityHumanClosure,'REPEATABLE READ READ ONLY');
}
export async function load(f:FoundationFixture):Promise<AuthorityHumanClosure>{
 const pool=new pg.Pool({connectionString:authn.config.owner,max:1,connectionTimeoutMillis:5000});
 try{return await createAuthorityFoundationRepository(pool).loadHumanClosure({sessionHash:f.hash as Digest,selectors:selectors(f)});}
 catch(error){
  // A later fresh snapshot is diagnostic only: never substitute it for the failed
  // repository result. Keep raw closures, session hashes and identity rows private.
  const safeCode=(e:unknown)=>e!==null&&typeof e==='object'&&'code'in e&&typeof e.code==='string'&&/^(?:[0-9A-Z]{5}|AUTHORITY_FOUNDATION_[A-Z_]+)$/.test(e.code)?e.code:'UNCLASSIFIED';
  let diagnostic:string;
  try{const raw=await rawLoad(f),parsed=parseAuthorityHumanClosure(raw,JSON.stringify(f.registry));
   diagnostic=parsed.ok?'later-raw-snapshot-parser-accepted':JSON.stringify(parsed.issues.slice(0,3).map(issue=>({code:issue.code,path:issue.path.slice(0,240),message:issue.message.slice(0,240)})));
  }catch(probe){diagnostic='later-raw-snapshot-sqlstate='+safeCode(probe);}
  throw Object.assign(new Error('Foundation repository refusal '+safeCode(error)+'; diagnostic '+diagnostic),{code:safeCode(error)});
 }finally{await pool.end();}
}
export function jsonMeasure(value:unknown):{bytes:number;nodes:number;depth:number;hash:Digest}{
 let nodes=0,depth=0;const walk=(v:unknown,d:number)=>{nodes++;depth=Math.max(depth,d);if(Array.isArray(v))v.forEach(x=>walk(x,d+1));else if(v!==null&&typeof v==='object')Object.values(v).forEach(x=>walk(x,d+1));};walk(value,1);
 return {bytes:Buffer.byteLength(canonicalDecisionJSON(value)),nodes,depth,hash:decisionHash(value)};
}
const scalarString=(s:string)=>`S${Buffer.byteLength(s)}:${s}`;
export function foundationEncoding(operation:'registry-install'|'tenant-initialize',values:unknown[]):Buffer{
 const common=['request_id','release_ref','operator_ref','expected_db_oid','expected_owner_oid'];
 const names=operation==='registry-install'?['registry_id','registry_version','registry_document','expected_digest']:['tenant_id','generation','expected_authn_fence_epoch','registry_id','registry_version','registry_digest'];
 const kinds=operation==='registry-install'?['U','I','S','S']:['U','I','I','U','I','S'];
 const fields=[...common,...names],types=['U','S','S','I','I',...kinds];assert.equal(values.length,fields.length);
 return Buffer.from('gc-authority-foundation/v1;'+scalarString(operation)+fields.map((name,i)=>scalarString(name)+(values[i]===null?'N;':types[i]==='S'?scalarString(String(values[i])):`${types[i]}${values[i]};`)).join(''));
}
export async function foundationInstall(client:pg.Client,operation:'registry-install'|'tenant-initialize',args:unknown[],requestId=uuid()){
 const ids=await scalar(client,"SELECT (SELECT oid::text FROM pg_database WHERE datname=current_database()) db,(SELECT oid::text FROM pg_roles WHERE rolname=session_user) owner");
 const values=[requestId,'synthetic-authority-release','synthetic-integrity-fixture',ids.db,ids.owner,...args];
 const functionName=operation==='registry-install'?'install_registry_v1':'initialize_tenant_v1';
 const sql=`SELECT gc_authority.${functionName}(${values.map((_,i)=>'$'+(i+1)).join(',')}) AS receipt`;
 const receipt=(await scalar(client,sql,values)).receipt;
 const encoded=foundationEncoding(operation,values);assert.equal(receipt.manifestHash,createHash('sha256').update(encoded).digest('hex'));
 const saved=await scalar(client,'SELECT manifest_encoding,manifest_hash FROM gc_authority.installation_receipts WHERE id=$1',[receipt.receiptId]);
 assert.ok(Buffer.isBuffer(saved.manifest_encoding)&&saved.manifest_encoding.equals(encoded),'Independent installation preimage disagrees');assert.equal(saved.manifest_hash,receipt.manifestHash);
 return {receipt,values,sql};
}
export async function fixture(t:TestContext):Promise<FoundationFixture>{
 const base=await authn.fixture(t),s=await authn.session(base),registry=makeDecisionFixture().registry;
 const found=await query(base.owner,'SELECT id FROM gc_authority.registries WHERE digest=$1',[registry.digest]);let registryId:string;
 if(found.rowCount===1)registryId=found.rows[0]!.id;else{registryId=uuid();await foundationInstall(base.owner,'registry-install',[registryId,registry.version,JSON.stringify(registry),registry.digest]);}
 for(const tenant of [base.tenant,base.otherTenant])await foundationInstall(base.owner,'tenant-initialize',[tenant,'1',1,registryId,registry.version,registry.digest]);
 await query(base.owner,"SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[base.tenant,base.identity]);
 return {...base,hash:s.hash,csrf:s.csrf,protectedSession:s.row,registry,registryId,now:await dbNow(base.owner) as UTC,pending:[],people:new Set([base.identity as UUID]),
  request:{action:'asset:metadata.read',resource:{kind:'asset',tenantId:base.tenant as UUID,id:uid()},revision:version,field:null},
  model:{grants:[],policies:[],definitions:[],memberships:[],parents:new Map(),uses:[]}};
}
export async function epoch(f:FoundationFixture,client=f.owner):Promise<string>{await query(client,"SELECT set_config('gc.tenant_id',$1,false)",[f.tenant]);return (await scalar(client,'SELECT authority_epoch::text epoch FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).epoch;}
export async function startWrite(f:FoundationFixture,client=f.owner,expected?:string,sessionIds:string[]=[]):Promise<void>{
 await query(client,'SELECT gc_authority.foundation_write_begin_v1($1::uuid,$2::bigint)',[f.tenant,expected??await epoch(f,client)]);
 await query(client,'SELECT gc_authority.foundation_write_locks_v1($1::uuid[],$2::uuid[])',[[...f.people].sort(),[...sessionIds].sort()]);
}
const headTables={definition:'definition_heads','group-membership':'group_memberships',grant:'grant_heads','elevation-use':'elevation_uses'} as const;
export async function complete(f:FoundationFixture,client=f.owner):Promise<void>{
 for(const entry of f.pending){
  const table=headTables[entry.family],condition=entry.family==='definition'?' AND kind=$3':'';
  const head=(await scalar(client,`SELECT to_jsonb(h) body FROM gc_authority.${table} h WHERE tenant_id=$1 AND id=$2${condition}`,entry.family==='definition'?[f.tenant,entry.id,entry.kind]:[f.tenant,entry.id])).body;
  await query(client,`INSERT INTO gc_authority.lifecycle_revisions(tenant_id,family,object_id,definition_kind,head_version,previous_head_version,state,definition_version,changed_at,changed_by,reason,body_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
   [f.tenant,entry.family,entry.id,entry.kind,entry.head,entry.head===1?null:entry.head-1,head.state,entry.family==='definition'?head.definition_version:null,head.changed_at,entry.actor,'Synthetic integrity qualification',decisionHash(head)]);
  const family=entry.family==='definition'?(entry.kind==='policy'?'policy':entry.kind==='group'?'group':'definition'):entry.family;
  const forms=entry.family==='elevation-use'?['dto','elevation-use-embedded']:entry.family==='grant'&&head.kind==='elevation'?['grant-base']:['dto'];
  const versions=entry.family==='definition'&&entry.kind!=='group'?(await query(client,'SELECT version FROM gc_authority.definition_versions WHERE tenant_id=$1 AND id=$2 ORDER BY version',[f.tenant,entry.id])).rows.map(r=>r.version as number):[entry.version];
  for(const projectedVersion of versions)for(const form of forms){
   const value=(await scalar(client,'SELECT gc_authority.projection_v1($1,$2,$3,$4,$5,$6,$7) AS value',[f.tenant,family,entry.id,projectedVersion,entry.head,entry.subId??null,form])).value;
   const measure=jsonMeasure(value),rawBytes=family==='policy'?(await scalar(client,'SELECT octet_length(policy_document) n FROM gc_authority.policy_versions WHERE tenant_id=$1 AND policy_id=$2 AND version=$3',[f.tenant,entry.id,projectedVersion])).n:0;
   await query(client,`INSERT INTO gc_authority.projection_measures(id,tenant_id,family,projection_form,object_id,definition_kind,issuance_or_definition_version,head_version,sub_id,canonical_bytes,raw_bytes,json_nodes,json_depth,projection_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [uuid(),f.tenant,family,form,entry.id,entry.kind,projectedVersion,entry.head,entry.subId??null,measure.bytes,rawBytes,measure.nodes,measure.depth,measure.hash]);
  }
  if(family==='policy')for(const projectedVersion of versions){const intents=(await query(client,'SELECT rule_id FROM gc_authority.policy_deny_intents WHERE tenant_id=$1 AND policy_id=$2 AND policy_version=$3 ORDER BY rule_id',[f.tenant,entry.id,projectedVersion])).rows;
   for(const intent of intents){const value=(await scalar(client,"SELECT gc_authority.projection_v1($1,'deny-intent',$2,$3,$4,$5,'dto') value",[f.tenant,entry.id,projectedVersion,entry.head,intent.rule_id])).value,m=jsonMeasure(value);
    await query(client,"INSERT INTO gc_authority.projection_measures(id,tenant_id,family,projection_form,object_id,definition_kind,issuance_or_definition_version,head_version,sub_id,canonical_bytes,raw_bytes,json_nodes,json_depth,projection_hash) VALUES($1,$2,'deny-intent','dto',$3,'policy',$4,$5,$6,$7,0,$8,$9,$10)",[uuid(),f.tenant,entry.id,projectedVersion,entry.head,intent.rule_id,m.bytes,m.nodes,m.depth,m.hash]);}
  }
 }
 f.pending=[];
}
export async function mutate<T>(f:FoundationFixture,fn:()=>Promise<T>,client=f.owner,sessionIds:string[]=[]):Promise<T>{
 assert.equal(f.pending.length,0);f.now=await dbNow(client) as UTC;const previous=structuredClone(f.model);
 try{return await tx(client,async()=>{await startWrite(f,client,undefined,sessionIds);try{const result=await fn();await complete(f,client);return result;}finally{f.pending=[];}});}catch(error){f.model=previous;throw error;}
}
async function definition(f:FoundationFixture,kind:DefinitionKind,id:UUID,content:unknown,hash:Digest,key:string,versionNumber=1,client=f.owner,description='Integrity fixture only'):Promise<void>{
 if(versionNumber===1)await query(client,`INSERT INTO gc_authority.definition_heads(tenant_id,kind,id,key,definition_version,head_version,state,changed_at) VALUES($1,$2,$3,$4,1,1,'active',$5)`,[f.tenant,kind,id,key,f.now]);
 await query(client,`INSERT INTO gc_authority.definition_versions(tenant_id,kind,id,version,label,description,semantic_hash,created_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[f.tenant,kind,id,versionNumber,'Synthetic '+kind,description,hash,f.now,f.identity]);
 f.pending.push({family:'definition',id,kind,version:versionNumber,head:versionNumber,actor:f.identity});
 void content;
}
export async function addPolicy(f:FoundationFixture,options:{effect?:'allow'|'deny';action?:ActionId;document?:PolicyDefinition;id?:UUID;raw?:string;resourceWide?:boolean}={}):Promise<PolicyPin>{
 const id=options.id??options.document?.id??uid(),action=options.action??f.request.action;
 const expanded=f.registry.actions.filter(a=>a.family==='human'&&a.resourceKinds.includes('asset')).map(a=>a.action).sort();
 const document=options.document??{formatVersion:1,id,version,rules:[{id:uid(),effect:options.effect??'allow',actions:options.resourceWide?expanded:[action],fields:null,when:options.resourceWide?{op:'resource-kind-in',kinds:['asset']}:{op:'action-in',actions:[action]}}]};
 const raw=options.raw??JSON.stringify(document),policy=parsed(parsePolicyFile(raw,f.registry.fields)),hash=parsed(policyHash(policy,f.registry.fields));
 await definition(f,'policy',id,document,hash,'policy_'+id.replaceAll('-',''));
 const count=(node:PolicyExpr):number=>1+(node.op==='all'||node.op==='any'?node.children.reduce((n,x)=>n+count(x),0):0);
 const expressionNodes=policy.rules.reduce((n,rule)=>n+count(rule.when),0);
 await query(f.owner,`INSERT INTO gc_authority.policy_versions(tenant_id,policy_id,version,definition_kind,policy_document,policy_hash,canonical_bytes,rule_count,expression_node_count) VALUES($1,$2,1,'policy',$3,$4,$5,$6,$7)`,[f.tenant,id,raw,hash,Buffer.byteLength(canonicalDecisionJSON(policy)),policy.rules.length,expressionNodes]);
 f.pending[f.pending.length-1]!.rawBytes=Buffer.byteLength(raw);
 const pin={policyId:id,version,hash};
 const intents:Mutable<PolicyEvidence>['resourceWideIntents']=[];
 if(options.resourceWide){const actions=expanded;for(const rule of policy.rules){assert.equal(rule.effect,'deny');await query(f.owner,'INSERT INTO gc_authority.policy_deny_intents(tenant_id,policy_id,policy_version,policy_hash,rule_id,registry_id,registry_version,registry_digest,resource_kinds,expanded_actions) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9)',[f.tenant,id,hash,rule.id,f.registryId,f.registry.version,f.registry.digest,['asset'],actions]);intents.push({ruleId:rule.id,registryVersion:f.registry.version,registryDigest:f.registry.digest,resourceKinds:['asset'],expandedActions:actions});}}
 f.model.policies.push({tenantId:f.tenant as UUID,currentHeadVersion:version,state:'active',pin,document:raw,resourceWideIntents:intents});return pin;
}
export async function addRole(f:FoundationFixture,inputPins:PolicyPin[],description='Integrity fixture only'):Promise<{roleId:UUID;version:Version}>{
 const pins=[...inputPins].sort((a,b)=>`${a.policyId}@${a.version}#${a.hash}`.localeCompare(`${b.policyId}@${b.version}#${b.hash}`));assert.equal(new Set(pins.map(p=>`${p.policyId}@${p.version}#${p.hash}`)).size,pins.length);
 const id=uid(),metadata={key:'role_'+id.replaceAll('-',''),label:'Synthetic role',description},content={metadata,policies:pins};
 const envelope={formatVersion:1 as const,kind:'role' as const,id,version,content};
 await definition(f,'role',id,content,decisionHash(envelope),metadata.key,1,f.owner,description);
 for(const [ordinal,pin]of pins.entries())await query(f.owner,`INSERT INTO gc_authority.role_policy_pins(tenant_id,role_id,role_version,role_kind,ordinal,policy_id,policy_version,policy_hash) VALUES($1,$2,1,'role',$3,$4,$5,$6)`,[f.tenant,id,ordinal,pin.policyId,pin.version,pin.hash]);
 f.model.definitions.push({...envelope,tenantId:f.tenant as UUID,currentHeadVersion:version,state:'active',hash:decisionHash(envelope)});return {roleId:id,version};
}
export async function addGroup(f:FoundationFixture):Promise<UUID>{
 const id=uid(),metadata={key:'group_'+id.replaceAll('-',''),label:'Synthetic group',description:'Integrity fixture only'};
 await definition(f,'group',id,{metadata},decisionHash({formatVersion:1,kind:'group',id,version,content:{metadata}}),metadata.key);return id;
}
export async function addPerson(f:FoundationFixture):Promise<UUID>{
 const id=uid();await query(f.owner,'INSERT INTO public.identities(id,issuer,subject,name) VALUES($1,$2,$3,$4)',[id,f.issuer,id,'Synthetic graph subject']);
 await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,id]);await query(f.owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic','[]')",[f.tenant,id]);});f.people.add(id);return id;
}
export async function addMembership(f:FoundationFixture,groupId:UUID,identityId=f.identity as UUID,validity:Validity=forever):Promise<UUID>{
 const id=uid();await query(f.owner,`INSERT INTO gc_authority.group_memberships(tenant_id,id,issuance_version,group_id,group_kind,identity_id,not_before,expires_at,created_by,created_at,head_version,state,changed_at) VALUES($1,$2,1,$3,'group',$4,$5,$6,$7,$8,1,'active',$8)`,[f.tenant,id,groupId,identityId,validity.notBefore,validity.expiresAt,f.identity,f.now]);
 f.pending.push({family:'group-membership',id,kind:null,version:1,head:1,actor:f.identity});f.model.memberships.push({id,groupId,identityId,state:'active',validity});return id;
}
export interface GrantOptions {kind?:'ordinary-role'|'responsibility'|'delegation'|'elevation';responsibility?:{typeId:UUID;mappedRole:{roleId:UUID;version:Version}|null};issuer?:UUID;beneficiary?:{kind:'human'|'group';id:UUID};parent?:HumanGrant;via?:UUID|null;actions?:ActionId[];validity?:Validity;delegable?:DelegableCeiling|null;scope?:Scope;control?:unknown;omitOrigin?:boolean}
export async function addGrant(f:FoundationFixture,role:{roleId:UUID;version:Version},options:GrantOptions={}):Promise<HumanGrant>{
 const id=uid(),kind=options.kind??'ordinary-role',issuer={kind:'human' as const,id:options.issuer??f.identity as UUID},beneficiary=options.beneficiary??{kind:'human' as const,id:f.identity as UUID};
 const scope=options.scope??{kind:'tenant' as const,tenantId:f.tenant as UUID},validity=options.validity??forever,actions=options.actions??[f.request.action],ceiling:EffectCeiling={actions,resourceKinds:['asset'],fields:null,scope,validity};
 const scopeParts=scope.kind==='tenant'?[null,null,null,null]:scope.kind==='domain'?[scope.domainId,scope.includeDescendants,null,null]:[null,null,scope.resource.kind,scope.resource.id];
 await query(f.owner,`INSERT INTO gc_authority.grant_heads(tenant_id,id,issuance_version,kind,issuer_identity_id,beneficiary_kind,beneficiary_id,scope_kind,scope_tenant_id,domain_id,include_descendants,resource_kind,resource_id,not_before,expires_at,effect_ceiling,delegable_ceiling,control_ceiling,registry_id,registry_version,registry_digest,created_at,created_by,head_version,state,changed_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$1,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$4,1,'active',$20)`,[f.tenant,id,kind,issuer.id,beneficiary.kind,beneficiary.id,scope.kind,...scopeParts,validity.notBefore,validity.expiresAt,JSON.stringify(ceiling),options.delegable?JSON.stringify(options.delegable):null,options.control?JSON.stringify(options.control):null,f.registryId,f.registry.version,f.registry.digest,f.now]);
 if(beneficiary.kind==='human')await query(f.owner,'INSERT INTO gc_authority.grant_human_beneficiaries(tenant_id,grant_id,grant_version,identity_id) VALUES($1,$2,1,$3)',[f.tenant,id,beneficiary.id]);
 else await query(f.owner,"INSERT INTO gc_authority.grant_group_beneficiaries(tenant_id,grant_id,grant_version,group_id,group_kind) VALUES($1,$2,1,$3,'group')",[f.tenant,id,beneficiary.id]);
 const base={ref:{kind:kind==='delegation'||kind==='elevation'?kind:'grant',id,version} as GrantRef,kind,tenantId:f.tenant as UUID,state:'active' as const,issuer,beneficiary,scope,validity,ceiling};
 let grant:HumanGrant;
 if(kind==='ordinary-role'){
  if(!options.omitOrigin)await query(f.owner,"INSERT INTO gc_authority.ordinary_role_origins(tenant_id,grant_id,grant_version,role_id,role_version,role_kind) VALUES($1,$2,1,$3,$4,'role')",[f.tenant,id,role.roleId,role.version]);
  grant={...base,kind,role,delegable:options.delegable??null};
 }else if(kind==='responsibility'){
  assert.ok(options.responsibility);const type=options.responsibility,assignmentId=uid();
  await query(f.owner,"INSERT INTO gc_authority.responsibility_origins(tenant_id,grant_id,grant_version,assignment_id,assignment_version,type_id,type_version,type_kind,mapped_role_id,mapped_role_version,effective_grant_id) VALUES($1,$2,1,$3,1,$4,1,'responsibility-type',$5,$6,$7)",[f.tenant,id,assignmentId,type.typeId,type.mappedRole?.roleId??null,type.mappedRole?.version??null,type.mappedRole?id:null]);
  grant={...base,kind,type:{id:type.typeId,version},mappedRole:type.mappedRole,assignmentId,assignmentVersion:version,effectiveGrantId:type.mappedRole?id:null,delegable:options.delegable??null};
 }else{
  assert.ok(options.parent);const parent=options.parent.ref;
  await query(f.owner,'INSERT INTO gc_authority.connected_parents(tenant_id,child_id,child_version,parent_id,parent_version,parent_kind,via_group_membership_id,via_group_membership_version) VALUES($1,$2,1,$3,$4,$5,$6,$7)',[f.tenant,id,parent.id,parent.version,parent.kind,options.via??null,options.via?1:null]);
  f.model.parents.set(id,{parent,via:options.via??null});
  assert.equal(beneficiary.kind,'human');grant=kind==='delegation'?{...base,kind,beneficiary:{kind:'human',id:beneficiary.id},parent,delegable:options.delegable??null}:{...base,kind,beneficiary:{kind:'human',id:beneficiary.id},parent,use:null};
 }
 f.pending.push({family:'grant',id,kind:null,version:1,head:1,actor:issuer.id});f.model.grants.push(grant);return grant;
}
export async function readerGraph(f:FoundationFixture,options:GrantOptions={}):Promise<HumanGrant>{
 return mutate(f,async()=>addGrant(f,await addRole(f,[await addPolicy(f)]),options));
}
export async function revoke(f:FoundationFixture,family:Exclude<Family,'definition'>,id:string,client=f.owner):Promise<void>{
 const table=headTables[family];const row=await scalar(client,`UPDATE gc_authority.${table} SET state='revoked',head_version=head_version+1,changed_at=$3 WHERE tenant_id=$1 AND id=$2 RETURNING head_version`,[f.tenant,id,f.now]);
 f.pending.push({family,id,kind:null,version:1,head:row.head_version,actor:f.identity});
 const grant=f.model.grants.find(x=>x.ref.id===id);if(grant)(grant as Mutable<HumanGrant>).state='revoked';const membership=f.model.memberships.find(x=>x.id===id);if(membership)membership.state='revoked';const use=f.model.uses.find(x=>x.ref.id===id);if(use)use.state='revoked';
}
/** Independent set oracle over fixture declarations; never calls SQL selection,
 * projection, production parser or a policy evaluator to choose candidates. */
export function expectedCandidates(f:FoundationFixture,subject:string,asOf:string,request=f.request):string[]{
 const at=Date.parse(asOf),groups=new Set(f.model.memberships.filter(m=>m.identityId===subject&&m.state==='active'&&(m.validity.expiresAt===null||Date.parse(m.validity.expiresAt)>at)).map(m=>m.groupId));
 const intent=(g:HumanGrant):boolean=>{const seen=new Set<string>();while(g.kind==='delegation'||g.kind==='elevation'){assert.ok(!seen.has(g.ref.id));seen.add(g.ref.id);const parentId=g.parent.id,parent=f.model.grants.find(p=>p.ref.id===parentId);assert.ok(parent);g=parent;}
  const role=g.kind==='ordinary-role'?g.role:g.mappedRole;if(!role)return false;const definition=f.model.definitions.find(d=>d.kind==='role'&&d.id===role.roleId&&d.version===role.version);assert.ok(definition&&definition.kind==='role');return definition.content.policies.some(pin=>f.model.policies.find(p=>p.pin.policyId===pin.policyId&&p.pin.version===pin.version)?.resourceWideIntents.some(i=>i.resourceKinds.includes(request.resource.kind)));};
 return f.model.grants.filter(g=>g.state==='active'&&(g.validity.expiresAt===null||Date.parse(g.validity.expiresAt)>at)&&((g.beneficiary.kind==='human'&&g.beneficiary.id===subject)||(g.beneficiary.kind==='group'&&groups.has(g.beneficiary.id)))&&((g.ceiling.actions.includes(request.action)&&g.ceiling.resourceKinds.includes(request.resource.kind)&&(request.field===null||g.ceiling.fields===null||g.ceiling.fields.includes(request.field)))||intent(g))).map(g=>g.ref.id).sort();
}
export function assertOracle(f:FoundationFixture,closure:AuthorityHumanClosure):void{
 assert.equal(closure.contentAuthority,false);assert.equal(closure.session.identityId,f.identity);
 const expected=new Map<string,{subject:string;request:AtomicRequest;candidates:string[]}>(),all=new Set<string>(),deps=new Set<string>();
 const partitionKey=(subject:string,request:AtomicRequest)=>decisionHash({formatVersion:1,subject:{kind:'human',id:subject},request});
 const queue=closure.selectors.map(request=>({subject:f.identity,request}));
 for(let index=0;index<queue.length;index++){const {subject,request}=queue[index]!,key=partitionKey(subject,request);if(expected.has(key))continue;const candidates=expectedCandidates(f,subject,closure.snapshot.asOf,request);expected.set(key,{subject,request,candidates});
  for(const id of candidates){let cursor:string|undefined=id;const seen=new Set<string>();while(cursor){assert.ok(!seen.has(cursor),'Independent fixture graph cycle');seen.add(cursor);all.add(cursor);const parent=f.model.parents.get(cursor);if(!parent)break;const g=f.model.grants.find(g=>g.ref.id===cursor);assert.ok(g);const issuer=partitionKey(g.issuer.id,request);deps.add(`${key}/${issuer}/${g.ref.id}`);queue.push({subject:g.issuer.id,request});cursor=parent.parent.id;}}
 }
 assert.deepEqual(closure.partitions.map(p=>p.key).sort(),[...expected.keys()].sort(),'Complete independently discovered issuer partition set');
 for(const p of closure.partitions)assert.deepEqual(p.candidates.map(x=>x.id).sort(),expected.get(p.key)!.candidates);
 assert.deepEqual(closure.dependencies.map(d=>`${d.from}/${d.issuer}/${d.child.id}`).sort(),[...deps].sort());
 assert.deepEqual(closure.grants.map(g=>g.ref.id).sort(),[...all].sort());
 const canonicalSet=(rows:readonly unknown[])=>rows.map(canonicalDecisionJSON).sort();const expectedGrants=f.model.grants.filter(g=>all.has(g.ref.id)).map(g=>{if(g.kind!=='elevation')return g;const at=Date.parse(closure.snapshot.asOf),uses=f.model.uses.filter(u=>u.elevation.id===g.ref.id&&u.sessionId===closure.session.sessionId&&u.sessionVersion===closure.session.sessionVersion&&u.state==='active'&&u.validity.expiresAt!==null&&Date.parse(u.validity.expiresAt)>at);uses.sort((a,b)=>{const n=(u:typeof a)=>u.validity.notBefore===null?-Infinity:Date.parse(u.validity.notBefore);const ac=n(a)<=at,bc=n(b)<=at;return ac!==bc?(ac?-1:1):n(a)-n(b)||a.ref.id.localeCompare(b.ref.id);});const u=uses[0];return {...g,use:u?{id:u.ref.id,version:u.ref.version,identityId:u.identityId,sessionId:u.sessionId,sessionVersion:u.sessionVersion,generation:u.generation,state:u.state,validity:u.validity}:null};});
 assert.deepEqual(canonicalSet(closure.grants),canonicalSet(expectedGrants),'Immutable grant bodies and exact selected elevation use');
 const definitionKeys=new Set<string>();for(const g of expectedGrants){if(g.kind==='ordinary-role')definitionKeys.add(`role:${g.role.roleId}@${g.role.version}`);if(g.kind==='responsibility'){definitionKeys.add(`responsibility-type:${g.type.id}@${g.type.version}`);if(g.mappedRole)definitionKeys.add(`role:${g.mappedRole.roleId}@${g.mappedRole.version}`);}}
 const definitions=f.model.definitions.filter(d=>definitionKeys.has(`${d.kind}:${d.id}@${d.version}`));assert.deepEqual(canonicalSet(closure.definitions),canonicalSet(definitions),'Exact immutable role/type pins and independent publication heads');
 const policyKeys=new Set(definitions.flatMap(d=>d.kind==='role'?d.content.policies.map(p=>`${p.policyId}@${p.version}#${p.hash}`):[]));assert.deepEqual(canonicalSet(closure.policies),canonicalSet(f.model.policies.filter(p=>policyKeys.has(`${p.pin.policyId}@${p.pin.version}#${p.pin.hash}`))),'Exact raw policy documents, hashes, pins and expanded intents');
 assert.deepEqual(canonicalSet(closure.elevationUses),canonicalSet(f.model.uses.filter(u=>all.has(u.elevation.id)&&u.state==='active'&&u.validity.expiresAt!==null&&Date.parse(u.validity.expiresAt)>Date.parse(closure.snapshot.asOf))));
 const expectedParents=[...all].flatMap(id=>{const row=f.model.parents.get(id);return row?[`${id}/${row.parent.id}/${row.via??''}`]:[];}).sort();assert.deepEqual(closure.parents.map(p=>`${p.child.id}/${p.parent.id}/${p.viaMembership?.id??''}`).sort(),expectedParents);
}

export async function addResponsibilityType(f:FoundationFixture,role:{roleId:UUID;version:Version}|null):Promise<UUID>{
 const id=uid(),metadata={key:'type_'+id.replaceAll('-',''),label:'Synthetic responsibility-type',description:'Integrity fixture only'},content={metadata,grantsRole:role};
 const envelope={formatVersion:1 as const,kind:'responsibility-type' as const,id,version,content};
 await definition(f,'responsibility-type',id,content,decisionHash(envelope),metadata.key);
 await query(f.owner,"INSERT INTO gc_authority.responsibility_role_pins(tenant_id,type_id,type_version,type_kind,role_id,role_version) VALUES($1,$2,1,'responsibility-type',$3,$4)",[f.tenant,id,role?.roleId??null,role?.version??null]);
 f.model.definitions.push({...envelope,tenantId:f.tenant as UUID,currentHeadVersion:version,state:'active',hash:decisionHash(envelope)});return id;
}
export async function addElevationUse(f:FoundationFixture,elevation:HumanGrant,validity:Validity,session=f.protectedSession):Promise<UUID>{
 assert.equal(elevation.kind,'elevation');assert.ok(validity.expiresAt);const id=uid();
 await query(f.owner,"INSERT INTO gc_authority.elevation_uses(tenant_id,id,issuance_version,elevation_id,elevation_version,identity_id,protected_session_id,protected_session_version,generation,not_before,expires_at,created_at,head_version,state,changed_at) VALUES($1,$2,1,$3,1,$4,$5,$6,1,$7,$8,$9,1,'active',$9)",[f.tenant,id,elevation.ref.id,f.identity,session.session_id,session.session_version,validity.notBefore,validity.expiresAt,f.now]);
 f.pending.push({family:'elevation-use',id,kind:null,version:1,head:1,actor:f.identity});f.model.uses.push({ref:{id,version},elevation:elevation.ref,identityId:f.identity as UUID,sessionId:session.session_id,sessionVersion:session.session_version,generation:'1' as Counter,state:'active',validity:structuredClone(validity)});return id;
}
export async function fourEdge(f:FoundationFixture):Promise<{origin:HumanGrant;terminal:HumanGrant;people:UUID[]}>{
 const people:UUID[]=[];for(let i=0;i<4;i++)people.push(await addPerson(f));people.push(f.identity as UUID);
 return mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),scope:Scope={kind:'tenant',tenantId:f.tenant as UUID};
  const origin=await addGrant(f,role,{issuer:people[0],beneficiary:{kind:'human',id:people[0]!},delegable:{actions:[f.request.action as 'asset:metadata.read'],fields:null,scope,validity:forever,remainingDepth:4}});
  let terminal=origin;for(let i=0;i<4;i++)terminal=await addGrant(f,role,{kind:'delegation',issuer:people[i],beneficiary:{kind:'human',id:people[i+1]!},parent:terminal,delegable:i===3?null:{actions:[f.request.action as 'asset:metadata.read'],fields:null,scope,validity:forever,remainingDepth:3-i}});
  return {origin,terminal,people};
 });
}
/** Complete synthetic content/fact/authentication assembly for the admitted asset
 * fixture only. The separately produced resource evidence is explicitly synthetic. */
export function syntheticAssembly(f:FoundationFixture,closure:AuthorityHumanClosure){
 assert.equal(closure.selectors.length,1,'Synthetic assembly currently proves one complete atomic root only');
 const result=makeDecisionFixture(),bundle=result.bundle;result.registry=structuredClone(f.registry);
 const base=structuredClone(bundle.nodes[0]!);bundle.nodes=[];bundle.candidates=[];bundle.chainLinks=[];
 bundle.snapshot={tenantId:closure.snapshot.tenantId,generation:closure.snapshot.generation,authorityEpoch:closure.snapshot.authorityEpoch,registryVersion:closure.snapshot.registryVersion,registryDigest:closure.snapshot.registryDigest,snapshotDigest:closure.snapshot.closureDigest,now:closure.snapshot.asOf};
 // SQL retains ordinary issuer identity for canonical attribution. The pure
 // engine consumes live principal evidence only for actual decision subjects
 // and connected human endpoints; attribution alone creates no issuer decision.
 const closureBytes=canonicalDecisionJSON(closure),neededPrincipals=new Set(closure.partitions.map(p=>p.subject.id));neededPrincipals.add(closure.session.identityId);
 for(const grant of closure.grants)if(grant.kind==='delegation'||grant.kind==='elevation'){neededPrincipals.add(grant.issuer.id);neededPrincipals.add(grant.beneficiary.id);}
 for(const principal of closure.principals)if(!neededPrincipals.has(principal.id)){
  const attributed=closure.grants.filter(g=>g.issuer.id===principal.id);
  assert.ok(attributed.length>0&&attributed.every(g=>g.kind==='ordinary-role'||g.kind==='responsibility'),'Only ordinary issuance attribution may be outside the pure principal input');
  assert.ok(!closure.grants.some(g=>g.beneficiary.kind==='human'&&g.beneficiary.id===principal.id)&&!closure.memberships.some(m=>m.identityId===principal.id)&&!closure.principalGroups.some(g=>g.subject.id===principal.id)&&!closure.elevationUses.some(u=>u.identityId===principal.id),'A referenced live principal must not be omitted from the pure input');
 }
 bundle.principals=structuredClone(closure.principals.filter(p=>neededPrincipals.has(p.id))) as typeof bundle.principals;
 for(const principal of bundle.principals)assert.equal(canonicalDecisionJSON(principal),canonicalDecisionJSON(closure.principals.find(p=>p.id===principal.id)),'Included principal evidence must remain byte-equivalent');
 bundle.groups=structuredClone(closure.groups) as typeof bundle.groups;bundle.memberships=structuredClone(closure.memberships) as typeof bundle.memberships;bundle.principalGroups=structuredClone(closure.principalGroups) as typeof bundle.principalGroups;
 bundle.definitions=structuredClone(closure.definitions) as typeof bundle.definitions;bundle.policies=structuredClone(closure.policies) as typeof bundle.policies;bundle.grants=structuredClone(closure.grants) as typeof bundle.grants;
 bundle.sessions=[{id:closure.session.sessionId,version:closure.session.sessionVersion,identityId:closure.session.identityId,selectedTenantId:closure.session.tenantId,generation:closure.session.generation,state:'active',validity:{notBefore:closure.session.issuedAt,expiresAt:closure.session.expiresAt}}];
 const contexts=new Map<string,typeof base>();let serial=1;
 const create=(subject:UUID,request:AtomicRequest,child:GrantRef|null):typeof base=>{
  const key=decisionHash({subject,request,child});const prior=contexts.get(key);if(prior)return prior;
  const node=structuredClone(base);node.id=(serial++).toString(16).padStart(64,'0') as Digest;node.subject={kind:'human',id:subject};node.request=structuredClone(request);
  node.authentication=child?{kind:'live-issuer',childGrant:child,elevationSession:null}:{kind:'human-session',sessionId:closure.session.sessionId,sessionVersion:closure.session.sessionVersion};
  const containment={resource:node.request.resource,revision:node.request.revision,context:'current' as const,securityRevision:'1' as Counter,domainPath:{status:'known' as const,value:[]},operation:null};
  node.resource={requestResource:node.request.resource,requestedRevision:node.request.revision,canonicalCurrentVersion:node.request.revision,containment,classifications:{status:'known',value:[]},approvedTags:{status:'known',value:[]}};
  node.intentGuard=(serial++).toString(16).padStart(64,'0') as Digest;node.guardOrigin=null;node.factDigest=zero;
  const guard={...structuredClone(node),id:node.intentGuard,mode:'resource-wide-deny' as const,adapterId:'asset.guard',intentGuard:null,guardOrigin:node.id};
  bundle.nodes.push(node,guard);contexts.set(key,node);
  const partition=closure.partitions.find(p=>p.subject.id===subject&&decisionHash(p.request)===decisionHash(request));assert.ok(partition,'Loaded complete issuer partition required');
  for(const n of [node,guard])bundle.candidates.push({nodeId:n.id,snapshotDigest:bundle.snapshot.snapshotDigest,subject:n.subject,request:n.request,anchorDigest:zero,candidates:structuredClone(partition.candidates) as typeof bundle.candidates[number]['candidates']});
  const ancestors=new Set<string>();const links=(ref:GrantRef)=>{if(ancestors.has(ref.id))return;ancestors.add(ref.id);const parent=closure.parents.find(p=>p.child.id===ref.id);if(!parent)return;const grant=closure.grants.find(g=>g.ref.id===ref.id);assert.ok(grant);const issuer=create(grant.issuer.id,request,grant.ref);for(const n of [node,guard])bundle.chainLinks.push({nodeId:n.id,child:parent.child,parent:parent.parent,issuerDecision:issuer.id,viaMembership:parent.viaMembership});links(parent.parent);};
  partition.candidates.forEach(links);return node;
 };
 const root=create(closure.session.identityId,closure.selectors[0]!,null);bundle.root=root.id;
 bundle.scopeAnchors=[];assert.ok(closure.grants.every(g=>(g.kind!=='delegation'&&g.kind!=='elevation')||g.scope.kind==='tenant'),'Synthetic assembler supports tenant-scoped connected chains only');
 const catalogs=()=>canonicalDecisionJSON({principals:bundle.principals,groups:bundle.groups,memberships:bundle.memberships,principalGroups:bundle.principalGroups,definitions:bundle.definitions,policies:bundle.policies,grants:bundle.grants,sessions:bundle.sessions});const before=catalogs();const sealed=sealDecisionFixture(result);assert.equal(catalogs(),before,'Synthetic adapter must not repair loaded hashes, pins or authority catalogs');assert.equal(canonicalDecisionJSON(closure),closureBytes,'Pure adaptation must preserve the complete SQL closure');return sealed;
}

export async function publishRole(f:FoundationFixture,roleId:UUID,inputPins:PolicyPin[]):Promise<void>{
 const pins=[...inputPins].sort((a,b)=>`${a.policyId}@${a.version}#${a.hash}`.localeCompare(`${b.policyId}@${b.version}#${b.hash}`));assert.equal(new Set(pins.map(p=>`${p.policyId}@${p.version}#${p.hash}`)).size,pins.length);
 const old=await scalar(f.owner,'SELECT key,definition_version,head_version FROM gc_authority.definition_heads WHERE tenant_id=$1 AND id=$2',[f.tenant,roleId]);
 const next=old.definition_version+1,head=old.head_version+1,content={metadata:{key:old.key,label:'Synthetic role',description:'Integrity fixture only'},policies:pins};
 await query(f.owner,'UPDATE gc_authority.definition_heads SET definition_version=$3,head_version=$4,changed_at=$5 WHERE tenant_id=$1 AND id=$2',[f.tenant,roleId,next,head,f.now]);
 await definition(f,'role',roleId,content,decisionHash({formatVersion:1,kind:'role',id:roleId,version:next,content}),old.key,next);
 f.pending[f.pending.length-1]!.head=head;
 for(const row of f.model.definitions)if(row.id===roleId)(row as Mutable<DefinitionEvidence>).currentHeadVersion=next as Version;f.model.definitions.push({formatVersion:1,kind:'role',id:roleId,version:next as Version,tenantId:f.tenant as UUID,currentHeadVersion:next as Version,state:'active',content,hash:decisionHash({formatVersion:1,kind:'role',id:roleId,version:next,content})});
 for(const [i,pin]of pins.entries())await query(f.owner,"INSERT INTO gc_authority.role_policy_pins(tenant_id,role_id,role_version,role_kind,ordinal,policy_id,policy_version,policy_hash) VALUES($1,$2,$3,'role',$4,$5,$6,$7)",[f.tenant,roleId,next,i,pin.policyId,pin.version,pin.hash]);
}
export async function retireDefinition(f:FoundationFixture,id:UUID):Promise<void>{
 const row=await scalar(f.owner,"UPDATE gc_authority.definition_heads SET state='retired',head_version=head_version+1,changed_at=$3 WHERE tenant_id=$1 AND id=$2 RETURNING kind,head_version,definition_version",[f.tenant,id,f.now]);
 f.pending.push({family:'definition',id,kind:row.kind,version:row.definition_version,head:row.head_version,actor:f.identity});for(const d of f.model.definitions)if(d.id===id)(d as Mutable<DefinitionEvidence>).state='retired';
}

/** Separate one-edge delegations create a deep issuer-decision DAG without
 * extending any individual grant lineage beyond its four-edge contract. */
export async function issuerDepthGraph(f:FoundationFixture,depth:number):Promise<void>{
 assert.ok(depth>=2&&depth<=17);const people:UUID[]=[];for(let i=0;i<depth-1;i++)people.push(await addPerson(f));people.push(f.identity as UUID);
 await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]);for(let i=0;i<depth-1;i++){const issuer=people[i]!,origin=await addGrant(f,role,{issuer,beneficiary:{kind:'human',id:issuer},delegable:{actions:['asset:metadata.read'],fields:null,scope:{kind:'tenant',tenantId:f.tenant as UUID},validity:forever,remainingDepth:4}});await addGrant(f,role,{kind:'delegation',issuer,parent:origin,beneficiary:{kind:'human',id:people[i+1]!}});}});
}
