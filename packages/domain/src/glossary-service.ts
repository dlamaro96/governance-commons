// SPDX-License-Identifier: Apache-2.0
import {sql,lockTenantLedger,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {parseGlossaryPublication} from './glossary.ts';
import type {GlossaryPublicationInput} from './glossary-contracts.ts';
import {approvalQuery,approvalFailure,getApprovalDefinition,getApprovalRequest,type ApprovalRequestView} from './approval-service.ts';
import {modelPersistence} from './model-service.ts';
import {validateAttributes} from './model.ts';
import {resolveAssetType,type ResolvedAssetType} from './asset-type.ts';
import {storedAssetType,typeHash} from './asset-type-policy.ts';
import {resolveRelationDefinition,validateRelationEndpoints} from './relation.ts';
import type {RelationEndpointPolicyState} from './relation-contracts.ts';

export interface GlossaryProposalInput {
 requestId:string;resourceId:string;resourceVersion:number|null;publication:GlossaryPublicationInput;
 workflowPin:{id:string;version:number;definitionHash:string};assignments:Readonly<Record<string,string>>;expiresAt:string;
}
type Row=Record<string,any>;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY=/^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const HASH=/^[0-9a-f]{64}$/;
const actions=['catalog:read','catalog:write','models:read','models:write'];
const invalid=()=>new Problem(400,'GLOSSARY_INPUT_INVALID','Provide exactly the declared glossary proposal fields and values.');
const unavailable=()=>new Problem(404,'GLOSSARY_REFERENCE_UNAVAILABLE','The glossary resource or a referenced resource is unavailable.');
const policyInvalid=()=>new Problem(422,'GLOSSARY_POLICY_INVALID','The proposal does not satisfy its pinned type, lifecycle or relationship rules.');
const conflict=(code='GLOSSARY_PIN_STALE')=>new Problem(409,code,'A proposed resource or definition changed. Reload before submitting.');
const integrity=()=>new Problem(500,'GLOSSARY_STORAGE_INVALID','The stored glossary references could not be verified.');
const limit=()=>new Problem(422,'GLOSSARY_LIMIT','The complete proposal exceeds its supported materialization bounds.');
function fields(value:unknown,names:readonly string[]|null,max=256):Record<string,unknown>{
 try{
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw 0;
  const keys=Reflect.ownKeys(value);if(keys.length>max||names&&(keys.length!==names.length||names.some(name=>!keys.includes(name))))throw 0;
  const entries=new Map<string,unknown>();
  for(const name of keys){if(typeof name!=='string'||names&&!names.includes(name)||!names&&!KEY.test(name))throw 0;
   const d=Object.getOwnPropertyDescriptor(value,name);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;entries.set(name,d.value);}
  return Object.fromEntries(entries);
 }catch{throw invalid();}
}
const integer=(value:unknown):value is number=>typeof value==='number'&&Number.isInteger(value)&&value>=1&&value<=2147483647;
const uuid=(value:unknown):value is string=>typeof value==='string'&&UUID.test(value)&&value!=='00000000-0000-0000-0000-000000000000';
function parse(input:unknown):GlossaryProposalInput{
 const v=fields(input,['requestId','resourceId','resourceVersion','publication','workflowPin','assignments','expiresAt']);
 const pin=fields(v.workflowPin,['id','version','definitionHash']),assignments=fields(v.assignments,null);
 if(!uuid(v.requestId)||!uuid(v.resourceId)||v.resourceVersion!==null&&!integer(v.resourceVersion)||typeof pin.id!=='string'||!KEY.test(pin.id)
  ||!integer(pin.version)||typeof pin.definitionHash!=='string'||!HASH.test(pin.definitionHash)||!Object.keys(assignments).length
  ||Object.values(assignments).some(value=>!uuid(value))||typeof v.expiresAt!=='string'||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(v.expiresAt)
  ||!Number.isFinite(Date.parse(v.expiresAt))||new Date(v.expiresAt).toISOString()!==v.expiresAt||v.expiresAt.startsWith('0000'))throw invalid();
 const publication=parseGlossaryPublication(v.publication);if(!publication.ok)throw new Problem(422,'GLOSSARY_PUBLICATION_INVALID','Correct the glossary publication.',publication.issues);
 if(publication.value.input.links.some(link=>link.targetAssetId===v.resourceId))throw policyInvalid();
 return {requestId:v.requestId,resourceId:v.resourceId,resourceVersion:v.resourceVersion as number|null,publication:publication.value.input,
  workflowPin:pin as unknown as GlossaryProposalInput['workflowPin'],assignments:assignments as Record<string,string>,expiresAt:v.expiresAt};
}
function context(key:string,correlation:string){
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation.length||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw invalid();
}
const visible=(row:Row,identity:string)=>row.visibility==='tenant'||Array.isArray(row.allowed_identities)&&row.allowed_identities.includes(identity);

/** Submission performs no resource effect. The canonical approval command owns
 * request/tasks, exact idempotency, journal and dispatch in this transaction. */
export async function submitGlossaryProposal(tx:Tx,p:Principal,correlationId:string,idempotencyKey:string,input:GlossaryProposalInput):Promise<{request:ApprovalRequestView}>{
 const value=parse(input);context(idempotencyKey,correlationId);
 const publication=value.publication,body={id:value.requestId,binding:'glossary.publish',resourceId:value.resourceId,resourceVersion:value.resourceVersion,payload:publication,
  workflowId:value.workflowPin.id,workflowVersion:value.workflowPin.version,workflowHash:value.workflowPin.definitionHash,assignments:value.assignments,expiresAt:value.expiresAt};
 if(Buffer.byteLength(JSON.stringify(body))>327680)throw limit();
 const query=<T>(work:()=>Promise<T>)=>approvalQuery(tx,work);
 await query(()=>modelPersistence.authorize(tx,p,actions));await query(()=>lockTenantLedger(tx,p.tenantId));
 const reviewers=[...new Set(Object.values(value.assignments))].sort(),audience=[...new Set([p.id,...reviewers])].sort();
 const principals=[...new Set([...audience,publication.ownerId,...publication.allowedIdentityIds])].sort();
 await query(()=>sql`select public.gc_lock_type_migration_principals(${principals}::uuid[])`.execute(tx));
 await query(()=>modelPersistence.authorize(tx,p,actions));
 const members=(await query(()=>sql<Row>`select m.identity_id,m.active,i.active as identity_active,(m.permissions @> '["catalog:read","catalog:write"]'::jsonb) as can_review from public.memberships m join public.identities i on i.id=m.identity_id
  where m.tenant_id=${p.tenantId}::uuid and m.identity_id=any(${principals}::uuid[]) order by m.identity_id`.execute(tx))).rows;
 if(members.length!==principals.length||members.some(m=>!m.active||!m.identity_active||reviewers.includes(m.identity_id)&&!m.can_review))
  throw new Problem(403,'GLOSSARY_PARTICIPANT_UNAVAILABLE','The complete active review and ownership scope is unavailable.');
 if(publication.visibility==='restricted'&&audience.some(id=>!publication.allowedIdentityIds.includes(id)))throw new Problem(422,'GLOSSARY_REVIEW_VISIBILITY','Every reviewer and the requester must be able to see the proposed glossary resource.');
 const ids=[...new Set([value.resourceId,...publication.links.map(link=>link.targetAssetId)])].sort();
 // Check all requested visibility before transferring values or reporting sizes.
 const hidden=(await query(()=>sql`select 1 from unnest(${ids}::uuid[]) selected(id) left join public.assets a on a.tenant_id=${p.tenantId}::uuid and a.id=selected.id
  where (a.id is null and (selected.id<>${value.resourceId}::uuid or ${value.resourceVersion!==null}))
   or (a.id is not null and exists(select 1 from unnest(${audience}::uuid[]) viewer(id) where a.visibility<>'tenant' and not(a.allowed_identities @> jsonb_build_array(viewer.id::text)))) limit 1`.execute(tx))).rows;
 if(hidden.length)throw unavailable();
 await query(()=>sql`select id from public.assets where tenant_id=${p.tenantId}::uuid and id=any(${ids}::uuid[]) order by id for share`.execute(tx));
 const size=(await query(()=>sql<{bytes:string}>`select coalesce(sum(octet_length(jsonb_build_object('id',id,'version',version,'model_id',model_id,'model_version',model_version,
  'type_state',type_state,'type',type,'source_id',source_id,'status',status,'visibility',visibility,'allowed_identities',allowed_identities)::text)),0)::text as bytes
  from public.assets where tenant_id=${p.tenantId}::uuid and id=any(${ids}::uuid[])`.execute(tx))).rows[0];
 if(!size||!/^\d+$/.test(size.bytes))throw integrity();if(BigInt(size.bytes)>524288n)throw limit();
 const rows=(await query(()=>sql<Row>`select id,version,model_id,model_version,type_state,type,source_id,status,visibility,allowed_identities from public.assets
  where tenant_id=${p.tenantId}::uuid and id=any(${ids}::uuid[]) order by id`.execute(tx))).rows;
 const assets=new Map(rows.map(row=>[row.id,row])),base=assets.get(value.resourceId);
 if(rows.some(row=>audience.some(id=>!visible(row,id)))||publication.links.some(link=>!assets.has(link.targetAssetId))||value.resourceVersion!==null&&!base)throw unavailable();
 const retained=(await query(()=>sql<{request_hash:string}>`select request_hash from public.idempotency where tenant_id=${p.tenantId}::uuid and actor_id=${p.id}
  and operation='approval.submit' and key=${idempotencyKey}`.execute(tx))).rows[0];
 const hash=modelPersistence.hash(body);
 if(retained&&retained.request_hash!==hash)throw conflict('IDEMPOTENCY_CONFLICT');
 // Exact historical retries retain current permission/participant/visibility checks.
 // New commands alone must match the current resource and definition versions.
 if(!retained){
  if(value.resourceVersion===null?!!base:base?.version!==value.resourceVersion)throw conflict('VERSION_CONFLICT');
  if(base&&(base.source_id!==null||base.type!=='business_term'||base.status!=='active'||base.model_id!==publication.typePin.modelId||base.model_version!==publication.typePin.version))throw policyInvalid();
  if(publication.links.some(link=>assets.get(link.targetAssetId)!.status!=='active'))throw unavailable();
  if(publication.links.some(link=>assets.get(link.targetAssetId)!.version!==link.targetAssetVersion))throw conflict('VERSION_CONFLICT');
  await query(()=>sql`select pg_advisory_xact_lock(hashtextextended(${`governance-models:${p.tenantId}`},0))`.execute(tx));
  const modelIds=[...new Set(['business_term',publication.typePin.modelId,...rows.map(row=>row.model_id).filter((id):id is string=>typeof id==='string')])].sort();
  const heads=(await query(()=>sql<Row>`select id,type_id,current_version from public.governance_models where tenant_id=${p.tenantId}::uuid and id=any(${modelIds}::text[]) order by id for share`.execute(tx))).rows;
  const models=new Map(heads.map(row=>[row.id,row]));
  const term=models.get('business_term'),head=models.get(publication.typePin.modelId);
  if(!term?.type_id||!head?.type_id)throw unavailable();
  if(head.type_id!==publication.typePin.typeId||head.current_version!==publication.typePin.version)throw conflict();
  let policyBytes=0;
  const charge=(bytes:unknown)=>{if(typeof bytes!=='number'&&!/^[0-9]+$/.test(String(bytes)))throw integrity();policyBytes+=Number(bytes);if(!Number.isSafeInteger(policyBytes)||policyBytes>524288)throw limit();};
  const cache=new Map<string,{policy:ResolvedAssetType;typeId:string;ancestorTypes:RelationEndpointPolicyState['ancestorTypes'];row:Row}>();
  const policy=async(modelId:string,version:number)=>{
   const key=`${modelId}:${version}`,cached=cache.get(key);if(cached)return cached;
   const count=(await query(()=>sql<{bytes:number}>`select octet_length(definition::text)+octet_length(resolved::text) as bytes from public.asset_type_versions
    where tenant_id=${p.tenantId}::uuid and model_id=${modelId} and version=${version}`.execute(tx))).rows[0];if(!count)throw unavailable();charge(count.bytes);
   const stored=(await query(()=>sql<Row>`select model_id,version,definition,resolved,definition_hash,resolution_hash from public.asset_type_versions
    where tenant_id=${p.tenantId}::uuid and model_id=${modelId} and version=${version}`.execute(tx))).rows[0];if(!stored)throw unavailable();
   const resolved=storedAssetType(stored),parents:unknown[]=[],ancestors:{typeId:string;id:string;version:number}[]=[];
   for(const pin of [...resolved.dependencies].sort((a,b)=>a.id.localeCompare(b.id))){
    const measured=(await query(()=>sql<{bytes:number}>`select octet_length(v.definition::text) as bytes from public.asset_type_versions v
     where v.tenant_id=${p.tenantId}::uuid and v.model_id=${pin.id} and v.version=${pin.version}`.execute(tx))).rows[0];if(!measured)throw integrity();charge(measured.bytes);
    const parent=(await query(()=>sql<Row>`select v.definition,v.definition_hash,m.type_id from public.asset_type_versions v join public.governance_models m on m.tenant_id=v.tenant_id and m.id=v.model_id
     where v.tenant_id=${p.tenantId}::uuid and v.model_id=${pin.id} and v.version=${pin.version} for share of m`.execute(tx))).rows[0];
    if(!parent?.type_id||typeHash(parent.definition)!==parent.definition_hash)throw integrity();parents.push(parent.definition);ancestors.push({typeId:parent.type_id,id:pin.id,version:pin.version});
   }
   const recomputed=resolveAssetType(resolved.definition,parents),identity=models.get(modelId);
   if(!identity?.type_id||!recomputed.ok||typeHash(recomputed.value)!==stored.resolution_hash)throw integrity();
   const result={policy:recomputed.value,typeId:identity.type_id,ancestorTypes:ancestors,row:stored};cache.set(key,result);return result;
  };
  const selected=await policy(publication.typePin.modelId,publication.typePin.version);
  if(selected.row.definition_hash!==publication.typePin.definitionHash||selected.row.resolution_hash!==publication.typePin.resolutionHash)throw conflict();
  const isTerm=(value:{typeId:string;ancestorTypes:RelationEndpointPolicyState['ancestorTypes']})=>value.typeId===term.type_id||value.ancestorTypes.some(parent=>parent.typeId===term.type_id&&parent.id==='business_term');
  if(!isTerm(selected)||!selected.policy.requiredOwner)throw policyInvalid();
  const attributes=validateAttributes(selected.policy.model,publication.attributes);if(!attributes.ok)throw new Problem(422,'GLOSSARY_ATTRIBUTES_INVALID','The glossary attributes do not satisfy the pinned model.',attributes.issues);
  if(!selected.policy.lifecycle.states.includes(publication.state)||!base&&selected.policy.lifecycle.initial!==publication.state||base&&base.type_state!==publication.state
   &&!selected.policy.lifecycle.transitions.some(t=>t.from===base.type_state&&t.to===publication.state))throw policyInvalid();
  const source:RelationEndpointPolicyState={assetId:value.resourceId,assetVersion:base?.version??1,modelId:publication.typePin.modelId,modelVersion:publication.typePin.version,state:publication.state,
   typeId:selected.typeId,policy:selected.policy,ancestorTypes:selected.ancestorTypes};
  const relationIds=[...new Set(publication.links.map(link=>link.typePin.relationTypeId))].sort();
  const relationHeads=relationIds.length?(await query(()=>sql<Row>`select id,type_id,current_version from public.relation_types where tenant_id=${p.tenantId}::uuid and type_id=any(${relationIds}::uuid[]) order by type_id for share`.execute(tx))).rows:[];
  for(const link of publication.links){
   const relationHead=relationHeads.find(row=>row.type_id===link.typePin.relationTypeId),asset=assets.get(link.targetAssetId)!;
   if(!relationHead)throw unavailable();if(relationHead.current_version!==link.typePin.version)throw conflict();
   const measured=(await query(()=>sql<{bytes:number}>`select octet_length(definition::text) as bytes from public.relation_type_versions where tenant_id=${p.tenantId}::uuid
    and relation_type_id=${link.typePin.relationTypeId}::uuid and version=${link.typePin.version}`.execute(tx))).rows[0];if(!measured)throw unavailable();charge(measured.bytes);
   const row=(await query(()=>sql<Row>`select definition,definition_hash from public.relation_type_versions where tenant_id=${p.tenantId}::uuid
    and relation_type_id=${link.typePin.relationTypeId}::uuid and version=${link.typePin.version}`.execute(tx))).rows[0];
   if(!row)throw unavailable();const parsed=resolveRelationDefinition(row.definition);
   if(!parsed.ok||parsed.value.definition.id!==relationHead.id||parsed.value.definition.version!==link.typePin.version||typeHash(parsed.value.definition)!==row.definition_hash)throw integrity();
   if(row.definition_hash!==link.typePin.definitionHash)throw conflict();
   if(typeof asset.model_id!=='string'||!integer(asset.model_version))throw policyInvalid();const target=await policy(asset.model_id,asset.model_version);
   if(link.kind!=='defines'&&(asset.source_id!==null||asset.type!=='business_term'||!isTerm(target)))throw policyInvalid();
   const definition=parsed.value.definition;
   if(link.kind==='broader'&&(definition.direction!=='directed'||definition.cycles!=='acyclic'||definition.cardinality.outgoing.max!==1))throw policyInvalid();
   const checked=validateRelationEndpoints({edge:{id:value.requestId,version:1,relationTypeId:link.typePin.relationTypeId,relationTypeVersion:link.typePin.version,sourceAssetId:value.resourceId,targetAssetId:asset.id},
    policies:[{relationTypeId:link.typePin.relationTypeId,policy:parsed.value}],source,target:{assetId:asset.id,assetVersion:asset.version,modelId:asset.model_id,modelVersion:asset.model_version,state:asset.type_state,
     typeId:target.typeId,policy:target.policy,ancestorTypes:target.ancestorTypes}});
   if(!checked.ok)throw new Problem(422,'GLOSSARY_LINK_INVALID','The proposed relationship endpoints do not satisfy their pinned rules.',checked.issues);
  }
  await query(()=>sql`select id from public.workflow_definitions where tenant_id=${p.tenantId}::uuid and id=${value.workflowPin.id} for share`.execute(tx));
  const workflow=await getApprovalDefinition(tx,p,value.workflowPin.id,value.workflowPin.version);
  if(workflow.currentVersion!==value.workflowPin.version||workflow.definitionHash!==value.workflowPin.definitionHash)throw conflict('WORKFLOW_PIN_STALE');
  const required=[...new Set(workflow.definition.stages.flatMap(stage=>stage.assignments))].sort();
  if(JSON.stringify(Object.keys(value.assignments).sort())!==JSON.stringify(required)||workflow.definition.separationOfDuties&&reviewers.includes(p.id)
   ||workflow.definition.stages.some(stage=>new Set(stage.assignments.map(key=>value.assignments[key])).size!==stage.assignments.length))throw policyInvalid();
 }
 const response=(await query(()=>sql<{value:Row}>`select public.gc_approval_command('approval.submit',${idempotencyKey},${JSON.stringify(body)}::jsonb,${correlationId}) as value`.execute(tx).catch(error=>{throw approvalFailure(error);}))).rows[0]?.value;
 const current=await getApprovalRequest(tx,p,value.requestId),receipt=response?.request;
 if(!receipt||receipt.id!==value.requestId||receipt.proposalDigest!==hash||receipt.resourceId!==value.resourceId||receipt.resourceVersion!==value.resourceVersion
  ||receipt.workflowId!==value.workflowPin.id||receipt.workflowVersion!==value.workflowPin.version||receipt.workflowHash!==value.workflowPin.definitionHash
  ||modelPersistence.hash(receipt.payload)!==modelPersistence.hash(publication)||current.proposalDigest!==hash||!Array.isArray(receipt.tasks)||receipt.tasks.length>256||!Array.isArray(receipt.decisions)||receipt.decisions.length>256)throw integrity();
 return {request:{...receipt,workflow:current.workflow,preconditionsCurrent:current.preconditionsCurrent} as ApprovalRequestView};
}
