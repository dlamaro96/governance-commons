// SPDX-License-Identifier: Apache-2.0
import {sql, type Tx} from '../../db/src/index.ts';
import {Problem, type Principal} from '../../authz/src/index.ts';
import {modelPersistence, type ModelHooks} from './model-service.ts';
import type {DomainHooks} from './business-domain-service-contracts.ts';
import {parseGlossaryPublication} from './glossary.ts';
import {GLOSSARY_LIMITS, type GlossaryPublicationInput} from './glossary-contracts.ts';
import {configureRelationTransaction, relationQuery, relationFailure, uuid, type Row} from './relation-store.ts';
import {GRAPH_WRITE, captureGlossaryRelationMigration, graphPhysicalBudget} from './relation-migration-store.ts';
import {previewGlossaryRelationMigration, executeGlossaryRelationMigration, graphInvalid} from './relation-migration-service.ts';
import {deriveRequiredParticipation,eligible} from './relation-participation.ts';
import {parseGraphChangeSet} from './relation-migration.ts';
import {typeHash} from './asset-type-policy.ts';
import type {GraphChangeSet, RelationMigrationContext, RelationMigrationTarget} from './relation-migration-contracts.ts';

export interface GlossaryPublicationReceipt {
  id:string; assetId:string; assetVersion:number; proposalDigest:string;
  workflowPin:{id:string;version:number;definitionHash:string};
  graphReceiptId:string|null; executedBy:string; executedAt:string;
}
export type GlossaryPublicationHooks=ModelHooks & Pick<DomainHooks,'once'>;
interface PublicationContext {
  publicationId:string;requestId:string;assetId:string;assetVersion:number;
  publication:GlossaryPublicationInput;proposalDigest:string;
  workflowId:string;workflowVersion:number;workflowHash:string;
  relationTypeIds:string[];graphKey:string;correlationId:string;previousPublicationId:string|null;
  state:'prepared'|'staged'|'sealed';receipt:GlossaryPublicationReceipt|null;
}
const hash=/^[a-f0-9]{64}$/;
const key=/^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>0&&v<=2147483647;
const storage=()=>new Problem(500,'GLOSSARY_STORAGE_INVALID','The glossary publication could not be verified.');
const unavailable=()=>new Problem(404,'GLOSSARY_UNAVAILABLE','The glossary term or its linked resources are unavailable.');
const invalid=()=>new Problem(400,'GLOSSARY_INPUT_INVALID','Provide a valid glossary identifier.');
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;
function ownedEndpoints(direction:unknown,source:string,target:string,term:string,linked:string):boolean{
  return direction==='directed'?source===term&&target===linked:direction==='undirected'&&source<target
    &&(source===term&&target===linked||source===linked&&target===term);
}
function fields(value:unknown,names:readonly string[]):Record<string,unknown>{
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw storage();
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
  if(keys.length!==names.length||keys.some(k=>typeof k!=='string'||!names.includes(k))||names.some(k=>!descriptors[k]||!('value' in descriptors[k])))throw storage();
  return Object.fromEntries(names.map(k=>[k,descriptors[k].value]));
}
function receipt(value:unknown):GlossaryPublicationReceipt {
  const v=fields(value,['id','assetId','assetVersion','proposalDigest','workflowPin','graphReceiptId','executedBy','executedAt']);
  const pin=fields(v.workflowPin,['id','version','definitionHash']);
  if(!uuid(v.id)||!uuid(v.assetId)||!integer(v.assetVersion)||typeof v.proposalDigest!=='string'||!hash.test(v.proposalDigest)
    ||typeof pin.id!=='string'||!key.test(pin.id)||!integer(pin.version)||typeof pin.definitionHash!=='string'||!hash.test(pin.definitionHash)
    ||v.graphReceiptId!==null&&!uuid(v.graphReceiptId)||!uuid(v.executedBy)||typeof v.executedAt!=='string'
    ||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v.executedAt)||!Number.isFinite(Date.parse(v.executedAt))
    ||new Date(v.executedAt).toISOString()!==v.executedAt)throw storage();
  return v as unknown as GlossaryPublicationReceipt;
}
function context(value:unknown,requestId:string):PublicationContext {
  const v=fields(value,['publicationId','requestId','assetId','assetVersion','publication','proposalDigest','workflowId','workflowVersion','workflowHash',
    'relationTypeIds','graphKey','correlationId','previousPublicationId','state','receipt']);
  const publication=parseGlossaryPublication(v.publication);
  if(!publication.ok||v.publicationId!==requestId||v.requestId!==requestId||!uuid(v.assetId)||!integer(v.assetVersion)
    ||typeof v.proposalDigest!=='string'||!hash.test(v.proposalDigest)||typeof v.workflowId!=='string'||!key.test(v.workflowId)
    ||!integer(v.workflowVersion)||typeof v.workflowHash!=='string'||!hash.test(v.workflowHash)
    ||!Array.isArray(v.relationTypeIds)||v.relationTypeIds.length>5000||v.relationTypeIds.some(id=>!uuid(id))
    ||new Set(v.relationTypeIds).size!==v.relationTypeIds.length||v.relationTypeIds.some((id,i,ids)=>i>0&&compare(ids[i-1],id)>=0)
    ||v.graphKey!==`glossary:${requestId}`||v.correlationId!==`glossary:${requestId}`
    ||v.previousPublicationId!==null&&!uuid(v.previousPublicationId)||!['prepared','staged','sealed'].includes(String(v.state)))throw storage();
  const result={...v,publication:publication.value.input,receipt:v.receipt===null?null:receipt(v.receipt)} as unknown as PublicationContext;
  if((result.state==='sealed')!==(result.receipt!==null))throw storage();
  return result;
}
function verifyReceipt(result:GlossaryPublicationReceipt,ctx:PublicationContext,p:Principal,graphId?:string|null):void {
  if(result.id!==ctx.publicationId||result.assetId!==ctx.assetId||result.assetVersion!==ctx.assetVersion||result.proposalDigest!==ctx.proposalDigest
    ||result.executedBy!==p.id||result.workflowPin.id!==ctx.workflowId||result.workflowPin.version!==ctx.workflowVersion
    ||result.workflowPin.definitionHash!==ctx.workflowHash||graphId!==undefined&&result.graphReceiptId!==graphId)throw storage();
}
function stableContext(ctx:PublicationContext){const {state:_,receipt:__,...rest}=ctx;return typeHash(rest);}
/** SQLSTATEs are mapped to closed product failures; database diagnostics never cross the service boundary. */
function mappedPublicationFailure(error:unknown):Problem {
  if(error instanceof Problem)return error;
  const source=error as {code?:unknown;message?:unknown}|null,code=source?.code;
  if(code==='40001'&&['GLOSSARY_PIN_STALE','GLOSSARY_SOURCE_CHANGED','GLOSSARY_STATE_CONFLICT'].includes(String(source?.message)))return new Problem(409,'GLOSSARY_CONFLICT','The approved publication is no longer current.');
  const related=relationFailure(error);if(related instanceof Problem)return related;
  if(code==='P0002')return unavailable();
  if(code==='42501')return new Problem(403,'GLOSSARY_FORBIDDEN','Your current permissions do not allow this publication.');
  if(code==='54000')return new Problem(422,'GLOSSARY_LIMIT','The complete publication exceeds its supported bounds.');
  if(code==='23514'||code==='23503')return new Problem(422,'GLOSSARY_PUBLICATION_INVALID','The publication does not satisfy its current policies.');
  if(['22023','22P02','22003','22007','22008'].includes(String(code)))return invalid();
  return storage();
}
/** Preserve the original failure for trusted native diagnostics only. HTTP
 * serialization exposes the closed Problem fields and never this hidden cause. */
export function glossaryPublicationFailure(error:unknown):Problem {
  const mapped=mappedPublicationFailure(error);
  if(mapped!==error)Object.defineProperty(mapped,'cause',{value:error,enumerable:false});
  return mapped;
}
async function previousLinks(tx:Tx,p:Principal,ctx:PublicationContext):Promise<Map<string,Row>>{
  if(ctx.previousPublicationId===null)return new Map();
  const rows=(await relationQuery(tx,()=>sql<Row>`select l.ordinal,l.kind,l.relation_id,l.relation_type_id,l.target_asset_id,r.version,r.status,r.source_asset_id,r.target_asset_id as actual_target_asset_id,v.definition->>'direction' as direction
    from public.glossary_publication_links l left join public.relations r on r.tenant_id=l.tenant_id and r.id=l.relation_id
    left join public.relation_type_versions v on v.tenant_id=r.tenant_id and v.relation_type_id=r.relation_type_id and v.version=r.relation_type_version
    where l.tenant_id=${p.tenantId}::uuid and l.publication_id=${ctx.previousPublicationId}::uuid order by l.ordinal limit ${GLOSSARY_LIMITS.links+1}`.execute(tx))).rows;
  if(rows.length>GLOSSARY_LIMITS.links||rows.some((r,i)=>r.ordinal!==i||!uuid(r.relation_id)||!integer(r.version)||r.status!=='active'||!ownedEndpoints(r.direction,r.source_asset_id,r.actual_target_asset_id,ctx.assetId,r.target_asset_id))
    ||new Set(rows.map(r=>r.relation_id)).size!==rows.length)throw storage();
  return new Map(rows.map(r=>[r.relation_id,r]));
}
function changes(ctx:PublicationContext,captured:RelationMigrationContext,previous:Map<string,Row>):GraphChangeSet|null {
  if(!captured.proposedEndpoints||!captured.assetPreparation)throw graphInvalid(captured.targetIssues);
  if(typeHash(captured.completeRelationTypeIds)!==typeHash(ctx.relationTypeIds))throw storage();
  const graph=captured.before,heads=new Map(graph.heads.map(h=>[h.relationTypeId,h.version]));
  const endpoints=new Map(graph.endpoints.map(e=>[e.assetId,e]));
  if(endpoints.get(ctx.assetId)?.assetVersion!==ctx.assetVersion)throw storage();
  for(const [id,old] of previous){const edge=graph.edges.find(e=>e.key.kind==='existing'&&e.key.relationId===id);
    const policy=edge&&captured.policies.find(p=>p.relationTypeId===edge.relationTypeId&&p.definition.version===edge.relationTypeVersion);
    if(!edge||!policy||edge.relationTypeId!==old.relation_type_id||edge.version!==old.version
      ||!ownedEndpoints(policy.definition.direction,edge.sourceAssetId,edge.targetAssetId,ctx.assetId,old.target_asset_id))throw storage();}
  const required=deriveRequiredParticipation({admissionHeads:graph.heads,policies:captured.policies,
    completeEligibleEndpointCandidates:captured.proposedEndpoints,currentBindings:graph.bindings});
  if(!required.ok)throw graphInvalid(required.issues);
  const affected=new Set([...previous.values()].map(r=>r.relation_type_id as string));
  const afterEndpoint=captured.proposedEndpoints.find(e=>e.assetId===ctx.assetId),releases=new Set<string>();
  if(!afterEndpoint||afterEndpoint.assetVersion!==ctx.assetVersion)throw storage();
  for(const binding of graph.bindings){
    if(binding.assetId!==ctx.assetId||binding.status!=='active')continue;
    const pin=captured.policies.find(p=>p.relationTypeId===binding.relationTypeId&&p.definition.version===binding.relationTypeVersion);
    if(binding.key.kind!=='existing'||!pin||(pin.definition.direction==='directed')===(binding.side==='incident'))throw storage();
    if(!eligible(afterEndpoint,pin.definition,binding.side)){releases.add(binding.key.bindingId);affected.add(binding.relationTypeId);}
  }
  for(const link of ctx.publication.links)affected.add(link.typePin.relationTypeId);
  for(const row of required.value)if(row.existingBindingId===null)affected.add(row.relationTypeId);
  const targets:RelationMigrationTarget[]=[];
  for(const typeId of [...affected].sort(compare)){
    const version=heads.get(typeId),policy=captured.policies.find(p=>p.relationTypeId===typeId&&p.definition.version===version);
    if(!version||!policy)throw storage();
    const edges=graph.edges.filter(e=>e.relationTypeId===typeId),bindings=graph.bindings.filter(b=>b.relationTypeId===typeId);
    const creations=ctx.publication.links.flatMap((link,ordinal)=>{
      if(link.typePin.relationTypeId!==typeId)return [];
      const target=endpoints.get(link.targetAssetId);
      if(version!==link.typePin.version||typeHash(policy.definition)!==link.typePin.definitionHash||target?.assetVersion!==link.targetAssetVersion)throw new Problem(409,'GLOSSARY_CONFLICT','The approved relation or target is no longer current.');
      const reverse=policy.definition.direction==='undirected'&&compare(ctx.assetId,link.targetAssetId)>0;
      return [{key:`glossary_link_${ordinal}`,sourceAssetId:reverse?link.targetAssetId:ctx.assetId,targetAssetId:reverse?ctx.assetId:link.targetAssetId,
        sourceAssetVersion:reverse?link.targetAssetVersion:ctx.assetVersion,targetAssetVersion:reverse?ctx.assetVersion:link.targetAssetVersion,
        values:{attributes:{},ownerId:ctx.publication.ownerId,state:policy.definition.lifecycle.initial,validFrom:null,validTo:null,
          visibility:ctx.publication.visibility,allowedIdentityIds:ctx.publication.allowedIdentityIds}}];
    });
    targets.push({kind:'repair',expectedHeadVersion:version,definition:null,plan:{formatVersion:1,relationTypeId:typeId,
      sourceVersions:[...new Set([...edges,...bindings].map(r=>r.relationTypeVersion))].sort((a,b)=>a-b),transform:null,
      edges:edges.map(e=>{if(e.key.kind!=='existing')throw storage();return previous.has(e.key.relationId)
        ?{relationId:e.key.relationId,expectedVersion:e.version,action:'tombstone' as const,reason:'Superseded by the approved glossary publication.'}
        :{relationId:e.key.relationId,expectedVersion:e.version,action:'preserve' as const};}),creations,
      bindings:bindings.map(b=>{if(b.key.kind!=='existing')throw storage();return releases.has(b.key.bindingId)
        ?{bindingId:b.key.bindingId,expectedVersion:b.version,action:'release' as const,reason:'Approved glossary lifecycle is no longer eligible for this pinned participation.'}
        :{bindingId:b.key.bindingId,expectedVersion:b.version,action:'preserve' as const};}),
      enrollment:'complete-eligible-assets',acknowledgedPolicyChanges:[]}});
  }
  if(!targets.length)return null;
  const parsed=parseGraphChangeSet({formatVersion:1,relationTargets:targets,assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null});
  if(!parsed.ok)throw graphInvalid(parsed.issues);return parsed.value;
}

/** The caller supplies an existing tenant/actor transaction; SQL independently
 * binds the approved requester and locks the complete canonical scope. */
export async function publishApprovedGlossary(tx:Tx,p:Principal,requestId:string,hooks:GlossaryPublicationHooks):Promise<{id:string;status:'succeeded';result:GlossaryPublicationReceipt}>{
  if(!uuid(requestId))throw invalid();
  try{
    await configureRelationTransaction(tx);
    await relationQuery(tx,()=>modelPersistence.authorize(tx,p,GRAPH_WRITE));
    const prepared=context((await relationQuery(tx,()=>sql<{value:unknown}>`select public.gc_glossary_prepare(${requestId}::uuid) as value`.execute(tx))).rows[0]?.value,requestId);
    await graphPhysicalBudget(tx,prepared);
    if(prepared.state==='sealed'){
      verifyReceipt(prepared.receipt!,prepared,p);
      return {id:requestId,status:'succeeded',result:prepared.receipt!};
    }
    // No partially completed state is a replay success. The SQL transaction is
    // atomic; a staged return here would represent an unexpected second call.
    if(prepared.state!=='prepared')throw storage();
    const staged=context((await relationQuery(tx,()=>sql<{value:unknown}>`select public.gc_glossary_stage(${prepared.publicationId}::uuid) as value`.execute(tx))).rows[0]?.value,requestId);
    if(staged.state!=='staged'||stableContext(prepared)!==stableContext(staged))throw storage();
    const prior=await previousLinks(tx,p,staged);
    const captured=await captureGlossaryRelationMigration(tx,p,staged.publicationId,{formatVersion:1,relationTargets:[],assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null});
    const changeSet=changes(staged,captured.context,prior);let graphReceiptId:string|null=null;
    if(changeSet){
      const {preview}=await previewGlossaryRelationMigration(tx,p,staged.publicationId,changeSet);
      if(!preview.ready)throw graphInvalid(preview.targetIssues);
      const body={changeSet,previewDigest:preview.previewDigest};
      const executed=await hooks.once(tx,p,'relation-migration.execute',staged.graphKey,body,
        ()=>executeGlossaryRelationMigration(tx,p,staged.publicationId,staged.correlationId,staged.graphKey,body,hooks),{
          query:work=>relationQuery(tx,work),
          // A sealed graph from an earlier transaction cannot coexist with this
          // newly staged publication. Whole-publication replay is handled above.
          authorizeReplay:async()=>{throw storage();},
        });
      graphReceiptId=executed.receipt.id;
    }
    const result=receipt((await relationQuery(tx,()=>sql<{value:unknown}>`select public.gc_glossary_finish(${staged.publicationId}::uuid,${graphReceiptId}::uuid) as value`.execute(tx))).rows[0]?.value);
    verifyReceipt(result,staged,p,graphReceiptId);
    await relationQuery(tx,()=>sql`set constraints all immediate`.execute(tx));
    await relationQuery(tx,()=>modelPersistence.authorize(tx,p,GRAPH_WRITE));
    return {id:requestId,status:'succeeded',result};
  }catch(error){throw glossaryPublicationFailure(error);}
}

/** A term DTO includes its complete owned links. Do not reveal part of a
 * publication when any current endpoint or relationship is hidden. */
export async function getGlossaryTerm(tx:Tx,p:Principal,assetId:string):Promise<{resourceId:string;resourceVersion:number;publication:GlossaryPublicationInput}>{
  if(!uuid(assetId))throw invalid();
  try{
    await relationQuery(tx,()=>modelPersistence.authorize(tx,p,['catalog:read','models:read']));
    const scope=sql`from public.glossary_terms g join public.glossary_publications pub on pub.tenant_id=g.tenant_id and pub.id=g.current_publication_id
      join public.assets a on a.tenant_id=g.tenant_id and a.id=g.asset_id
      where g.tenant_id=${p.tenantId}::uuid and g.asset_id=${assetId}::uuid and pub.asset_id=g.asset_id and pub.state='sealed'
      and a.status='active' and a.type='business_term' and a.source_id is null and a.version=pub.asset_version
      and (a.visibility='tenant' or a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)
      and not exists(select 1 from public.glossary_publication_links l
        left join public.relations r on r.tenant_id=l.tenant_id and r.id=l.relation_id
        left join public.assets target on target.tenant_id=l.tenant_id and target.id=l.target_asset_id
        left join public.relation_type_versions policy on policy.tenant_id=r.tenant_id and policy.relation_type_id=r.relation_type_id and policy.version=r.relation_type_version
        where l.tenant_id=g.tenant_id and l.publication_id=pub.id and (r.id is null or target.id is null or r.status<>'active' or target.status<>'active'
          or policy.version is null or r.relation_type_id<>l.relation_type_id
          or not((policy.definition->>'direction'='directed' and r.source_asset_id=g.asset_id and r.target_asset_id=l.target_asset_id)
            or (policy.definition->>'direction'='undirected' and r.source_asset_id<r.target_asset_id
              and ((r.source_asset_id=g.asset_id and r.target_asset_id=l.target_asset_id) or (r.target_asset_id=g.asset_id and r.source_asset_id=l.target_asset_id))))
          or not(r.visibility='tenant' or r.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)
          or not(target.visibility='tenant' or target.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)))`;
    const size=(await relationQuery(tx,()=>sql<Row>`select pub.id,a.version,octet_length(pub.payload::text) as bytes,
      (select count(*)::int from public.glossary_publication_links l where l.tenant_id=g.tenant_id and l.publication_id=pub.id) as links ${scope}`.execute(tx))).rows[0];
    if(!size)throw unavailable();if(size.bytes>GLOSSARY_LIMITS.bytes||size.links>GLOSSARY_LIMITS.links)throw storage();
    const row=(await relationQuery(tx,()=>sql<Row>`select pub.payload,a.version ${scope} and pub.id=${size.id}::uuid and a.version=${size.version}`.execute(tx))).rows[0];
    if(!row)throw unavailable();const parsed=parseGlossaryPublication(row.payload);if(!parsed.ok||parsed.value.input.links.length!==size.links)throw storage();
    const links=(await relationQuery(tx,()=>sql<Row>`select ordinal,kind,relation_type_id,target_asset_id from public.glossary_publication_links
      where tenant_id=${p.tenantId}::uuid and publication_id=${size.id}::uuid order by ordinal limit ${GLOSSARY_LIMITS.links+1}`.execute(tx))).rows;
    if(links.length!==parsed.value.input.links.length||links.some((l,i)=>l.ordinal!==i||l.kind!==parsed.value.input.links[i].kind
      ||l.relation_type_id!==parsed.value.input.links[i].typePin.relationTypeId||l.target_asset_id!==parsed.value.input.links[i].targetAssetId))throw storage();
    return {resourceId:assetId,resourceVersion:row.version,publication:parsed.value.input};
  }catch(error){throw glossaryPublicationFailure(error);}
}
