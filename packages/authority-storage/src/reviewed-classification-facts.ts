// SPDX-License-Identifier: Apache-2.0
// Fixed canonical discovery inside the caller's admitted owner RR transaction.
import {canonicalDecisionJSON as canonical, decisionHash, decisionFailure} from '../../authority/src/decision-schema.ts';
import type {ApprovedSetFact, Fact, FactRef} from '../../authority/src/decision-types.ts';
import type {Digest, UUID, Version} from '../../authority/src/types.ts';
import {parseVersionedHumanAssetContext, type VersionedHumanAssetContext} from '../../authority-runtime/src/versioned-asset-context.ts';
import {parseReviewedClassificationProducerSnapshot, reviewedClassificationProducerAvailable, type ReviewedClassificationProducerSnapshot, type ReviewedClassificationProducerBinding} from '../../authority-runtime/src/classified-asset-context.ts';
import {parseClassificationTaxonomy, parseMetadataClassificationRule, classificationDefinitionHash, evaluateMetadataClassification, classificationInputDigest} from '../../domain/src/classification.ts';
import {parseClassificationEvidence, parseClassificationApprovalPayload, parseClassificationApprovalResult} from '../../domain/src/classification-service.ts';
import {parseApprovalDefinition} from '../../domain/src/approval.ts';
import type {ApprovalDefinition} from '../../domain/src/approval-contracts.ts';
import type {ClassificationAssetInput, MetadataClassificationRule} from '../../domain/src/classification-contracts.ts';
import {AuthorityFoundationError} from './contracts.ts';
import {admitted, array, digest, equal, integer, literal, nullable, row, shape, str, utc, uuid, version, type Validator} from './shape.ts';

export type ClassificationFactQuery=(text:string,values?:unknown[])=>Promise<{rows:unknown[]}>;
export type ClassificationReadBudget={check():void;admitSource(value:unknown):void};
export type ReviewedClassificationFacts={producerBinding:ReviewedClassificationProducerBinding|null;classifications:Fact<readonly FactRef[]>;approvedFacts:readonly ApprovedSetFact[]};
const PROFILE=Object.freeze({assignments:256,tasks:4096,decisions:4096,perRequest:256,proofBytes:2097152,factBytes:1048576});
const fail=():never=>{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_INTEGRITY');};
const limit=():never=>{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');};
function requireValue(value:unknown):asserts value{if(!value)fail();}
function parsed<T>(value:{ok:true;value:T}|{ok:false;issues:readonly {code:string}[]}):T{
 if(value.ok)return value.value;if(value.issues.some(i=>i.code==='limit'))limit();return fail();
}
function boundedText(max:number,empty=true):Validator{return (v,p)=>{const s=str(v,p) as string;if(s.length>max)limit();if(!empty&&!s.length)fail();return s;};}
const key:Validator=(v,p)=>{const s=str(v,p) as string;if(!/^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(s))fail();return s;};
const body:Validator=v=>v;
const identityShape=shape({tenant_id:uuid,id:uuid,taxonomy_id:uuid,label_key:key,first_registered_version:version,retired_at_version:nullable(version)});
const assignmentShape=shape({tenant_id:uuid,id:uuid,asset_id:uuid,taxonomy_id:uuid,label_key:key,version,status:literal('active','withdrawn'),created_by:uuid,created_at:utc});
const revisionShape=shape({tenant_id:uuid,assignment_id:uuid,version,status:literal('active','withdrawn'),suggestion_id:uuid,approval_request_id:uuid,reason:nullable(boundedText(4096,false)),actor_id:uuid,created_at:utc});
const evaluationShape=shape({tenant_id:uuid,id:uuid,asset_id:uuid,asset_version:version,rule_id:uuid,rule_version:version,rule_hash:digest,outcome:literal('matched','not_matched','unsupported'),evidence:body,evidence_hash:digest,created_by:uuid,created_at:utc});
const ruleShape=shape({tenant_id:uuid,rule_id:uuid,version,definition:body,definition_hash:digest,taxonomy_id:uuid,taxonomy_version:version,taxonomy_hash:digest,owner_id:uuid,created_by:uuid,created_at:utc});
const taxonomyShape=shape({tenant_id:uuid,taxonomy_id:uuid,version,definition:body,definition_hash:digest,created_by:uuid,created_at:utc});
const headShape=shape({tenant_id:uuid,id:uuid,current_version:version});
const baselineShape=shape({tenant_id:uuid,taxonomy_id:uuid,baseline_version:version,baseline_hash:digest});
const labelBindingShape=shape({tenant_id:uuid,taxonomy_id:uuid,taxonomy_version:version,label_key:key,label_id:uuid,label_status:literal('active','deprecated')});
const requestShape=shape({tenant_id:uuid,id:uuid,binding:literal('classification.review'),resource_id:uuid,resource_version:version,payload:body,proposal_digest:digest,
 workflow_id:key,workflow_version:version,workflow_hash:digest,requester_id:uuid,stage_index:integer(0,15),version,status:literal('succeeded'),result:body,error_code:literal(null),expires_at:utc,created_at:utc,updated_at:utc});
const workflowShape=shape({tenant_id:uuid,workflow_id:key,version,definition:body,definition_hash:digest});
const taskShape=shape({tenant_id:uuid,id:uuid,request_id:uuid,stage_index:integer(0,15),assignment:key,assigned_identity_id:uuid,version,status:literal('decided','cancelled'),opened_at:utc,expires_at:utc});
const decisionShape=shape({tenant_id:uuid,id:uuid,request_id:uuid,task_id:uuid,task_version:version,proposal_digest:digest,actor_id:uuid,decision:literal('approve'),reason:boundedText(4096,false),decided_at:utc});
const inputShape=shape({id:uuid,version,type:boundedText(64,false),name:boundedText(2048),qualifiedName:boundedText(2048),dataType:nullable(boundedText(2048))});
const proofShape=shape({assignment:assignmentShape,revision:revisionShape,evaluation:evaluationShape,rule:ruleShape,taxonomy:taxonomyShape,
 ruleHead:headShape,taxonomyHead:headShape,baseline:nullable(baselineShape),identity:nullable(identityShape),labelBinding:nullable(labelBindingShape),
 request:requestShape,workflow:workflowShape,tasks:array(taskShape,v=>(v as Record<string,string>).id!,256),decisions:array(decisionShape,v=>(v as Record<string,string>).id!,256),historicalInput:inputShape,currentInput:inputShape});
type Fields=Record<string,unknown>;
type Proof={assignment:Fields;revision:Fields;evaluation:Fields;rule:Fields;taxonomy:Fields;ruleHead:Fields;taxonomyHead:Fields;baseline:Fields|null;identity:Fields|null;labelBinding:Fields|null;request:Fields;workflow:Fields;tasks:Fields[];decisions:Fields[];historicalInput:ClassificationAssetInput;currentInput:ClassificationAssetInput};
const json=(alias:string,fields:string[],timestamps:string[]=[])=>`CASE WHEN ${alias}.${fields.includes('id')?'id':fields.includes('assignment_id')?'assignment_id':fields.includes('rule_id')?'rule_id':fields.includes('taxonomy_id')?'taxonomy_id':'workflow_id'} IS NULL THEN NULL ELSE jsonb_build_object(${fields.map(f=>`'${f}',${timestamps.includes(f)?`gc_authority.utc(${alias}.${f})`:`${alias}.${f}`}`).join(',')}) END`;
const projection=(alias:string,historical=false)=>historical
 ?`CASE WHEN ${alias}.asset_id IS NULL THEN NULL ELSE jsonb_build_object('id',${alias}.snapshot->'id','version',${alias}.snapshot->'version','type',${alias}.snapshot->'type','name',${alias}.snapshot->'name','qualifiedName',${alias}.snapshot->'qualifiedName','dataType',CASE WHEN jsonb_typeof(${alias}.snapshot#>'{metadata,dataType}')='string' THEN ${alias}.snapshot#>'{metadata,dataType}' ELSE 'null'::jsonb END) END`
 :`CASE WHEN ${alias}.id IS NULL THEN NULL ELSE jsonb_build_object('id',${alias}.id,'version',${alias}.version,'type',${alias}.type,'name',${alias}.name,'qualifiedName',${alias}.qualified_name,'dataType',CASE WHEN jsonb_typeof(${alias}.metadata->'dataType')='string' THEN ${alias}.metadata->'dataType' ELSE 'null'::jsonb END) END`;
const scope=`FROM public.classification_assignments a LEFT JOIN public.classification_assignment_revisions ar ON (ar.tenant_id,ar.assignment_id,ar.version)=(a.tenant_id,a.id,a.version)`;
const predicate=`a.tenant_id=$1::uuid AND a.asset_id=$2::uuid`;
const countQuery=`/* reviewed-classification:counts */ SELECT count(*)::text AS assignments,
 coalesce(sum(t.n),0)::text AS tasks,coalesce(max(t.n),0)::text AS max_tasks,
 coalesce(sum(d.n),0)::text AS decisions,coalesce(max(d.n),0)::text AS max_decisions
 ${scope} LEFT JOIN LATERAL(SELECT count(*) n FROM public.approval_tasks WHERE tenant_id=a.tenant_id AND request_id=ar.approval_request_id)t ON true
 LEFT JOIN LATERAL(SELECT count(*) n FROM public.approval_decisions WHERE tenant_id=a.tenant_id AND request_id=ar.approval_request_id)d ON true WHERE ${predicate}`;
const proofQuery=`WITH proofs AS (SELECT jsonb_build_object(
 'assignment',${json('a',['tenant_id','id','asset_id','taxonomy_id','label_key','version','status','created_by','created_at'],['created_at'])},
 'revision',${json('ar',['tenant_id','assignment_id','version','status','suggestion_id','approval_request_id','reason','actor_id','created_at'],['created_at'])},
 'evaluation',${json('e',['tenant_id','id','asset_id','asset_version','rule_id','rule_version','rule_hash','outcome','evidence','evidence_hash','created_by','created_at'],['created_at'])},
 'rule',${json('rv',['tenant_id','rule_id','version','definition','definition_hash','taxonomy_id','taxonomy_version','taxonomy_hash','owner_id','created_by','created_at'],['created_at'])},
 'taxonomy',${json('tv',['tenant_id','taxonomy_id','version','definition','definition_hash','created_by','created_at'],['created_at'])},
 'ruleHead',${json('rh',['tenant_id','id','current_version'])},'taxonomyHead',${json('th',['tenant_id','id','current_version'])},
 'baseline',${json('b',['tenant_id','taxonomy_id','baseline_version','baseline_hash'])},
 'identity',${json('li',['tenant_id','id','taxonomy_id','label_key','first_registered_version','retired_at_version'])},
 'labelBinding',${json('lb',['tenant_id','taxonomy_id','taxonomy_version','label_key','label_id','label_status'])},
 'request',${json('r',['tenant_id','id','binding','resource_id','resource_version','payload','proposal_digest','workflow_id','workflow_version','workflow_hash','requester_id','stage_index','version','status','result','error_code','expires_at','created_at','updated_at'],['expires_at','created_at','updated_at'])},
 'workflow',${json('w',['tenant_id','workflow_id','version','definition','definition_hash'])},
 'tasks',coalesce((SELECT jsonb_agg(${json('t',['tenant_id','id','request_id','stage_index','assignment','assigned_identity_id','version','status','opened_at','expires_at'],['opened_at','expires_at'])} ORDER BY t.id) FROM public.approval_tasks t WHERE t.tenant_id=a.tenant_id AND t.request_id=ar.approval_request_id),'[]'::jsonb),
 'decisions',coalesce((SELECT jsonb_agg(${json('d',['tenant_id','id','request_id','task_id','task_version','proposal_digest','actor_id','decision','reason','decided_at'],['decided_at'])} ORDER BY d.id) FROM public.approval_decisions d WHERE d.tenant_id=a.tenant_id AND d.request_id=ar.approval_request_id),'[]'::jsonb),
 'historicalInput',${projection('historic',true)},'currentInput',${projection('current_asset')}) AS proof
 ${scope}
 LEFT JOIN public.classification_evaluations e ON (e.tenant_id,e.id)=(a.tenant_id,ar.suggestion_id)
 LEFT JOIN public.classification_rule_versions rv ON (rv.tenant_id,rv.rule_id,rv.version)=(a.tenant_id,e.rule_id,e.rule_version)
 LEFT JOIN public.classification_taxonomy_versions tv ON (tv.tenant_id,tv.taxonomy_id,tv.version)=(a.tenant_id,rv.taxonomy_id,rv.taxonomy_version)
 LEFT JOIN public.classification_rules rh ON (rh.tenant_id,rh.id)=(a.tenant_id,e.rule_id)
 LEFT JOIN public.classification_taxonomies th ON (th.tenant_id,th.id)=(a.tenant_id,rv.taxonomy_id)
 LEFT JOIN gc_authority.classification_label_baselines b ON (b.tenant_id,b.taxonomy_id)=(a.tenant_id,a.taxonomy_id)
 LEFT JOIN gc_authority.classification_label_identities li ON (li.tenant_id,li.taxonomy_id,li.label_key)=(a.tenant_id,a.taxonomy_id,a.label_key)
 LEFT JOIN gc_authority.classification_label_version_bindings lb ON (lb.tenant_id,lb.taxonomy_id,lb.taxonomy_version,lb.label_key)=(a.tenant_id,a.taxonomy_id,rv.taxonomy_version,a.label_key)
 LEFT JOIN public.approval_requests r ON (r.tenant_id,r.id)=(a.tenant_id,ar.approval_request_id)
 LEFT JOIN public.workflow_definition_versions w ON (w.tenant_id,w.workflow_id,w.version)=(a.tenant_id,r.workflow_id,r.workflow_version)
 LEFT JOIN public.asset_revisions historic ON (historic.tenant_id,historic.asset_id,historic.version)=(a.tenant_id,e.asset_id,e.asset_version)
 LEFT JOIN public.assets current_asset ON (current_asset.tenant_id,current_asset.id)=(a.tenant_id,a.asset_id)
 WHERE ${predicate})`;
const measureQuery=`/* reviewed-classification:measure */ ${proofQuery}
 SELECT count(*)::text AS assignments,coalesce(sum(octet_length(public.gc_type_migration_canonical(proof))),0)::text AS canonical_bytes,
 coalesce(sum(octet_length(proof::text)),0)::text AS raw_bytes,
 coalesce(bool_and(proof->'revision'<>'null'::jsonb AND proof->'evaluation'<>'null'::jsonb AND proof->'rule'<>'null'::jsonb
 AND proof->'taxonomy'<>'null'::jsonb AND proof->'ruleHead'<>'null'::jsonb AND proof->'taxonomyHead'<>'null'::jsonb
 AND proof->'request'<>'null'::jsonb AND proof->'workflow'<>'null'::jsonb AND proof->'historicalInput'<>'null'::jsonb AND proof->'currentInput'<>'null'::jsonb),true) AS dependencies_complete,
 coalesce(bool_and(octet_length(public.gc_type_migration_canonical(jsonb_build_object('outcome',proof#>'{evaluation,outcome}','evidence',proof#>'{evaluation,evidence}')))<=32768
 AND octet_length(public.gc_type_migration_canonical(proof#>'{request,payload}'))<=65536
 AND octet_length(public.gc_type_migration_canonical(proof#>'{rule,definition}'))<=65536
 AND octet_length(public.gc_type_migration_canonical(proof#>'{taxonomy,definition}'))<=65536
 AND octet_length(public.gc_type_migration_canonical(proof#>'{workflow,definition}'))<=65536
 AND octet_length(public.gc_type_migration_canonical(proof->'historicalInput'))<=32768
 AND octet_length(public.gc_type_migration_canonical(proof->'currentInput'))<=32768),true) AS component_bounds FROM proofs`;
const bodyQuery=`/* reviewed-classification:bodies */ ${proofQuery} SELECT proof FROM proofs ORDER BY proof#>>'{assignment,id}'`;

function decimal(v:unknown,max:number):number{
 if(typeof v!=='string'||!/^(0|[1-9][0-9]{0,18})$/.test(v))return fail();if(BigInt(v)>BigInt(max))limit();return Number(v);
}
function one(result:{rows:unknown[]}):Fields{requireValue(Array.isArray(result.rows)&&result.rows.length===1);return row(admitted(result.rows[0]).data);}
function same(a:unknown,b:unknown){equal(a,b,'Canonical classification proof differs.');}
function bytes(value:unknown,max:number){if(Buffer.byteLength(canonical(value))>max)limit();}
function validateWorkflow(p:Proof,definition:ApprovalDefinition,budget:ClassificationReadBudget){
 const r=p.request,stages=definition.stages,byTask=new Map(p.tasks.map(t=>[t.id,t])),byDecision=new Map<unknown,Fields>(),assignments=new Map<string,string>();
 requireValue(definition.separationOfDuties&&stages.length>0&&r.stage_index===stages.length-1);
 requireValue(byTask.size===p.tasks.length);
 for(const d of p.decisions){
  budget.check();requireValue(!byDecision.has(d.task_id));byDecision.set(d.task_id,d);
  const t=byTask.get(d.task_id);requireValue(t);
  same([d.tenant_id,d.request_id,d.proposal_digest,d.actor_id],[r.tenant_id,r.id,r.proposal_digest,t.assigned_identity_id]);
  requireValue(d.actor_id!==r.requester_id&&t.status==='decided'&&t.version===(d.task_version as number)+1);
  requireValue(d.reason===(d.reason as string).normalize('NFC').trim()&&(d.reason as string).length>0&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(d.reason as string));
  requireValue((d.decided_at as string)>=(t.opened_at as string)&&(d.decided_at as string)<(t.expires_at as string)&&(d.decided_at as string)<=(r.updated_at as string));
 }
 let previousDecision:string|null=null,previousExpiry:string|null=null,totalTasks=0;
 for(const [index,stage] of stages.entries()){
  budget.check();const tasks=p.tasks.filter(t=>t.stage_index===index);totalTasks+=tasks.length;
  requireValue(tasks.length===stage.assignments.length&&tasks.length>0);
  same(tasks.map(t=>t.assignment).sort(),[...stage.assignments].sort());
  const opened=tasks[0]!.opened_at as string,expiry=tasks[0]!.expires_at as string;
  requireValue(Date.parse(expiry)===Math.min(Date.parse(r.expires_at as string),Date.parse(opened)+stage.deadlineSeconds*1000));
  requireValue(opened>=(r.created_at as string)&&opened<=(r.updated_at as string));
  if(index===0)same(opened,r.created_at);else requireValue(previousDecision!==null&&opened>=previousDecision&&previousExpiry!==null&&opened<previousExpiry);
  let approvals=0,last=opened;
  for(const t of tasks){
   same([t.tenant_id,t.request_id,t.opened_at,t.expires_at],[r.tenant_id,r.id,opened,expiry]);
   requireValue(t.assigned_identity_id!==r.requester_id);
   const assignment=t.assignment as string,identity=t.assigned_identity_id as string,prior=assignments.get(assignment);if(prior!==undefined)same(prior,identity);else assignments.set(assignment,identity);
   const d=byDecision.get(t.id),openVersion=index===0?1:2;
   if(d){requireValue(t.status==='decided'&&d.task_version===openVersion);approvals++;last=last>(d.decided_at as string)?last:d.decided_at as string;}
   else requireValue(t.status==='cancelled'&&t.version===openVersion+1);
  }
  requireValue(approvals>=stage.quorum);previousDecision=last;previousExpiry=expiry;
 }
 requireValue(totalTasks===p.tasks.length&&new Set(assignments.values()).size===assignments.size&&r.version===p.decisions.length+stages.length+2);
 same(decisionHash({id:r.id,binding:r.binding,payload:r.payload,workflow:{id:r.workflow_id,version:r.workflow_version,definitionHash:r.workflow_hash},assignments:Object.fromEntries(assignments),expiresAt:r.expires_at}),r.proposal_digest);
}

function validateProof(raw:unknown,context:VersionedHumanAssetContext,producer:ReviewedClassificationProducerBinding,budget:ClassificationReadBudget):{active:boolean;available:boolean;fact:ApprovedSetFact|null}{
 const p=proofShape(raw,'') as unknown as Proof,{assignment:a,revision:ar,evaluation:e,rule:rv,taxonomy:tv,request:r,workflow:w}=p;
 const target=context.context.asset,tenant=target.tenantId,asOf=context.context.closure.snapshot.asOf;
 for(const entry of [a,ar,e,rv,tv,p.ruleHead,p.taxonomyHead,r,w,...p.tasks,...p.decisions,p.baseline,p.identity,p.labelBinding])if(entry)same(entry.tenant_id,tenant);
 same([a.asset_id,ar.assignment_id,ar.version,ar.status,e.id,e.asset_id,rv.rule_id,rv.version,rv.definition_hash,tv.taxonomy_id,tv.version,tv.definition_hash],
  [target.id,a.id,a.version,a.status,ar.suggestion_id,target.id,e.rule_id,e.rule_version,e.rule_hash,rv.taxonomy_id,rv.taxonomy_version,rv.taxonomy_hash]);
 same([p.ruleHead.id,p.taxonomyHead.id,a.taxonomy_id],[rv.rule_id,tv.taxonomy_id,tv.taxonomy_id]);
 requireValue((p.ruleHead.current_version as number)>=(rv.version as number)&&(p.taxonomyHead.current_version as number)>=(tv.version as number));
 requireValue((a.created_at as string)<=(ar.created_at as string)&&(ar.created_at as string)<=asOf);
 requireValue((tv.created_at as string)<=(rv.created_at as string)&&(rv.created_at as string)<=(e.created_at as string));
 if(a.version===1)same([a.created_by,a.created_at],[ar.actor_id,ar.created_at]);
 bytes(rv.definition,65536);bytes(tv.definition,65536);bytes(w.definition,65536);bytes(r.payload,65536);bytes(p.historicalInput,32768);bytes(p.currentInput,32768);
 const rule=parsed(parseMetadataClassificationRule(rv.definition)),taxonomy=parsed(parseClassificationTaxonomy(tv.definition)),workflow=parsed(parseApprovalDefinition(w.definition));
 same(rv.definition,rule);same(tv.definition,taxonomy);same(w.definition,workflow);
 same([classificationDefinitionHash(rule),classificationDefinitionHash(taxonomy),decisionHash(workflow)],[rv.definition_hash,tv.definition_hash,w.definition_hash]);
 same([rule.ownerId,rule.label.taxonomy.id,rule.label.taxonomy.version,rule.label.taxonomy.definitionHash,rule.label.labelKey],
  [rv.owner_id,tv.taxonomy_id,tv.version,tv.definition_hash,a.label_key]);
 requireValue(rule.status==='active');
 const label=taxonomy.labels.find(x=>x.key===a.label_key);requireValue(label&&label.status==='active');
 same([p.historicalInput.id,p.historicalInput.version,p.currentInput.id,p.currentInput.version],[target.id,e.asset_version,target.id,target.version]);
 requireValue(p.historicalInput.version<=p.currentInput.version);
 const evidence=parseClassificationEvidence(e.evidence),evaluation=parsed(evaluateMetadataClassification(rule,{id:rv.rule_id,version:rv.version,definitionHash:rv.definition_hash},p.historicalInput,e.created_at));
 bytes({outcome:e.outcome,evidence:evidence},32768);
 same(evaluation,{outcome:e.outcome,evidence:evidence});requireValue(e.outcome==='matched');same(decisionHash(evidence),e.evidence_hash);
 const payload=parseClassificationApprovalPayload(r.payload),result=parseClassificationApprovalResult(r.result);
 same([r.id,r.resource_id,r.requester_id,r.updated_at,r.workflow_id,r.workflow_version,r.workflow_hash],
  [ar.approval_request_id,target.id,ar.actor_id,ar.created_at,w.workflow_id,w.version,w.definition_hash]);
 same([workflow.id,workflow.version],[w.workflow_id,w.version]);
 requireValue((r.resource_version as number)>=p.historicalInput.version&&(r.resource_version as number)<=target.version);
 requireValue((e.created_at as string)<=(r.created_at as string)&&(r.created_at as string)<=(r.updated_at as string)&&(r.updated_at as string)<(r.expires_at as string));
 same([payload.assetId,payload.assignmentId,payload.expectedAssignmentVersion+1,payload.suggestionId,payload.label,payload.evidence,payload.evidenceHash],
  [target.id,a.id,ar.version,e.id,rule.label,evidence,e.evidence_hash]);
 if(a.status==='active')same([payload.change,payload.reason,ar.reason],['apply','',null]);
 else{same([payload.change,payload.reason],['withdraw',ar.reason]);requireValue(payload.reason===payload.reason.normalize('NFC').trim());}
 same(result,{binding:'classification.review',assetId:target.id,assignmentId:a.id,assignmentVersion:ar.version,status:ar.status,evidenceHash:e.evidence_hash});
 validateWorkflow(p,workflow,budget);
 if(a.status==='withdrawn')return {active:false,available:true,fact:null};
 let available=target.status==='active'&&p.ruleHead.current_version===rv.version&&p.taxonomyHead.current_version===tv.version
  &&classificationInputDigest(rule,p.currentInput)===evidence.inputDigest;
 const baseline=p.baseline,identity=p.identity,binding=p.labelBinding;
 requireValue(baseline&&baseline.taxonomy_id===a.taxonomy_id&&(baseline.baseline_version as number)<=(p.taxonomyHead.current_version as number));
 if(tv.version===baseline.baseline_version)same(tv.definition_hash,baseline.baseline_hash);
 if((tv.version as number)<(baseline.baseline_version as number))available=false;
 else{
  requireValue(identity&&binding);
  same([identity.taxonomy_id,identity.label_key,binding.taxonomy_id,binding.taxonomy_version,binding.label_key,binding.label_id,binding.label_status],
   [a.taxonomy_id,a.label_key,a.taxonomy_id,tv.version,a.label_key,identity.id,label.status]);
  requireValue((identity.first_registered_version as number)>=(baseline.baseline_version as number)&&(identity.first_registered_version as number)<=(tv.version as number));
  if(identity.retired_at_version!==null){requireValue((identity.retired_at_version as number)>(tv.version as number)&&(identity.retired_at_version as number)<=(p.taxonomyHead.current_version as number));available=false;}
 }
 if(!available)return {active:true,available:false,fact:null};
 const ref={id:a.id as UUID,version:a.version as Version};
 return {active:true,available:true,fact:{ref,kind:'classifications',provenance:{producer:producer.producer,tenantId:tenant,registryDigest:context.context.registry.digest,sourceRecordId:ref.id,sourceRecordVersion:ref.version},
  resource:{tenantId:tenant,kind:'asset',id:target.id},revision:target.version,fieldId:null,securityRevision:context.securityRevision,state:'approved',validity:{notBefore:ar.created_at as ApprovedSetFact['validity']['notBefore'],expiresAt:null},values:[identity!.id as UUID]}};
}

export async function loadReviewedClassificationFacts(input:{query:ClassificationFactQuery;context:VersionedHumanAssetContext;producerSnapshot:ReviewedClassificationProducerSnapshot;budget:ClassificationReadBudget}):Promise<ReviewedClassificationFacts>{
 const {budget}=input;
 try{
  budget.check();const context=parsed(parseVersionedHumanAssetContext(input.context)),producer=parsed(parseReviewedClassificationProducerSnapshot(input.producerSnapshot));
  const snapshot=context.context.closure.snapshot;
  same([producer.tenantId,producer.generation,producer.authorityEpoch,producer.registryId,producer.registryVersion,producer.registryDigest,producer.asOf],
   [snapshot.tenantId,snapshot.generation,snapshot.authorityEpoch,snapshot.registryId,snapshot.registryVersion,snapshot.registryDigest,snapshot.asOf]);
  const unavailable=():ReviewedClassificationFacts=>({producerBinding:producer.binding,classifications:{status:'unavailable'},approvedFacts:[]});
  if(!reviewedClassificationProducerAvailable(context,producer.binding)){budget.admitSource([]);budget.check();return unavailable();}
  const query=async(text:string)=>{budget.check();const result=await input.query(text,[snapshot.tenantId,context.context.asset.id]);budget.check();return result;};
  const counts=one(await query(countQuery));same(Object.keys(counts).sort(),['assignments','decisions','max_decisions','max_tasks','tasks']);
  const count=decimal(counts.assignments,PROFILE.assignments),tasks=decimal(counts.tasks,PROFILE.tasks),decisions=decimal(counts.decisions,PROFILE.decisions);
  decimal(counts.max_tasks,PROFILE.perRequest);decimal(counts.max_decisions,PROFILE.perRequest);
  let source:unknown[]=[];
  if(count){
   const measured=one(await query(measureQuery));same(Object.keys(measured).sort(),['assignments','canonical_bytes','component_bounds','dependencies_complete','raw_bytes']);
   requireValue(decimal(measured.assignments,PROFILE.assignments)===count&&measured.dependencies_complete===true);if(measured.component_bounds!==true)limit();
   const canonicalBytes=decimal(measured.canonical_bytes,PROFILE.proofBytes),rawBytes=decimal(measured.raw_bytes,PROFILE.proofBytes);
   // Brackets/commas are part of the retained inventory, not a free allowance.
   if(canonicalBytes+count+1>PROFILE.proofBytes||rawBytes+count+1>PROFILE.proofBytes)limit();
   const bodies=await query(bodyQuery);requireValue(Array.isArray(bodies.rows)&&bodies.rows.length===count);
   source=bodies.rows.map(value=>{const selected=row(admitted(value).data);same(Object.keys(selected),['proof']);return selected.proof;});
   requireValue(source.reduce<number>((n,v)=>n+Buffer.byteLength(canonical(v)),0)===canonicalBytes);
  }else requireValue(tasks===0&&decisions===0);
  const detached=admitted(source);if(detached.metrics.canonicalBytes>PROFILE.proofBytes)limit();
  budget.admitSource(detached.data);budget.check();
  const facts:ApprovedSetFact[]=[],slots=new Set<string>(),requests=new Set<unknown>();let available=true,totalTasks=0,totalDecisions=0,previous='';
  for(const raw of detached.data as readonly unknown[]){
   budget.check();const p=row(raw),a=row(p.assignment);requireValue(typeof a.id==='string'&&a.id>previous);previous=a.id;
   const slot=`${a.taxonomy_id}:${a.label_key}`,request=row(p.request).id;requireValue(!slots.has(slot)&&!requests.has(request));slots.add(slot);requests.add(request);
   requireValue(Array.isArray(p.tasks)&&Array.isArray(p.decisions));totalTasks+=p.tasks.length;totalDecisions+=p.decisions.length;
   const result=validateProof(raw,context,producer.binding!,budget);available=available&&result.available;
   if(result.fact)facts.push(result.fact);
  }
  requireValue(totalTasks===tasks&&totalDecisions===decisions);budget.check();
  if(!available)return unavailable();
  facts.sort((a,b)=>`${a.ref.id}@${a.ref.version}`.localeCompare(`${b.ref.id}@${b.ref.version}`));bytes(facts,PROFILE.factBytes);
  return {producerBinding:producer.binding,classifications:{status:'known',value:facts.map(f=>f.ref)},approvedFacts:Object.freeze(facts)};
 }catch(error){
  if(error instanceof AuthorityFoundationError)throw error;
  const issue=decisionFailure(error);if(!issue.ok&&issue.issues.some(i=>i.code==='limit'))limit();return fail();
 }
}
