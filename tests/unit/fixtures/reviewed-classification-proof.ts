// SPDX-License-Identifier: Apache-2.0
// Copied synthetic proof fixture from the qualified fact unit test; no DB evidence.
import assert from 'node:assert/strict';
import {decisionHash} from '../../../packages/authority/src/decision-schema.ts';
import {classificationDefinitionHash,evaluateMetadataClassification} from '../../../packages/domain/src/classification.ts';
import {id,zero} from './authority-decision.ts';
export function sourceProof(index=0):any{
 const tenant=id(1),actor=id(2),asset=id(3),reviewer=id(900),alternate=id(901),taxonomyId=id(1000+index),ruleId=id(2000+index),evaluationId=id(3000+index),assignmentId=id(4000+index),requestId=id(5000+index);
 const evaluated='2026-11-16T05:10:00.000Z',created='2026-11-16T05:20:00.000Z',decided='2026-11-16T05:21:00.000Z',published='2026-11-16T05:22:00.000Z',expires='2026-11-16T05:50:00.000Z';
 const taxonomy={formatVersion:1,name:'Synthetic taxonomy',description:'Synthetic proof',labels:[{key:'sensitive',name:'Sensitive metadata',description:'Synthetic label',status:'active'}]},taxonomyHash=classificationDefinitionHash(taxonomy);
 const rule={formatVersion:1,kind:'metadata-literal',name:'Synthetic rule',purpose:'Metadata match only',ownerId:actor,status:'active',assetTypes:['table'],label:{taxonomy:{id:taxonomyId,version:1,definitionHash:taxonomyHash},labelKey:'sensitive'},all:[{field:'name',operator:'contains',comparison:'exact',literal:'sensitive'}]},ruleHash=classificationDefinitionHash(rule);
 const assetInput={id:asset,version:1,type:'table',name:'sensitive records',qualifiedName:'synthetic.sensitive_records',dataType:null};
 const evaluatedResult=evaluateMetadataClassification(rule,{id:ruleId,version:1,definitionHash:ruleHash},assetInput,evaluated);assert.equal(evaluatedResult.ok,true);if(!evaluatedResult.ok)throw new Error('Synthetic evaluation refused');
 const evaluation=evaluatedResult.value,evidence=evaluation.evidence,evidenceHash=decisionHash(evidence);
 const workflow={formatVersion:1,id:'classification_review',version:1,name:'Independent review',separationOfDuties:true,stages:[{id:'review',name:'Review',assignments:['alternate','reviewer'],quorum:1,deadlineSeconds:1800,rejection:'any'}]},workflowHash=decisionHash(workflow);
 const payload={formatVersion:1,kind:'classification-review',change:'apply',assetId:asset,assignmentId,expectedAssignmentVersion:0,suggestionId:evaluationId,label:rule.label,evidence,evidenceHash,reason:''};
 const proof={
  assignment:{tenant_id:tenant,id:assignmentId,asset_id:asset,taxonomy_id:taxonomyId,label_key:'sensitive',version:1,status:'active',created_by:actor,created_at:published},
  revision:{tenant_id:tenant,assignment_id:assignmentId,version:1,status:'active',suggestion_id:evaluationId,approval_request_id:requestId,reason:null,actor_id:actor,created_at:published},
  evaluation:{tenant_id:tenant,id:evaluationId,asset_id:asset,asset_version:1,rule_id:ruleId,rule_version:1,rule_hash:ruleHash,...evaluation,evidence_hash:evidenceHash,created_by:actor,created_at:evaluated},
  rule:{tenant_id:tenant,rule_id:ruleId,version:1,definition:rule,definition_hash:ruleHash,taxonomy_id:taxonomyId,taxonomy_version:1,taxonomy_hash:taxonomyHash,owner_id:actor,created_by:actor,created_at:evaluated},
  taxonomy:{tenant_id:tenant,taxonomy_id:taxonomyId,version:1,definition:taxonomy,definition_hash:taxonomyHash,created_by:actor,created_at:evaluated},
  ruleHead:{tenant_id:tenant,id:ruleId,current_version:1},taxonomyHead:{tenant_id:tenant,id:taxonomyId,current_version:1},
  baseline:{tenant_id:tenant,taxonomy_id:taxonomyId,baseline_version:1,baseline_hash:taxonomyHash},
  identity:{tenant_id:tenant,id:id(6000+index),taxonomy_id:taxonomyId,label_key:'sensitive',first_registered_version:1,retired_at_version:null},
  labelBinding:{tenant_id:tenant,taxonomy_id:taxonomyId,taxonomy_version:1,label_key:'sensitive',label_id:id(6000+index),label_status:'active'},
  request:{tenant_id:tenant,id:requestId,binding:'classification.review',resource_id:asset,resource_version:1,payload,proposal_digest:zero,workflow_id:workflow.id,workflow_version:1,workflow_hash:workflowHash,requester_id:actor,stage_index:0,version:4,status:'succeeded',result:{binding:'classification.review',assetId:asset,assignmentId,assignmentVersion:1,status:'active',evidenceHash},error_code:null,expires_at:expires,created_at:created,updated_at:published},
  workflow:{tenant_id:tenant,workflow_id:workflow.id,version:1,definition:workflow,definition_hash:workflowHash},
  tasks:[{tenant_id:tenant,id:id(7000+index*2),request_id:requestId,stage_index:0,assignment:'reviewer',assigned_identity_id:reviewer,version:2,status:'decided',opened_at:created,expires_at:expires},{tenant_id:tenant,id:id(7001+index*2),request_id:requestId,stage_index:0,assignment:'alternate',assigned_identity_id:alternate,version:2,status:'cancelled',opened_at:created,expires_at:expires}],
  decisions:[{tenant_id:tenant,id:id(8000+index),request_id:requestId,task_id:id(7000+index*2),task_version:1,proposal_digest:zero,actor_id:reviewer,decision:'approve',reason:'Reviewed synthetic metadata',decided_at:decided}],
  historicalInput:assetInput,currentInput:structuredClone(assetInput)};
 sealProof(proof);return structuredClone(proof);
}
export function sealProof(p:any){
 const assignments=Object.fromEntries(p.tasks.map((t:any)=>[t.assignment,t.assigned_identity_id]));
 p.request.proposal_digest=decisionHash({id:p.request.id,binding:p.request.binding,payload:p.request.payload,workflow:{id:p.request.workflow_id,version:p.request.workflow_version,definitionHash:p.request.workflow_hash},assignments,expiresAt:p.request.expires_at});
 for(const d of p.decisions)d.proposal_digest=p.request.proposal_digest;
}
