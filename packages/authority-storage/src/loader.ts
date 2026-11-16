// SPDX-License-Identifier: Apache-2.0
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS } from '../../authority/src/actions.ts';
import { AUTHORITY_ADMISSION_LIMITS as L } from '../../authority/src/admission.ts';
import { canonicalDecisionJSON, decisionFailure, decisionShapes, validateRegistry } from '../../authority/src/decision-schema.ts';
import { grantKey, versionKey } from '../../authority/src/decision-types.ts';
import type { AtomicRequest, AuthorityDecisionRegistry, DecisionCatalogs } from '../../authority/src/decision-types.ts';
import type { Parsed } from '../../authority/src/types.ts';
import type { AuthorityHumanClosure, ClosureSelectors } from './contracts.ts';
import { validateClosureConsistency } from './consistency.ts';
import { admitted,array,counter,digest,equal,fail,foundationScalars,grantRef,integer,literal,nullable,ref,row,shape,str,utc,uuid,validity,version,type Row,type Validator } from './shape.ts';
const actions=[...COMPATIBILITY_ACTIONS.flatMap(([a])=>a),...ADMIN_ACTIONS,...FIELD_ACTIONS,...SERVICE_ACTIONS];
const kinds=['tenant','tenant-member','source','scan-job','asset','model-definition','model-migration','asset-type-migration','relation-type','relation','relation-participation','relation-operation','relation-preparation','domain-type','domain','asset-domain-placement','domain-type-migration','audit-event','authority-group','authority-role','authority-policy','authority-grant','responsibility-type','responsibility-assignment','authority-delegation','authority-elevation','execution-site','service-principal','authority-decision'];
const request:Validator=(v,p)=>{const r=shape({action:literal(...actions),resource:shape({tenantId:uuid,kind:literal(...kinds),id:uuid}),revision:nullable(version),field:nullable(str)})(v,p) as unknown as AtomicRequest;
 if((FIELD_ACTIONS as readonly string[]).includes(r.action)!==(r.field!==null))fail('Action and field disagree.');if(r.field!==null&&(!r.field.length||Buffer.byteLength(r.field)>L.fieldBytes))fail('Invalid bounded field handle.','format');return r;};
const requests=array(request,canonicalDecisionJSON,128);
const selectorsShape=shape({formatVersion:literal(1),requests});
export function parseClosureSelectors(value:unknown):Parsed<ClosureSelectors>{try{const a=admitted(value);if((a.metrics.rawBytes??a.metrics.canonicalBytes)>131072||a.metrics.canonicalBytes>131072)fail('Selectors exceed128KiB.','limit');const out=selectorsShape(a.data,'') as ClosureSelectors;if(out.requests.some(q=>(SERVICE_ACTIONS as readonly string[]).includes(q.action)))fail('Service selectors are outside the human foundation.');if(!out.requests.length)fail('At least one selector is required.','required');return {ok:true,value:out};}catch(e){return decisionFailure(e);}}
const subject=shape({kind:literal('human'),id:uuid});
const session=shape({formatVersion:literal(1),sessionId:uuid,sessionVersion:version,identityId:uuid,tenantId:uuid,generation:counter,authnFenceEpoch:counter,issuingRegistrationId:uuid,issuerRegistrationId:uuid,identityBindingId:uuid,authenticatedAt:utc,issuedAt:utc,expiresAt:utc});
const snapshot=shape({tenantId:uuid,generation:counter,authorityEpoch:counter,registryId:uuid,registryVersion:version,registryDigest:digest,asOf:utc,identityRevisionDigest:digest,closureDigest:digest});
const partition=shape({key:digest,subject,request,candidates:array(grantRef,v=>grantKey(v as never),1536)});
const parent=shape({child:grantRef,parent:grantRef,viaMembership:nullable(ref)});
const dependency=shape({from:digest,issuer:digest,child:grantRef});
const elevationUse=shape({ref, elevation:grantRef,identityId:uuid,sessionId:uuid,sessionVersion:version,generation:counter,state:literal('active','revoked'),validity});
const head:Validator=(v,p)=>{const r=shape({family:literal('definition','group-membership','grant','elevation-use'),id:uuid,definitionKind:nullable(literal('policy','role','responsibility-type','group')),headVersion:version})(v,p) as Row;if((r.family==='definition')!==(r.definitionKind!==null))fail('Lifecycle definition discriminant mismatch.');return r;};
const metricLimits={selectors:128,partitions:128,dependencyEdges:1024,dependencyReferences:4096,dependencyDepth:16,canonicalBytes:L.canonicalBytes,jsonNodes:L.jsonNodes,maxDepth:L.jsonDepth,policies:32,policyBytes:L.policyBytes,policyRules:4096,expressionNodes:4096,ordinaryOrigins:512,connectedRecords:1024,principals:2048,directGroupsMaximum:1024,proofBytes:L.proofBytes};
const metrics=shape(Object.fromEntries(Object.entries(metricLimits).map(([k,n])=>[k,integer(0,n)])));
const catalogKeys=['principals','groups','memberships','principalGroups','definitions','policies','grants'] as const;
const unrelatedKeys=['sessions','credentials','scopeAnchors','visibility','creators','serviceAssignments','approvedFacts','contextFacts','operations','references','sources','jobs','claims','leases','projectionEvents','journalClaims','terminals'];
/** Invoke the frozen closed catalog DTO grammar only, never a fabricated DecisionBundle. */
function humanCatalogs(value:Row):Pick<DecisionCatalogs,typeof catalogKeys[number]>{
 const input=Object.fromEntries([...catalogKeys.map(k=>[k,value[k]]),...unrelatedKeys.map(k=>[k,[]])]);
 const normalized=decisionShapes.catalogs(input,'') as DecisionCatalogs;
 for(const k of catalogKeys)equal(input[k],normalized[k],'Catalog rows and nested sets must use distinct canonical ordering.');
 if(normalized.principals.some(x=>x.kind!=='human')||normalized.grants.some(x=>x.kind==='service')||normalized.principalGroups.some(x=>x.subject.kind!=='human'||x.memberships.status!=='known'))fail('Foundation closure contains nonhuman or unavailable catalog evidence.');
 return Object.fromEntries(catalogKeys.map(k=>[k,normalized[k]])) as Pick<DecisionCatalogs,typeof catalogKeys[number]>;
}
const pass:Validator=v=>v;
const closureShape=shape({formatVersion:literal(1),kind:literal('inactive-human-candidate-closure'),contentAuthority:literal(false),session,snapshot,selectors:requests,
 partitions:array(partition,v=>(v as Row).key as string,128),parents:array(parent,v=>grantKey((v as Row).child as never),1024),
 dependencies:array(dependency,v=>{const r=v as Row;return `${r.from}:${r.issuer}:${grantKey(r.child as never)}`;},4096),
 ...Object.fromEntries(catalogKeys.map(k=>[k,pass])),
 elevationUses:array(elevationUse,v=>versionKey((v as Row).ref as never)),
 lifecycleHeads:array(head,v=>{const r=v as Row;return `${r.family}:${r.definitionKind??''}:${r.id}`;}),metrics});
export function parseAuthorityHumanClosure(value:unknown,registry:unknown):Parsed<AuthorityHumanClosure>{
 try{
  const a=admitted(value),r=admitted(registry);
  if(a.metrics.canonicalBytes+r.metrics.canonicalBytes>L.canonicalBytes||a.metrics.nodes+r.metrics.nodes>L.jsonNodes||
    (a.metrics.rawBytes??a.metrics.canonicalBytes)+(r.metrics.rawBytes??r.metrics.canonicalBytes)>L.rawBytes)fail('Registry and closure exceed one shared physical profile.','limit');
  const parsedRegistry=decisionShapes.registry(r.data,'/registry') as AuthorityDecisionRegistry;validateRegistry(parsedRegistry);foundationScalars(parsedRegistry);
  const out=closureShape(a.data,'') as unknown as AuthorityHumanClosure;
  const catalogs=humanCatalogs(row(a.data));
  const closure=Object.freeze({...out,...catalogs}) as AuthorityHumanClosure;
  foundationScalars(closure);
  equal(closure.metrics.canonicalBytes,a.metrics.canonicalBytes,'Closure canonical byte metric mismatch.');equal(closure.metrics.jsonNodes,a.metrics.nodes,'Closure node metric mismatch.');equal(closure.metrics.maxDepth,a.metrics.depth,'Closure depth metric mismatch.');
  validateClosureConsistency(closure,parsedRegistry);
  return {ok:true,value:closure};
 }catch(e){return decisionFailure(e);}
}
