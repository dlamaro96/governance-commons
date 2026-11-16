// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { admitAuthorityInput, parseAuthorityInputFile, AUTHORITY_ADMISSION_LIMITS as L } from './admission.ts';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS } from './actions.ts';
import { parsePolicyFile, policyHash } from './policy.ts';
import type { AuthorityIssue, Digest, Parsed, PolicyDefinition } from './types.ts';
import type * as T from './decision-types.ts';
import { DecisionInputError, versionKey, subjectKey, grantKey, policyKey, definitionKey, chainLinkKey, scopeKey } from './decision-types.ts';

type V = (value: unknown, path: string) => unknown;
type Row = Record<string, unknown>;
const kinds = ['tenant','tenant-member','source','scan-job','asset','model-definition','model-migration','asset-type-migration','relation-type','relation','relation-participation','relation-operation','relation-preparation','domain-type','domain','asset-domain-placement','domain-type-migration','audit-event','authority-group','authority-role','authority-policy','authority-grant','responsibility-type','responsibility-assignment','authority-delegation','authority-elevation','execution-site','service-principal','authority-decision'] as const;
const humanActions = [...COMPATIBILITY_ACTIONS.flatMap(([actions]) => actions), ...ADMIN_ACTIONS];
const allActions = [...humanActions,...FIELD_ACTIONS,...SERVICE_ACTIONS];
const point = (path: string, key: string | number): string => { const text=String(key); if(text.length>1024)return ''; const result=`${path}/${text.replaceAll('~','~0').replaceAll('/','~1')}`; return result.length>1024?'':result; };
export function decisionInvalid(code: AuthorityIssue['code'], path: string, message: string): never {
  throw new DecisionInputError(code === 'limit' ? 'profile_limit' : code === 'unsupported' ? 'unsupported' : 'invalid', {code,path,message});
}
export function decisionFailure(error: unknown): Parsed<never> {
  return {ok:false,issues:[error instanceof DecisionInputError ? error.issue : {code:'invalid_json',path:'',message:'Expected bounded closed authority data.'}]};
}
/** Internal canonical serializer: callers pass admitted, schema-validated JSON only. */
export function canonicalDecisionJSON(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalDecisionJSON).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonicalDecisionJSON((value as Row)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const decisionHash = (value: unknown): Digest => createHash('sha256').update(canonicalDecisionJSON(value)).digest('hex') as Digest;
const text: V = (v,p) => { if (typeof v !== 'string') decisionInvalid('type',p,'Expected a string.'); return v; };
const handle: V = (v,p) => { const s=text(v,p) as string; if (!s.length) decisionInvalid('range',p,'Expected a nonempty registered handle.'); return s; };
const bool: V = (v,p) => { if (typeof v !== 'boolean') decisionInvalid('type',p,'Expected a boolean.'); return v; };
const integer = (min:number,max:number):V => (v,p) => { if (!Number.isSafeInteger(v) || Object.is(v,-0) || (v as number)<min || (v as number)>max) decisionInvalid('range',p,'Expected an integer in the declared range.'); return v; };
const version=integer(1,2_147_483_647);
const uuid:V=(v,p)=>{ const s=text(v,p) as string; if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) decisionInvalid('format',p,'Expected a canonical UUID.'); return s; };
const digest:V=(v,p)=>{ const s=text(v,p) as string; if (!/^[0-9a-f]{64}$/.test(s)) decisionInvalid('format',p,'Expected a lowercase SHA-256 digest.'); return s; };
const counter:V=(v,p)=>{ const s=text(v,p) as string; if (!/^(0|[1-9][0-9]*)$/.test(s)) decisionInvalid('format',p,'Expected a canonical decimal counter.'); return s; };
const utc:V=(v,p)=>{ const s=text(v,p) as string; if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s) || !Number.isFinite(Date.parse(s)) || new Date(s).toISOString()!==s) decisionInvalid('format',p,'Expected canonical millisecond UTC.'); return s; };
const literal=(...values:readonly unknown[]):V=>(v,p)=>{if(!values.includes(v)) decisionInvalid('unsupported',p,'Unknown declared vocabulary.');return v;};
const nullable=(validate:V):V=>(v,p)=>v===null?null:validate(v,p);
function object(v:unknown,p:string):Row { if (!v || typeof v!=='object' || Array.isArray(v)) decisionInvalid('type',p,'Expected an object.');return v as Row; }
const shape=(fields:Record<string,V>):V=>(v,p)=>{
  const r=object(v,p); for(const key of Object.keys(r).sort()) if(!Object.hasOwn(fields,key)) decisionInvalid('unknown_field',point(p,key),'Unknown field.');
  const out:Row=Object.create(null); for(const [key,validate] of Object.entries(fields)) {if(!Object.hasOwn(r,key)) decisionInvalid('required',point(p,key),'Required field.');out[key]=validate(r[key],point(p,key));} return Object.freeze(out);
};
const keyed=(item:V,key:(v:unknown)=>string,max:number=L.jsonNodes,ordered=false):V=>(v,p)=>{
  if(!Array.isArray(v)) decisionInvalid('type',p,'Expected an array.');if(v.length>max)decisionInvalid('limit',p,'Array exceeds its shared profile.');
  const seen=new Set<string>(); const rows=v.map((x,i)=>{const n=item(x,point(p,i)),k=key(n);if(seen.has(k))decisionInvalid('duplicate',point(p,i),'Duplicate semantic identity.');seen.add(k);return n;});
  if(!ordered)rows.sort((a,b)=>{const x=key(a),y=key(b);return x<y?-1:x>y?1:0;});return Object.freeze(rows);
};
const scalarSet=(v:V,max:number=L.jsonNodes)=>keyed(v,x=>String(x),max);
const fact=(known:V):V=>(v,p)=>{const r=object(v,p);return (r.status==='known'?shape({status:literal('known'),value:known}):shape({status:literal('unavailable')}))(v,p);};
const tagged=(field:string,choices:Record<string,V>):V=>(v,p)=>{const r=object(v,p),tag=r[field];if(typeof tag!=='string'||!Object.hasOwn(choices,tag))decisionInvalid('unsupported',point(p,field),'Unknown discriminant.');return choices[tag]!(v,p);};
const ref=shape({id:uuid,version});const refKey=(v:unknown)=>versionKey(v as T.VersionRef);
const refs=keyed(ref,refKey);
const subject=shape({kind:literal('human','service'),id:uuid});
const humanGroup=shape({kind:literal('human','group'),id:uuid});
const resource=shape({tenantId:uuid,kind:literal(...kinds),id:uuid});
const request=shape({action:literal(...allActions),resource,revision:nullable(version),field:nullable(handle)});
const validity:V=(v,p)=>{const r=shape({notBefore:nullable(utc),expiresAt:nullable(utc)})(v,p) as Row;if(r.notBefore!==null&&r.expiresAt!==null&&(r.notBefore as string)>=(r.expiresAt as string))decisionInvalid('range',p,'Validity must be a nonempty half-open interval.');return r;};
const scope=tagged('kind',{
  tenant:shape({kind:literal('tenant'),tenantId:uuid}),
  domain:shape({kind:literal('domain'),tenantId:uuid,domainId:uuid,includeDescendants:bool}),
  resource:shape({kind:literal('resource'),resource}),
});
const rolePin=shape({roleId:uuid,version}); const policyPin=shape({policyId:uuid,version,hash:digest});
const policyPins=keyed(policyPin,v=>policyKey(v as T.PolicyEvidence['pin']),32);
const grantRef=shape({kind:literal('grant','delegation','elevation'),id:uuid,version});
const grantRefKey=(v:unknown)=>grantKey(v as T.GrantRef);
const state=literal('active','revoked'), definitionState=literal('active','retired');
const effect=shape({actions:scalarSet(literal(...allActions),136),resourceKinds:scalarSet(literal(...kinds),kinds.length),fields:nullable(scalarSet(handle)),scope,validity});
const delegable=shape({actions:scalarSet(literal(...humanActions),humanActions.length),fields:nullable(scalarSet(handle)),scope,validity,remainingDepth:integer(0,4)});
const metadataText=(min:number,max:number):V=>(v,p)=>{const s=text(v,p) as string;if(s.length>max*2||[...s].length<min||[...s].length>max||/[\u0000-\u001f\u007f]/.test(s))decisionInvalid('range',p,'Invalid bounded metadata text.');return s;};
const metadata=shape({key:(v,p)=>{const s=text(v,p) as string;if(!/^[a-z][a-z0-9_-]{0,79}$/.test(s))decisionInvalid('format',p,'Invalid immutable definition key.');return s;},label:metadataText(1,200),description:metadataText(0,4000)});
const definitionContentFields={formatVersion:literal(1),id:uuid,version};
const definitionContent=tagged('kind',{
  role:shape({...definitionContentFields,kind:literal('role'),content:shape({metadata,policies:policyPins})}),
  'responsibility-type':shape({...definitionContentFields,kind:literal('responsibility-type'),content:shape({metadata,grantsRole:nullable(rolePin)})}),
});
const definition:V=(v,p)=>{const r=object(v,p);const common={tenantId:uuid,currentHeadVersion:version,state:definitionState,hash:digest,...definitionContentFields};return tagged('kind',{
  role:shape({...common,kind:literal('role'),content:shape({metadata,policies:policyPins})}),
  'responsibility-type':shape({...common,kind:literal('responsibility-type'),content:shape({metadata,grantsRole:nullable(rolePin)})}),
})(r,p);};
const intent=shape({ruleId:uuid,registryVersion:version,registryDigest:digest,resourceKinds:scalarSet(literal(...kinds)),expandedActions:scalarSet(literal(...allActions))});
const policy=shape({tenantId:uuid,currentHeadVersion:version,state:definitionState,pin:policyPin,document:text,resourceWideIntents:keyed(intent,v=>(v as Row).ruleId as string)});
const grantCommon={ref:grantRef,tenantId:uuid,state,issuer:subject,scope,validity,ceiling:effect};
const grant=tagged('kind',{
  'ordinary-role':shape({...grantCommon,kind:literal('ordinary-role'),beneficiary:humanGroup,role:rolePin,delegable:nullable(delegable)}),
  responsibility:shape({...grantCommon,kind:literal('responsibility'),beneficiary:humanGroup,type:ref,mappedRole:nullable(rolePin),assignmentId:uuid,assignmentVersion:version,effectiveGrantId:nullable(uuid),delegable:nullable(delegable)}),
  delegation:shape({...grantCommon,kind:literal('delegation'),parent:grantRef,beneficiary:subject,delegable:nullable(delegable)}),
  elevation:shape({...grantCommon,kind:literal('elevation'),parent:grantRef,beneficiary:subject,use:nullable(shape({id:uuid,version,state,identityId:uuid,sessionId:uuid,sessionVersion:version,generation:counter,validity}))}),
  service:shape({...grantCommon,kind:literal('service'),beneficiary:subject,policies:policyPins,assignment:ref}),
});
const principal=tagged('kind',{
  human:shape({kind:literal('human'),id:uuid,identityRevision:counter,active:bool,membership:nullable(shape({ref,tenantId:uuid,identityId:uuid,state,validity}))}),
  service:shape({kind:literal('service'),id:uuid,revision:counter,tenantId:uuid,state,validity}),
});
const group=shape({id:uuid,tenantId:uuid,revision:counter,state:definitionState});
const membership=shape({ref,tenantId:uuid,groupId:uuid,identityId:uuid,state,validity});
const principalGroups=shape({subject,memberships:fact(refs)});
const session=shape({id:uuid,version,identityId:uuid,selectedTenantId:uuid,generation:counter,state,validity});
const credential=shape({id:uuid,version,serviceId:uuid,tenantId:uuid,generation:counter,state,validity});
const operationRef=shape({operationId:uuid,version,planHash:digest,memberKey:handle,side:literal('before','after','original')});
const containment=shape({resource,revision:nullable(version),context:literal('current','proposed','original-scope'),securityRevision:counter,domainPath:fact(keyed(uuid,String,33,true)),operation:nullable(operationRef)});
const resourceEvidence=shape({requestResource:resource,requestedRevision:nullable(version),canonicalCurrentVersion:nullable(version),containment,classifications:fact(refs),approvedTags:fact(refs)});
const authentication=tagged('kind',{
  'human-session':shape({kind:literal('human-session'),sessionId:uuid,sessionVersion:version}),
  'service-credential':shape({kind:literal('service-credential'),credentialId:uuid,credentialVersion:version}),
  'live-issuer':shape({kind:literal('live-issuer'),childGrant:grantRef,elevationSession:nullable(ref)}),
  'scan-initiator':shape({kind:literal('scan-initiator'),jobId:uuid,jobVersion:version,elevationSession:nullable(ref)}),
});
const projectionPath=tagged('kind',{direct:shape({kind:literal('direct')}),'registered-reference':shape({kind:literal('registered-reference'),referenceId:uuid,referenceVersion:version})});
const projection=shape({projectionId:handle,version,registrationHash:digest,fieldId:handle,resource,revision:nullable(version),sensitivityRevision:counter,sensitivity:literal('ordinary','sensitive'),prerequisites:scalarSet(digest),sensitiveDecision:nullable(digest),path:projectionPath});
const serviceUse=tagged('kind',{
  dispatch:shape({kind:literal('dispatch'),assignment:ref,source:ref,job:ref}),
  claim:shape({kind:literal('claim'),assignment:ref,source:ref,job:ref,initiatingDecision:digest}),
  ...Object.fromEntries(['metadata','secret','complete'].map(k=>[k,shape({kind:literal(k),assignment:ref,source:ref,job:ref,claim:ref,lease:ref,initiatingDecision:digest,requestHash:digest,secretBinding:nullable(ref)})])),
  fail:shape({kind:literal('fail'),assignment:ref,job:ref,requestHash:digest,terminalAction:literal('failed','cancelled')}),
  'terminal-replay':shape({kind:literal('terminal-replay'),assignment:ref,job:ref,terminal:ref,initiatingDecision:nullable(digest),requestHash:digest}),
  ...Object.fromEntries(['project-consume','project-write'].map(k=>[k,shape({kind:literal(k),assignment:ref,event:ref,mode:literal('apply','replay'),requestHash:digest})])),
  ...Object.fromEntries(['audit','outbox'].map(k=>[k,shape({kind:literal(k),assignment:ref,claim:ref,payloadHash:digest})])),
});
const nodeFields={mode:literal('authorize','resource-wide-deny'),subject,request,authentication,resource:resourceEvidence,adapterId:handle,projection:nullable(projection),ceilingRefs:keyed(shape({slot:handle,recordId:handle}),v=>(v as Row).slot as string),service:nullable(serviceUse),intentGuard:nullable(digest),guardOrigin:nullable(digest),purpose:fact(ref),environment:fact(ref)};
const nodeDescriptor=shape(nodeFields), node=shape({...nodeFields,id:digest,factDigest:digest});
const snapshot=shape({tenantId:uuid,generation:counter,authorityEpoch:counter,registryVersion:version,registryDigest:digest,snapshotDigest:digest,now:utc});
const provenance=shape({producer:ref,tenantId:uuid,registryDigest:digest,sourceRecordId:uuid,sourceRecordVersion:version});
const approvedFact=shape({ref,kind:literal('classifications','approved-tags'),provenance,resource,revision:nullable(version),fieldId:nullable(handle),securityRevision:counter,state:literal('approved','withdrawn'),validity,values:scalarSet(uuid,4096)});
const contextFact=shape({ref,kind:literal('purpose','environment'),provenance,subject,request,containmentDigest:digest,state:literal('approved','revoked'),validity,value:nullable(uuid)});
const operation=shape({id:uuid,version,tenantId:uuid,actor:subject,planHash:digest,requestHash:digest,state:literal('prepared','sealed'),validity,members:keyed(shape({key:handle,side:literal('before','after','original'),resource,revision:nullable(version),securityRevision:counter,domainPath:keyed(uuid,String,33,true)}),v=>`${(v as Row).key}:${(v as Row).side}`)});
const visibility=shape({id:handle,resource,revision:nullable(version),visibility:literal('tenant','restricted'),allowedIdentities:scalarSet(uuid)});
const creator=shape({id:handle,resource,creator:subject});
const assignment=shape({ref,tenantId:uuid,serviceId:uuid,state,validity,actions:scalarSet(literal(...SERVICE_ACTIONS),10),siteId:nullable(uuid),sourceId:nullable(uuid),indexId:nullable(handle),eventFamilies:scalarSet(handle)});
const reference=shape({id:uuid,version,tenantId:uuid,projectionId:handle,projectionVersion:version,registrationHash:digest,parent:shape({resource,revision:nullable(version)}),target:shape({resource,revision:nullable(version)}),fieldId:handle,sourceRecordId:uuid,sourceRecordVersion:version});
const source=shape({ref,tenantId:uuid,siteId:uuid,securityRevision:counter,secretBinding:shape({id:uuid,version,sourceId:uuid,siteId:uuid})});
const job=shape({ref,tenantId:uuid,sourceId:uuid,siteId:uuid,serviceId:uuid,initiatingIdentityId:uuid,requestHash:digest,generation:counter,claimVersion:counter,status:literal('queued','running','succeeded','failed','cancelled'),deadlineAt:utc});
const claim=shape({ref,tenantId:uuid,jobId:uuid,sourceId:uuid,siteId:uuid,serviceId:uuid,credentialId:uuid,credentialVersion:version,generation:counter,claimVersion:counter,requestHash:digest,state:literal('active','sealed','revoked'),validity});
const lease=shape({ref,tenantId:uuid,issuer:tagged('kind',{gateway:shape({kind:literal('gateway'),registration:ref}),'parent-service':shape({kind:literal('parent-service'),serviceId:uuid,credential:ref,assignment:ref})}),assignment:ref,audienceServiceId:uuid,serviceId:uuid,credentialId:uuid,credentialVersion:version,siteId:uuid,sourceId:uuid,jobId:uuid,initiatingIdentityId:uuid,claim:ref,claimVersion:counter,generation:counter,actions:scalarSet(literal(...SERVICE_ACTIONS),10),requestHash:digest,state:literal('active','sealed','revoked'),validity,parentLease:nullable(ref)});
const event=shape({ref,tenantId:uuid,family:handle,indexId:handle,resource,revision:nullable(version),securityRevision:counter,generation:counter,state:literal('pending','applied'),eventHash:digest,requestAction:literal('projection:consume','projection:write'),requestHash:digest});
const journal=shape({ref,tenantId:uuid,operationId:uuid,operationVersion:version,actor:subject,executorServiceId:uuid,generation:counter,action:literal('audit:append','outbox:append'),resource,revision:nullable(version),payloadHash:digest,state:literal('unconsumed','consumed'),validity,parentDecisions:scalarSet(digest)});
const terminal=shape({ref,tenantId:uuid,jobId:uuid,sourceId:uuid,serviceId:uuid,claim:nullable(ref),generation:counter,action:literal('scan-job:claim','scan-job:complete','scan-job:fail'),requestHash:digest,result:literal('succeeded','failed','cancelled')});
const branches=['human-resource','human-create','human-history','human-creator','human-submitted-file','field','intent-guard','service-dispatch','service-claim','service-metadata','service-secret','service-complete','service-fail','service-terminal-replay','service-project-consume','service-project-write','service-audit','service-outbox'];
const adapter=shape({id:handle,version,action:literal(...allActions),branch:literal(...branches),resourceKinds:scalarSet(literal(...kinds)),containment:literal('domain-self','asset-placement','authority-scope','none'),ceilings:keyed(shape({slot:handle,kind:literal('visibility','creator')}),v=>(v as Row).slot as string),dependencyElevation:literal('forbidden','exact-live-session'),ceilingFailure:literal('ceiling_denied','scope_unavailable')});
const producer=shape({ref,kind:literal('classifications','approved-tags','purpose','environment'),tenantId:uuid,state:definitionState,validity});
const leaseIssuer=shape({ref,tenantId:uuid,generation:counter,state,validity});
const projectionRegistration=shape({projectionId:handle,version,registrationHash:digest,fieldId:handle,resourceKind:literal(...kinds),path:literal('direct','registered-reference'),prerequisites:keyed(shape({action:literal(...humanActions,...SERVICE_ACTIONS),resource:literal('field-owner','reference-parent')}),v=>`${(v as Row).action}:${(v as Row).resource}`)});
const registryFields={formatVersion:literal(1),version,actions:keyed(shape({action:literal(...allActions),family:literal('human','field','service'),resourceKinds:scalarSet(literal(...kinds))}),v=>(v as Row).action as string,136),adapters:keyed(adapter,v=>(v as Row).id as string),fields:scalarSet(handle,L.catalogEntries),projections:keyed(projectionRegistration,v=>`${(v as Row).projectionId}@${(v as Row).version}:${(v as Row).fieldId}:${(v as Row).resourceKind}:${(v as Row).path}`),intentContexts:keyed(shape({resourceKind:literal(...kinds),subjectKind:literal('human','service'),denyContextAction:literal(...humanActions,...SERVICE_ACTIONS),guardAdapterId:handle}),v=>`${(v as Row).resourceKind}:${(v as Row).subjectKind}`),producers:keyed(producer,v=>refKey((v as Row).ref)),leaseIssuers:keyed(leaseIssuer,v=>refKey((v as Row).ref))};
const registry=shape({...registryFields,digest});
const id=(v:unknown)=>(v as Row).id as string;
const byRef=(v:unknown)=>refKey((v as Row).ref);
const catalogsFields={
 principals:keyed(principal,v=>subjectKey(v as T.PrincipalEvidence),L.authorityPrincipals),groups:keyed(group,id),memberships:keyed(membership,byRef),principalGroups:keyed(principalGroups,v=>subjectKey((v as T.PrincipalGroups).subject)),sessions:keyed(session,refKey),credentials:keyed(credential,refKey),definitions:keyed(definition,v=>{const r=v as T.DefinitionEvidence;return definitionKey(r.kind,r.id,r.version);}),policies:keyed(policy,v=>policyKey((v as T.PolicyEvidence).pin),32),grants:keyed(grant,v=>grantRefKey((v as T.AuthorityGrant).ref)),scopeAnchors:keyed(shape({scope,containment}),v=>scopeKey((v as T.ScopeAnchorEvidence).scope)),visibility:keyed(visibility,id),creators:keyed(creator,id),serviceAssignments:keyed(assignment,byRef),approvedFacts:keyed(approvedFact,byRef),contextFacts:keyed(contextFact,byRef),operations:keyed(operation,refKey),references:keyed(reference,refKey),sources:keyed(source,byRef),jobs:keyed(job,byRef),claims:keyed(claim,byRef),leases:keyed(lease,byRef),projectionEvents:keyed(event,byRef),journalClaims:keyed(journal,byRef),terminals:keyed(terminal,byRef),
};
const catalogs=shape(catalogsFields);
const bundle=shape({...catalogsFields,formatVersion:literal(1),snapshot,root:digest,nodes:keyed(node,id,128),candidates:keyed(shape({nodeId:digest,snapshotDigest:digest,subject,request,anchorDigest:digest,candidates:keyed(grantRef,grantRefKey)}),v=>(v as Row).nodeId as string,128),chainLinks:keyed(shape({nodeId:digest,child:grantRef,parent:grantRef,issuerDecision:digest,viaMembership:nullable(ref)}),v=>chainLinkKey((v as T.ChainLink).nodeId,(v as T.ChainLink).child))});

/** Foundational shape normalizers accept ONLY already-admitted data internally. */
export const decisionShapes = Object.freeze({registry,registryContent:shape(registryFields),definitionContent,resourceEvidence,nodeDescriptor,catalogs,snapshot});

function same(a:unknown,b:unknown):boolean{return canonicalDecisionJSON(a)===canonicalDecisionJSON(b);}
function requireEqual(a:unknown,b:unknown,path:string,message:string):void{if(!same(a,b))decisionInvalid('version',path,message);}
const mapRows=<A>(rows:readonly A[],key:(row:A)=>string):ReadonlyMap<string,A>=>new Map(rows.map(row=>[key(row),row]));
export function buildDecisionIndexes(b:T.DecisionBundle,r:T.AuthorityDecisionRegistry):T.DecisionIndexes {
 return {
  nodes:mapRows(b.nodes,x=>x.id),principals:mapRows(b.principals,subjectKey),groups:mapRows(b.groups,x=>x.id),memberships:mapRows(b.memberships,x=>versionKey(x.ref)),principalGroups:mapRows(b.principalGroups,x=>subjectKey(x.subject)),sessions:mapRows(b.sessions,versionKey),credentials:mapRows(b.credentials,versionKey),definitions:mapRows(b.definitions,x=>definitionKey(x.kind,x.id,x.version)),policies:mapRows(b.policies,x=>policyKey(x.pin)),grants:mapRows(b.grants,x=>grantKey(x.ref)),candidates:mapRows(b.candidates,x=>x.nodeId),chainLinks:mapRows(b.chainLinks,x=>chainLinkKey(x.nodeId,x.child)),scopeAnchors:mapRows(b.scopeAnchors,x=>scopeKey(x.scope)),visibility:mapRows(b.visibility,x=>x.id),creators:mapRows(b.creators,x=>x.id),serviceAssignments:mapRows(b.serviceAssignments,x=>versionKey(x.ref)),approvedFacts:mapRows(b.approvedFacts,x=>versionKey(x.ref)),contextFacts:mapRows(b.contextFacts,x=>versionKey(x.ref)),operations:mapRows(b.operations,versionKey),references:mapRows(b.references,versionKey),sources:mapRows(b.sources,x=>versionKey(x.ref)),jobs:mapRows(b.jobs,x=>versionKey(x.ref)),claims:mapRows(b.claims,x=>versionKey(x.ref)),leases:mapRows(b.leases,x=>versionKey(x.ref)),projectionEvents:mapRows(b.projectionEvents,x=>versionKey(x.ref)),journalClaims:mapRows(b.journalClaims,x=>versionKey(x.ref)),terminals:mapRows(b.terminals,x=>versionKey(x.ref)),adapters:mapRows(r.adapters,x=>x.id),producers:mapRows(r.producers,x=>versionKey(x.ref)),leaseIssuers:mapRows(r.leaseIssuers,x=>versionKey(x.ref)),
 };
}
export function validateRegistry(r:T.AuthorityDecisionRegistry,checkDigest=true):void {
 const {digest:actual,...content}=r;
 if(checkDigest)requireEqual(actual,decisionHash(content),'/registry/digest','Registry digest does not match its normalized registration.');
 if(r.actions.length!==allActions.length)decisionInvalid('required','/registry/actions','Every literal action must be registered exactly once.');
 let fieldBytes=0;
 for(const field of r.fields){const bytes=Buffer.byteLength(field);if(bytes>L.fieldBytes)decisionInvalid('limit','/registry/fields','A registered field exceeds256 UTF-8 bytes.');fieldBytes+=bytes;}
 if(fieldBytes>L.catalogBytes)decisionInvalid('limit','/registry/fields','Field catalog exceeds128KiB.');
 const actionRows=new Map(r.actions.map(a=>[a.action,a]));
 for(const action of allActions){const row=actionRows.get(action);if(!row)decisionInvalid('required','/registry/actions','Missing literal action.');const family=(FIELD_ACTIONS as readonly string[]).includes(action)?'field':(SERVICE_ACTIONS as readonly string[]).includes(action)?'service':'human';if(row.family!==family)decisionInvalid('scope','/registry/actions','Action family differs from the closed registry.');}
 const branchActions:Record<string,string>={'service-dispatch':'scan-job:dispatch','service-claim':'scan-job:claim','service-metadata':'source:metadata.scan','service-secret':'secret:resolve','service-complete':'scan-job:complete','service-fail':'scan-job:fail','service-project-consume':'projection:consume','service-project-write':'projection:write','service-audit':'audit:append','service-outbox':'outbox:append'};
 const adapters=new Map(r.adapters.map(a=>[a.id,a]));
 for(const a of r.adapters){const entry=actionRows.get(a.action)!;if(a.resourceKinds.some(k=>!entry.resourceKinds.includes(k)))decisionInvalid('scope','/registry/adapters','Adapter kind is outside the registered action.');if(a.branch.startsWith('human-')&&entry.family!=='human'||a.branch==='field'&&entry.family!=='field'||a.branch==='intent-guard'&&entry.family==='field')decisionInvalid('scope','/registry/adapters','Adapter branch and action family disagree.');if(a.branch in branchActions&&a.action!==branchActions[a.branch])decisionInvalid('scope','/registry/adapters','Service branch has a different literal action.');if(a.branch==='service-terminal-replay'&&!['scan-job:claim','scan-job:complete','scan-job:fail'].includes(a.action))decisionInvalid('scope','/registry/adapters','Invalid terminal replay action.');}
 for(const i of r.intentContexts){const a=adapters.get(i.guardAdapterId);if(!a||a.branch!=='intent-guard'||a.action!==i.denyContextAction||!a.resourceKinds.includes(i.resourceKind)||actionRows.get(i.denyContextAction)!.family!==i.subjectKind)decisionInvalid('scope','/registry/intentContexts','Invalid exact guard registration.');}
 const fields=new Set<string>(r.fields);
 for(const p of r.projections){if(!fields.has(p.fieldId))decisionInvalid('scope','/registry/projections','Projection field is not registered.');const {registrationHash,...data}=p;requireEqual(registrationHash,decisionHash(data),'/registry/projections','Projection registration hash mismatch.');if(!p.prerequisites.length)decisionInvalid('required','/registry/projections','A field requires non-field prerequisites.');let family:string|null=null;for(const q of p.prerequisites){const a=actionRows.get(q.action)!;if(a.family==='field'||family!==null&&family!==a.family||q.resource!==(p.path==='direct'?'field-owner':'reference-parent'))decisionInvalid('scope','/registry/projections','Projection prerequisite family or origin mismatch.');family=a.family;if(q.resource==='field-owner'&&!a.resourceKinds.includes(p.resourceKind))decisionInvalid('scope','/registry/projections','Field-owner prerequisite cannot use this resource kind.');}}
}
function tenantWalk(v:unknown,tenant:string,path:string):void{
 if(Array.isArray(v)){v.forEach((x,i)=>tenantWalk(x,tenant,point(path,i)));return;}
 if(v===null||typeof v!=='object')return;
 for(const [key,value] of Object.entries(v)){if(key==='tenantId'&&value!==tenant)decisionInvalid('scope',point(path,key),'Cross-tenant evidence is invalid.');tenantWalk(value,tenant,point(path,key));}
}
function validatePolicies(b:T.DecisionBundle,r:T.AuthorityDecisionRegistry):ReadonlyMap<string,PolicyDefinition>{
 const parsed=new Map<string,PolicyDefinition>(), identities=new Set<string>(),heads=new Map<string,string>();
 for(const evidence of b.policies){const key=`${evidence.pin.policyId}@${evidence.pin.version}`;if(identities.has(key))decisionInvalid('duplicate','/bundle/policies','Conflicting exact policy identity.');identities.add(key);if(evidence.currentHeadVersion<evidence.pin.version)decisionInvalid('version','/bundle/policies','Pinned version exceeds current head.');const head=canonicalDecisionJSON([evidence.currentHeadVersion,evidence.state]);if(heads.has(evidence.pin.policyId)&&heads.get(evidence.pin.policyId)!==head)decisionInvalid('version','/bundle/policies','Conflicting current policy head.');heads.set(evidence.pin.policyId,head);
  const result=parsePolicyFile(evidence.document,r.fields);if(!result.ok)throw new DecisionInputError(result.issues.some(i=>i.code==='limit')?'profile_limit':'invalid',result.issues[0]!);
  if(result.value.id!==evidence.pin.policyId||result.value.version!==evidence.pin.version)decisionInvalid('version','/bundle/policies','Policy document differs from its immutable pin.');
  const hash=policyHash(result.value,r.fields);if(!hash.ok)throw new DecisionInputError('invalid',hash.issues[0]!);requireEqual(hash.value,evidence.pin.hash,'/bundle/policies','Policy hash mismatch.');parsed.set(policyKey(evidence.pin),result.value);
  for(const mark of evidence.resourceWideIntents){if(mark.registryVersion!==r.version||mark.registryDigest!==r.digest)decisionInvalid('version','/bundle/policies/resourceWideIntents','Resource-wide intent uses another registry.');const rule=result.value.rules.find(x=>x.id===mark.ruleId);if(!rule||rule.effect!=='deny'||rule.fields!==null||!mark.resourceKinds.length||!mark.expandedActions.length)decisionInvalid('scope','/bundle/policies/resourceWideIntents','Invalid resource-wide deny rule.');const visit=(expr:typeof rule.when):boolean=>expr.op==='action-in'||(('children'in expr)&&expr.children.some(visit));if(visit(rule.when))decisionInvalid('scope','/bundle/policies/resourceWideIntents','Resource-wide intent cannot contain action-in.');const service=(SERVICE_ACTIONS as readonly string[]).includes(mark.expandedActions[0]!);const family=service?'service':'human';if(mark.expandedActions.some(a=>r.actions.find(x=>x.action===a)!.family!==family))decisionInvalid('scope','/bundle/policies/resourceWideIntents','Resource-wide intent cannot mix action families.');const expected=r.actions.filter(a=>a.family===family&&a.resourceKinds.some(k=>mark.resourceKinds.includes(k))).map(a=>a.action).sort();requireEqual(mark.expandedActions,expected,'/bundle/policies/resourceWideIntents','Resource-wide action expansion is incomplete.');requireEqual(rule.actions,mark.expandedActions,'/bundle/policies/resourceWideIntents','Marked rule differs from protected expansion.');}
 }
 return parsed;
}
function validateDefinitions(b:T.DecisionBundle):void{
 const heads=new Map<string,string>();
 for(const d of b.definitions){if(d.currentHeadVersion<d.version)decisionInvalid('version','/bundle/definitions','Pinned definition exceeds current head.');const content={formatVersion:d.formatVersion,kind:d.kind,id:d.id,version:d.version,content:d.content};requireEqual(d.hash,decisionHash(content),'/bundle/definitions','Definition hash mismatch.');const key=`${d.kind}:${d.id}`,head=canonicalDecisionJSON([d.currentHeadVersion,d.state]);if(heads.has(key)&&heads.get(key)!==head)decisionInvalid('version','/bundle/definitions','Conflicting current definition head.');heads.set(key,head);if(d.kind==='role'&&!d.content.policies.length)decisionInvalid('required','/bundle/definitions','Role must pin at least one policy.');}
}
function finishInput(b:T.DecisionBundle,r:T.AuthorityDecisionRegistry,admission:T.DecisionInput['admission']):T.DecisionInput{
 validateRegistry(r);tenantWalk(b,b.snapshot.tenantId,'/bundle');if(b.snapshot.registryVersion!==r.version||b.snapshot.registryDigest!==r.digest)decisionInvalid('version','/bundle/snapshot','Snapshot and registry disagree.');
 validateDefinitions(b);const parsedPolicies=validatePolicies(b,r),indexes=buildDecisionIndexes(b,r);
 const registeredFields=new Set<string>(r.fields);
 for(const grant of b.grants){for(const fields of [grant.ceiling.fields,'delegable' in grant?grant.delegable?.fields:null])if(fields)for(const field of fields)if(!registeredFields.has(field))decisionInvalid('scope','/bundle/grants','Grant field ceiling contains an unregistered field.');}

 if(!indexes.nodes.has(b.root)||indexes.nodes.get(b.root)!.mode!=='authorize')decisionInvalid('required','/bundle/root','Root must be an authorize node.');
 if(b.candidates.length!==b.nodes.length)decisionInvalid('required','/bundle/candidates','Every node requires exactly one candidate partition.');
 for(const n of b.nodes){const field=(FIELD_ACTIONS as readonly string[]).includes(n.request.action);if(field!==(n.request.field!==null))decisionInvalid('scope','/bundle/nodes','Action and field context disagree.');if(n.request.field!==null&&!r.fields.includes(n.request.field))decisionInvalid('scope','/bundle/nodes','Field is not registered.');requireEqual(n.request.resource,n.resource.requestResource,'/bundle/nodes','Resource descriptor mismatch.');requireEqual(n.request.revision,n.resource.requestedRevision,'/bundle/nodes','Revision descriptor mismatch.');const c=indexes.candidates.get(n.id);if(!c)decisionInvalid('required','/bundle/candidates','Node candidate partition is missing.');requireEqual([c.subject,c.request,c.snapshotDigest],[n.subject,n.request,b.snapshot.snapshotDigest],'/bundle/candidates','Candidate context mismatch.');requireEqual(c.anchorDigest,decisionHash({resource:n.resource.requestResource,revision:n.resource.requestedRevision,containment:n.resource.containment}),'/bundle/candidates','Candidate anchor mismatch.');for(const g of c.candidates)if(!indexes.grants.has(grantKey(g)))decisionInvalid('required','/bundle/candidates','Candidate grant is missing.');}
 for(const c of b.candidates)if(!indexes.nodes.has(c.nodeId))decisionInvalid('scope','/bundle/candidates','Unknown candidate node.');
 for(const l of b.chainLinks)if(!indexes.nodes.has(l.nodeId)||!indexes.nodes.has(l.issuerDecision)||!indexes.grants.has(grantKey(l.child))||!indexes.grants.has(grantKey(l.parent)))decisionInvalid('required','/bundle/chainLinks','Unresolved exact chain reference.');
 return Object.freeze({bundle:b,registry:r,admission,parsedPolicies,indexes});
}
export function parseDecisionInput(input:unknown,catalog:unknown):Parsed<T.DecisionInput>{
 try{const admitted=admitAuthorityInput({bundle:input,registry:catalog});if(!admitted.ok)return admitted;const data=admitted.value.data as unknown as {bundle:unknown;registry:unknown};const b=bundle(data.bundle,'/bundle') as T.DecisionBundle,r=registry(data.registry,'/registry') as T.AuthorityDecisionRegistry;const normalized=admitAuthorityInput({bundle:b,registry:r});if(!normalized.ok)return normalized;return {ok:true,value:finishInput(b,r,admitted.value.metrics)};}catch(e){return decisionFailure(e);}
}
export function parseDecisionInputFile(text:string,catalog:unknown):Parsed<T.DecisionInput>{
 const raw=parseAuthorityInputFile(text);if(!raw.ok)return raw;const result=parseDecisionInput(raw.value.data,catalog);if(!result.ok)return result;
 const rawBytes=raw.value.metrics.rawBytes!+Buffer.byteLength(canonicalDecisionJSON(result.value.registry));if(rawBytes>L.rawBytes)return {ok:false,issues:[{code:'limit',path:'',message:'Raw bundle and protected registry exceed8MiB.'}]};
 return {ok:true,value:Object.freeze({...result.value,admission:Object.freeze({...result.value.admission,rawBytes})})};
}
