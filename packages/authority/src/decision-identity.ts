// SPDX-License-Identifier: Apache-2.0
import { admitAuthorityInput } from './admission.ts';
import type { Digest, Parsed } from './types.ts';
import type { AuthorityDecisionRegistry, DecisionCatalogs, DecisionInput, DefinitionEvidence, NodeDescriptor, NodeId, ResourceEvidence, SnapshotRef } from './decision-types.ts';
import { selectNodeEvidence } from './decision-context.ts';
import { decisionShapes, decisionHash, decisionFailure, decisionInvalid, validateRegistry } from './decision-schema.ts';

function admitted(value:unknown):unknown {
  const result=admitAuthorityInput(value);if(!result.ok)decisionInvalid(result.issues[0]!.code,result.issues[0]!.path,result.issues[0]!.message);return result.value.data;
}
export function hashAuthorityRegistry(input:Omit<AuthorityDecisionRegistry,'digest'>):Parsed<Digest>{
 try{const content=decisionShapes.registryContent(admitted(input),'') as Omit<AuthorityDecisionRegistry,'digest'>;const digest=decisionHash(content);validateRegistry({...content,digest});return {ok:true,value:digest};}catch(error){return decisionFailure(error);}
}
export function hashAuthorityDefinition(input:Pick<DefinitionEvidence,'formatVersion'|'kind'|'id'|'version'|'content'>):Parsed<Digest>{
 try{const definition=decisionShapes.definitionContent(admitted(input),'') as Pick<DefinitionEvidence,'formatVersion'|'kind'|'id'|'version'|'content'>;if(definition.kind==='role'&&'policies'in definition.content&&!definition.content.policies.length)decisionInvalid('required','/content/policies','Role requires an exact policy pin.');return {ok:true,value:decisionHash(definition)};}catch(error){return decisionFailure(error);}
}
function anchor(resource:ResourceEvidence):Digest{return decisionHash({resource:resource.requestResource,revision:resource.requestedRevision,containment:resource.containment});}
export function authorityAnchorDigest(input:ResourceEvidence):Parsed<Digest>{
 try{const resource=decisionShapes.resourceEvidence(admitted(input),'') as ResourceEvidence;return {ok:true,value:anchor(resource)};}catch(error){return decisionFailure(error);}
}
function identity(snapshot:SnapshotRef,node:NodeDescriptor,catalogs:DecisionCatalogs,registry:AuthorityDecisionRegistry,origin:NodeDescriptor|null):{nodeId:NodeId;factDigest:Digest}{
 const factDigest=decisionHash(selectNodeEvidence(snapshot,node,catalogs,registry,origin));
 const projectionIdentity=node.projection===null?null:((({prerequisites:_p,sensitiveDecision:_s,...rest})=>rest)(node.projection));
 const serviceIdentity=node.service!==null&&'initiatingDecision'in node.service?((({initiatingDecision:_i,...rest})=>rest)(node.service)):node.service;
 const nodeId=decisionHash({snapshot,mode:node.mode,subject:node.subject,request:node.request,authentication:node.authentication,adapterId:node.adapterId,resource:node.resource,purpose:node.purpose,environment:node.environment,factDigest,projectionIdentity,serviceIdentity});
 return {nodeId,factDigest};
}
export function authorityNodeIdentity(snapshotInput:SnapshotRef,nodeInput:NodeDescriptor,catalogsInput:DecisionCatalogs,registryInput:AuthorityDecisionRegistry,originInput:NodeDescriptor|null):Parsed<{nodeId:NodeId;factDigest:Digest}>{
 try{
  const envelope=admitted({snapshot:snapshotInput,node:nodeInput,catalogs:catalogsInput,registry:registryInput,origin:originInput}) as Record<string,unknown>;
  const snapshot=decisionShapes.snapshot(envelope.snapshot,'/snapshot') as SnapshotRef,node=decisionShapes.nodeDescriptor(envelope.node,'/node') as NodeDescriptor,catalogs=decisionShapes.catalogs(envelope.catalogs,'/catalogs') as DecisionCatalogs,registry=decisionShapes.registry(envelope.registry,'/registry') as AuthorityDecisionRegistry,origin=envelope.origin===null?null:decisionShapes.nodeDescriptor(envelope.origin,'/origin') as NodeDescriptor;
  validateRegistry(registry);if(snapshot.registryDigest!==registry.digest||snapshot.registryVersion!==registry.version)decisionInvalid('version','/snapshot','Snapshot registry differs from protected registry.');
  return {ok:true,value:identity(snapshot,node,catalogs,registry,origin)};
 }catch(error){return decisionFailure(error);}
}
/** Internal post-schema stage; public evaluate always admits before calling this. */
export function validateDecisionIdentities(input:DecisionInput):void{
 const {formatVersion:_f,snapshot,root:_r,nodes:_n,candidates:_c,chainLinks:_l,...catalogs}=input.bundle;
 for(const node of input.bundle.nodes){
  const {id,factDigest,...descriptor}=node;
  let origin:NodeDescriptor|null=null;
  if(node.mode==='resource-wide-deny'){
   const original=node.guardOrigin===null?undefined:input.indexes.nodes.get(node.guardOrigin);
   if(!original||original.mode!=='authorize'||original.intentGuard!==id)decisionInvalid('scope','/nodes','Guard origin must be a reciprocal authorize node.');
   const {id:_oid,factDigest:_ofd,...rest}=original;origin=rest;
  }
  const expected=identity(snapshot,descriptor,catalogs,input.registry,origin);
  if(id!==expected.nodeId||factDigest!==expected.factDigest)decisionInvalid('version','/nodes','Canonical node identity or selected fact digest mismatch.');
 }
}
