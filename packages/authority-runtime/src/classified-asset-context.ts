// SPDX-License-Identifier: Apache-2.0
// Private provenance only. A parsed envelope never authorizes a later effect.
import {AUTHORITY_ADMISSION_LIMITS as limits} from '../../authority/src/admission.ts';
import {decisionFailure, decisionHash, canonicalDecisionJSON} from '../../authority/src/decision-schema.ts';
import type {ApprovedSetFact, Fact, FactRef} from '../../authority/src/decision-types.ts';
import type {Counter, Digest, Parsed, UTC, UUID, Version} from '../../authority/src/types.ts';
import {admitted, array, counter, digest, equal, fail, literal, nullable, ref, shape, utc, uuid, version, type Validator} from '../../authority-storage/src/shape.ts';
import {parseVersionedHumanAssetContext, type VersionedHumanAssetContext} from './versioned-asset-context.ts';

export type ReviewedClassificationProducerBinding = {
 readonly installationId: UUID; readonly version: Version; readonly operation: 'bind'|'revoke';
 readonly implementation: 'reviewed-metadata-classification-v1';
 readonly producer: {readonly id:UUID; readonly version:Version};
 readonly authorityEpochAfter: Counter; readonly manifestHash: Digest;
};
export type ReviewedClassificationProducerSnapshot = {
 readonly formatVersion:1; readonly tenantId:UUID; readonly generation:Counter; readonly authorityEpoch:Counter;
 readonly registryId:UUID; readonly registryVersion:Version; readonly registryDigest:Digest; readonly asOf:UTC;
 readonly binding:ReviewedClassificationProducerBinding|null;
};
export type InactiveClassifiedAssetContext = {
 readonly formatVersion:1; readonly kind:'inactive-classified-asset-context'; readonly contentAuthority:false;
 readonly context:VersionedHumanAssetContext; readonly producerBinding:ReviewedClassificationProducerBinding|null;
 readonly classifications:Fact<readonly FactRef[]>; readonly approvedFacts:readonly ApprovedSetFact[];
 readonly contextDigest:Digest;
};
const zero='0'.repeat(64) as Digest;
const binding=shape({installationId:uuid,version,operation:literal('bind','revoke'),implementation:literal('reviewed-metadata-classification-v1'),producer:ref,authorityEpochAfter:counter,manifestHash:digest});
const snapshotShape=shape({formatVersion:literal(1),tenantId:uuid,generation:counter,authorityEpoch:counter,registryId:uuid,registryVersion:version,registryDigest:digest,asOf:utc,binding:nullable(binding)});
const factKey=(v:unknown)=>{const r=v as FactRef;return `${r.id}@${r.version}`;};
const partition:Validator=(v,p)=>{
 if(v!==null&&typeof v==='object'&&!Array.isArray(v)&&(v as Record<string,unknown>).status==='unavailable')return shape({status:literal('unavailable')})(v,p);
 return shape({status:literal('known'),value:array(ref,factKey,256)})(v,p);
};
const fact=shape({ref,kind:literal('classifications'),provenance:shape({producer:ref,tenantId:uuid,registryDigest:digest,sourceRecordId:uuid,sourceRecordVersion:version}),
 resource:shape({tenantId:uuid,kind:literal('asset'),id:uuid}),revision:version,fieldId:literal(null),securityRevision:counter,state:literal('approved'),
 validity:shape({notBefore:utc,expiresAt:literal(null)}),values:array(uuid,v=>v as string,1)});
const envelope=shape({formatVersion:literal(1),kind:literal('inactive-classified-asset-context'),contentAuthority:literal(false),context:v=>v,
 producerBinding:nullable(binding),classifications:partition,approvedFacts:array(fact,v=>factKey((v as ApprovedSetFact).ref),256),contextDigest:digest});

export function parseReviewedClassificationProducerSnapshot(value:unknown):Parsed<ReviewedClassificationProducerSnapshot>{
 try{
  const out=snapshotShape(admitted(value).data,'') as ReviewedClassificationProducerSnapshot;
  if(out.binding&&BigInt(out.binding.authorityEpochAfter)>BigInt(out.authorityEpoch))fail('Producer installation exceeds current authority epoch.');
  return {ok:true,value:out};
 }catch(error){return decisionFailure(error);}
}

/** Validate even a known-empty partition against its explicitly installed
 * producer. Registry registration alone is not installation consent. */
export function reviewedClassificationProducerAvailable(context:VersionedHumanAssetContext,selected:ReviewedClassificationProducerBinding|null):boolean{
 if(selected===null)return false;
 const {registry,closure}=context.context;
 if(BigInt(selected.authorityEpochAfter)>BigInt(closure.snapshot.authorityEpoch))fail('Producer installation exceeds current authority epoch.');
 const matches=registry.producers.filter(p=>p.ref.id===selected.producer.id&&p.ref.version===selected.producer.version);
 if(matches.length!==1)fail('Installed classification producer registration is missing or ambiguous.');
 const producer=matches[0]!;
 if(producer.kind!=='classifications'||producer.tenantId!==closure.snapshot.tenantId)fail('Installed classification producer registration differs.');
 const asOf=closure.snapshot.asOf;
 return selected.operation==='bind'&&producer.state==='active'&&(producer.validity.notBefore===null||producer.validity.notBefore<=asOf)
  &&(producer.validity.expiresAt===null||asOf<producer.validity.expiresAt);
}

export function parseInactiveClassifiedAssetContext(value:unknown):Parsed<InactiveClassifiedAssetContext>{
 try{
  // Admission of the entire outer envelope precedes nested validation. Inner
  // parser admission cannot expand this shared byte/node/depth allowance.
  const out=envelope(admitted(value).data,'') as InactiveClassifiedAssetContext;
  const parsed=parseVersionedHumanAssetContext(out.context);if(!parsed.ok)return parsed;
  equal(out.context,parsed.value,'Classified context must retain its canonical inner envelope.');
  const result=Object.freeze({...out,context:parsed.value}),inner=result.context.context;
  const available=reviewedClassificationProducerAvailable(result.context,result.producerBinding);
  if(result.classifications.status==='unavailable'){
   if(result.approvedFacts.length)fail('Unavailable classifications cannot expose a partial fact set.');
  }else{
   if(!available)fail('Known classifications require an available installed producer.');
   equal(result.classifications.value,result.approvedFacts.map(f=>f.ref),'Classification references must cover exactly the emitted facts.');
  }
  if(Buffer.byteLength(canonicalDecisionJSON(result.approvedFacts))>limits.factBytes)fail('Classification facts exceed the declared byte profile.','limit');
  for(const f of result.approvedFacts){
   equal(f.provenance.producer,result.producerBinding!.producer,'Fact producer differs from installation.');
   equal([f.provenance.tenantId,f.resource.tenantId,f.resource.id,f.revision,f.securityRevision],
    [inner.asset.tenantId,inner.asset.tenantId,inner.asset.id,inner.asset.version,result.context.securityRevision],'Fact target differs from the current asset snapshot.');
   equal([f.provenance.sourceRecordId,f.provenance.sourceRecordVersion,f.provenance.registryDigest],
    [f.ref.id,f.ref.version,inner.registry.digest],'Fact source or registry pin differs.');
   if(f.values.length!==1||f.validity.notBefore===null||f.validity.notBefore>inner.closure.snapshot.asOf)fail('Fact label or publication timestamp differs.');
   if(inner.asset.status!=='active')fail('Active classification facts require an active asset.');
  }
  equal(result.contextDigest,decisionHash({...result,contextDigest:zero}),'Classified asset context digest differs.');
  return {ok:true,value:result};
 }catch(error){return decisionFailure(error);}
}
