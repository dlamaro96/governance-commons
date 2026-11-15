// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {stableString} from './repository.ts';
export function verifyAuditChain(rows:any[]){
 let previous='0'.repeat(64);
 for(const row of rows){
  const {resourceVersion,...changes}=row.changes;
  const reconstructed={id:row.id,tenantId:row.tenant_id,actorId:row.actor_id,actorName:row.actor_name,action:row.action,resourceId:row.resource_id,version:resourceVersion,changes,correlationId:row.correlation_id,occurredAt:new Date(row.occurred_at).toISOString(),previousHash:row.previous_hash};
  const envelope=row.envelope??reconstructed;
  if(stableString(envelope)!==stableString(reconstructed)||row.previous_hash!==previous||createHash('sha256').update(stableString(envelope)).digest('hex')!==row.hash)return {valid:false,checked:rows.indexOf(row),failedId:row.id,reason:'CHAIN_MISMATCH'};
  previous=row.hash;
 }
 return {valid:true,checked:rows.length,head:previous,limitations:['Local hash chains are tamper-evident, not tamper-proof. External signed checkpoints are not implemented.']};
}
