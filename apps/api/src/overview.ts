// SPDX-License-Identifier: Apache-2.0
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {requirePermission,type Principal} from '../../../packages/authz/src/index.ts';
import {auditView,visibleAssets,visibleAudit} from './repository.ts';

/** Aggregate in PostgreSQL: overview memory must not grow with catalog size.
 * Keep the canonical tenant/visibility predicates and the existing audit cap. */
export async function overviewSnapshot(tx:Tx,principal:Principal){
 const assets=await visibleAssets(tx,principal).clearSelect().select(eb=>[
  eb.fn.countAll<string>().as('assetCount'),
  eb.fn.count<string>('assets.owner_id').as('ownedCount'),
 ]).where('assets.status','=','active').executeTakeFirstOrThrow();
 let sourceCount=0,jobCount=0;
 if(principal.permissions.includes('sources:read')){
  const sources=await tx.selectFrom('sources').select(eb=>eb.fn.countAll<string>().as('count')).executeTakeFirstOrThrow();
  const jobs=await tx.selectFrom('jobs').select(eb=>eb.fn.countAll<string>().as('count')).executeTakeFirstOrThrow();
  sourceCount=Number(sources.count);jobCount=Number(jobs.count);
 }
 const recent=principal.permissions.includes('audit:read')
  ?await visibleAudit(tx,principal).orderBy('sequence','desc').limit(8).execute():[];
 return {assetCount:Number(assets.assetCount),sourceCount,ownedCount:Number(assets.ownedCount),jobCount,recentAudit:recent.map(auditView)};
}

export async function readOverview(principal:Principal){
 requirePermission(principal,'catalog:read');
 return scope(principal.tenantId,principal.id,tx=>overviewSnapshot(tx,principal));
}
