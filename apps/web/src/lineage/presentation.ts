// SPDX-License-Identifier: Apache-2.0
import type {LineageView,LineageQuery} from '../../../../packages/domain/src/lineage-contracts.ts';
export type LineageFilters=Required<Pick<LineageQuery,'direction'|'depth'|'limit'>>;
export const initialLineageFilters:LineageFilters={direction:'both',depth:1,limit:25};
export function lineagePath(assetId:string,filters:LineageFilters,cursor:string|null=null):string {
 const params=new URLSearchParams({direction:filters.direction,depth:String(filters.depth),limit:String(filters.limit)});
 if(cursor!==null)params.set('cursor',cursor);
 return `/assets/${encodeURIComponent(assetId)}/lineage?${params}`;
}
/** Layout only the current authorized page. Cycles/self-dependencies retain their
 * actual edges; a visited set bounds traversal without inventing a DAG. */
export function lineageLayout(page:Pick<LineageView,'assetId'|'nodes'|'edges'>,rtl=false){
 const nodes=[...page.nodes].sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:a.id<b.id?-1:a.id>b.id?1:0);
 const known=new Set(nodes.map(n=>n.id)),levels=new Map<string,number>([[page.assetId,0]]),queue=[page.assetId];
 const neighbors=new Map<string,{id:string;offset:number}[]>();
 for(const edge of page.edges){
  if(!known.has(edge.upstreamAssetId)||!known.has(edge.downstreamAssetId))continue;
  const up=neighbors.get(edge.upstreamAssetId)??[],down=neighbors.get(edge.downstreamAssetId)??[];
  up.push({id:edge.downstreamAssetId,offset:1});neighbors.set(edge.upstreamAssetId,up);
  down.push({id:edge.upstreamAssetId,offset:-1});neighbors.set(edge.downstreamAssetId,down);
 }
 for(let index=0;index<queue.length;index++)for(const next of neighbors.get(queue[index])??[]){
  if(levels.has(next.id))continue;levels.set(next.id,levels.get(queue[index])!+next.offset);queue.push(next.id);
 }
 const columns=new Map<number,number>();
 return nodes.map(node=>{const level=levels.get(node.id)??0,row=columns.get(level)??0;columns.set(level,row+1);
  return {id:node.id,position:{x:level*320*(rtl?-1:1),y:row*154}};
 });
}
