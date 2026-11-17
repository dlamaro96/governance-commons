// SPDX-License-Identifier: Apache-2.0
import type {CrosswalkMapping,HierarchyEdge} from '../../../../../packages/domain/src/reference-structure-contracts.ts';
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;
const interval=(a:HierarchyEdge|CrosswalkMapping,b:HierarchyEdge|CrosswalkMapping)=>compare(a.validFrom??'',b.validFrom??'')||compare(a.validUntil??'\uffff',b.validUntil??'\uffff');
/** Form-owned rows only. No deduplication: the service must reject conflicting
 * rows, rather than silently discard a relationship the author supplied. */
export const previewEdges=(rows:readonly HierarchyEdge[]):HierarchyEdge[]=>rows.map(row=>({...row})).sort((a,b)=>compare(a.parentCode,b.parentCode)||compare(a.childCode,b.childCode)||interval(a,b));
export const previewMappings=(rows:readonly CrosswalkMapping[]):CrosswalkMapping[]=>rows.map(row=>({...row,methodDetails:row.methodDetails.normalize('NFC').trim(),transformationNotes:row.transformationNotes.normalize('NFC').trim(),confidence:row.confidence.kind==='declared'?{...row.confidence,basis:row.confidence.basis.normalize('NFC').trim()}:{...row.confidence}})).sort((a,b)=>compare(a.sourceCode,b.sourceCode)||compare(a.targetCode,b.targetCode)||interval(a,b));

/** Preserve the authored query binding: a Now cursor already retains its first
 * resolved instant; switching null into an explicit asOf would invalidate it. */
export function effectivePath(id:string,asOf:string|null,cursor:string|null){return '/reference-data/structures/'+id+'/effective?limit=25'+(asOf?'&asOf='+encodeURIComponent(asOf):'')+(cursor?'&cursor='+encodeURIComponent(cursor):'');}
