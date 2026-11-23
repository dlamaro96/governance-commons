// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {lineageLayout,lineagePath,initialLineageFilters} from '../../apps/web/src/lineage/presentation.ts';
import {lineageCopy} from '../../apps/web/src/lineage/messages.ts';
import type {LineageNode,LineageView} from '../../packages/domain/src/lineage-contracts.ts';
const node=(id:string,name=id):LineageNode=>({id,name,qualifiedName:`harbor.public.${name}`,type:'view',version:1});
const page=(assetId:string,nodes:LineageNode[],pairs:[string,string][])=>({assetId,nodes,edges:pairs.map(([upstreamAssetId,downstreamAssetId],i)=>({id:`edge-${i}`,upstreamAssetId,downstreamAssetId}))}) as Pick<LineageView,'assetId'|'nodes'|'edges'>;
test('lineage requests bind every selected filter and escape opaque cursor and asset path',()=>{
 assert.equal(lineagePath('a/b',initialLineageFilters),'/assets/a%2Fb/lineage?direction=both&depth=1&limit=25');
 const result=new URL(lineagePath('root',{direction:'upstream',depth:6,limit:1},'signed+/=?&cursor=forged'),'https://example.invalid');
 assert.equal(result.searchParams.get('direction'),'upstream');assert.equal(result.searchParams.get('depth'),'6');assert.equal(result.searchParams.get('limit'),'1');
 assert.deepEqual(result.searchParams.getAll('cursor'),['signed+/=?&cursor=forged']);assert.equal([...result.searchParams].length,4);
 assert.equal(new URL(lineagePath('root',{direction:'downstream',depth:2,limit:100}),'https://example.invalid').searchParams.has('cursor'),false);
});
test('lineage positions preserve real upstream/downstream orientation and mirror RTL without changing identities',()=>{
 const graph=page('root',[node('down'),node('root'),node('up')],[['up','root'],['root','down']]),copy=JSON.stringify(graph);
 const ltr=new Map(lineageLayout(graph).map(n=>[n.id,n.position])),rtl=new Map(lineageLayout(graph,true).map(n=>[n.id,n.position]));
 assert.ok(ltr.get('up')!.x<ltr.get('root')!.x);assert.ok(ltr.get('root')!.x<ltr.get('down')!.x);
 for(const id of ['up','root','down']){assert.equal(rtl.get(id)!.x,-ltr.get(id)!.x);assert.equal(rtl.get(id)!.y,ltr.get(id)!.y);}
 assert.equal(JSON.stringify(graph),copy);
});
test('cycles and recursive self-dependencies terminate with one position per admitted node',()=>{
 const graph=page('a',[node('a'),node('b'),node('c')],[['a','a'],['a','b'],['b','c'],['c','a']]);
 const positions=lineageLayout(graph);assert.equal(positions.length,3);assert.equal(new Set(positions.map(n=>n.id)).size,3);
 assert.ok(positions.every(n=>Number.isFinite(n.position.x)&&Number.isFinite(n.position.y)));assert.equal(graph.edges.length,4);
});
test('only current page nodes are materialized; disconnected components and duplicate names retain separate stable identities',()=>{
 const nodes=[node('b','same'),node('a','same'),node('root'),node('c','same')],graph=page('root',nodes,[['unreturned','root'],['a','b']]);
 const result=lineageLayout(graph);assert.deepEqual(result.map(n=>n.id),['root','a','b','c']);assert.equal(result.some(n=>n.id==='unreturned'),false);
 assert.equal(new Set(result.map(n=>`${n.position.x}:${n.position.y}`)).size,4);assert.deepEqual(result,lineageLayout({...graph,nodes:[...nodes].reverse()}));
});
test('maximum page-sized cyclic input stays finite without mutating evidence or pretending to be acyclic',()=>{
 const nodes=Array.from({length:101},(_,i)=>node(String(i))),pairs:[string,string][]=Array.from({length:100},(_,i)=>[String(i),String((i+1)%100)]);
 const graph=page('0',nodes,pairs),frozen=JSON.stringify(graph);assert.equal(lineageLayout(graph).length,101);assert.equal(JSON.stringify(graph),frozen);
});
test('English and Arabic preserve explicit collection gaps and unavailable column/SQL evidence',()=>{
 assert.deepEqual(Object.keys(lineageCopy.ar).sort(),Object.keys(lineageCopy.en).sort());
 for(const copy of Object.values(lineageCopy))for(const key of ['COLLECTED','NOT_COLLECTED','UNSUPPORTED','OPAQUE_ROUTINE_DEPENDENCY','OUT_OF_SCOPE_RELATION','UNSUPPORTED_RELATION_KIND','columnLimit','sqlLimit','confidenceValue','attributeHint'] as const)assert.ok(copy[key].length>0);
 assert.match(lineageCopy.en.columnLimit,/not been collected/);assert.match(lineageCopy.en.sqlLimit,/not been analyzed/);assert.match(lineageCopy.en.emptyHint,/does not establish/);
});
