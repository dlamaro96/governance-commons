// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useMemo,useState} from 'react';
import {ReactFlow,Controls,Handle,Position,MarkerType,useReactFlow,useStore,type Node,type NodeProps,type Edge} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type {LineageView,LineageNode,LineageEdge} from '../../../../packages/domain/src/lineage-contracts';
import {DetailDrawer,EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import {useResource} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission} from '../session';
import {lineageCopy} from './messages';
import {initialLineageFilters,lineageLayout,lineagePath,type LineageFilters} from './presentation';
import './lineage.css';

type GraphNode=Node<{asset:LineageNode;root:boolean},'lineage'>;
function AssetNode({data}:NodeProps<GraphNode>){
 const {locale,label,number}=useLocale(),c=lineageCopy[locale];
 return <div key={locale} className={`lineage-node ${data.root?'is-root':''}`}>
  <Handle type="target" position={locale==='ar'?Position.Right:Position.Left}/>
  <Link className="nodrag nopan" href={`/catalog/${encodeURIComponent(data.asset.id)}`}><bdi>{data.asset.name}</bdi></Link>
  <small><bdi>{data.asset.qualifiedName}</bdi></small><small>{label(data.asset.type)} · {c.version} {number(data.asset.version)}</small>
  <Link className="nodrag nopan lineage-expand" href={`/catalog/${encodeURIComponent(data.asset.id)}?tab=lineage`}>{c.title}</Link>
  <Handle type="source" position={locale==='ar'?Position.Left:Position.Right}/>
 </div>;
}
const nodeTypes={lineage:AssetNode},fitOptions={padding:.18,maxZoom:1};
function FitGraph(){
 const {fitView}=useReactFlow();
 const geometry=useStore(state=>{
  const nodes=[...state.nodeLookup.values()];
  if(!state.width||!state.height||!nodes.length||nodes.some(node=>!node.measured.width||!node.measured.height))return '';
  return `${state.width}:${state.height}:`+nodes.map(node=>`${node.id}:${node.internals.positionAbsolute.x}:${node.internals.positionAbsolute.y}:${node.measured.width}:${node.measured.height}`).join('|');
 });
 useEffect(()=>{if(!geometry)return;const frame=requestAnimationFrame(()=>{void fitView(fitOptions);});return()=>cancelAnimationFrame(frame);},[geometry,fitView]);return null;
}
function Graph({page,onSelect}:{page:LineageView;onSelect:(id:string)=>void}){
 const {locale}=useLocale(),c=lineageCopy[locale],hint=useId();
 const nodes=useMemo<GraphNode[]>(()=>{
  const layout=new Map(lineageLayout(page,locale==='ar').map(node=>[node.id,node.position]));
  return page.nodes.map(asset=>({id:asset.id,type:'lineage',position:layout.get(asset.id)!,data:{asset,root:asset.id===page.assetId},draggable:false,connectable:false,focusable:false,ariaRole:'group'}));
 },[page,locale]);
 const edges=useMemo<Edge[]>(()=>{const byId=new Map(page.nodes.map(node=>[node.id,node]));return page.edges.map(edge=>({
  id:edge.id,source:edge.upstreamAssetId,target:edge.downstreamAssetId,markerEnd:{type:MarkerType.ArrowClosed},interactionWidth:30,focusable:true,
  ariaLabel:`${c.inspect}: ${byId.get(edge.upstreamAssetId)?.name} → ${byId.get(edge.downstreamAssetId)?.name}`,
 }));},[page,c.inspect]);
 return <><p id={hint} className="supporting-text">{c.keyboard}</p><div className="lineage-canvas" role="region" aria-label={c.graph} aria-describedby={hint}>
  <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} nodesDraggable={false} nodesConnectable={false} edgesReconnectable={false} deleteKeyCode={null}
   onlyRenderVisibleElements fitView fitViewOptions={fitOptions} minZoom={.1} maxZoom={2} onEdgeClick={(_,edge)=>onSelect(edge.id)}
   ariaLabelConfig={{'controls.ariaLabel':c.controls,'controls.zoomIn.ariaLabel':c.zoomIn,'controls.zoomOut.ariaLabel':c.zoomOut,'controls.fitView.ariaLabel':c.fit,'handle.ariaLabel':c.endpoint,'node.a11yDescription.default':c.keyboard,'node.a11yDescription.keyboardDisabled':c.keyboard,'edge.a11yDescription.default':c.keyboard}}>
   <FitGraph/><Controls showInteractive={false} fitViewOptions={fitOptions}/>
  </ReactFlow>
 </div></>;
}
function DependencyTable({page,onSelect}:{page:LineageView;onSelect:(id:string)=>void}){
 const {locale,date}=useLocale(),c=lineageCopy[locale],byId=new Map(page.nodes.map(node=>[node.id,node]));
 return <div className="lineage-table-scroll"><table className="lineage-table"><caption>{c.table}</caption><thead><tr><th scope="col">{c.referenced}</th><th scope="col">{c.dependent}</th><th scope="col">{c.evidence}</th></tr></thead>
  <tbody>{page.edges.map(edge=>{const up=byId.get(edge.upstreamAssetId),down=byId.get(edge.downstreamAssetId);return <tr key={edge.id}>
   <td><Link href={`/catalog/${encodeURIComponent(edge.upstreamAssetId)}?tab=lineage`}><bdi>{up?.name}</bdi></Link><small><bdi>{up?.qualifiedName}</bdi></small></td>
   <td><Link href={`/catalog/${encodeURIComponent(edge.downstreamAssetId)}?tab=lineage`}><bdi>{down?.name}</bdi></Link><small><bdi>{down?.qualifiedName}</bdi></small></td>
   <td><button type="button" className="button secondary" aria-label={`${c.inspect}: ${up?.name} → ${down?.name}`} onClick={()=>onSelect(edge.id)}>{c.inspect}</button><small><time dateTime={edge.observation.observedAt}>{date(edge.observation.observedAt)}</time></small></td>
  </tr>;})}</tbody></table></div>;
}
function Evidence({edge,page,close}:{edge:LineageEdge;page:LineageView;close:()=>void}){
 const {locale,date,number}=useLocale(),c=lineageCopy[locale],up=page.nodes.find(node=>node.id===edge.upstreamAssetId),down=page.nodes.find(node=>node.id===edge.downstreamAssetId);
 return <DetailDrawer open onOpenChange={open=>{if(!open)close();}} title={c.evidence} description={`${up?.name} → ${down?.name}`} closeLabel={c.close}>
  <div className="lineage-evidence"><p>{c.scope}</p><div className="lineage-pair"><span>{c.referenced}: <Link href={`/catalog/${encodeURIComponent(edge.upstreamAssetId)}`}><bdi>{up?.name}</bdi></Link> · {c.observedVersion} {number(edge.upstreamVersion)}</span><span>{c.dependent}: <Link href={`/catalog/${encodeURIComponent(edge.downstreamAssetId)}`}><bdi>{down?.name}</bdi></Link> · {c.observedVersion} {number(edge.downstreamVersion)}</span></div>
   <dl className="detail-list"><div><dt>{c.method}</dt><dd>{c.methodValue}</dd></div><div><dt>{c.observed}</dt><dd><time dateTime={edge.observation.observedAt}>{date(edge.observation.observedAt)}</time></dd></div>
    <div><dt>{c.recorded}</dt><dd><time dateTime={edge.observation.recordedAt}>{date(edge.observation.recordedAt)}</time></dd></div><div><dt>{c.sourceVersion}</dt><dd><bdi>{edge.observation.sourceVersion}</bdi></dd></div><div><dt>{c.adapter}</dt><dd>{edge.observation.adapterVersion}</dd></div><div><dt>{c.confidence}</dt><dd>{c.confidenceValue}</dd></div><div><dt>{c.sourceCode}</dt><dd>{c.sourceCodeValue}</dd></div>
   </dl><p>{c.columnLimit} {c.sqlLimit}</p><details><summary>{c.technical}</summary><dl className="detail-list">
    {[[c.pointer,edge.evidencePointer],[c.hash,edge.evidenceHash],[c.observationId,edge.observation.id],[c.sourceId,edge.observation.sourceId],[c.generation,edge.observation.generation],[c.query,edge.observation.queryTemplate]].map(([name,value])=><div key={name}><dt>{name}</dt><dd className="mono"><bdi>{value}</bdi></dd></div>)}
    <div><dt>{c.attributeNumbers}</dt><dd><bdi>{edge.referencedAttributeNumbers.map(number).join(', ')||'—'}</bdi><p className="supporting-text">{c.attributeHint}</p></dd></div>
   </dl></details>
  </div>
 </DetailDrawer>;
}
function Page({assetId,filters,cursor,navigate,mode}:{assetId:string;filters:LineageFilters;cursor:string|null;navigate:(cursor:string|null)=>void;mode:'graph'|'table'}){
 const {locale}=useLocale(),c=lineageCopy[locale],resource=useResource<LineageView>(lineagePath(assetId,filters,cursor)),[selected,setSelected]=useState<string|null>(null);
 const restart=()=>{setSelected(null);if(cursor)navigate(null);else resource.reload();};
 const page=resource.data,edge=page?.edges.find(item=>item.id===selected);
 return <><div className="lineage-actions"><button type="button" className="button secondary" disabled={resource.loading} onClick={restart}>{c.refresh}</button></div>
  {resource.error?<><RequestError error={resource.error} retry={restart}/>{cursor&&<button type="button" className="button secondary" onClick={restart}>{c.restart}</button>}</>:resource.loading||!page?<LoadingState label={c.loading}/>:<>
   {page.coverage!=='COLLECTED'?<EmptyState title={c[page.coverage]} description={page.coverage==='NOT_COLLECTED'?c.notCollected:c.unsupported}/>:<>
    <p className="supporting-text">{c.COLLECTED}. {c.pageHint}</p>
    {page.gaps.length>0&&<Notice><h3>{c.gaps}</h3><ul className="lineage-gaps">{page.gaps.map(gap=><li key={`${gap.assetId}:${gap.code}`}><bdi>{page.nodes.find(node=>node.id===gap.assetId)?.name}</bdi>: {c[gap.code]}</li>)}</ul></Notice>}
    {!page.edges.length?<EmptyState title={c.empty} description={c.emptyHint}/>:mode==='graph'?<Graph page={page} onSelect={setSelected}/>:<DependencyTable page={page} onSelect={setSelected}/>}
    <p role="status" className="supporting-text">{page.nextCursor?c.more:c.last}</p>
    <nav className="lineage-actions" aria-label={c.pages}><button type="button" className="button secondary" disabled={!cursor} onClick={()=>navigate(null)}>{c.first}</button><button type="button" className="button secondary" disabled={!page.nextCursor} onClick={()=>navigate(page.nextCursor)}>{c.next}</button></nav>
    {edge&&<Evidence edge={edge} page={page} close={()=>setSelected(null)}/>}
   </>}
  </>}
 </>;
}
export function AssetLineage({assetId,assetVersion}:{assetId:string;assetVersion:number}){
 const {locale,number}=useLocale(),c=lineageCopy[locale],heading=useId(),canRead=usePermission('catalog:read');
 const [state,setState]=useState<{filters:LineageFilters;cursor:string|null}>({filters:initialLineageFilters,cursor:null}),[mode,setMode]=useState<'graph'|'table'>('graph');
 const filters=state.filters;
 const change=(patch:Partial<LineageFilters>)=>setState({filters:{...filters,...patch},cursor:null});
 return <section className="lineage-workspace" aria-labelledby={heading}>
  <header className="lineage-heading"><div><h2 id={heading}>{c.title}</h2><p>{c.intro}</p></div></header>
  <ul className="lineage-limitations"><li>{c.columnLimit}</li><li>{c.sqlLimit}</li></ul>
  {!canRead?<Notice>{c.permission}</Notice>:<>
   <div className="lineage-filters"><label className="form-field"><span>{c.direction}</span><select value={filters.direction} onChange={event=>change({direction:event.target.value as LineageFilters['direction']})}>{(['upstream','downstream','both'] as const).map(value=><option key={value} value={value}>{c[value]}</option>)}</select></label>
    <label className="form-field"><span>{c.depth}</span><select value={filters.depth} onChange={event=>change({depth:Number(event.target.value)})}>{[1,2,3,4,5,6].map(value=><option key={value} value={value}>{number(value)}</option>)}</select></label>
    <label className="form-field"><span>{c.pageSize}</span><select value={filters.limit} onChange={event=>change({limit:Number(event.target.value)})}>{[1,10,25,50,100].map(value=><option key={value} value={value}>{number(value)}</option>)}</select></label>
   </div><div className="lineage-display" role="group" aria-label={c.display}>{(['graph','table'] as const).map(value=><button key={value} type="button" className="button secondary" aria-pressed={mode===value} onClick={()=>setMode(value)}>{c[value]}</button>)}</div>
   <Page key={`${assetId}:${assetVersion}:${filters.direction}:${filters.depth}:${filters.limit}:${state.cursor??'first'}`} assetId={assetId} filters={filters} cursor={state.cursor} navigate={cursor=>setState(previous=>({...previous,cursor}))} mode={mode}/>
  </>}
 </section>;
}
