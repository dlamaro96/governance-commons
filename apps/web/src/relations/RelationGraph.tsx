// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from 'react';
import { ReactFlow, Controls, Handle, Position, MarkerType, useReactFlow, useStore, type Node, type NodeProps, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { RelationEndpointView, RelationGraphPage, RelationView } from '../../../../packages/domain/src/relation-contracts';
import { LoadingState, Notice } from '../../../../packages/ui/src';
import { api, ApiError } from '../api';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { RelationError, relationPath } from './shared';
import { RelationTable, type RelationFilters } from './AssetRelations';

type AssetNode=Node<{endpoint:RelationEndpointView;expandHref:string;root:boolean},'asset'>;
// Replace stateless localized content when direction changes so transformed
// graph layers repaint the current glyphs without resetting the graph camera.
function AssetNodeView({data}:NodeProps<AssetNode>){const{t,locale}=useLocale();return <div key={locale} className={`relation-graph-node ${data.root?'is-root':''}`}><Handle type="target" position={Position.Left}/><Link className="nodrag nopan" href={`/catalog/${data.endpoint.assetId}`}>{data.endpoint.name}</Link><span><bdi>{data.endpoint.modelId||t('notSet')}</bdi> · {data.endpoint.modelVersion||'—'}</span><Link className="nodrag nopan relation-expand-link" href={data.expandHref}>{t('relationExpand')}</Link><Handle type="source" position={Position.Right}/></div>;}
const nodeTypes={asset:AssetNodeView};
const fitOptions={padding:0.12,maxZoom:1};
// Fit after measured node/layout or canvas size changes, never on ordinary
// renders or user pan/zoom. React Flow's initial fit alone does not handle resize.
function FitGraph() {
 const{fitView}=useReactFlow();
 // Controlled nodes and the viewport commit to the flow store asynchronously.
 // Observe their committed geometry instead of fitting against previous props.
 const geometry=useStore(state=>{
  const nodes=[...state.nodeLookup.values()];
  if(!state.width||!state.height||!nodes.length||nodes.some(node=>!node.measured.width||!node.measured.height))return '';
  return `${state.width}:${state.height}:`+nodes.map(node=>`${node.id}:${node.internals.positionAbsolute.x}:${node.internals.positionAbsolute.y}:${node.measured.width}:${node.measured.height}`).join('|');
 });
 useEffect(()=>{if(!geometry)return;const frame=requestAnimationFrame(()=>{void fitView(fitOptions);});return()=>cancelAnimationFrame(frame);},[geometry,fitView]);
 return null;
}
function GraphCanvas({page,assetId,filters,onSelect}:{page:RelationGraphPage;assetId:string;filters:RelationFilters;onSelect:(relation:RelationView|null)=>void}) {
 const{t}=useLocale();const[canvas,setCanvas]=useState<HTMLDivElement|null>(null);const[size,setSize]=useState({width:0,height:0});
 useEffect(()=>{if(!canvas)return;const observer=new ResizeObserver(([entry])=>{if(entry)setSize(previous=>previous.width===entry.contentRect.width&&previous.height===entry.contentRect.height?previous:{width:entry.contentRect.width,height:entry.contentRect.height});});observer.observe(canvas);return()=>observer.disconnect();},[canvas]);
 const columns=size.width>640?Math.max(1,Math.ceil(Math.sqrt(page.nodes.length))):1;
 const nodes=useMemo<AssetNode[]>(()=>page.nodes.map((endpoint,index)=>{const params=new URLSearchParams({tab:'relations',view:'graph',direction:filters.direction,depth:String(filters.depth)});if(filters.relationTypeId)params.set('relationTypeId',filters.relationTypeId);params.set('validAt',page.validAt);return{id:endpoint.assetId,type:'asset',position:{x:(index%columns)*320,y:Math.floor(index/columns)*160},data:{endpoint,root:endpoint.assetId===assetId,expandHref:`/catalog/${endpoint.assetId}?${params}`},draggable:false,connectable:false,focusable:false,ariaRole:'group'};}),[page,assetId,filters,columns]);
 const edges=useMemo<Edge[]>(()=>page.edges.map(edge=>({id:edge.id,source:edge.source.assetId,target:edge.target.assetId,label:edge.label,focusable:true,ariaLabel:`${edge.source.name} ${edge.label} ${edge.target.name}`,markerEnd:edge.direction==='directed'?{type:MarkerType.ArrowClosed}:undefined,interactionWidth:30})),[page]);
 return <div ref={setCanvas} className="relation-graph-canvas" role="region" aria-label={t('relationGraph')} aria-describedby="relation-graph-keyboard"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onlyRenderVisibleElements nodesDraggable={false} nodesConnectable={false} edgesReconnectable={false} deleteKeyCode={null} fitView fitViewOptions={fitOptions} minZoom={0.2} maxZoom={2} onEdgeClick={(_,edge)=>onSelect(page.edges.find(item=>item.id===edge.id)||null)} ariaLabelConfig={{'controls.ariaLabel':t('relationGraphControls'),'handle.ariaLabel':t('relationGraphEndpoint'),'node.a11yDescription.default':t('relationGraphKeyboard'),'node.a11yDescription.keyboardDisabled':t('relationGraphKeyboard'),'edge.a11yDescription.default':t('relationGraphKeyboard'),'controls.zoomIn.ariaLabel':t('relationZoomIn'),'controls.zoomOut.ariaLabel':t('relationZoomOut'),'controls.fitView.ariaLabel':t('relationFit')}}><FitGraph/><Controls showInteractive={false} fitViewOptions={fitOptions}/></ReactFlow></div>;
}
export function RelationGraph({assetId,filters}:{assetId:string;filters:RelationFilters}) {
 const{t,number}=useLocale();const[pageSize,setPageSize]=useState(100);const[page,setPage]=useState<RelationGraphPage|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null),[selected,setSelected]=useState<RelationView|null>(null);
 const controller=useRef<AbortController|null>(null);const serial=useRef(0);
 async function load(more=false){controller.current?.abort();const abort=new AbortController();controller.current=abort;const request=++serial.current;setBusy(true);setError(null);setSelected(null);if(!more)setPage(null);
  const params=new URLSearchParams({direction:filters.direction,depth:String(filters.depth),limit:String(pageSize)});if(filters.relationTypeId)params.set('relationTypeId',filters.relationTypeId);const instant=more?page?.validAt:filters.validAt;if(instant)params.set('validAt',instant);if(more&&page?.nextCursor)params.set('cursor',page.nextCursor);
  try{const result=await api<RelationGraphPage>(`/assets/${assetId}/graph?${params}`,{signal:abort.signal});if(request!==serial.current)return;if(more&&page&&page.graphRevision!==result.graphRevision)throw new ApiError(409,{code:'RELATION_GRAPH_STALE'});setPage(more&&page?{...result,nodes:[...new Map([...page.nodes,...result.nodes].map(node=>[node.assetId,node])).values()],edges:[...new Map([...page.edges,...result.edges].map(edge=>[edge.id,edge])).values()]}:result);}catch(e){if(request!==serial.current||abort.signal.aborted)return;setPage(null);setError(e as Error);}finally{if(request===serial.current)setBusy(false);}}
 useEffect(()=>{void load();return()=>{controller.current?.abort();serial.current++;};},[assetId,filters.direction,filters.depth,filters.relationTypeId,filters.validAt,pageSize]);
 return <section className="relation-graph-section"><div className="panel-heading"><h2>{t('relationGraph')}</h2><button className="button secondary" disabled={busy} onClick={()=>load()}>{t('relationGraphRestart')}</button></div><p className="supporting-text">{t('relationGraphHint')}</p><label className="form-field"><span>{t('relationGraphPageSize')}</span><select value={pageSize} disabled={busy} onChange={event=>setPageSize(Number(event.target.value))}>{[1,25,50,100].map(size=><option key={size} value={size}>{number(size)}</option>)}</select></label>{error&&<RelationError error={error}/>} {busy?<LoadingState label={t('relationGraphLoading')}/>:page&&<><dl className="detail-list"><div><dt>{t('relationGraphInstant')}</dt><dd><time dateTime={page.validAt}>{page.validAt}</time></dd></div><div><dt>{t('relationGraphRows')}</dt><dd>{number(page.edges.length)}</dd></div></dl><p className="supporting-text" id="relation-graph-keyboard">{t('relationGraphKeyboard')}</p><GraphCanvas page={page} assetId={assetId} filters={filters} onSelect={setSelected}/>{selected&&<Notice><span>{t('relationGraphSelection')}: </span><Link href={relationPath(selected.id)}>{selected.source.name} · {selected.label} · {selected.target.name}</Link></Notice>}<p role="status" className="supporting-text">{t(page.nextCursor?'relationGraphPartial':'relationGraphComplete')}</p>{page.nextCursor&&<button className="button secondary" disabled={busy} onClick={()=>load(true)}>{t('relationGraphMore')}</button>}<RelationTable rows={page.edges} paginate/></>}</section>;
}
