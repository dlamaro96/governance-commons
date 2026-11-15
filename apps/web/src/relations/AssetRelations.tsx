// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense, useEffect, useState } from 'react';
import type { ColumnDef } from '@tanstack/react-table';
import type { RelationTypeSummary, RelationView } from '../../../../packages/domain/src/relation-contracts';
import { DataGrid, DetailDrawer, EmptyState, LoadingState, Notice } from '../../../../packages/ui/src';
import { ApiError } from '../api';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import { RelationForm } from './RelationForm';
import { CursorControls, RelationError, RelationTypeChooser, relationPath, useCursorPage } from './shared';
const RelationGraph = lazy(()=>import('./RelationGraph').then(module=>({default:module.RelationGraph})));
export interface RelationFilters { direction:'in'|'out'|'both'; relationTypeId:string;validAt:string;depth:number }
export function AssetRelations({assetId}:{assetId:string}) {
 const{t}=useLocale();const{search,go}=useNavigation();const params=new URLSearchParams(search);
 const direction=['in','out','both'].includes(params.get('direction')||'')?params.get('direction') as RelationFilters['direction']:'both';
 const applied:RelationFilters={direction,relationTypeId:params.get('relationTypeId')||'',validAt:params.get('validAt')||'',depth:/^[1-6]$/.test(params.get('depth')||'')?Number(params.get('depth')):1};
 const[draft,setDraft]=useState<RelationFilters>(applied),[type,setType]=useState<RelationTypeSummary|null>(null),[creating,setCreating]=useState(false),[epoch,setEpoch]=useState(0);
 useEffect(()=>{setDraft(applied);setType(current=>current?.relationTypeId===applied.relationTypeId?current:null);},[search]);
 const canWrite=usePermission('catalog:write');const graph=params.get('view')==='graph';
 const listParams=new URLSearchParams({direction:applied.direction});if(applied.relationTypeId)listParams.set('relationTypeId',applied.relationTypeId);if(applied.validAt)listParams.set('validAt',applied.validAt);
 const pager=useCursorPage<RelationView>(`/assets/${assetId}/relations?${listParams}`);
 const path=(view=graph?'graph':'table',filters=applied)=>{const next=new URLSearchParams({tab:'relations',view,direction:filters.direction,depth:String(filters.depth)});if(filters.relationTypeId)next.set('relationTypeId',filters.relationTypeId);if(filters.validAt)next.set('validAt',filters.validAt);return `/catalog/${assetId}?${next}`;};
 return <section className="asset-relations"><div className="panel-heading"><h2>{t('relations')}</h2>{canWrite&&<button className="button primary" onClick={()=>setCreating(true)}>{t('relationNew')}</button>}</div><p className="supporting-text">{t('relationAssertedHint')}</p><details className="panel relation-filters"><summary>{t('relationApply')}</summary><div className="panel-body"><RelationTypeChooser selected={type} selectedId={draft.relationTypeId} allowAll onSelect={selected=>{setType(selected);setDraft({...draft,relationTypeId:selected?.relationTypeId||''});}}/>{draft.relationTypeId&&!type&&<p className="supporting-text mono break-all">{draft.relationTypeId}</p>}<form className="stacked-form" onSubmit={e=>{e.preventDefault();go(path(graph?'graph':'table',draft));pager.restart();setEpoch(n=>n+1);}}><div className="form-row"><label className="form-field"><span>{t('relationFilterDirection')}</span><select value={draft.direction} onChange={e=>setDraft({...draft,direction:e.target.value as RelationFilters['direction']})}><option value="both">{t('relationBoth')}</option><option value="out">{t('relationOutgoing')}</option><option value="in">{t('relationIncoming')}</option></select></label><label className="form-field"><span>{t('relationDepth')}</span><select value={draft.depth} onChange={e=>setDraft({...draft,depth:Number(e.target.value)})}>{[1,2,3,4,5,6].map(depth=><option key={depth} value={depth}>{depth}</option>)}</select></label></div><label className="form-field"><span>{t('relationValidAt')}</span><input dir="ltr" maxLength={24} value={draft.validAt} placeholder="2026-01-01T00:00:00.000Z" onChange={e=>setDraft({...draft,validAt:e.target.value})}/><small>{t('relationAllDates')}</small></label><button className="button secondary">{t('relationApply')}</button></form></div></details><div className="entity-tabs" role="navigation" aria-label={t('relations')}><Link className={!graph?'active':''} aria-current={!graph?'page':undefined} href={path('table')}>{t('relationTable')}</Link><Link className={graph?'active':''} aria-current={graph?'page':undefined} href={path('graph')}>{t('relationGraph')}</Link></div>{graph?<Suspense fallback={<LoadingState label={t('relationGraphLoading')}/>}><RelationGraph key={`${assetId}:${epoch}:${JSON.stringify(applied)}`} assetId={assetId} filters={applied}/></Suspense>:<><CursorControls pager={pager}/>{pager.error?<><RelationError error={pager.error}/>{pager.error instanceof ApiError&&pager.error.code==='RELATION_GRAPH_STALE'&&<Notice><button className="button secondary" onClick={pager.restart}>{t('relationGraphRestart')}</button></Notice>}</>:pager.loading?<LoadingState label={t('loading')}/>:<RelationTable rows={pager.items}/>}</>}<DetailDrawer open={creating} onOpenChange={setCreating} title={t('relationCreate')} description={t('relationEndpointHint')} closeLabel={t('close')}>{creating&&<RelationForm rootAssetId={assetId} onSaved={relation=>{setCreating(false);pager.restart();setEpoch(n=>n+1);go(relationPath(relation.id));}} onCancel={()=>setCreating(false)}/>}</DetailDrawer></section>;
}
export function RelationTable({rows,paginate=false}:{rows:readonly RelationView[];paginate?:boolean}) {
 const[index,setIndex]=useState(0),[limit,setLimit]=useState(25);const pageIndex=Math.min(index,Math.max(0,Math.ceil(rows.length/limit)-1));
 const{t,number}=useLocale();const columns:ColumnDef<RelationView>[]=[
 {id:'relation',header:t('relations'),cell:({row})=><Link className="asset-link" href={relationPath(row.original.id)}>{row.original.label}</Link>},
 {id:'source',header:t('relationSource'),cell:({row})=><Link href={`/catalog/${row.original.source.assetId}`}>{row.original.source.name}</Link>},
 {id:'target',header:t('relationTarget'),cell:({row})=><Link href={`/catalog/${row.original.target.assetId}`}>{row.original.target.name}</Link>},
 {accessorKey:'state',header:t('relationState')},
 {id:'pin',header:t('relationTypePin'),cell:({row})=><span>{row.original.relationTypeKey} · {number(row.original.relationTypeVersion)}</span>},
 {id:'validity',header:t('relationValidFrom'),cell:({row})=><span className="mono">{row.original.validFrom||'−∞'} → {row.original.validTo||'+∞'}</span>},
 {id:'origin',header:t('provenance'),cell:()=>t('relationAsserted')},
 ];
 return <section className="panel relation-table">{paginate&&<CursorControls pager={{limit,page:pageIndex+1,previous:pageIndex>0,next:(pageIndex+1)*limit<rows.length,loading:false,setLimit:n=>{setLimit(n);setIndex(0);},prevPage:()=>setIndex(Math.max(0,pageIndex-1)),nextPage:()=>setIndex(pageIndex+1)}}/>}<DataGrid caption={t('relationTable')} columns={columns} data={paginate?rows.slice(pageIndex*limit,(pageIndex+1)*limit):[...rows]} empty={<EmptyState title={t('relationNoEdges')} description={t('relationNoEdgesBody')}/>}/></section>;
}
