// SPDX-License-Identifier: Apache-2.0
import {useId,useState} from 'react';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import type {AssetGlossaryContextPage} from '../../../../packages/domain/src/glossary-context-contracts';
import {useResource} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission} from '../session';
import {glossaryCopy} from './glossary-copy';
import './glossary.css';

/** Each page is a fresh authorized summary, not the term's full publication.
 * A locale or asset-version change discards the old bound cursor and content. */
export function AssetGlossaryContext({assetId,assetVersion}:{assetId:string;assetVersion:number}){
 const {locale}=useLocale(),c=glossaryCopy[locale],heading=useId();
 const canRead=usePermission('catalog:read'),canModels=usePermission('models:read');
 return <section className="panel asset-glossary-context" aria-labelledby={heading}>
  <header className="panel-heading"><div><h2 id={heading}>{c.context}</h2><p>{c.contextHint}</p></div></header>
  <div className="panel-body">{!canRead||!canModels?<Notice>{c.contextPermission}</Notice>:<ContextPages key={`${assetId}:${assetVersion}:${locale}`} assetId={assetId} locale={locale}/>}</div>
 </section>;
}
function ContextPages({assetId,locale}:{assetId:string;locale:'en'|'ar'}){
 const [cursor,setCursor]=useState<string|null>(null);
 return <ContextPage key={cursor??'first'} assetId={assetId} locale={locale} cursor={cursor} navigate={setCursor}/>;
}
function ContextPage({assetId,locale,cursor,navigate}:{assetId:string;locale:'en'|'ar';cursor:string|null;navigate:(cursor:string|null)=>void}){
 const c=glossaryCopy[locale],{number}=useLocale(),params=new URLSearchParams({locale,limit:'10'});
 if(cursor)params.set('cursor',cursor);
 const resource=useResource<AssetGlossaryContextPage>(`/assets/${encodeURIComponent(assetId)}/glossary-context?${params}`);
 return <>
  <div className="asset-glossary-context-actions"><button type="button" className="button secondary" disabled={resource.loading} onClick={resource.reload}>{c.refreshContext}</button></div>
  {resource.error?<RequestError error={resource.error} retry={resource.reload} compact/>:resource.loading||!resource.data?<LoadingState label={c.loading}/>:<>
   {resource.data.items.length?<ul className="asset-glossary-context-list">{resource.data.items.map(item=><li key={`${item.termId}:${item.relationId}`}>
    <h3 lang={item.locale} dir="auto"><Link href={`/catalog/${encodeURIComponent(item.termId)}`}>{item.name}</Link></h3>
    <p className="glossary-value" lang={item.locale} dir="auto">{item.definition}</p>
    <dl className="asset-glossary-context-meta"><div><dt>{c.version}</dt><dd>{number(item.termVersion)}</dd></div><div><dt>{c.state}</dt><dd><bdi>{item.state==='active'?c.active:item.state==='deprecated'?c.deprecated:item.state}</bdi></dd></div><div><dt>{c.locale}</dt><dd><bdi>{item.locale}</bdi>{item.locale!==locale&&<span> · {c.contextFallback}</span>}</dd></div></dl>
   </li>)}</ul>:<EmptyState title={c.contextEmpty} description={c.contextEmptyBody}/>}
   <nav className="glossary-page-controls" aria-label={c.contextPages}><button type="button" className="button secondary" disabled={!cursor} onClick={()=>navigate(null)}>{c.first}</button><button type="button" className="button secondary" disabled={!resource.data.nextCursor} onClick={()=>navigate(resource.data!.nextCursor)}>{c.next}</button></nav>
  </>}
 </>;
}
