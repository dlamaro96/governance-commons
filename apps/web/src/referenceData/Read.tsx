// SPDX-License-Identifier: Apache-2.0
import {useState,type FormEvent} from 'react';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import {LIMITS,type PublishedBundle,type ReferenceEffectiveView,type ReferencePage,type ReferenceReleaseSummary,type ReferenceReleaseView,type ReferenceSetSummary,type ReferenceValue} from '../../../../packages/domain/src/reference-data-contracts';
import {useResource} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission} from '../session';
import {exactTime,Field,Pager,Panel,useContextKey,useCopy} from './shared';
import './reference-data.css';
const base='/reference-data/sets/';
export function ReferenceDataPage(){const key=useContextKey(),reference=usePermission('reference:read'),catalog=usePermission('catalog:read'),read=reference&&catalog;return read?<SetList key={key}/>:<PermissionDenied/>;}
function SetList(){
 const c=useCopy(),{locale,number}=useLocale(),write=usePermission('reference:write'),[draft,setDraft]=useState(''),[q,setQuery]=useState(''),[cursor,setCursor]=useState<string|null>(null);
 const resource=useResource<ReferencePage<ReferenceSetSummary>>('/reference-data/sets?limit=25&q='+encodeURIComponent(q)+(cursor?'&cursor='+encodeURIComponent(cursor):''));
 function search(event:FormEvent){event.preventDefault();setQuery(draft.normalize('NFC').trim());setCursor(null);}
 return <section className="reference-workspace"><header className="reference-heading"><div><h1 id="main-heading" tabIndex={-1}>{c.title}</h1><p>{c.intro}</p></div>{write&&<Link className="button primary" href="/reference-data/new">{c.newSet}</Link>}</header>{!write&&<Notice>{c.readOnly}</Notice>}
  <form className="reference-form" onSubmit={search}><Field title={c.search}>{id=><input type="search" maxLength={200} aria-labelledby={id} value={draft} onChange={event=>setDraft(event.target.value)}/>}</Field><div className="reference-actions"><button className="button secondary">{c.search}</button><button className="button secondary" type="button" onClick={resource.reload}>{c.refresh}</button></div></form>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading?<LoadingState label={c.loading}/>:resource.data?.items.length?<ul className="reference-records">{resource.data.items.map(set=><li key={set.id}><h2><Link href={'/reference-data/'+set.id}>{set.latest.labels[locale].label}</Link></h2><p className="reference-text">{set.latest.labels[locale].description}</p><p>{c.latest} {number(set.latest.version)} · {c[set.effective.phase]}</p></li>)}</ul>:<EmptyState title={c.empty}/>}
  <Pager cursor={cursor} next={resource.error?null:resource.data?.nextCursor??null} change={setCursor} disabled={resource.loading}/>
 </section>;
}
export function ReferenceSetPage({id}:{id:string}){const context=useContextKey(),reference=usePermission('reference:read'),catalog=usePermission('catalog:read'),read=reference&&catalog;return read?<SetWorkspace key={context+id} id={id}/>:<PermissionDenied/>;}
function SetWorkspace({id}:{id:string}){
 const c=useCopy(),{locale,number}=useLocale(),write=usePermission('reference:write'),[asOf,setAsOf]=useState<string|null>(null),[draft,setDraft]=useState(''),[invalid,setInvalid]=useState(false),[mode,setMode]=useState<'effective'|'history'>('effective');
 const summary=useResource<ReferenceEffectiveView>(base+id+'/effective?limit=1');
 function apply(event:FormEvent){event.preventDefault();const time=exactTime(draft);if(!time||Date.parse(time)>Date.now()){setInvalid(true);return;}setInvalid(false);setAsOf(time);}
 if(summary.error)return <RequestError error={summary.error} retry={summary.reload}/>;
 if(summary.loading||!summary.data||summary.data.set.id!==id)return <LoadingState label={c.loading}/>;
 const set=summary.data.set;
 return <section className="reference-workspace"><Link href="/reference-data">{c.back}</Link><header className="reference-heading"><div><h1 id="main-heading" tabIndex={-1}>{set.latest.labels[locale].label}</h1><p className="reference-text">{set.latest.labels[locale].description}</p><p>{c.latest} {number(set.latest.version)}</p></div>{write&&set.latest.version<LIMITS.version&&<Link className="button primary" href={'/reference-data/'+id+'/propose'}>{c.successor}</Link>}</header>
  <div className="reference-actions" role="group" aria-label={c.title}><button type="button" className="button secondary" aria-pressed={mode==='effective'} onClick={()=>setMode('effective')}>{c.effective}</button><button type="button" className="button secondary" aria-pressed={mode==='history'} onClick={()=>setMode('history')}>{c.history}</button></div>
  {mode==='effective'?<><form className="reference-form" onSubmit={apply}><Field title={c.asOf}>{label=><input type="datetime-local" step="1" required aria-labelledby={label} value={draft} onChange={event=>setDraft(event.target.value)}/>}</Field><div className="reference-actions"><button className="button secondary">{c.applyTime}</button><button type="button" className="button secondary" onClick={()=>{setAsOf(null);setDraft('');setInvalid(false);summary.reload();}}>{c.now}</button></div></form>{invalid&&<Notice tone="error">{c.invalid}</Notice>}<EffectiveValues key={id+asOf} id={id} asOf={asOf}/></>:<ReleaseHistory id={id}/>}
 </section>;
}
function EffectiveValues({id,asOf}:{id:string;asOf:string|null}){
 const c=useCopy(),{date,number}=useLocale(),[cursor,setCursor]=useState<string|null>(null);
 const resource=useResource<ReferenceEffectiveView>(base+id+'/effective?limit=25'+(asOf?'&asOf='+encodeURIComponent(asOf):'')+(cursor?'&cursor='+encodeURIComponent(cursor):''));
 if(resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;
 if(resource.loading||!resource.data||resource.data.set.id!==id)return <LoadingState label={c.loading}/>;
 const view=resource.data;
 return <Panel title={c.effective}><div className="reference-state"><strong>{c[view.selection.phase]}</strong><span>{c.at}: <time dateTime={view.selection.asOf}>{date(view.selection.asOf)}</time></span>{view.selection.version!==null&&<span>{c.version} {number(view.selection.version)}</span>}</div>
  <p>{c.scheduledNotice}</p>{view.items.length?<ValuesTable values={view.items}/>:<EmptyState compact title={c.none}/>}
  <Pager cursor={cursor} next={view.nextCursor} change={setCursor}/>{view.selection.version!==null&&<Downloads id={id} version={view.selection.version}/>}<button type="button" className="button secondary" onClick={()=>{setCursor(null);resource.reload();}}>{c.refresh}</button>
 </Panel>;
}
function ReleaseHistory({id}:{id:string}){
 const c=useCopy(),{number,date,locale}=useLocale(),[cursor,setCursor]=useState<string|null>(null),[version,setVersion]=useState<number|null>(null);
 const resource=useResource<ReferencePage<ReferenceReleaseSummary>>(base+id+'/releases?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):''));
 return <><Panel title={c.history}>{resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading?<LoadingState label={c.loading}/>:<ul className="reference-records">{resource.data?.items.map(row=><li key={row.version}><h3>{row.labels[locale].label} · {c.version} {number(row.version)}</h3><p>{c.published}: {date(row.publishedAt)} · {c.from}: {date(row.effectiveFrom)}</p><button className="button secondary" type="button" aria-pressed={version===row.version} onClick={()=>setVersion(row.version)}>{c.open} {number(row.version)}</button></li>)}</ul>}<Pager cursor={cursor} next={resource.error?null:resource.data?.nextCursor??null} change={setCursor} disabled={resource.loading}/></Panel>{version!==null&&<ExactRelease key={id+':'+version} id={id} version={version}/>}</>;
}
function ExactRelease({id,version}:{id:string;version:number}){
 const c=useCopy(),resource=useResource<ReferenceReleaseView>(base+id+'/releases/'+version);
 if(resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;
 if(resource.loading||!resource.data||resource.data.release.setId!==id||resource.data.release.version!==version)return <LoadingState label={c.loading}/>;
 return <Panel title={c.exact}><ReleaseDetails release={resource.data.release} hash={resource.data.publicationHash}/><ValuesTable values={resource.data.release.values}/><Downloads id={id} version={version}/></Panel>;
}
export function ReleaseDetails({release,hash}:{release:PublishedBundle;hash:string}){const c=useCopy(),{number,date}=useLocale();return <dl className="detail-list reference-pins"><div><dt>{c.identifier}</dt><dd><bdi className="mono">{release.setId}</bdi></dd></div><div><dt>{c.version}</dt><dd>{number(release.version)}</dd></div><div><dt>{c.hash}</dt><dd><bdi className="mono">{hash}</bdi></dd></div><div><dt>{c.published}</dt><dd><time dateTime={release.publishedAt}>{date(release.publishedAt)}</time></dd></div><div><dt>{c.from}</dt><dd><time dateTime={release.effectiveFrom}>{date(release.effectiveFrom)}</time></dd></div><div><dt>{c.until}</dt><dd>{release.validUntil?date(release.validUntil):c.unbounded}</dd></div><div><dt>{c.owner}</dt><dd><bdi className="reference-owner">{release.ownerId}</bdi></dd></div><div><dt>{c.status}</dt><dd>{c[release.status]}</dd></div></dl>;}
export function Downloads({id,version}:{id:string;version:number}){const c=useCopy();return <><p>{c.immutable}</p><div className="reference-actions"><a className="button secondary" href={'/api/v1'+base+id+'/releases/'+version+'/download?format=json'} download>{c.downloadJson}</a><a className="button secondary" href={'/api/v1'+base+id+'/releases/'+version+'/download?format=csv'} download>{c.downloadCsv}</a></div></>;}
export function ValuesTable({values}:{values:readonly ReferenceValue[]}){const c=useCopy(),{locale,date}=useLocale();return <div className="reference-table-wrap" tabIndex={0} role="region" aria-label={c.values}><table className="reference-table"><caption>{c.values}</caption><thead><tr><th scope="col">{c.code}</th><th scope="col">{locale==='en'?c.nameEn:c.nameAr}</th><th scope="col">{locale==='en'?c.descriptionEn:c.descriptionAr}</th><th scope="col">{c.status}</th><th scope="col">{c.owner}</th><th scope="col">{c.from}</th><th scope="col">{c.until}</th></tr></thead><tbody>{values.map(value=><tr key={value.code}><td><bdi className="reference-code">{value.code}</bdi></td><td dir="auto">{value.labels[locale].label}</td><td className="reference-text" dir="auto">{value.labels[locale].description}</td><td>{c[value.status]}</td><td><bdi className="reference-owner">{value.ownerId}</bdi></td><td>{value.validFrom?date(value.validFrom):c.unbounded}</td><td>{value.validUntil?date(value.validUntil):c.unbounded}</td></tr>)}</tbody></table></div>;}
