// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useState} from 'react';
import type {QualityReferenceMetadata} from '../../../../packages/domain/src/quality-contracts';
import type {ReferenceEffectiveView,ReferencePage,ReferenceSetSummary} from '../../../../packages/domain/src/reference-data-contracts';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import {useResource} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission} from '../session';
import {qualityCopy} from './messages';

/** Lists are current-authorized and paged. No identifier fallback or authoring
 * directory call is used to circumvent reference-read discovery. */
export function ReferencePicker({value,onChange,ready,disabled}:{value:string;onChange:(id:string)=>void;ready:(ready:boolean)=>void;disabled:boolean}){
 const {locale,number,date}=useLocale(),c=qualityCopy[locale],read=usePermission('reference:read'),label=useId();
 const [draft,setDraft]=useState(''),[query,setQuery]=useState(''),[cursor,setCursor]=useState<string|null>(null);
 const list=useResource<ReferencePage<ReferenceSetSummary>>(read?'/reference-data/sets?limit=25&q='+encodeURIComponent(query)+(cursor?'&cursor='+encodeURIComponent(cursor):''):null);
 const selected=useResource<ReferenceEffectiveView>(read&&value?'/reference-data/sets/'+encodeURIComponent(value)+'/effective?limit=1':null);
 const available=read&&!selected.loading&&!selected.error&&!!selected.data&&selected.data.set.id===value;
 useEffect(()=>{ready(available);},[available,ready]);
 useEffect(()=>()=>ready(false),[ready]);
 function search(){setQuery(draft.normalize('NFC').trim());setCursor(null);}
 if(!read)return <Notice tone="error">{c.referencePermission}</Notice>;
 return <section className="quality-reference-picker" aria-label={c.referenceSet}>
  <h3>{c.referenceSet}</h3><p>{c.referenceSelection}</p>
  <label className="form-field"><span id={label}>{c.referenceSearch}</span><input type="search" maxLength={200} aria-labelledby={label} value={draft} disabled={disabled} onChange={event=>setDraft(event.target.value)} onKeyDown={event=>{if(event.key==='Enter'){event.preventDefault();if(!disabled)search();}}}/></label>
  <div className="quality-actions"><button type="button" className="button secondary" disabled={disabled} onClick={search}>{c.search}</button><button type="button" className="button secondary" disabled={disabled||list.loading} onClick={list.reload}>{c.refresh}</button></div>
  {list.error?<RequestError error={list.error} retry={list.reload} compact/>:list.loading?<LoadingState label={c.loading}/>:list.data?.items.length?<ul className="quality-rule-list">{list.data.items.map(set=><li key={set.id}><button type="button" className="text-button" disabled={disabled} aria-pressed={set.id===value} aria-label={c.selectSet+' '+set.latest.labels[locale].label} onClick={()=>{ready(false);onChange(set.id);}}>{set.latest.labels[locale].label}</button><span>{c[set.effective.phase]} · {c.version} {number(set.latest.version)}</span></li>)}</ul>:<EmptyState compact title={c.noSets}/>}
  <nav className="quality-actions" aria-label={c.referencePages}><button type="button" className="button secondary" disabled={disabled||list.loading||!cursor} onClick={()=>setCursor(null)}>{c.first}</button><button type="button" className="button secondary" disabled={disabled||list.loading||!!list.error||!list.data?.nextCursor} onClick={()=>setCursor(list.data!.nextCursor)}>{c.next}</button></nav>
  {value&&(selected.error?<RequestError error={selected.error} retry={selected.reload} compact/>:!available?<LoadingState label={c.loading}/>:<div className="quality-reference-selection"><h4>{c.selectedSet}: {selected.data!.set.latest.labels[locale].label}</h4><Link href={'/reference-data/'+value}>{c.openReference}</Link><dl className="detail-list"><div><dt>{c.preview}</dt><dd>{c[selected.data!.selection.phase]}</dd></div><div><dt>{c.referenceTime}</dt><dd><time dateTime={selected.data!.selection.asOf}>{date(selected.data!.selection.asOf)}</time></dd></div>{selected.data!.selection.version!==null&&<><div><dt>{c.referenceVersion}</dt><dd>{number(selected.data!.selection.version!)}</dd></div><div><dt>{c.referenceHash}</dt><dd className="mono break-all">{selected.data!.selection.publicationHash}</dd></div></>}</dl></div>)}
  <Notice>{c.privateTransfer}</Notice><p>{c.referenceComparison}</p>
 </section>;
}
export function ReferenceRunEvidence({reference}:{reference:QualityReferenceMetadata}){
 const {locale,number,date}=useLocale(),c=qualityCopy[locale];
 return <section className="quality-reference-selection" aria-label={c.referenceSet}>
  <h4>{c.referenceSet}</h4><p>{c.sourceWindow}</p>
  <dl className="detail-list"><div><dt>{c.referenceSet}</dt><dd><Link href={'/reference-data/'+reference.setId}>{reference.setId}</Link></dd></div><div><dt>{c.referenceVersion}</dt><dd data-testid="quality-reference-version">{number(reference.version)}</dd></div><div><dt>{c.referenceTime}</dt><dd><time dateTime={reference.asOf} data-testid="quality-reference-as-of">{date(reference.asOf)}</time><bdi className="mono quality-exact-time">{reference.asOf}</bdi></dd></div><div><dt>{c.referenceHash}</dt><dd className="mono break-all" data-testid="quality-reference-hash">{reference.publicationHash}</dd></div><div><dt>{c.bindingHash}</dt><dd className="mono break-all">{reference.bindingHash}</dd></div></dl>
  <Link className="button secondary" href={'/reference-data/'+reference.setId+'?version='+reference.version}>{c.exactReference}</Link>
 </section>;
}
