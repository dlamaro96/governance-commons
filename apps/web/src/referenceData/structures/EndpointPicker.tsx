// SPDX-License-Identifier: Apache-2.0
import {useEffect,useRef,useState} from 'react';
import {EmptyState,LoadingState} from '../../../../../packages/ui/src';
import type {ReferencePage,ReferenceReleaseSummary,ReferenceReleaseView,ReferenceSetSummary} from '../../../../../packages/domain/src/reference-data-contracts.ts';
import type {ReferenceReleasePin} from '../../../../../packages/domain/src/reference-structure-contracts.ts';
import {useResource} from '../../api.ts';
import {RequestError} from '../../components.tsx';
import {useLocale} from '../../i18n.tsx';
import {Field,Pager,PinDetails,useCopy} from './shared.tsx';
export function EndpointPicker({title,initial,fixedSetId,onReady,onChange}:{title:string;initial:ReferenceReleasePin|null;fixedSetId?:string;onReady:(view:ReferenceReleaseView|null)=>void;onChange:()=>void}){
 const c=useCopy(),{locale,number,date}=useLocale(),[setId,setIdState]=useState(initial?.setId??fixedSetId??''),[version,setVersion]=useState<number|null>(initial?.version??null),[q,setQuery]=useState(''),[draft,setDraft]=useState(''),[cursor,setCursor]=useState<string|null>(null),[versionsCursor,setVersionsCursor]=useState<string|null>(null);
 const callbacks=useRef({onReady,onChange});callbacks.current={onReady,onChange};
 const sets=useResource<ReferencePage<ReferenceSetSummary>>(fixedSetId?null:'/reference-data/sets?limit=25&q='+encodeURIComponent(q)+(cursor?'&cursor='+encodeURIComponent(cursor):''));
 const releases=useResource<ReferencePage<ReferenceReleaseSummary>>(setId?'/reference-data/sets/'+setId+'/releases?limit=25'+(versionsCursor?'&cursor='+encodeURIComponent(versionsCursor):''):null);
 const detail=useResource<ReferenceReleaseView>(setId&&version?'/reference-data/sets/'+setId+'/releases/'+version:null);
 const selected=detail.data&&!detail.loading&&!detail.error&&detail.data.release.setId===setId&&detail.data.release.version===version&&detail.data.release.status==='active'?detail.data:null;
 useEffect(()=>{callbacks.current.onReady(selected);},[selected]);
 function pickSet(id:string){if(id===setId)return;callbacks.current.onChange();callbacks.current.onReady(null);setIdState(id);setVersion(null);setVersionsCursor(null);}
 function pickVersion(v:number){if(v!==version){callbacks.current.onChange();callbacks.current.onReady(null);setVersion(v);}}
 return <fieldset className="reference-card structure-endpoint"><legend>{title}</legend><p>{c.pinNotice}</p>{!fixedSetId&&<><Field title={c.searchSets}>{id=><input type="search" aria-labelledby={id} value={draft} maxLength={200} onChange={e=>setDraft(e.target.value)}/>}</Field><button type="button" className="button secondary" onClick={()=>{setQuery(draft.normalize('NFC').trim());setCursor(null);}}>{c.search}</button>{sets.error?<RequestError error={sets.error} retry={sets.reload}/>:sets.loading?<LoadingState label={c.loading}/>:sets.data?.items.length?<ul className="reference-records">{sets.data.items.map(set=><li key={set.id}><button type="button" className="text-button" aria-pressed={setId===set.id} onClick={()=>pickSet(set.id)}>{set.latest.labels[locale].label}</button></li>)}</ul>:<EmptyState compact title={c.empty}/>}<Pager cursor={cursor} next={sets.error?null:sets.data?.nextCursor??null} change={setCursor} disabled={sets.loading}/></>}
  {setId&&<><h3>{c.selectRelease}</h3>{releases.error?<RequestError error={releases.error} retry={releases.reload}/>:releases.loading?<LoadingState label={c.loading}/>:<ul className="reference-records">{releases.data?.items.map(row=><li key={row.version}><button type="button" className="text-button" disabled={row.status!=='active'} aria-pressed={version===row.version} onClick={()=>pickVersion(row.version)}>{row.labels[locale].label} · {c.version} {number(row.version)}</button><small>{c[row.status]}</small></li>)}</ul>}<Pager cursor={versionsCursor} next={releases.error?null:releases.data?.nextCursor??null} change={setVersionsCursor} disabled={releases.loading}/></>}
  {detail.error?<RequestError error={detail.error} retry={detail.reload}/>:detail.loading?<LoadingState label={c.loading}/>:selected?<><PinDetails title={c.selectedRelease} pin={{setId:selected.release.setId,version:selected.release.version,publicationHash:selected.publicationHash}}/><p>{c.from}: {date(selected.release.effectiveFrom)} · {c.until}: {selected.release.validUntil?date(selected.release.validUntil):c.unbounded}</p><p>{c.endpointWindowHint}</p></>:<p>{c.chooseRelease}</p>}
 </fieldset>;
}
