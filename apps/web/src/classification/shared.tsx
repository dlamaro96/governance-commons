// SPDX-License-Identifier: Apache-2.0
import {useId,useRef,useState,type ReactNode} from 'react';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import type {ClassificationEvidence,ClassificationLabelPin,ClassificationPage,ClassificationPin} from '../../../../packages/domain/src/classification-contracts';
import {api,ApiError,useResource} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import {useSession} from '../session';
import {classificationCopy} from './messages';

export const useCopy=()=>classificationCopy[useLocale().locale];
export function useContextKey(){const s=useSession();return JSON.stringify([s.tenant.id,s.user.id,[...s.permissions].sort()]);}
export function Field({title,hint,children}:{title:string;hint?:string;children:(id:string,hint:string)=>ReactNode}){
 const id=useId();return <label className="form-field"><span id={id}>{title}</span>{children(id,id+'-hint')}{hint&&<small id={id+'-hint'}>{hint}</small>}</label>;
}
export function Panel({title,children,actions}:{title:string;children:ReactNode;actions?:ReactNode}){
 return <section className="panel"><div className="panel-heading"><h3>{title}</h3>{actions}</div><div className="panel-body">{children}</div></section>;
}
export function Pager({cursor,next,change,disabled=false}:{cursor:string|null;next:string|null;change:(cursor:string|null)=>void;disabled?:boolean}){
 const c=useCopy();return <nav className="classification-actions" aria-label={c.pages}><button type="button" className="button secondary" disabled={disabled||!cursor} onClick={()=>change(null)}>{c.first}</button><button type="button" className="button secondary" disabled={disabled||!next} onClick={()=>change(next)}>{c.next}</button></nav>;
}
type Intent={path:string;body:string;key:string};
export function useCommand<T>(done:(value:T)=>void){
 const [intent,setIntent]=useState<Intent|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null);
 const running=useRef(false),retained=useRef<Intent|null>(null),complete=useRef(done);complete.current=done;
 async function execute(value:Intent){
  if(running.current)return;running.current=true;retained.current=value;setIntent(value);setBusy(true);setError(null);
  try{const result=await api<T>(value.path,{method:'POST',headers:{'Idempotency-Key':value.key},body:value.body});retained.current=null;setIntent(null);complete.current(result);}
  catch(caught){const failure=caught instanceof Error?caught:new Error('Classification request failed');setError(failure);
   if(failure instanceof ApiError&&failure.status<500&&![408,429].includes(failure.status)){retained.current=null;setIntent(null);}
  }finally{running.current=false;setBusy(false);}
 }
 return {busy,error,intent,locked:busy||intent!==null,
  submit:(path:string,body:unknown)=>{if(!running.current&&!retained.current)void execute({path,body:JSON.stringify(body),key:crypto.randomUUID()});},
  retry:()=>{if(retained.current)void execute(retained.current);}};
}
export function Feedback({command}:{command:ReturnType<typeof useCommand<unknown>>}){
 const c=useCopy();return <>{command.error&&<RequestError error={command.error} compact/>}
  {command.error instanceof ApiError&&command.error.status===409&&<Notice tone="error">{c.stale}</Notice>}
  {command.error instanceof ApiError&&command.error.issues.length>0&&<Notice tone="error"><strong>{c.invalid}</strong><ul>{command.error.issues.map((issue,index)=><li key={index}><code dir="ltr">{issue.path||'/'}</code> — {issue.message}</li>)}</ul></Notice>}
  {command.intent&&command.error&&<Notice><p>{c.uncertain}</p><button type="button" className="button secondary" disabled={command.busy} onClick={command.retry}>{c.retry}</button></Notice>}</>;
}
export function Picker<T>({path,title,idOf,labelOf,onSelect,selectedId='',disabled=false,filter,empty}:{path:string|null;title:string;idOf:(item:T)=>string;labelOf:(item:T)=>string;onSelect:(item:T)=>void;selectedId?:string;disabled?:boolean;filter?:(item:T)=>boolean;empty?:string}){
 const c=useCopy(),[cursor,setCursor]=useState<string|null>(null);
 const resource=useResource<ClassificationPage<T>>(path?path+'?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):''):null);
 const items=resource.data?.items.filter(filter??(()=>true))??[];
 if(!path)return null;
 return <fieldset className="classification-picker" disabled={disabled}><legend>{title}</legend>
  {resource.error?<RequestError error={resource.error} retry={resource.reload} compact/>:resource.loading?<LoadingState label={c.loading}/>:items.length?<ul className="classification-picker-list">{items.map(item=><li key={idOf(item)}><button type="button" className="text-button" aria-pressed={selectedId===idOf(item)} onClick={()=>onSelect(item)}>{labelOf(item)}</button></li>)}</ul>:<EmptyState compact title={empty??c.emptyDefinitions}/>}
  <Pager cursor={cursor} next={resource.error?null:resource.data?.nextCursor??null} change={setCursor} disabled={disabled||resource.loading}/>
 </fieldset>;
}
export function Pin({pin}:{pin:ClassificationPin}){
 const c=useCopy(),{number}=useLocale();return <dl className="detail-list classification-pins"><div><dt>{c.identifier}</dt><dd><bdi className="mono">{pin.id}</bdi></dd></div><div><dt>{c.version}</dt><dd>{number(pin.version)}</dd></div><div><dt>{c.hash}</dt><dd><bdi className="mono">{pin.definitionHash}</bdi></dd></div></dl>;
}
export function LabelPin({label}:{label:ClassificationLabelPin}){
 const c=useCopy();return <div className="classification-label-pin"><strong><bdi>{label.labelKey}</bdi></strong><details><summary>{c.taxonomy}</summary><Pin pin={label.taxonomy}/></details></div>;
}
export function Evidence({value,hash,current}:{value:ClassificationEvidence;hash?:string;current?:boolean}){
 const c=useCopy(),{number,date}=useLocale();return <div className="classification-evidence">
  {current!==undefined&&<Notice tone={current?'info':'error'}>{current?c.evidenceCurrent:c.evidenceStale}</Notice>}
  <dl className="detail-list"><div><dt>{c.observedVersion}</dt><dd>{number(value.observedAssetVersion)}</dd></div><div><dt>{c.evaluatedAt}</dt><dd>{date(value.evaluatedAt)}</dd></div><div><dt>{c.confidence}</dt><dd>{c.notEstimated}</dd></div><div><dt>{c.sourceRows}</dt><dd>{number(value.samplePolicy.sourceRowsRead)}</dd></div><div><dt>{c.sourceSamples}</dt><dd>{number(value.samplePolicy.sourceSamplesStored)}</dd></div></dl>
  <details><summary>{c.evidence}</summary><h4>{c.ruleVersion}</h4><Pin pin={value.rule}/><h4>{c.label}</h4><LabelPin label={value.label}/>
   <dl className="detail-list classification-pins"><div><dt>{c.inputDigest}</dt><dd><bdi className="mono">{value.inputDigest}</bdi></dd></div>{hash&&<div><dt>{c.evidenceHash}</dt><dd><bdi className="mono">{hash}</bdi></dd></div>}</dl>
   <ol className="classification-conditions">{value.matches.map(match=><li key={match.conditionIndex}><h4>{c.condition} {number(match.conditionIndex+1)} · {c[match.field==='name'?'fieldName':match.field]}</h4><p className="classification-literal" dir="auto">{match.value}</p><small>{c.valueHash}</small><p className="mono classification-hash" dir="ltr">{match.valueHash}</p></li>)}</ol>
  </details>
 </div>;
}
