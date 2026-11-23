// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useRef,useState,type ReactNode} from 'react';
import {Notice} from '../../../../packages/ui/src';
import {api,ApiError} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import {useSession} from '../session';
import {referenceCopy} from './messages';
export const useCopy=()=>referenceCopy[useLocale().locale];
export function useContextKey(){const s=useSession();return JSON.stringify([s.tenant.id,s.user.id,[...s.permissions].sort()]);}
export function Field({title,hint,children}:{title:string;hint?:string;children:(id:string,hint:string)=>ReactNode}){const id=useId();return <label className="form-field"><span id={id}>{title}</span>{children(id,id+'-hint')}{hint&&<small id={id+'-hint'}>{hint}</small>}</label>;}
export function Panel({title,children}:{title:string;children:ReactNode}){return <section className="panel"><div className="panel-heading"><h2>{title}</h2></div><div className="panel-body">{children}</div></section>;}
export function Pager({cursor,next,change,disabled=false}:{cursor:string|null;next:string|null;change:(value:string|null)=>void;disabled?:boolean}){const c=useCopy();return <nav className="reference-actions" aria-label={c.pages}><button type="button" className="button secondary" disabled={disabled||!cursor} onClick={()=>change(null)}>{c.first}</button><button type="button" className="button secondary" disabled={disabled||!next} onClick={()=>change(next)}>{c.next}</button></nav>;}
type Intent={path:string;body:string;key:string};
export function useCommand<T>(done:(value:T)=>void){
 const [intent,setIntent]=useState<Intent|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null),running=useRef(false),retained=useRef<Intent|null>(null),complete=useRef(done),mounted=useRef(true);complete.current=done;
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
 async function execute(value:Intent){if(running.current)return;running.current=true;retained.current=value;setIntent(value);setBusy(true);setError(null);
  try{const result=await api<T>(value.path,{method:'POST',headers:{'Idempotency-Key':value.key},body:value.body});if(!mounted.current)return;retained.current=null;setIntent(null);complete.current(result);}
  catch(caught){if(!mounted.current)return;const failure=caught instanceof Error?caught:new Error('Reference request failed');setError(failure);if(failure instanceof ApiError&&failure.status<500&&![408,429].includes(failure.status)){retained.current=null;setIntent(null);}}
  finally{running.current=false;if(mounted.current)setBusy(false);}}
 return {busy,error,intent,locked:busy||intent!==null,submit:(path:string,body:unknown)=>{if(!running.current&&!retained.current)void execute({path,body:JSON.stringify(body),key:crypto.randomUUID()});},retry:()=>{if(retained.current)void execute(retained.current);}};
}
export function Feedback({command}:{command:ReturnType<typeof useCommand<unknown>>}){const c=useCopy();return <>{command.error&&<RequestError error={command.error} compact/>}{command.error instanceof ApiError&&command.error.status===409&&<Notice tone="error">{c.stale}</Notice>}{command.error instanceof ApiError&&command.error.issues.length>0&&<Notice tone="error"><ul>{command.error.issues.map((issue,index)=><li key={index}><code dir="ltr">{issue.path||'/'}</code> — {issue.message}</li>)}</ul></Notice>}{command.intent&&command.error&&<Notice><p>{c.uncertain}</p><button className="button secondary" type="button" disabled={command.busy} onClick={command.retry}>{c.retry}</button></Notice>}</>;}
export function localTime(instant:string|null){if(!instant)return '';const d=new Date(instant),pad=(n:number)=>String(n).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;}
export function exactTime(value:string):string|null{if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value))return null;const d=new Date(value);if(!Number.isFinite(d.getTime()))return null;const expected=value.length===16?value+':00':value;return localTime(d.toISOString())===expected?d.toISOString():null;}
