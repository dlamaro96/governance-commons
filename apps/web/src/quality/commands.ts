// SPDX-License-Identifier: Apache-2.0
import {useRef,useState} from 'react';
import {api,ApiError} from '../api';
export interface QualityIntent {path:string;body:string;key:string}
export function useQualityCommand<T>(done:(value:T)=>void){
 const [intent,setIntent]=useState<QualityIntent|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null);
 const running=useRef(false),complete=useRef(done);complete.current=done;
 async function execute(saved:QualityIntent){
  if(running.current)return;running.current=true;setBusy(true);setError(null);setIntent(saved);
  try{const result=await api<T>(saved.path,{method:'POST',headers:{'Idempotency-Key':saved.key},body:saved.body});setIntent(null);complete.current(result);}
  catch(caught){const failure=caught instanceof Error?caught:new Error('Quality request failed');setError(failure);
   if(failure instanceof ApiError&&failure.status<500&&![408,429].includes(failure.status))setIntent(null);
  }finally{running.current=false;setBusy(false);}
 }
 return {busy,error,intent,locked:busy||intent!==null,submit:(path:string,body:unknown)=>{if(!running.current&&!intent)void execute({path,body:JSON.stringify(body),key:crypto.randomUUID()});},retry:()=>{if(intent)void execute(intent);}};
}
