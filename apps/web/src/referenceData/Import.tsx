// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useRef,useState} from 'react';
import {Notice} from '../../../../packages/ui/src';
import {IMPORT_LIMITS,type ImportBase,type ImportField,type ImportFormat,type ImportMode,type ImportPreview,type ValueChange} from '../../../../packages/domain/src/reference-import-contracts.ts';
import type {ReferenceValue} from '../../../../packages/domain/src/reference-data-contracts.ts';
import {api} from '../api';
import {RequestError} from '../components';
import {useLocale} from '../i18n';
import type {Member} from '../types';
import {Field,useCopy} from './shared';
import {importContentType,importPath,importTemplate,sameImportPreview} from './import-state.ts';

export function ReferenceImport({base,values,people,ownerId,disabled,apply}:{base:ImportBase;values:readonly ReferenceValue[];people:readonly Member[];ownerId:string;disabled:boolean;apply:(values:readonly ReferenceValue[])=>void}){
 const c=useCopy(),{number}=useLocale(),title=useId();
 const [file,setFile]=useState<File|null>(null),[format,setFormat]=useState<ImportFormat>('json'),[mode,setMode]=useState<ImportMode>('merge'),[preview,setPreview]=useState<ImportPreview|null>(null),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null),[localFailure,setLocalFailure]=useState(false),[applied,setApplied]=useState(false);
 const generation=useRef(0),controller=useRef<AbortController|null>(null);
 function clear(){generation.current++;controller.current?.abort();controller.current=null;setPreview(null);setConsent(false);setError(null);setBusy(false);setLocalFailure(false);}
 useEffect(()=>{clear();},[base.setId,base.expectedVersion,base.publicationHash,values]);
 useEffect(()=>()=>{generation.current++;controller.current?.abort();},[]);
 async function inspect(){
  if(disabled||busy||!file)return;clear();setApplied(false);
  if(file.size===0||file.size>IMPORT_LIMITS.rawBytes){setLocalFailure(true);return;}
  const version=generation.current,active=new AbortController();controller.current=active;setBusy(true);
  try{
   const raw=await file.arrayBuffer();if(version!==generation.current)return;
   if(raw.byteLength!==file.size||raw.byteLength>IMPORT_LIMITS.rawBytes)throw Error(c.importFileInvalid);
   const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),value=>value.toString(16).padStart(2,'0')).join('');
   if(version!==generation.current)return;
   const response=await api<ImportPreview>(importPath(base,mode),{method:'POST',headers:{'Content-Type':importContentType(format)},body:raw,signal:active.signal});
   if(version!==generation.current)return;
   if(response.state==='ready'&&!sameImportPreview(response,{base,mode,sourceSha256:digest})||response.state!=='ready'&&response.state!=='invalid')throw Error(c.importResponseInvalid);
   setPreview(response);setConsent(false);
  }catch(caught){if(version===generation.current&&!active.signal.aborted)setError(caught instanceof Error?caught:Error(c.importResponseInvalid));}
  finally{if(version===generation.current){setBusy(false);controller.current=null;}}
 }
 function template(){const url=URL.createObjectURL(new Blob([importTemplate(format,ownerId)],{type:importContentType(format)})),link=document.createElement('a');link.href=url;link.download='reference-code-rows.'+format;link.click();setTimeout(()=>URL.revokeObjectURL(url),0);}
 function applyPreview(){if(disabled||busy||!consent||preview?.state!=='ready')return;const next=structuredClone(preview.values);clear();apply(next);setApplied(true);}
 const field=(key:ImportField|'')=>({'':c.importWholeFile,code:c.code,'labels.en.label':c.nameEn,'labels.en.description':c.descriptionEn,'labels.ar.label':c.nameAr,'labels.ar.description':c.descriptionAr,ownerId:c.owner,status:c.status,validFrom:c.importValidFrom,validUntil:c.importValidUntil}[key]);
 const issueCopy={FORMAT:c.importFormatIssue,FIELDS:c.importFieldsIssue,DUPLICATE:c.importDuplicateIssue,INTERVAL:c.importIntervalIssue,LIMIT:c.importLimitIssue};
 return <section className="reference-card reference-import" aria-labelledby={title}><h2 id={title}>{c.importTitle}</h2><p>{c.importHint}</p><p>{c.importDraftHint}</p>
  <div className="reference-fields"><Field title={c.importFormat}>{id=><select aria-labelledby={id} disabled={disabled||busy} value={format} onChange={event=>{clear();setApplied(false);setFormat(event.target.value as ImportFormat);}}><option value="json">JSON</option><option value="csv">CSV</option></select>}</Field><Field title={c.importMode}>{id=><select aria-labelledby={id} disabled={disabled||busy} value={mode} onChange={event=>{clear();setApplied(false);setMode(event.target.value as ImportMode);}}><option value="merge">{c.importMerge}</option><option value="replace">{c.importReplace}</option></select>}</Field></div>
  <p>{mode==='merge'?c.importMergeHint:c.importReplaceHint}</p><Field title={c.importFile} hint={c.importFileHint}>{(id,hint)=><input type="file" aria-labelledby={id} aria-describedby={hint} disabled={disabled} accept={format==='json'?'.json,application/json':'.csv,text/csv'} onChange={event=>{clear();setApplied(false);setFile(event.target.files?.[0]??null);}}/>}</Field>
  <div className="reference-actions"><button type="button" className="button secondary" disabled={disabled||busy} onClick={template}>{c.importTemplate}</button><button type="button" className="button secondary" disabled={disabled||busy||!file} onClick={()=>void inspect()}>{busy?c.importLoading:c.importPreview}</button></div><p className="muted">{c.importTemplateHint}</p>
  {localFailure&&<Notice tone="error">{c.importFileInvalid}</Notice>}{error&&<RequestError error={error} compact/>}{applied&&<Notice tone="success">{c.importApplied}</Notice>}
  {preview?.state==='invalid'&&<div role="alert"><h3>{c.importInvalid}</h3><ul>{preview.issues.map((issue,index)=><li key={index}>{issue.row===null?c.importWholeFile:c.importRow+' '+number(issue.row)} · {field(issue.field)}: {issueCopy[issue.code]}{issue.relatedRow!==null&&<> {c.importRelated} {number(issue.relatedRow)}.</>}</li>)}</ul>{preview.issuesTruncated&&<p>{c.importTruncated}</p>}</div>}
  {preview?.state==='ready'&&<div className="reference-import-preview" aria-label={c.importReady}><h3>{c.importReady}</h3><p>{c.importBase} {number(preview.base.expectedVersion)} · {c.importUtc}</p><dl className="reference-import-counts">{(['added','changed','removed','unchanged'] as const).map(kind=><div key={kind}><dt>{c['import'+kind[0].toUpperCase()+kind.slice(1) as 'importAdded'|'importChanged'|'importRemoved'|'importUnchanged']}</dt><dd>{number(preview.counts[kind])}</dd></div>)}</dl><p>{c.importAdvisory}</p>
   <ul className="reference-records">{preview.changes.map(change=><Change key={change.code} change={change} people={people} field={field}/>)}</ul>
   <label className="checkbox-label"><input type="checkbox" disabled={disabled||busy} checked={consent} onChange={event=>setConsent(event.target.checked)}/>{c.importConsent}</label><div className="reference-actions"><button type="button" className="button secondary" disabled={disabled||busy||!consent} onClick={applyPreview}>{c.importApply}</button></div>
  </div>}
 </section>;
}
function Change({change,people,field}:{change:ValueChange;people:readonly Member[];field:(field:ImportField|'')=>string}){
 const c=useCopy(),kind={added:c.importAdded,changed:c.importChanged,removed:c.importRemoved,unchanged:c.importUnchanged}[change.kind];
 return <li><details className="reference-import-change" open={change.kind!=='unchanged'}><summary><bdi className="reference-code">{change.code}</bdi> — {kind}</summary>{change.changedFields.length>0&&<p>{c.importFields}: {change.changedFields.map(field).join(' · ')}</p>}<div className="reference-fields"><Value value={change.before} title={c.importBefore} people={people}/><Value value={change.after} title={c.importAfter} people={people}/></div></details></li>;
}
function Value({value,title,people}:{value:ReferenceValue|null;title:string;people:readonly Member[]}){
 const c=useCopy();return <div><h4>{title}</h4>{value?<dl className="reference-import-value"><dt>{c.code}</dt><dd><bdi>{value.code}</bdi></dd>{(['en','ar'] as const).map(locale=><div key={locale}><dt>{locale==='en'?c.nameEn:c.nameAr}</dt><dd className="reference-text" lang={locale} dir={locale==='ar'?'rtl':'ltr'}>{value.labels[locale].label}</dd><dt>{locale==='en'?c.descriptionEn:c.descriptionAr}</dt><dd className="reference-text" lang={locale} dir={locale==='ar'?'rtl':'ltr'}>{value.labels[locale].description}</dd></div>)}<dt>{c.owner}</dt><dd>{people.find(person=>person.id===value.ownerId)?.name??c.unavailableOwner}<details><summary>{c.importOwnerRef}</summary><bdi>{value.ownerId}</bdi></details></dd><dt>{c.status}</dt><dd>{value.status==='active'?c.active:c.deprecated}</dd><dt>{c.importValidFrom}</dt><dd>{value.validFrom?<time dateTime={value.validFrom}>{value.validFrom}</time>:c.unbounded}</dd><dt>{c.importValidUntil}</dt><dd>{value.validUntil?<time dateTime={value.validUntil}>{value.validUntil}</time>:c.unbounded}</dd></dl>:<p>{c.importAbsent}</p>}</div>;
}
