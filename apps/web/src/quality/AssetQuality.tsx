// SPDX-License-Identifier: Apache-2.0
import {useCallback,useEffect,useId,useState,type FormEvent,type ReactNode} from 'react';
import {DataGrid,DetailDrawer,EmptyState,LoadingState,Notice,StatusBadge} from '../../../../packages/ui/src';
import type {QualityRuleDefinition,QualityAssetView,QualityPage,QualityRuleView,QualityRunView} from '../../../../packages/domain/src/quality-contracts';
import {useResource,ApiError} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission,useSession} from '../session';
import type {Member} from '../types';
import {qualityCopy} from './messages';
import {basisPointsToInput,percentageLabel,percentageToBasisPoints,referenceTimeInput,qualityEvidenceMatches} from './presentation';
import {useQualityCommand} from './commands';
import {ReferencePicker,ReferenceRunEvidence} from './ReferenceFields';
import './quality.css';

const useCopy=()=>qualityCopy[useLocale().locale];
function Field({title,hint,children}:{title:string;hint?:string;children:(label:string,description:string)=>ReactNode}){
 const id=useId();return <label className="form-field"><span id={id}>{title}</span>{children(id,id+'-hint')}{hint&&<small id={id+'-hint'}>{hint}</small>}</label>;
}
function Feedback({command}:{command:ReturnType<typeof useQualityCommand<unknown>>}){
 const c=useCopy(),code=command.error instanceof ApiError?command.error.code:undefined;
 return <>{command.error&&(code==='VERSION_CONFLICT'||code==='QUALITY_TARGET_STALE'?<Notice tone="error">{c.stale}</Notice>:<RequestError error={command.error} compact/>)}
  {command.intent&&command.error&&<Notice><p>{c.uncertain}</p><button type="button" className="button secondary" disabled={command.busy} onClick={command.retry}>{c.retry}</button></Notice>}</>;
}
function Paging({cursor,next,label,change,disabled=false}:{cursor:string|null;next:string|null;label:string;change:(value:string|null)=>void;disabled?:boolean}){
 const c=useCopy();return <nav className="quality-actions" aria-label={label}><button type="button" className="button secondary" disabled={disabled||!cursor} onClick={()=>change(null)}>{c.first}</button><button type="button" className="button secondary" disabled={disabled||!next} onClick={()=>change(next)}>{c.next}</button></nav>;
}
function Outcome({run}:{run:QualityRunView}){
 const c=useCopy();return <div className="quality-outcomes"><span>{c.execution}: <StatusBadge status={run.status==='succeeded'?'complete':run.status} label={c[run.status]}/></span><span>{c.result}: <StatusBadge status={run.verdict==='PASS'?'verified':run.verdict==='FAIL'?'failed':'unknown'} label={run.verdict?c[run.verdict]:c.notEvaluated}/></span></div>;
}
export function AssetQuality({assetId,assetVersion,assetType}:{assetId:string;assetVersion:number;assetType:string}){
 const session=useSession(),read=usePermission('catalog:read'),qualityRead=usePermission('quality:read');
 if(!read||!qualityRead)return <PermissionDenied/>;
 const context=JSON.stringify([session.tenant.id,session.user.id,[...session.permissions].sort(),assetId,assetVersion]);
 return <QualityWorkspace key={context} assetId={assetId} assetType={assetType}/>;
}
function QualityWorkspace({assetId,assetType}:{assetId:string;assetType:string}){
 const c=useCopy(),canWrite=usePermission('quality:write'),canExecute=usePermission('quality:execute');
 const [cursor,setCursor]=useState<string|null>(null),[selected,setSelected]=useState<string|null>(null),[epoch,setEpoch]=useState(0);
 const [editor,setEditor]=useState<{rule:QualityRuleView|null}|null>(null);
 const path='/assets/'+encodeURIComponent(assetId)+'/quality?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):'');
 const resource=useResource<QualityAssetView>(path);
 function saved(rule:QualityRuleView){setEditor(null);setSelected(rule.id);setEpoch(value=>value+1);resource.reload();}
 return <section className="quality-workspace" aria-label={c.quality}><header className="quality-header"><div><h2>{c.quality}</h2><p>{c.intro}</p><p className="supporting-text">{c.scope}</p></div><button className="button secondary" disabled={resource.loading} onClick={resource.reload}>{c.refresh}</button></header>
  {!canWrite&&!canExecute&&<Notice>{c.readOnly}</Notice>}
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading||!resource.data?<LoadingState label={c.loading}/>:<>
   {!resource.data.eligibility.supported?<EmptyState title={c.unsupported} description={c.unsupportedBody} action={['table','view'].includes(assetType)?<Link className="button secondary" href={'/catalog/'+assetId+'?tab=schema'}>{c.openColumns}</Link>:undefined}/>:<>
    <section className="panel"><div className="panel-heading"><h3>{c.rules}</h3>{canWrite&&<button className="button primary" onClick={()=>setEditor({rule:null})}>{c.newRule}</button>}</div><div className="panel-body">
     {resource.data.items.length?<ul className="quality-rule-list">{resource.data.items.map(rule=><li key={rule.id}><button className="text-button" aria-pressed={selected===rule.id} onClick={()=>setSelected(rule.id)}>{rule.definition.name}</button><span>{c.version} {rule.version} · {c[rule.definition.severity]}</span><p>{rule.definition.purpose}</p></li>)}</ul>:<EmptyState title={c.unmonitored} description={c.unmonitoredBody}/>}
     <Paging cursor={cursor} next={resource.data.nextCursor} label={c.rulePages} change={setCursor}/>
    </div></section>
    {selected&&<RulePanel key={selected+':'+epoch} id={selected} canWrite={canWrite} canExecute={canExecute} edit={rule=>setEditor({rule})}/>}
   </>}
   {editor&&resource.data.eligibility.supported&&resource.data.eligibility.tableAssetId&&resource.data.eligibility.columnAssetId&&<RuleEditor initial={editor.rule} target={{tableAssetId:resource.data.eligibility.tableAssetId,columnAssetId:resource.data.eligibility.columnAssetId}} onClose={()=>setEditor(null)} onSaved={saved}/>}
  </>}
 </section>;
}
function RuleEditor({initial,target,onClose,onSaved}:{initial:QualityRuleView|null;target:QualityRuleDefinition['target'];onClose:()=>void;onSaved:(rule:QualityRuleView)=>void}){
 const c=useCopy(),session=useSession(),directory=usePermission('catalog:write');
 const members=useResource<{items:Member[]}>(directory?'/members':null);
 const [id]=useState(()=>initial?.id??crypto.randomUUID()),[name,setName]=useState(initial?.definition.name??''),[purpose,setPurpose]=useState(initial?.definition.purpose??'');
 const [owner,setOwner]=useState(initial?.definition.ownerId??session.user.id),[severity,setSeverity]=useState<QualityRuleDefinition['severity']>(initial?.definition.severity??'warning');
 const [kind,setKind]=useState<QualityRuleDefinition['kind']>(initial?.definition.kind??'completeness');
 const [referenceId,setReferenceId]=useState(initial?.definition.kind==='reference-allowed-values'?initial.definition.reference.setId:''),[referenceReady,setReferenceReady]=useState(false);
 const [threshold,setThreshold]=useState(basisPointsToInput(initial?.definition.kind==='reference-allowed-values'?initial.definition.maximumInvalidBasisPoints:initial?.definition.maximumNullBasisPoints??0)),[invalid,setInvalid]=useState(false);
 const referenceAllowed=kind==='completeness'||referenceReady;
 const command=useQualityCommand<{rule:QualityRuleView}>(value=>onSaved(value.rule)),basisPoints=percentageToBasisPoints(threshold);
 const ownerKnown=!!members.data?.items.some(member=>member.id===owner),preservesOwner=!!initial&&initial.definition.ownerId===owner;
 // A known current-session identity needs no directory discovery. This only
 // controls the form; the service independently checks current owner authority.
 const ownerAllowed=directory?ownerKnown:preservesOwner||owner===session.user.id;
 function submit(event:FormEvent){event.preventDefault();if(command.locked)return;
  if(basisPoints===null||!name.trim()||!purpose.trim()||!ownerAllowed||!referenceAllowed||(initial&&initial.currentVersion===null)){setInvalid(true);return;}
  const common={formatVersion:1 as const,target:initial?.definition.target??target,name:name.normalize('NFC').trim(),purpose:purpose.normalize('NFC').trim(),ownerId:owner,severity};
  const definition:QualityRuleDefinition=kind==='completeness'?{...common,kind,maximumNullBasisPoints:basisPoints}:{...common,kind,maximumInvalidBasisPoints:basisPoints,reference:{setId:referenceId,selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'};
  command.submit(initial?'/quality/rules/'+id+'/versions':'/quality/rules',{id,expectedVersion:initial?.currentVersion??0,definition});
 }
 return <DetailDrawer open onOpenChange={open=>{if(!open&&!command.locked)onClose();}} title={initial?c.editRule:c.newRule} description={c.versionHint} closeLabel={c.close}>
  <form className="stacked-form quality-form" onSubmit={submit}><Feedback command={command}/>{invalid&&<Notice tone="error">{basisPoints===null?c.thresholdInvalid:c.invalid}</Notice>}
   {!directory&&<Notice>{c.memberPermission}</Notice>}{members.error&&<RequestError error={members.error} retry={members.reload} compact/>}
   <fieldset disabled={command.locked}><legend className="sr-only">{c.rules}</legend>
    <Field title={c.ruleKind}>{label=><select aria-labelledby={label} value={kind} onChange={event=>{setKind(event.target.value as QualityRuleDefinition['kind']);setInvalid(false);}}>{(['completeness','reference-allowed-values'] as const).map(value=><option key={value} value={value}>{c[value]}</option>)}</select>}</Field>
    <Field title={c.ruleName}>{label=><input required maxLength={240} aria-labelledby={label} value={name} onChange={event=>setName(event.target.value)} dir="auto"/>}</Field>
    <Field title={c.purpose}>{label=><textarea required maxLength={4096} rows={4} aria-labelledby={label} value={purpose} onChange={event=>setPurpose(event.target.value)} dir="auto"/>}</Field>
    <Field title={c.owner}>{label=><select required aria-labelledby={label} disabled={!directory||members.loading||!!members.error} value={owner} onChange={event=>setOwner(event.target.value)}><option value="">{c.chooseOwner}</option>{owner&&!ownerKnown&&<option value={owner}>{owner===session.user.id?session.user.name:c.ownerUnavailable}</option>}{members.data?.items.map(member=><option key={member.id} value={member.id}>{member.name}</option>)}</select>}</Field>
    <Field title={c.severity}>{label=><select aria-labelledby={label} value={severity} onChange={event=>setSeverity(event.target.value as QualityRuleDefinition['severity'])}>{(['info','warning','critical'] as const).map(value=><option key={value} value={value}>{c[value]}</option>)}</select>}</Field>
    {kind==='reference-allowed-values'&&<ReferencePicker value={referenceId} onChange={setReferenceId} ready={setReferenceReady} disabled={command.locked}/>}
    <Field title={kind==='completeness'?c.maximumNull:c.maximumInvalid} hint={kind==='completeness'?c.thresholdHint:c.referenceThresholdHint}>{(label,description)=><input required type="text" inputMode="decimal" maxLength={6} dir="ltr" aria-labelledby={label} aria-describedby={description} value={threshold} onChange={event=>setThreshold(event.target.value)}/>}</Field>
    <p>{c.column}: <Link href={'/catalog/'+target.columnAssetId}>{target.columnAssetId}</Link></p>
   </fieldset>
   <div className="quality-actions"><button type="button" className="button secondary" disabled={command.locked} onClick={onClose}>{c.cancel}</button><button className="button primary" disabled={command.locked||!ownerAllowed||!referenceAllowed||members.loading||!!members.error||(!!initial&&initial.currentVersion===null)}>{command.busy?c.publishing:initial?c.saveVersion:c.publish}</button></div>
  </form>
 </DetailDrawer>;
}
function RulePanel({id,canWrite,canExecute,edit}:{id:string;canWrite:boolean;canExecute:boolean;edit:(rule:QualityRuleView)=>void}){
 const c=useCopy(),{locale,number}=useLocale(),[version,setVersion]=useState<number|null>(null),[runId,setRunId]=useState<string|null>(null);
 const [observedRun,setObservedRun]=useState<{id:string;version:number}|null>(null);
 const selectRun=useCallback((next:string|null)=>{setObservedRun(null);setRunId(next);},[]);
 const observeRun=useCallback((run:QualityRunView|null)=>{
  if(!run||run.id!==runId||run.ruleId!==id){setObservedRun(null);return;}
  setObservedRun(previous=>previous?.id===run.id&&previous.version>=run.version?previous:{id:run.id,version:run.version});
 },[id,runId]);
 const resource=useResource<{rule:QualityRuleView}>('/quality/rules/'+id+(version?'?version='+version:''));
 const command=useQualityCommand<{run:QualityRunView}>(value=>selectRun(value.run.id)),rule=resource.data?.rule;
 const [referenceDate,setReferenceDate]=useState(''),[invalidDate,setInvalidDate]=useState(false);
 function requestRun(){if(!rule||command.locked||rule.currentVersion===null||rule.currentVersion!==rule.version)return;
  const asOf=rule.definition.kind==='reference-allowed-values'?referenceTimeInput(referenceDate):'';
  if(asOf===null){setInvalidDate(true);return;}setInvalidDate(false);
  command.submit('/quality/rules/'+id+'/runs',{id:crypto.randomUUID(),ruleVersion:rule.version,ruleHash:rule.definitionHash,...(asOf?{referenceAsOf:asOf}:{})});
 }
 return <section className="panel quality-rule-detail" aria-label={c.pinned}><div className="panel-heading"><h3>{c.pinned}</h3><button className="button secondary" disabled={command.locked||resource.loading} onClick={resource.reload}>{c.refresh}</button></div><div className="panel-body"><Feedback command={command}/>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading||!rule?<LoadingState label={c.loading}/>:<>
   <h4>{rule.definition.name}</h4><p className="quality-text">{rule.definition.purpose}</p><p>{c.version} <strong>{number(rule.version)}</strong> · {c.currentVersion} {rule.currentVersion===null?c.headUnavailable:number(rule.currentVersion)}</p>
   <dl className="detail-list"><div><dt>{c.ruleKind}</dt><dd>{c[rule.definition.kind]}</dd></div><div><dt>{rule.definition.kind==='completeness'?c.maximumNull:c.maximumInvalid}</dt><dd>{percentageLabel(rule.definition.kind==='completeness'?rule.definition.maximumNullBasisPoints:rule.definition.maximumInvalidBasisPoints,locale)}</dd></div><div><dt>{c.severity}</dt><dd>{c[rule.definition.severity]}</dd></div></dl><p className="supporting-text">{c.versionHint}</p>
   <div className="quality-actions"><button className="button secondary" disabled={command.locked||rule.version<=1} onClick={()=>setVersion(rule.version-1)}>{c.previousVersion}</button><button className="button secondary" disabled={command.locked||rule.currentVersion===null||rule.version>=rule.currentVersion} onClick={()=>setVersion(rule.version+1)}>{c.nextVersion}</button><button className="button secondary" disabled={command.locked||rule.currentVersion===null||version===null} onClick={()=>setVersion(null)}>{c.latestVersion}</button></div>
   {rule.definition.kind==='reference-allowed-values'&&<><p>{c.referenceComparison}</p><p>{c.referenceSelection}</p><Link href={'/reference-data/'+rule.definition.reference.setId}>{c.openReference}</Link>{canExecute&&<><Field title={c.referenceAsOf} hint={c.referenceAsOfHint}>{(label,description)=><input type="text" maxLength={24} dir="ltr" aria-labelledby={label} aria-describedby={description} disabled={command.locked||rule.currentVersion===null||rule.version!==rule.currentVersion} placeholder="YYYY-MM-DDTHH:mm:ss.sssZ" value={referenceDate} onChange={event=>{setReferenceDate(event.target.value);setInvalidDate(false);}}/>}</Field>{invalidDate&&<Notice tone="error">{c.referenceDateInvalid}</Notice>}<Notice>{c.privateTransfer}</Notice></>}<p>{c.sourceWindow}</p></>}
   <div className="quality-actions">{canWrite&&rule.version===rule.currentVersion&&<button className="button secondary" disabled={command.locked} onClick={()=>edit(rule)}>{c.editRule}</button>}{canExecute&&<button className="button primary" disabled={command.locked||rule.version!==rule.currentVersion} onClick={requestRun}>{command.busy?c.sending:c.run}</button>}</div>
   <details><summary>{c.evidence}</summary><dl className="detail-list"><div><dt>{c.ruleId}</dt><dd className="mono break-all">{rule.id}</dd></div><div><dt>{c.hash}</dt><dd className="mono break-all">{rule.definitionHash}</dd></div><div><dt>{c.table}</dt><dd><Link href={'/catalog/'+rule.definition.target.tableAssetId}>{rule.definition.target.tableAssetId}</Link></dd></div><div><dt>{c.column}</dt><dd><Link href={'/catalog/'+rule.definition.target.columnAssetId}>{rule.definition.target.columnAssetId}</Link></dd></div></dl></details>
   <RunHistory ruleId={id} open={selectRun} selectedRunId={runId} observedVersion={observedRun?.id===runId?observedRun.version:null}/>
   {runId&&<RunInspector key={runId} id={runId} canExecute={canExecute} close={()=>selectRun(null)} observed={observeRun}/>}
  </>}
 </div></section>;
}
function RunHistory({ruleId,open,selectedRunId,observedVersion}:{ruleId:string;open:(id:string)=>void;selectedRunId:string|null;observedVersion:number|null}){
 const c=useCopy(),{date,number}=useLocale(),[cursor,setCursor]=useState<string|null>(null);
 const path='/quality/rules/'+ruleId+'/runs?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):'');
 const resource=useResource<QualityPage<QualityRunView>>(path,5000);
 // Inspector polling can observe completion before the history timer. Refetch
 // through the history endpoint so current access and pagination stay authoritative.
 useEffect(()=>resource.reload(),[selectedRunId,observedVersion,resource.reload]);
 return <section className="quality-runs"><h3>{c.runHistory}</h3>{resource.error?<RequestError error={resource.error} retry={resource.reload} compact/>:resource.loading&&!resource.data||!resource.data?<LoadingState label={c.loading}/>:<>
  <DataGrid caption={c.runHistory} data={resource.data.items} columns={[
   {id:'open',header:c.viewRun,cell:({row})=><button className="text-button" aria-label={c.viewRun+' '+row.original.id} onClick={()=>open(row.original.id)}>{date(row.original.createdAt)}</button>},
   {id:'version',header:c.version,cell:({row})=>number(row.original.ruleVersion)},
   {id:'outcome',header:c.result,cell:({row})=><Outcome run={row.original}/>},
  ]} empty={<EmptyState compact title={c.noRuns} description={c.noRunsBody}/>}/>
  <Paging cursor={cursor} next={resource.data.nextCursor} label={c.runPages} change={setCursor} disabled={resource.loading}/>
 </>}</section>;
}
function RunInspector({id,canExecute,close,observed}:{id:string;canExecute:boolean;close:()=>void;observed:(run:QualityRunView|null)=>void}){
 const c=useCopy(),{locale,date,number}=useLocale(),resource=useResource<{run:QualityRunView}>('/quality/runs/'+id),run=resource.data?.run;
 const pinned=useResource<{rule:QualityRuleView}>(run?'/quality/rules/'+run.ruleId+'?version='+run.ruleVersion:null);
 const [reason,setReason]=useState(''),command=useQualityCommand<{run:QualityRunView}>(()=>{setReason('');resource.reload();});
 const pending=run?.status==='queued'||run?.status==='running';
 useEffect(()=>{if(!pending)return;const timer=window.setInterval(resource.reload,3000);return()=>window.clearInterval(timer);},[pending,resource.reload]);
 function cancel(event:FormEvent){event.preventDefault();if(run&&pending&&reason.trim()&&!command.locked)command.submit('/quality/runs/'+id+'/cancel',{expectedVersion:run.version,reason:reason.normalize('NFC').trim()});}
 const measurement=run?.measurement,rule=pinned.data?.rule,evidenceReady=!!run&&!!rule&&qualityEvidenceMatches(run,rule);
 useEffect(()=>{
  if(resource.error||pinned.error||!evidenceReady){observed(null);return;}
  if(!resource.loading&&!pinned.loading&&run?.id===id)observed(run);
 },[id,run,evidenceReady,resource.error,resource.loading,pinned.error,pinned.loading,observed]);
 useEffect(()=>()=>observed(null),[observed]);
 return <section className="quality-run-inspector" aria-label={c.evidence}><div className="quality-header"><h3>{c.evidence}</h3><div className="quality-actions"><button className="button secondary" disabled={command.locked||resource.loading} onClick={resource.reload}>{c.refresh}</button><button className="button secondary" disabled={command.locked} onClick={close}>{c.close}</button></div></div><Feedback command={command}/>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading&&!run||!run?<LoadingState label={c.loading}/>:<>
   <Outcome run={run}/><p className="supporting-text">{c.resultHint}</p>{run.errorCode&&<Notice tone="error">{c[run.errorCode]}</Notice>}
   {pinned.error?<RequestError error={pinned.error} retry={pinned.reload} compact/>:pinned.loading||!rule?<LoadingState label={c.loading}/>:!evidenceReady?<Notice tone="error">{c.evidenceUnavailable}</Notice>:<><h4>{rule.definition.name} · {c.version} {number(rule.version)}</h4><p>{rule.definition.kind==='completeness'?c.maximumNull:c.maximumInvalid}: <strong data-testid="quality-pinned-threshold">{percentageLabel(rule.definition.kind==='completeness'?rule.definition.maximumNullBasisPoints:rule.definition.maximumInvalidBasisPoints,locale)}</strong></p>
    {run.kind==='reference-allowed-values'&&<ReferenceRunEvidence reference={run.reference}/>}
    {measurement?<><p>{c.strategy}</p><dl className="quality-measurements"><div><dt>{c.observedRows}</dt><dd data-testid="quality-row-count">{number(measurement.rowCount)}</dd></div><div><dt>{c.nullRows}</dt><dd data-testid="quality-null-count">{number(measurement.nullCount)}</dd></div>
     {measurement.kind==='completeness'?<div><dt>{c.nullPercentage}</dt><dd>{measurement.rowCount?new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:2}).format(measurement.nullCount/measurement.rowCount):c.NO_DATA}</dd></div>:<><div><dt>{c.nonNullRows}</dt><dd data-testid="quality-non-null-count">{number(measurement.rowCount-measurement.nullCount)}</dd></div><div><dt>{c.invalidRows}</dt><dd data-testid="quality-invalid-count">{number(measurement.invalidCount)}</dd></div><div><dt>{c.invalidPercentage}</dt><dd>{measurement.rowCount>measurement.nullCount?new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:2}).format(measurement.invalidCount/(measurement.rowCount-measurement.nullCount)):c.NO_DATA}</dd></div></>}
     </dl><p>{measurement.kind==='completeness'?c.formula:c.referenceFormula}</p><p className="supporting-text">{c.rounding}</p>{run.verdict==='NO_DATA'&&<Notice>{measurement.kind==='completeness'?c.noDataHint:c.referenceNoData}</Notice>}
     <dl className="detail-list"><div><dt>{c.observationStart}</dt><dd><time dateTime={measurement.observedStartedAt}>{date(measurement.observedStartedAt)}</time></dd></div><div><dt>{c.observationEnd}</dt><dd><time dateTime={measurement.observedFinishedAt}>{date(measurement.observedFinishedAt)}</time></dd></div><div><dt>{c.elapsed}</dt><dd>{number(measurement.elapsedMs)}</dd></div></dl>
     <details><summary>{c.estimates}</summary><p>{c.estimateHint}</p><dl className="detail-list"><div><dt>{c.estimatedCost}</dt><dd>{number(measurement.estimatedCost)}</dd></div><div><dt>{c.estimatedBytes}</dt><dd>{number(measurement.estimatedBytes)}</dd></div></dl></details>
    </>:!pending&&<Notice>{c.failureHint}</Notice>}
   </>}
   <details><summary>{c.evidence}</summary><dl className="detail-list"><div><dt>{c.runId}</dt><dd className="mono break-all">{run.id}</dd></div><div><dt>{c.hash}</dt><dd className="mono break-all">{run.ruleHash}</dd></div><div><dt>{c.attempt}</dt><dd>{number(run.attempt)}</dd></div><div><dt>{c.requested}</dt><dd>{date(run.createdAt)}</dd></div><div><dt>{c.expires}</dt><dd>{date(run.expiresAt)}</dd></div>{measurement&&<div><dt>{c.sourceVersion}</dt><dd>{measurement.sourceVersion}</dd></div>}</dl></details>
   {pending&&canExecute&&<form className="quality-cancel" onSubmit={cancel}><p>{c.cancelHint}</p><Field title={c.cancelReason}>{label=><textarea required maxLength={4096} aria-labelledby={label} disabled={command.locked} value={reason} onChange={event=>setReason(event.target.value)}/>}</Field><button className="button secondary" disabled={command.locked||!reason.trim()}>{command.busy?c.sending:c.cancelRun}</button></form>}
  </>}
 </section>;
}
