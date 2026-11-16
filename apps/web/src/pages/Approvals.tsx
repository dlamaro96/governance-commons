// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useRef,useState,type FormEvent,type ReactNode} from 'react';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import type {ApprovalDefinition,ApprovalStageDefinition} from '../../../../packages/domain/src/approval-contracts';
import type {ApprovalDefinitionView,ApprovalRequestSummary,ApprovalRequestView,ApprovalStatus,ApprovalTaskView} from '../../../../packages/domain/src/approval-service';
import type {GlossaryTranslation} from '../../../../packages/domain/src/glossary-contracts';
import {parseApprovalDefinition} from '../../../../packages/domain/src/approval';
import {api,ApiError,useResource} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link,useNavigation} from '../navigation';
import {usePermission,useSession} from '../session';
import {approvalsCopy} from './approvals-copy';
import './approvals.css';

const useCopy=()=>{const {locale}=useLocale();return approvalsCopy[locale];};
const statuses:ApprovalStatus[]=['pending','ready','rejected','cancelled','expired','succeeded','failed'];
type Page<T>={items:T[];nextCursor:string|null};
function Heading({title,description,actions}:{title:string;description?:string;actions?:ReactNode}){return <header className="page-header"><div><h1 id="main-heading" tabIndex={-1}>{title}</h1>{description&&<p className="page-description">{description}</p>}</div>{actions&&<div className="approval-actions">{actions}</div>}</header>;}
function Badge({status}:{status:ApprovalStatus|'open'|'waiting'|'decided'}){const c=useCopy();return <span className="status-badge">{c[status]}</span>;}
function Panel({title,children}:{title:string;children:ReactNode}){return <section className="panel"><div className="panel-heading"><h2>{title}</h2></div><div className="panel-body">{children}</div></section>;}
function Pager({first,next,workflow=false}:{first:string;next:string|null;workflow?:boolean}){const c=useCopy();return <nav className="approval-pagination" aria-label={workflow?c.workflows:c.approvals}><Link className="button secondary" href={first}>{c.first}</Link>{next&&<Link className="button secondary" href={next}>{c.next}</Link>}</nav>;}
function Issues({error}:{error:Error|null}){const c=useCopy();return error instanceof ApiError&&error.issues.length?<Notice tone="error"><strong>{c.validation}</strong><ul className="approval-issues">{error.issues.map((issue,index)=><li key={index}><code>{issue.path||'/'}</code> — {issue.message}</li>)}</ul></Notice>:null;}
type Intent={path:string;body:string;key:string};
/** An uncertain response freezes the submitted bytes and key. Retrying never
 * reads edited form state or substitutes a newly generated idempotency key. */
function useCommand<T>(success:(value:T)=>void){
 const [error,setError]=useState<Error|null>(null),[intent,setIntent]=useState<Intent|null>(null),[busy,setBusy]=useState(false);
 const running=useRef(false),retained=useRef<Intent|null>(null);
 async function execute(value:Intent){if(running.current)return;running.current=true;setBusy(true);setError(null);retained.current=value;setIntent(value);
  try{const result=await api<T>(value.path,{method:'POST',headers:{'Idempotency-Key':value.key},body:value.body});retained.current=null;setIntent(null);success(result);}
  catch(caught){const failure=caught instanceof Error?caught:new Error('Request failed');setError(failure);
   if(failure instanceof ApiError&&failure.status<500&&![408,429].includes(failure.status)){retained.current=null;setIntent(null);}
  }finally{running.current=false;setBusy(false);}
 }
 return {error,busy,locked:busy||intent!==null,setError,
  submit:(path:string,body:unknown)=>{if(retained.current||running.current)return;void execute({path,body:JSON.stringify(body),key:crypto.randomUUID()});},
  retry:intent&&!busy?()=>{if(retained.current)void execute(retained.current);}:undefined};
}
function CommandFeedback({command,reload}:{command:ReturnType<typeof useCommand<unknown>>;reload?:()=>void}){const c=useCopy();return <>{command.error&&<RequestError error={command.error} compact retry={command.retry}/>}<Issues error={command.error}/>{command.locked&&!command.busy&&<Notice>{c.retryNote}</Notice>}{command.error instanceof ApiError&&command.error.status===409&&reload&&<button className="button secondary" type="button" onClick={reload}>{c.reload}</button>}</>;}

export function ApprovalsPage(){
 const c=useCopy(),{date}=useLocale(),{search,go}=useNavigation(),canRead=usePermission('catalog:read'),canWrite=usePermission('catalog:write'),permitted=canRead&&canWrite;
 const params=new URLSearchParams(search),status=params.get('status')??'pending',assigned=params.get('assignedToMe')!=='false',cursor=params.get('cursor');
 const selectors=new URLSearchParams({limit:'25',assignedToMe:String(assigned)});if(status&&status!=='all')selectors.set('status',status);if(cursor)selectors.set('cursor',cursor);
 const resource=useResource<Page<ApprovalRequestSummary>>(permitted?`/approval-requests?${selectors}`:null,15000);
 const location=(changes:Record<string,string|null>)=>{const next=new URLSearchParams(search);for(const[k,v]of Object.entries(changes)){if(v===null||v==='')next.delete(k);else next.set(k,v);}return '/approvals'+(next.size?'?'+next:'');};
 if(!permitted)return <PermissionDenied/>;
 return <><Heading title={c.inbox} description={c.inboxBody} actions={<button className="button secondary" onClick={resource.reload} disabled={resource.loading}>{c.refresh}</button>}/>
  <div className="approvals-toolbar"><label className="form-field"><span>{c.status}</span><select value={status} onChange={e=>go(location({status:e.target.value||'all',cursor:null}))}><option value="all">{c.allStatuses}</option>{statuses.map(value=><option key={value} value={value}>{c[value]}</option>)}</select></label>
   <label className="checkbox-label"><input type="checkbox" checked={assigned} onChange={e=>go(location({assignedToMe:String(e.target.checked),cursor:null}))}/>{c.assigned}</label><span className="supporting-text">{c.allParticipants}</span></div>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading&&!resource.data?<LoadingState label={c.loading}/>:resource.data?.items.length?<>
   <ul className="approval-list">{resource.data.items.map(item=><li key={item.id}><div className="approval-list-heading"><h2><Link href={`/approvals/${item.id}`}>{c.request} <bdi className="mono">{item.id}</bdi></Link></h2><Badge status={item.status}/></div>
    <dl className="approval-metadata"><div><dt>{c.pinned}</dt><dd>{item.workflowId} · {c.version} {item.workflowVersion}</dd></div><div><dt>{c.requester}</dt><dd><bdi className="mono">{item.requesterId}</bdi></dd></div><div><dt>{c.expires}</dt><dd>{date(item.expiresAt)}</dd></div></dl>
    {!item.preconditionsCurrent&&<p className="supporting-text">{c.stale}</p>}</li>)}</ul>
   <Pager first={location({cursor:null})} next={resource.data.nextCursor?location({cursor:resource.data.nextCursor}):null}/>
  </>:<EmptyState title={c.empty} description={c.emptyBody}/>}</>;
}

function WorkflowStages({definition}:{definition:ApprovalDefinition}){const c=useCopy(),{number}=useLocale();return <ol className="approval-stage-list">{definition.stages.map((stage,index)=><li className="approval-stage" key={stage.id}>
 <h3>{number(index+1)}. {stage.name}</h3><p className="supporting-text">{c.quorum}: {number(stage.quorum)} {c.of} {number(stage.assignments.length)} · {c.deadline}: {number(stage.deadlineSeconds)}</p><p className="supporting-text">{c.anyReject}</p>
 <p>{c.assignments}: {stage.assignments.map((assignment,i)=><span key={assignment}>{i>0?', ':''}<code>{assignment}</code></span>)}</p></li>)}</ol>;}
function Proposal({request}:{request:ApprovalRequestView}){const c=useCopy(),{payload}=request;
 const translations=payload.attributes.translations as unknown as GlossaryTranslation[];
 const additional=Object.fromEntries(Object.entries(payload.attributes).filter(([key])=>key!=='translations'));
 return <div className="approval-proposal"><dl className="detail-list"><div><dt>{c.primaryLocale}</dt><dd><bdi>{payload.primaryLocale}</bdi></dd></div><div><dt>{c.owner}</dt><dd className="mono break-all">{payload.ownerId}</dd></div>
  <div><dt>{c.visibility}</dt><dd>{c[payload.visibility]}</dd></div>{payload.visibility==='restricted'&&<div><dt>{c.allowed}</dt><dd>{payload.allowedIdentityIds.map(id=><p className="mono" key={id}>{id}</p>)}</dd></div>}
  <div><dt>{c.lifecycle}</dt><dd>{c[payload.state]}</dd></div><div><dt>{c.baseVersion}</dt><dd>{request.resourceVersion??c.newResource}</dd></div></dl>
  <h3>{c.translations}</h3>{translations.map(value=><section className="approval-stage" key={value.locale} lang={value.locale} dir="auto"><h4>{value.name} <small>({value.locale})</small></h4><p>{value.definition}</p>
   <dl className="detail-list"><div><dt>{c.synonyms}</dt><dd>{value.synonyms.join(', ')||c.noAliases}</dd></div><div><dt>{c.abbreviations}</dt><dd>{value.abbreviations.join(', ')||c.noAliases}</dd></div></dl>
   {!!value.examples.length&&<><h4>{c.examples}</h4><ul>{value.examples.map((example,i)=><li className="approval-reason" key={i}>{example}</li>)}</ul></>}</section>)}
  <h3>{c.links}</h3>{payload.links.length?<ul>{payload.links.map(link=><li key={`${link.kind}:${link.targetAssetId}`}><strong>{c[link.kind]}</strong> · <Link href={`/catalog/${link.targetAssetId}`}><bdi>{link.targetAssetId}</bdi></Link><p className="supporting-text">{c.linkVersion}: {link.targetAssetVersion} · {c.type}: <bdi>{link.typePin.relationTypeId}</bdi> · {c.version} {link.typePin.version}</p></li>)}</ul>:<p>{c.noLinks}</p>}
  {!!Object.keys(additional).length&&<details><summary>{c.attributes}</summary><pre tabIndex={0}>{JSON.stringify(additional,null,2)}</pre></details>}
  <details><summary>{c.pins}</summary><dl className="detail-list"><div><dt>{c.type}</dt><dd className="mono break-all">{payload.typePin.typeId}</dd></div><div><dt>{c.model}</dt><dd>{payload.typePin.modelId} · {c.version} {payload.typePin.version}</dd></div><div><dt>{c.hash}</dt><dd className="mono break-all">{payload.typePin.definitionHash}</dd></div><div><dt>{c.resolutionHash}</dt><dd className="mono break-all">{payload.typePin.resolutionHash}</dd></div><div><dt>{c.proposalDigest}</dt><dd className="mono break-all">{request.proposalDigest}</dd></div></dl></details>
 </div>;
}
function DecisionForm({task,request,locked,submit}:{task:ApprovalTaskView;request:ApprovalRequestView;locked:boolean;submit:(body:unknown)=>void}){
 const c=useCopy(),[reason,setReason]=useState(''),[choice,setChoice]=useState<'approve'|'reject'>('approve');
 const valid=!!reason.trim()&&reason.length<=4096;
 function decide(e:FormEvent){e.preventDefault();if(!locked&&valid&&request.preconditionsCurrent)submit({proposalDigest:request.proposalDigest,taskId:task.id,taskVersion:task.version,decision:choice,reason});}
 return <form onSubmit={decide}><fieldset disabled={locked||!request.preconditionsCurrent}><legend>{c.yourTask}</legend><label className="form-field"><span id={`reason-label-${task.id}`}>{c.reason}</span><textarea required maxLength={4096} value={reason} onChange={e=>setReason(e.target.value)} aria-labelledby={`reason-label-${task.id}`} aria-describedby={`reason-${task.id}`}/><small id={`reason-${task.id}`}>{c.reasonHint}</small></label>
  <label className="form-field"><span>{c.decisions}</span><select value={choice} onChange={e=>setChoice(e.target.value as 'approve'|'reject')}><option value="approve">{c.approve}</option><option value="reject">{c.reject}</option></select></label><button className="button primary" type="submit" disabled={!valid}>{c[choice]}</button></fieldset></form>;
}
export function ApprovalPage({id}:{id:string}){
 const c=useCopy(),{date,number}=useLocale(),session=useSession(),catalogRead=usePermission('catalog:read'),catalogWrite=usePermission('catalog:write'),canRead=catalogRead&&catalogWrite,canModels=usePermission('models:read');
 const resource=useResource<{request:ApprovalRequestView}>(canRead?`/approval-requests/${id}`:null,15000);
 const [saved,setSaved]=useState(false),[cancelReason,setCancelReason]=useState('');
 const command=useCommand<{request:ApprovalRequestView}>(()=>{setSaved(true);setCancelReason('');resource.reload();});
 if(!canRead)return <PermissionDenied/>;if(resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;if(!resource.data)return <LoadingState label={c.loading}/>;
 const request=resource.data.request,own=request.tasks.filter(task=>task.stageIndex===request.stageIndex&&task.status==='open'&&task.assignedIdentityId===session.user.id);
 return <><Link className="back-link" href="/approvals">{c.backInbox}</Link><Heading title={c.request} actions={<><Badge status={request.status}/><button className="button secondary" disabled={command.busy||resource.loading} onClick={resource.reload}>{c.refresh}</button></>}/>
  {saved&&<Notice tone="success">{c.recorded}</Notice>}<CommandFeedback command={command} reload={resource.reload}/>{request.status==='pending'&&!request.preconditionsCurrent&&<Notice>{c.stale}</Notice>}{request.status==='ready'&&<Notice>{c.readyNote}</Notice>}{request.status==='succeeded'&&<Notice tone="success"><Link href={`/glossary/${request.resourceId}`}>{c.openResource}</Link></Notice>}{request.status==='failed'&&<Notice tone="error">{c.failedPublication}</Notice>}
  <div className="approval-detail-grid"><div><Panel title={c.proposal}><Proposal request={request}/></Panel><Panel title={c.decisions}>{request.decisions.length?<ol className="approval-task-list">{request.decisions.map(decision=><li key={decision.id}><strong>{c[decision.decision]}</strong><p className="mono">{decision.actorId}</p><p className="approval-reason">{decision.reason}</p><small>{date(decision.decidedAt)} · {c.taskVersion} {number(decision.taskVersion)}</small></li>)}</ol>:<p>{c.noDecisions}</p>}</Panel></div>
   <div><Panel title={c.requestDetails}><dl className="detail-list"><div><dt>{c.request}</dt><dd className="mono break-all">{request.id}</dd></div><div><dt>{c.requester}</dt><dd className="mono break-all">{request.requesterId}</dd></div><div><dt>{c.stage}</dt><dd>{number(request.stageIndex+1)} {c.of} {number(request.workflow.definition.stages.length)}</dd></div><div><dt>{c.expires}</dt><dd>{date(request.expiresAt)}</dd></div><div><dt>{c.version}</dt><dd>{number(request.version)}</dd></div></dl>
    {request.status==='pending'&&<><ul className="approval-task-list">{request.tasks.filter(task=>task.stageIndex===request.stageIndex).map(task=><li key={task.id}><strong>{task.assignment}</strong> <Badge status={task.status}/><p className="mono">{task.assignedIdentityId}</p><small>{c.expires}: {date(task.expiresAt)}</small>{own.some(item=>item.id===task.id)&&<DecisionForm task={task} request={request} locked={command.locked} submit={body=>{setSaved(false);command.submit(`/approval-requests/${id}/decisions`,body);}}/>}</li>)}</ul>{!own.length&&<p className="supporting-text">{c.noAssignedTask}</p>}</>}
    {request.status==='pending'&&request.requesterId===session.user.id&&<details className="approval-cancel"><summary>{c.cancel}</summary><p>{c.cancelHint}</p><form onSubmit={e=>{e.preventDefault();if(cancelReason.trim()&&!command.locked){setSaved(false);command.submit(`/approval-requests/${id}/cancel`,{proposalDigest:request.proposalDigest,reason:cancelReason});}}}><label className="form-field"><span>{c.cancelReason}</span><textarea value={cancelReason} required maxLength={4096} disabled={command.locked} onChange={e=>setCancelReason(e.target.value)}/></label><button className="button secondary" disabled={command.locked||!cancelReason.trim()}>{command.busy?c.sending:c.cancel}</button></form></details>}
   </Panel><Panel title={c.pinned}><h3>{request.workflow.definition.name}</h3><p>{canModels?<Link href={`/workflows/${encodeURIComponent(request.workflowId)}?version=${request.workflowVersion}`}>{request.workflowId} · {c.version} {number(request.workflowVersion)}</Link>:<>{request.workflowId} · {c.version} {number(request.workflowVersion)}</>}</p><WorkflowStages definition={request.workflow.definition}/>{request.workflow.definition.separationOfDuties&&<p className="supporting-text">{c.sodHint}</p>}</Panel></div></div>
 </>;
}

export function WorkflowsPage(){const c=useCopy(),{search,go}=useNavigation(),{number,date}=useLocale(),canRead=usePermission('models:read'),canWrite=usePermission('models:write');
 const params=new URLSearchParams(search),q=params.get('q')??'',[draft,setDraft]=useState(q);useEffect(()=>setDraft(q),[q]);
 const selectors=new URLSearchParams({limit:'25'});if(q)selectors.set('q',q);if(params.get('cursor'))selectors.set('cursor',params.get('cursor')!);
 const resource=useResource<Page<ApprovalDefinitionView>>(canRead?`/workflow-definitions?${selectors}`:null);
 const location=(cursor?:string)=>'/workflows'+(q||cursor?'?'+new URLSearchParams({...q?{q}:{},...cursor?{cursor}:{}}):'');
 if(!canRead)return <PermissionDenied/>;
 return <><Heading title={c.workflows} description={c.workflowsBody} actions={canWrite&&<Link className="button primary" href="/workflows/new/definition">{c.newWorkflow}</Link>}/>{!canWrite&&<Notice>{c.readOnly}</Notice>}
  <form className="approvals-toolbar" onSubmit={e=>{e.preventDefault();go('/workflows'+(draft?'?'+new URLSearchParams({q:draft}):''));}}><label className="form-field"><span>{c.search}</span><input value={draft} maxLength={120} onChange={e=>setDraft(e.target.value)}/></label><button className="button secondary">{c.searchAction}</button>{q&&<Link className="button secondary" href="/workflows">{c.clear}</Link>}</form>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading&&!resource.data?<LoadingState label={c.loading}/>:resource.data?.items.length?<><ul className="approval-list">{resource.data.items.map(item=><li key={item.definition.id}><div className="approval-list-heading"><h2><Link href={`/workflows/${encodeURIComponent(item.definition.id)}`}>{item.definition.name}</Link></h2><span>{c.version} {number(item.definition.version)}</span></div><dl className="approval-metadata"><div><dt>{c.workflowId}</dt><dd><code>{item.definition.id}</code></dd></div><div><dt>{c.stages}</dt><dd>{number(item.definition.stages.length)}</dd></div><div><dt>{c.created}</dt><dd>{date(item.createdAt)}</dd></div></dl></li>)}</ul><Pager workflow first={location()} next={resource.data.nextCursor?location(resource.data.nextCursor):null}/></>:<EmptyState title={c.emptyWorkflows} description={c.emptyWorkflowsBody}/>}</>;
}
export function WorkflowPage({id}:{id:string}){const c=useCopy(),{search,go}=useNavigation(),{number,date}=useLocale(),canRead=usePermission('models:read'),canWrite=usePermission('models:write');
 const rawVersion=new URLSearchParams(search).get('version'),valid=rawVersion===null||/^[1-9][0-9]{0,9}$/.test(rawVersion)&&Number(rawVersion)<=2147483647;
 const resource=useResource<{workflow:ApprovalDefinitionView}>(canRead&&valid?`/workflow-definitions/${encodeURIComponent(id)}${rawVersion?'/versions/'+rawVersion:''}`:null);
 const [version,setVersion]=useState(rawVersion??'1');useEffect(()=>{if(resource.data)setVersion(String(resource.data.workflow.definition.version));},[resource.data]);
 if(!canRead)return <PermissionDenied/>;if(!valid)return <Notice tone="error">{c.malformedVersion}</Notice>;if(resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;if(!resource.data)return <LoadingState label={c.loading}/>;
 const workflow=resource.data.workflow;return <><Link className="back-link" href="/workflows">{c.backWorkflows}</Link><Heading title={workflow.definition.name} actions={canWrite&&<Link className="button primary" href={`/workflows/${encodeURIComponent(id)}/edit`}>{c.newVersion}</Link>}/>{new URLSearchParams(search).has('published')&&<Notice tone="success">{c.published}</Notice>}<Notice>{c.immutable}</Notice>
  <form className="approvals-toolbar" onSubmit={e=>{e.preventDefault();if(/^[1-9][0-9]*$/.test(version)&&Number(version)<=workflow.currentVersion)go(`/workflows/${encodeURIComponent(id)}?version=${version}`);}}><label className="form-field"><span>{c.viewVersion}</span><input type="number" min={1} max={workflow.currentVersion} step={1} required value={version} onChange={e=>setVersion(e.target.value)}/></label><button className="button secondary">{c.view}</button><span>{c.currentVersion}: {number(workflow.currentVersion)}</span></form>
  <div className="approval-detail-grid"><Panel title={c.reviewPlan}><WorkflowStages definition={workflow.definition}/><p>{workflow.definition.separationOfDuties?c.sodHint:c.anyReject}</p></Panel><Panel title={c.definition}><dl className="detail-list"><div><dt>{c.workflowId}</dt><dd>{workflow.definition.id}</dd></div><div><dt>{c.version}</dt><dd>{number(workflow.definition.version)}</dd></div><div><dt>{c.created}</dt><dd>{date(workflow.createdAt)}</dd></div><div><dt>{c.creator}</dt><dd className="mono break-all">{workflow.createdBy}</dd></div><div><dt>{c.hash}</dt><dd className="mono break-all">{workflow.definitionHash}</dd></div></dl><details><summary>{c.definition}</summary><pre className="workflow-definition-json" tabIndex={0}>{JSON.stringify(workflow.definition,null,2)}</pre></details></Panel></div></>;
}
export function WorkflowEditorPage({id}:{id?:string}){const c=useCopy(),canRead=usePermission('models:read'),canWrite=usePermission('models:write');
 const resource=useResource<{workflow:ApprovalDefinitionView}>(id&&canRead&&canWrite?`/workflow-definitions/${encodeURIComponent(id)}`:null);
 if(!canRead||!canWrite)return <PermissionDenied/>;if(id&&resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;if(id&&!resource.data)return <LoadingState label={c.loading}/>;
 return <WorkflowForm key={id?`${id}:${resource.data!.workflow.currentVersion}`:'new'} source={resource.data?.workflow} reload={resource.reload}/>;
}
function WorkflowForm({source,reload}:{source?:ApprovalDefinitionView;reload:()=>void}){const c=useCopy(),{go}=useNavigation(),{number}=useLocale(),fieldId=useId();
 const [draft,setDraft]=useState<ApprovalDefinition>(()=>source?{...structuredClone(source.definition),version:source.currentVersion+1}:{formatVersion:1,id:'',version:1,name:'',separationOfDuties:true,
  stages:[{id:'review',name:'',assignments:['steward'],quorum:1,deadlineSeconds:86400,rejection:'any'}]});
 const command=useCommand<{workflow:ApprovalDefinitionView}>(value=>go(`/workflows/${encodeURIComponent(value.workflow.definition.id)}?version=${value.workflow.definition.version}&published=1`));
 const change=(index:number,patch:Partial<ApprovalStageDefinition>)=>setDraft(old=>({...old,stages:old.stages.map((stage,i)=>i===index?{...stage,...patch}:stage)}));
 const move=(index:number,direction:number)=>setDraft(old=>{const stages=[...old.stages];[stages[index],stages[index+direction]]=[stages[index+direction],stages[index]];return {...old,stages};});
 function submit(e:FormEvent){e.preventDefault();if(command.locked)return;const parsed=parseApprovalDefinition(draft);if(!parsed.ok){command.setError(new ApiError(422,{code:'APPROVAL_DEFINITION_INVALID',issues:[...parsed.issues]}));return;}
  command.submit(source?`/workflow-definitions/${encodeURIComponent(source.definition.id)}/versions`:'/workflow-definitions',source?{definition:parsed.value,expectedVersion:source.currentVersion}:{definition:parsed.value});}
 return <><Link className="back-link" href={source?`/workflows/${encodeURIComponent(source.definition.id)}`:'/workflows'}>{c.backWorkflows}</Link><Heading title={source?c.newVersion:c.newWorkflow}/><Notice>{c.draftNotice}</Notice><CommandFeedback command={command} reload={reload}/>
  <form className="stacked-form workflow-form" onSubmit={submit}><fieldset disabled={command.locked}><legend>{c.definition}</legend><div className="form-row"><label className="form-field"><span>{c.workflowName}</span><input required maxLength={240} value={draft.name} onChange={e=>setDraft({...draft,name:e.target.value})}/></label><label className="form-field"><span>{c.workflowId}</span><input required maxLength={64} pattern="[A-Za-z_][A-Za-z0-9_.-]*" dir="ltr" readOnly={!!source} value={draft.id} onChange={e=>setDraft({...draft,id:e.target.value})}/></label></div>
   <p>{c.version}: {number(draft.version)}</p><label className="checkbox-label"><input type="checkbox" checked={draft.separationOfDuties} onChange={e=>setDraft({...draft,separationOfDuties:e.target.checked})}/>{c.sod}</label><p className="supporting-text">{c.sodHint}</p>
   {draft.stages.map((stage,index)=><fieldset className="workflow-stage-editor" key={index}><legend>{c.stage} {number(index+1)}</legend><div className="form-row"><label className="form-field"><span>{c.stageName}</span><input required maxLength={240} value={stage.name} onChange={e=>change(index,{name:e.target.value})}/></label><label className="form-field"><span>{c.stageId}</span><input required maxLength={64} pattern="[A-Za-z_][A-Za-z0-9_.-]*" dir="ltr" value={stage.id} onChange={e=>change(index,{id:e.target.value})}/></label></div>
    <label className="form-field"><span id={`${fieldId}-assignments-${index}`}>{c.assignments}</span><input required dir="ltr" maxLength={1040} aria-labelledby={`${fieldId}-assignments-${index}`} aria-describedby={`${fieldId}-assignments-help-${index}`} value={stage.assignments.join(',')} onChange={e=>change(index,{assignments:e.target.value.split(',').map(value=>value.trim())})}/><small id={`${fieldId}-assignments-help-${index}`}>{c.assignmentHint}</small></label>
    <div className="form-row"><label className="form-field"><span>{c.quorum}</span><input required type="number" min={1} max={Math.min(16,stage.assignments.length)} step={1} value={Number.isFinite(stage.quorum)?stage.quorum:''} onChange={e=>change(index,{quorum:e.target.valueAsNumber})}/></label><label className="form-field"><span>{c.deadline}</span><input required type="number" min={1} max={31536000} step={1} value={Number.isFinite(stage.deadlineSeconds)?stage.deadlineSeconds:''} onChange={e=>change(index,{deadlineSeconds:e.target.valueAsNumber})}/></label></div><p className="supporting-text">{c.anyReject}</p>
    <div className="workflow-order-controls"><button className="button secondary" type="button" disabled={index===0} aria-label={`${c.moveUp}: ${stage.name||index+1}`} onClick={()=>move(index,-1)}>{c.moveUp}</button><button className="button secondary" type="button" disabled={index===draft.stages.length-1} aria-label={`${c.moveDown}: ${stage.name||index+1}`} onClick={()=>move(index,1)}>{c.moveDown}</button><button className="button secondary" type="button" disabled={draft.stages.length===1} aria-label={`${c.removeStage}: ${stage.name||index+1}`} onClick={()=>setDraft({...draft,stages:draft.stages.filter((_,i)=>i!==index)})}>{c.removeStage}</button></div>
   </fieldset>)}
   <button type="button" className="button secondary" disabled={draft.stages.length>=16} onClick={()=>{let suffix=draft.stages.length+1;while(draft.stages.some(stage=>stage.id===`stage_${suffix}`))suffix++;setDraft({...draft,stages:[...draft.stages,{id:`stage_${suffix}`,name:'',assignments:['reviewer'],quorum:1,deadlineSeconds:86400,rejection:'any'}]});}}>{c.addStage}</button>
  </fieldset><button className="button primary" disabled={command.locked} type="submit">{command.busy?c.publishing:c.publish}</button></form></>;
}
