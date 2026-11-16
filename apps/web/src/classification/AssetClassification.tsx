// SPDX-License-Identifier: Apache-2.0
import {useEffect,useState,type FormEvent} from 'react';
import {DetailDrawer,EmptyState,LoadingState,Notice,StatusBadge} from '../../../../packages/ui/src';
import type {ClassificationAssignmentView,ClassificationEvaluationView,ClassificationPage,ClassificationProposal,ClassificationRuleView,ClassificationSuggestionView} from '../../../../packages/domain/src/classification-contracts';
import type {ApprovalDefinitionView} from '../../../../packages/domain/src/approval-service';
import {useResource} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {usePermission,useSession} from '../session';
import type {Member} from '../types';
import {Evidence,Feedback,Field,LabelPin,Pager,Panel,Picker,Pin,useCommand,useContextKey,useCopy} from './shared';
import {RuleSummary} from './Definitions';
import {localExpiry,pinOf,proposalExpiry,reviewAssignments,reviewerKeys} from './presentation';
import './classification.css';

type ReviewTarget={kind:'apply';suggestion:ClassificationSuggestionView}|{kind:'withdraw';assignment:ClassificationAssignmentView};
export function AssetClassification({assetId,assetVersion,assetType}:{assetId:string;assetVersion:number;assetType:string}){
 const context=useContextKey(),catalog=usePermission('catalog:read'),read=usePermission('classification:read');
 if(!catalog||!read)return <PermissionDenied/>;
 return <AssetWorkspace key={context+':'+assetId+':'+assetVersion} assetId={assetId} assetVersion={assetVersion} assetType={assetType}/>;
}
function AssetWorkspace({assetId,assetVersion,assetType}:{assetId:string;assetVersion:number;assetType:string}){
 const c=useCopy(),canWrite=usePermission('classification:write'),[assignmentCursor,setAssignmentCursor]=useState<string|null>(null),[suggestionCursor,setSuggestionCursor]=useState<string|null>(null),[review,setReview]=useState<ReviewTarget|null>(null),[receipt,setReceipt]=useState<string|null>(null);
 const assignments=useResource<ClassificationPage<ClassificationAssignmentView>>('/assets/'+assetId+'/classifications?limit=25'+(assignmentCursor?'&cursor='+encodeURIComponent(assignmentCursor):''));
 const suggestions=useResource<ClassificationPage<ClassificationSuggestionView>>('/assets/'+assetId+'/classification-suggestions?limit=25'+(suggestionCursor?'&cursor='+encodeURIComponent(suggestionCursor):''));
 function refresh(){assignments.reload();suggestions.reload();}
 return <section className="classification-workspace" aria-label={c.title}><header className="classification-heading"><div><h2>{c.title}</h2><p>{c.intro}</p></div><button className="button secondary" disabled={assignments.loading||suggestions.loading} onClick={refresh}>{c.refresh}</button></header>
  <Notice>{c.metadataOnly}</Notice>{!canWrite&&<Notice>{c.readOnly}</Notice>}
  {receipt&&<Notice tone="success"><p>{c.submitted}</p><Link className="button secondary" href={'/approvals/'+receipt}>{c.openApproval}</Link></Notice>}
  {['table','view','column'].includes(assetType)?canWrite&&<Evaluation assetId={assetId} assetVersion={assetVersion} assetType={assetType} evaluated={()=>{setSuggestionCursor(null);suggestions.reload();}}/>:<Notice>{c.unsupportedAsset}</Notice>}
  <Panel title={c.approved}>{assignments.error?<RequestError error={assignments.error} retry={assignments.reload}/>:assignments.loading||!assignments.data?<LoadingState label={c.loading}/>:<>
   {assignments.data.items.length?<ul className="classification-records">{assignments.data.items.map(value=><li key={value.id}><div className="classification-heading"><LabelPin label={value.label}/><StatusBadge status={value.status==='active'?'verified':'stale'} label={value.status==='active'?c.reviewed:c.withdrawn}/></div><p>{c.assignmentVersion}: {value.version}</p><Evidence value={value.evidence} current={value.evidenceCurrent}/><p className="classification-text">{value.reason}</p><Link href={'/approvals/'+value.approvalInstanceId}>{c.approval}</Link>
    {canWrite&&value.status==='active'&&<div className="classification-actions"><button className="button secondary" onClick={()=>setReview({kind:'withdraw',assignment:value})}>{c.proposeWithdraw}</button></div>}
   </li>)}</ul>:<EmptyState compact title={c.emptyAssignments}/>}
   <Pager cursor={assignmentCursor} next={assignments.data.nextCursor} change={setAssignmentCursor}/>
  </>}</Panel>
  <Panel title={c.suggestions}>{suggestions.error?<RequestError error={suggestions.error} retry={suggestions.reload}/>:suggestions.loading||!suggestions.data?<LoadingState label={c.loading}/>:<>
   {suggestions.data.items.length?<ul className="classification-records">{suggestions.data.items.map(value=><li key={value.id}><LabelPin label={value.evidence.label}/><Evidence value={value.evidence} hash={value.evidenceHash} current={value.evidenceCurrent}/><p>{c.expectedVersion}: {value.currentAssignmentVersion}</p>
    {canWrite&&<div className="classification-actions"><button className="button primary" disabled={!value.evidenceCurrent} onClick={()=>setReview({kind:'apply',suggestion:value})}>{c.proposeApply}</button>{!value.evidenceCurrent&&<p>{c.staleDisabled}</p>}</div>}
   </li>)}</ul>:<EmptyState compact title={c.emptySuggestions}/>}
   <Pager cursor={suggestionCursor} next={suggestions.data.nextCursor} change={setSuggestionCursor}/>
  </>}</Panel>
  {review&&<ProposalDialog key={review.kind+':'+(review.kind==='apply'?review.suggestion.id:review.assignment.id)} target={review} close={()=>setReview(null)} submitted={id=>{setReview(null);setReceipt(id);refresh();}}/>}
 </section>;
}
function Evaluation({assetId,assetVersion,assetType,evaluated}:{assetId:string;assetVersion:number;assetType:string;evaluated:()=>void}){
 const c=useCopy(),[ruleId,setRuleId]=useState<string|null>(null),[result,setResult]=useState<ClassificationEvaluationView|null>(null),[locked,setLocked]=useState(false);
 return <Panel title={c.evaluate}><Picker<ClassificationRuleView> path="/classification/rules" title={c.selectRule} idOf={value=>value.id} labelOf={value=>value.definition.name+' · '+c.version+' '+value.version} selectedId={ruleId??''} disabled={locked} filter={value=>value.definition.status==='active'&&value.definition.assetTypes.some(type=>type===assetType)} onSelect={value=>{setRuleId(value.id);setResult(null);}}/>
  {ruleId&&<EvaluateSelected key={ruleId} id={ruleId} assetId={assetId} assetVersion={assetVersion} assetType={assetType} lock={setLocked} complete={value=>{setResult(value);evaluated();}}/>}
  {result&&<section className="classification-card" aria-label={c.evaluation}><h4>{result.outcome==='matched'?c.matched:result.outcome==='not_matched'?c.notMatched:c.unsupported}</h4><p>{c.suggestionOnly}</p><Evidence value={result.evidence} hash={result.evidenceHash}/></section>}
 </Panel>;
}
function EvaluateSelected({id,assetId,assetVersion,assetType,complete,lock}:{id:string;assetId:string;assetVersion:number;assetType:string;complete:(value:ClassificationEvaluationView)=>void;lock:(value:boolean)=>void}){
 const c=useCopy(),resource=useResource<{rule:ClassificationRuleView}>('/classification/rules/'+id),rule=resource.data?.rule;
 const command=useCommand<{evaluation:ClassificationEvaluationView}>(value=>complete(value.evaluation));
 useEffect(()=>lock(command.locked),[command.locked,lock]);
 const valid=rule?.definition.status==='active'&&rule.definition.assetTypes.some(type=>type===assetType);
 return <><Feedback command={command}/>{resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading||!rule?<LoadingState label={c.loading}/>:<>
  <h4>{rule.definition.name}</h4><p>{c.ruleVersion}: {rule.version}</p><RuleSummary value={rule}/><details><summary>{c.pin}</summary><Pin pin={rule}/></details>
  <div className="classification-actions"><button type="button" className="button primary" disabled={command.locked||!valid} onClick={()=>command.submit('/assets/'+assetId+'/classification-evaluations',{id:crypto.randomUUID(),expectedAssetVersion:assetVersion,rule:pinOf(rule)})}>{command.busy?c.evaluating:c.evaluate}</button></div>
 </>}</>;
}
function ProposalDialog({target,close,submitted}:{target:ReviewTarget;close:()=>void;submitted:(id:string)=>void}){
 const c=useCopy(),models=usePermission('models:read'),directory=usePermission('catalog:write'),[locked,setLocked]=useState(false);
 return <DetailDrawer open onOpenChange={open=>{if(!open&&!locked)close();}} title={target.kind==='apply'?c.applyReview:c.withdrawReview} description={c.reviewHint} closeLabel={c.close}>
  {!models||!directory?<Notice>{c.discoveryMissing}</Notice>:<ProposalForm target={target} close={close} submitted={submitted} locked={locked} lock={setLocked}/>}
 </DetailDrawer>;
}
function ProposalForm({target,close,submitted,locked,lock}:{target:ReviewTarget;close:()=>void;submitted:(id:string)=>void;locked:boolean;lock:(value:boolean)=>void}){
 const c=useCopy(),[workflowId,setWorkflowId]=useState<string|null>(null);
 const evidence=target.kind==='apply'?target.suggestion.evidence:target.assignment.evidence;
 return <div className="classification-form"><LabelPin label={evidence.label}/><p>{c.expectedVersion}: {target.kind==='apply'?target.suggestion.currentAssignmentVersion:target.assignment.version}</p><Evidence value={evidence} current={target.kind==='apply'?target.suggestion.evidenceCurrent:target.assignment.evidenceCurrent}/>
  <Picker<ApprovalDefinitionView> path="/workflow-definitions" title={c.workflow} idOf={value=>value.definition.id} labelOf={value=>value.definition.name+' · '+c.version+' '+value.definition.version} selectedId={workflowId??''} disabled={locked} filter={value=>value.definition.separationOfDuties} empty={c.workflowMissing} onSelect={value=>setWorkflowId(value.definition.id)}/>
  <p>{c.workflowHint}</p>{workflowId&&<ReviewForm key={workflowId} workflowId={workflowId} target={target} close={close} submitted={submitted} lock={lock}/>}
 </div>;
}
function ReviewForm({workflowId,target,close,submitted,lock}:{workflowId:string;target:ReviewTarget;close:()=>void;submitted:(id:string)=>void;lock:(value:boolean)=>void}){
 const c=useCopy(),session=useSession(),{number}=useLocale(),[assignments,setAssignments]=useState<Record<string,string>>({}),[expires,setExpires]=useState(localExpiry),[reason,setReason]=useState(''),[confirmed,setConfirmed]=useState(false),[invalid,setInvalid]=useState(false);
 const [id]=useState(()=>crypto.randomUUID()),workflow=useResource<{workflow:ApprovalDefinitionView}>('/workflow-definitions/'+encodeURIComponent(workflowId)),members=useResource<{items:Member[]}>('/members');
 const selected=workflow.data?.workflow,keys=selected?reviewerKeys(selected.definition):[];
 const active=members.data?.items.filter(member=>member.id!==session.user.id)??[];
 const bindings=selected?reviewAssignments(selected.definition,assignments,active.map(member=>member.id),session.user.id):null;
 const command=useCommand<{instance:{id:string}}>(value=>submitted(value.instance.id));
 useEffect(()=>lock(command.locked),[command.locked,lock]);
 useEffect(()=>{setConfirmed(false);setAssignments({});},[selected?.definition.id,selected?.definition.version,selected?.definitionHash]);
 function submit(event:FormEvent){event.preventDefault();if(command.locked)return;const expiry=proposalExpiry(expires);
  if(!confirmed||!selected||workflow.loading||workflow.error||members.loading||members.error||!bindings||!expiry||target.kind==='withdraw'&&!reason.trim()){setInvalid(true);return;}
  const proposal:ClassificationProposal={id,change:target.kind==='apply'?{kind:'apply',suggestionId:target.suggestion.id,expectedAssignmentVersion:target.suggestion.currentAssignmentVersion}:{kind:'withdraw',assignmentId:target.assignment.id,expectedAssignmentVersion:target.assignment.version,reason:reason.normalize('NFC').trim()},workflow:{id:selected.definition.id,version:selected.definition.version,definitionHash:selected.definitionHash},assignments:bindings,expiresAt:expiry};
  command.submit('/classification/proposals',proposal);
 }
 return <form className="classification-form" onSubmit={submit}><Feedback command={command}/>{invalid&&<Notice tone="error">{c.invalid}</Notice>}
  {workflow.error?<RequestError error={workflow.error} retry={workflow.reload}/>:workflow.loading||!selected?<LoadingState label={c.loading}/>:!selected.definition.separationOfDuties?<Notice tone="error">{c.workflowHint}</Notice>:<>
   <div className="classification-heading"><h4>{selected.definition.name} · {c.version} {number(selected.definition.version)}</h4><button type="button" className="button secondary" disabled={command.locked} onClick={()=>{setConfirmed(false);workflow.reload();members.reload();}}>{c.refresh}</button></div><Pin pin={{id:selected.definition.id,version:selected.definition.version,definitionHash:selected.definitionHash}}/>
   <ol className="classification-conditions">{selected.definition.stages.map(stage=><li key={stage.id}><strong>{stage.name}</strong><p>{c.quorum}: {number(stage.quorum)} / {number(stage.assignments.length)} · {c.deadline}: {number(stage.deadlineSeconds)}</p><p className="mono">{stage.assignments.join(', ')}</p></li>)}</ol>
  </>}
  {members.error?<RequestError error={members.error} retry={members.reload}/>:members.loading?<LoadingState label={c.loading}/>:!active.length&&<Notice>{c.noMembers}</Notice>}
  <fieldset disabled={command.locked||workflow.loading||!!workflow.error||members.loading||!!members.error}><legend>{c.reviewers}</legend><p>{c.reviewerHint}</p>
   {keys.map(key=><Field key={key} title={c.reviewer+': '+key}>{label=><select required aria-labelledby={label} value={assignments[key]??''} onChange={event=>{setConfirmed(false);setAssignments(previous=>({...previous,[key]:event.target.value}));}}><option value="">{c.choose}</option>{active.map(member=><option key={member.id} value={member.id} disabled={Object.entries(assignments).some(([other,id])=>other!==key&&id===member.id)}>{member.name} · {member.role}</option>)}</select>}</Field>)}
   {target.kind==='withdraw'&&<Field title={c.withdrawReason}>{label=><textarea required maxLength={4096} rows={3} aria-labelledby={label} dir="auto" value={reason} onChange={event=>{setReason(event.target.value);setConfirmed(false);}}/>}</Field>}
   <Field title={c.expiry} hint={c.expiryHint}>{(label,hint)=><input required type="datetime-local" aria-labelledby={label} aria-describedby={hint} value={expires} onChange={event=>{setExpires(event.target.value);setConfirmed(false);}}/>}</Field>
   <label className="checkbox-label"><input type="checkbox" required checked={confirmed} onChange={event=>setConfirmed(event.target.checked)}/>{c.confirm}</label>
  </fieldset>
  <div className="classification-actions"><button type="button" className="button secondary" disabled={command.locked} onClick={close}>{c.cancel}</button><button className="button primary" type="submit" disabled={command.locked||!bindings||!confirmed||!selected?.definition.separationOfDuties||workflow.loading||!!workflow.error||members.loading||!!members.error}>{command.busy?c.submitting:c.submit}</button></div>
 </form>;
}
