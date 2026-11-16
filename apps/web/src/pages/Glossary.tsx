// SPDX-License-Identifier: Apache-2.0
import {useEffect,useId,useRef,useState,type FormEvent,type ReactNode} from 'react';
import {EmptyState,LoadingState,Notice} from '../../../../packages/ui/src';
import {parseGlossaryPublication} from '../../../../packages/domain/src/glossary';
import {validateAttributes,type AttributeSchema,type AttributeValues} from '../../../../packages/domain/src/model';
import {resolveRelationDefinition,validateRelationEndpoints} from '../../../../packages/domain/src/relation';
import type {GlossaryLink,GlossaryPublicationInput,GlossaryTranslation} from '../../../../packages/domain/src/glossary-contracts';
import type {GlossaryProposalInput} from '../../../../packages/domain/src/glossary-service';
import type {ApprovalDefinitionView,ApprovalRequestView} from '../../../../packages/domain/src/approval-service';
import type {RelationEndpointPolicyState,RelationTypeSummary,RelationTypeView} from '../../../../packages/domain/src/relation-contracts';
import type {PublishedAssetType,AssetTypeState} from '../assetTypes/contracts';
import type {Asset,Member} from '../types';
import {ValueFields,serializeAttributes} from '../models/ValueFields';
import {api,ApiError,useResource} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {Link,useNavigation} from '../navigation';
import {useSession} from '../session';
import {glossaryCopy} from './glossary-copy';
import './glossary.css';

export interface GlossaryTermContext {resourceId:string;resourceVersion:number;publication:GlossaryPublicationInput}
type Page<T>={items:T[];nextCursor:string|null};
type TypeSummary=Pick<PublishedAssetType,'id'|'typeId'|'currentVersion'>;
type TypeContext={view:PublishedAssetType;ancestors:RelationEndpointPolicyState['ancestorTypes']};
type TargetContext={asset:Asset;state:AssetTypeState;type:TypeContext};
class FormIssue extends Error {constructor(readonly copy: keyof typeof glossaryCopy.en){super(copy);}}
const useCopy=()=>{const {locale}=useLocale();return glossaryCopy[locale];};
const useRights=()=>{const p=useSession().permissions;return {read:p.includes('catalog:read'),models:p.includes('models:read'),write:['catalog:read','catalog:write','models:read','models:write'].every(value=>p.includes(value))};};
const pin=(value:PublishedAssetType)=>({typeId:value.typeId,modelId:value.id,version:value.version,definitionHash:value.definitionHash,resolutionHash:value.resolutionHash});
function termType(selected:TypeContext,root:PublishedAssetType){return selected.view.typeId===root.typeId||selected.ancestors.some(parent=>parent.typeId===root.typeId&&parent.id===root.id);}
async function loadType(id:string,version?:number):Promise<TypeContext>{
 const {type}=await api<{type:PublishedAssetType}>(`/asset-types/${encodeURIComponent(id)}${version?'/versions/'+version:''}`);
 const ancestors:RelationEndpointPolicyState['ancestorTypes'][number][]=[];
 // Published types already bound the complete dependency set (maximum64).
 // Load exact ancestor identities; display labels never establish eligibility.
 for(const dependency of type.resolved.dependencies){const parent=await api<{type:PublishedAssetType}>(`/asset-types/${encodeURIComponent(dependency.id)}/versions/${dependency.version}`);ancestors.push({typeId:parent.type.typeId,id:dependency.id,version:dependency.version});}
 return {view:type,ancestors};
}
function policy(context:TypeContext):NonNullable<RelationEndpointPolicyState['policy']>{return {definition:context.view.definition,...context.view.resolved};}
function Field({title,hint,children}:{title:string;hint?:string;children:(id:string,hintId:string)=>ReactNode}){const id=useId();return <label className="form-field"><span id={id}>{title}</span>{children(id,`${id}-help`)}{hint&&<small id={`${id}-help`}>{hint}</small>}</label>;}
function Heading({title,body,actions}:{title:string;body?:string;actions?:ReactNode}){return <header className="page-header"><div><h1 id="main-heading" tabIndex={-1}>{title}</h1>{body&&<p className="page-description">{body}</p>}</div>{actions&&<div className="glossary-actions">{actions}</div>}</header>;}
function Errors({error,retry}:{error:Error|null;retry?:()=>void}){const c=useCopy();return error instanceof FormIssue?<Notice tone="error">{c[error.copy]}</Notice>:error?<><RequestError error={error} retry={retry} compact/>{error instanceof ApiError&&!!error.issues.length&&<Notice tone="error"><strong>{c.validation}</strong><ul className="glossary-issues">{error.issues.map((issue,i)=><li key={i}><code>{issue.path||'/'}</code> — {issue.message}</li>)}</ul></Notice>}</>:null;}

/** Pages remain server-filtered and cursor-bound; choosing an item loads its
 * exact canonical detail. No first-page assumption or full inventory fetch. */
function Picker<T>({path,title,selected,onSelect,idOf,labelOf,maxQuery=64}:{path:string;title:string;selected?:{id:string;label:string};onSelect:(item:T)=>void;idOf:(item:T)=>string;labelOf:(item:T)=>string;maxQuery?:number}){
 const c=useCopy(),[draft,setDraft]=useState(''),[q,setQ]=useState(''),[cursor,setCursor]=useState<string|null>(null);
 const params=new URLSearchParams({limit:'25'});if(q)params.set('q',q);if(cursor)params.set('cursor',cursor);
 const resource=useResource<Page<T>>(`${path}${path.includes('?')?'&':'?'}${params}`),items=resource.data?.items??[];
 return <section className="glossary-picker" aria-label={title}><div className="glossary-picker-search"><Field title={`${c.search}: ${title}`}>{label=><input type="search" aria-labelledby={label} maxLength={maxQuery} value={draft} onChange={event=>setDraft(event.target.value)} onKeyDown={event=>{if(event.key==='Enter'){event.preventDefault();setQ(draft);setCursor(null);}}}/>}</Field><button type="button" className="button secondary" onClick={()=>{setQ(draft);setCursor(null);}}>{c.search}</button></div>
  {resource.error?<Errors error={resource.error} retry={resource.reload}/>:resource.loading?<LoadingState label={c.loading}/>:<><Field title={title}>{label=><select aria-labelledby={label} value={selected?.id??''} onChange={event=>{const row=items.find(item=>idOf(item)===event.target.value);if(row)onSelect(row);}}><option value="">{c.choose}</option>{selected&&!items.some(item=>idOf(item)===selected.id)&&<option value={selected.id}>{selected.label} ({c.selected})</option>}{items.map(item=><option key={idOf(item)} value={idOf(item)}>{labelOf(item)}</option>)}</select>}</Field>{!items.length&&<p>{c.none}</p>}
   <div className="glossary-page-controls"><button type="button" className="button secondary" disabled={!cursor} onClick={()=>setCursor(null)}>{c.first}</button><button type="button" className="button secondary" disabled={!resource.data?.nextCursor} onClick={()=>setCursor(resource.data!.nextCursor)}>{c.next}</button></div></>}
 </section>;
}

export function GlossaryPage(){const c=useCopy(),rights=useRights(),{search,go}=useNavigation();
 const params=new URLSearchParams(search),q=params.get('q')??'',[draft,setDraft]=useState(q);useEffect(()=>setDraft(q),[q]);
 const query=new URLSearchParams({type:'business_term',limit:'25'});if(q)query.set('q',q);if(params.get('cursor'))query.set('cursor',params.get('cursor')!);
 const resource=useResource<Page<Asset>>(rights.read?`/assets?${query}`:null);
 const href=(cursor?:string)=>'/glossary'+(q||cursor?'?'+new URLSearchParams({...q?{q}:{},...cursor?{cursor}:{}}):'');
 if(!rights.read)return <PermissionDenied/>;
 return <><Heading title={c.glossary} body={c.intro} actions={rights.write&&<Link className="button primary" href="/glossary/new">{c.newTerm}</Link>}/>{!rights.write&&<Notice>{c.readOnly}</Notice>}
  <form className="glossary-toolbar" onSubmit={event=>{event.preventDefault();go('/glossary'+(draft?'?'+new URLSearchParams({q:draft}):''));}}><Field title={c.searchTerms}>{label=><input type="search" maxLength={200} aria-labelledby={label} value={draft} onChange={event=>setDraft(event.target.value)}/>}</Field><button className="button secondary">{c.search}</button>{q&&<Link className="button secondary" href="/glossary">{c.clear}</Link>}</form>
  {resource.error?<RequestError error={resource.error} retry={resource.reload}/>:!resource.data?<LoadingState label={c.loading}/>:resource.data.items.length?<><ul className="glossary-list">{resource.data.items.map(term=><li key={term.id}><h2><Link href={`/glossary/${term.id}`}>{term.name}</Link></h2><p>{term.description}</p><span>{c.version}: {term.version}</span></li>)}</ul><nav className="glossary-page-controls" aria-label={c.glossary}><Link className="button secondary" href={href()}>{c.first}</Link>{resource.data.nextCursor&&<Link className="button secondary" href={href(resource.data.nextCursor)}>{c.next}</Link>}</nav></>:<EmptyState title={c.empty} description={c.emptyBody}/>}</>;
}
function Publication({value}:{value:GlossaryPublicationInput}){
 const c=useCopy(),canListMembers=useSession().permissions.includes('catalog:write');
 const members=useResource<{items:Member[]}>(canListMembers?'/members':null),parsed=parseGlossaryPublication(value);
 if(!parsed.ok)return <Notice tone="error">{c.sourceUnavailable}</Notice>;
 const names=new Map(members.data?.items.map(member=>[member.id,member.name])??[]);
 const memberName=(id:string)=>names.get(id)??(canListMembers&&members.loading?c.loading:c.memberUnavailable);
 return <><dl className="glossary-publication-summary"><div><dt>{c.owner}</dt><dd><bdi>{memberName(value.ownerId)}</bdi></dd></div><div><dt>{c.visibility}</dt><dd>{c[value.visibility]}</dd></div><div><dt>{c.state}</dt><dd>{c[value.state]}</dd></div></dl>
  {parsed.value.translations.map(translation=><section key={translation.locale} className="glossary-translation" lang={translation.locale} dir="auto"><h2>{translation.name} <small>({translation.locale})</small></h2><p className="glossary-value">{translation.definition}</p><dl className="detail-list"><div><dt>{c.synonyms}</dt><dd>{translation.synonyms.join(', ')}</dd></div><div><dt>{c.abbreviations}</dt><dd>{translation.abbreviations.join(', ')}</dd></div></dl>{translation.examples.map((example,index)=><p className="glossary-value" key={index}>{example}</p>)}</section>)}
  {value.visibility==='restricted'&&<section><h2>{c.allowed}</h2><ul>{value.allowedIdentityIds.map(id=><li key={id}><bdi>{memberName(id)}</bdi></li>)}</ul></section>}
  <h2>{c.links}</h2>{value.links.length?<ul className="glossary-link-list">{value.links.map(link=><li key={`${link.kind}:${link.targetAssetId}`}><strong>{c[link.kind]}</strong> · <Link href={`/catalog/${link.targetAssetId}`}>{link.targetAssetId}</Link> · {c.version} {link.targetAssetVersion}<p className="glossary-pins">{link.typePin.relationTypeId} · {c.version} {link.typePin.version}</p></li>)}</ul>:<p>{c.noLinks}</p>}
  <details className="glossary-publication-details"><summary>{c.technicalDetails}</summary><dl className="detail-list"><div><dt>{c.owner}</dt><dd className="mono break-all"><bdi>{value.ownerId}</bdi></dd></div>{value.visibility==='restricted'&&<div><dt>{c.allowed}</dt><dd className="glossary-pins">{value.allowedIdentityIds.map(id=><div key={id}><bdi>{id}</bdi></div>)}</dd></div>}<div><dt>{c.primary}</dt><dd><bdi>{value.primaryLocale}</bdi></dd></div><div><dt>{c.typePin}</dt><dd className="glossary-pins">{value.typePin.modelId} · {c.version} {value.typePin.version}<br/>{value.typePin.typeId}</dd></div></dl></details>
  <details><summary>{c.attributes}</summary><pre className="glossary-json" tabIndex={0}>{JSON.stringify(value.attributes,null,2)}</pre></details></>;
}
export function GlossaryTermPage({id}:{id:string}){const c=useCopy(),rights=useRights(),resource=useResource<GlossaryTermContext>(rights.read?`/glossary/terms/${id}`:null);
 if(!rights.read)return <PermissionDenied/>;if(resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;if(!resource.data)return <LoadingState label={c.loading}/>;
 const parsed=parseGlossaryPublication(resource.data.publication);if(!parsed.ok)return <Notice tone="error">{c.sourceUnavailable}</Notice>;
 return <><Link className="back-link" href="/glossary">{c.back}</Link><Heading title={parsed.value.name} body={`${c.version} ${resource.data.resourceVersion}`} actions={rights.write&&<Link className="button primary" href={`/glossary/${id}/edit`}>{c.edit}</Link>}/><Publication value={resource.data.publication}/></>;
}
export function GlossaryProposalPage({id}:{id?:string}){const c=useCopy(),rights=useRights(),resource=useResource<GlossaryTermContext>(id&&rights.write?`/glossary/terms/${id}`:null);
 if(!rights.write)return <PermissionDenied/>;if(id&&resource.error)return <RequestError error={resource.error} retry={resource.reload}/>;if(id&&!resource.data)return <LoadingState label={c.loading}/>;
 if(resource.data&&!parseGlossaryPublication(resource.data.publication).ok)return <Notice tone="error">{c.sourceUnavailable}</Notice>;
 return <GlossaryForm key={id?`${id}:${resource.data!.resourceVersion}`:'new'} base={resource.data??undefined} reload={resource.reload}/>;
}

// Preserve every authored key while preparing existing numeric values for the
// shared typed editor. Unknown keys remain visible to exact-model validation.
function valueDraft(schema:AttributeSchema|undefined,value:unknown):unknown{
 if(!schema)return value;if(schema.type==='number')return value===undefined?undefined:String(value);
 if(schema.type==='list'&&Array.isArray(value))return value.map(item=>valueDraft(schema.items,item));
 if(schema.type==='object'&&value&&typeof value==='object'&&!Array.isArray(value))return Object.fromEntries(Object.entries(value).map(([key,child])=>[key,valueDraft(schema.properties[key],child)]));return value;
}
function initialExpiry(){const date=new Date(Date.now()+7*86400_000);date.setMinutes(date.getMinutes()-date.getTimezoneOffset());return date.toISOString().slice(0,16);}
const translation=():GlossaryTranslation=>({locale:'',name:'',definition:'',synonyms:[],abbreviations:[],examples:[]});
type Intent={body:string;key:string};
function GlossaryForm({base,reload}:{base?:GlossaryTermContext;reload:()=>void}){
 const c=useCopy(),{go}=useNavigation(),session=useSession(),[resourceId]=useState(()=>base?.resourceId??crypto.randomUUID());
 const root=useResource<{type:PublishedAssetType}>('/asset-types/business_term'),members=useResource<{items:Member[]}>('/members');
 const [selected,setSelected]=useState<TypeContext|null>(null),[selectionBusy,setSelectionBusy]=useState(false),[selectionError,setSelectionError]=useState<Error|null>(null);
 const [translations,setTranslations]=useState<GlossaryTranslation[]>(()=>base?[...(base.publication.attributes.translations as unknown as GlossaryTranslation[])]:[{...translation(),locale:'en'}]);
 const [primary,setPrimary]=useState(base?.publication.primaryLocale??'en'),[owner,setOwner]=useState(base?.publication.ownerId??''),[visibility,setVisibility]=useState<'tenant'|'restricted'>(base?.publication.visibility??'tenant');
 const [allowed,setAllowed]=useState<string[]>(base?[...base.publication.allowedIdentityIds]:[]),[state,setState]=useState<'active'|'deprecated'>(base?.publication.state??'active');
 const [additional,setAdditional]=useState<Record<string,unknown>>(()=>Object.fromEntries(Object.entries(base?.publication.attributes??{}).filter(([key])=>key!=='translations')));
 const [links,setLinks]=useState<GlossaryLink[]>(()=>base?[...base.publication.links]:[]),[workflow,setWorkflow]=useState<ApprovalDefinitionView|null>(null),[assignments,setAssignments]=useState<Record<string,string>>({}),[expires,setExpires]=useState(initialExpiry);
 const [error,setError]=useState<Error|null>(null),[busy,setBusy]=useState(false),[intent,setIntent]=useState<Intent|null>(null),running=useRef(false),selection=useRef(0);
 const [workflowBusy,setWorkflowBusy]=useState(false),[workflowError,setWorkflowError]=useState<Error|null>(null),workflowSelection=useRef(0);
 const locked=busy||intent!==null,extraFields=Object.fromEntries(Object.entries(selected?.view.resolved.model.attributes??{}).filter(([key])=>key!=='translations'));
 async function chooseType(id:string,version?:number){const revision=++selection.current;setSelectionBusy(true);setSelectionError(null);
  try{const value=await loadType(id,version);if(revision!==selection.current)return;if(!root.data||!termType(value,root.data.type)||!value.view.resolved.requiredOwner)throw new FormIssue('typeInvalid');
   if(base&&(value.view.id!==base.publication.typePin.modelId||value.view.version!==base.publication.typePin.version))throw new FormIssue('typeStale');
   setSelected(value);setAdditional(old=>Object.fromEntries(Object.entries(old).map(([key,child])=>[key,valueDraft(value.view.resolved.model.attributes[key],child)])));
   if(!base&&['active','deprecated'].includes(value.view.resolved.lifecycle.initial))setState(value.view.resolved.lifecycle.initial as 'active'|'deprecated');
  }catch(caught){if(revision===selection.current){setSelected(null);setSelectionError(caught instanceof Error?caught:new Error(c.typeMissing));}}finally{if(revision===selection.current)setSelectionBusy(false);}
 }
 useEffect(()=>{if(!root.data)return;void chooseType(base?.publication.typePin.modelId??root.data.type.id,base?.publication.typePin.version);return()=>{selection.current++;};},[root.data]);
 useEffect(()=>()=>{workflowSelection.current++;},[]);
 async function chooseWorkflow(id:string){const revision=++workflowSelection.current;setWorkflowBusy(true);setWorkflowError(null);setWorkflow(null);
  try{const value=await api<{workflow:ApprovalDefinitionView}>(`/workflow-definitions/${encodeURIComponent(id)}`);if(revision===workflowSelection.current){setWorkflow(value.workflow);setAssignments({});}}
  catch(caught){if(revision===workflowSelection.current)setWorkflowError(caught instanceof Error?caught:new FormIssue('workflowMissing'));}
  finally{if(revision===workflowSelection.current)setWorkflowBusy(false);}
 }
 const required=workflow?[...new Set(workflow.definition.stages.flatMap(stage=>stage.assignments))]:[],activeIds=new Set(members.data?.items.map(member=>member.id)??[]);
 const typeCurrent=!!selected&&selected.view.currentVersion===selected.view.version;
 const states=selected?[...new Set(base?[base.publication.state,...selected.view.resolved.lifecycle.transitions.filter(item=>item.from===base.publication.state).map(item=>item.to)]:[selected.view.resolved.lifecycle.initial])].filter(item=>item==='active'||item==='deprecated'):[];
 function editTranslation(index:number,patch:Partial<GlossaryTranslation>){setTranslations(old=>old.map((row,i)=>i===index?{...row,...patch}:row));}
 async function execute(value:Intent){if(running.current)return;running.current=true;setBusy(true);setError(null);setIntent(value);
  try{const result=await api<{request:ApprovalRequestView}>('/glossary/proposals',{method:'POST',headers:{'Idempotency-Key':value.key},body:value.body});setIntent(null);go(`/approvals/${result.request.id}`);}
  catch(caught){const failure=caught instanceof Error?caught:new Error('Request failed');setError(failure);if(failure instanceof ApiError&&failure.status<500&&![408,429].includes(failure.status))setIntent(null);}
  finally{running.current=false;setBusy(false);}
 }
 function submit(event:FormEvent){event.preventDefault();if(locked||selectionBusy||workflowBusy)return;setError(null);
  if(!selected||!typeCurrent||!owner||!activeIds.has(owner)||!workflow||required.some(key=>!activeIds.has(assignments[key]))){setError(new FormIssue('chooseRequired'));return;}
  if(workflow.definition.separationOfDuties&&Object.values(assignments).includes(session.user.id)||workflow.definition.stages.some(stage=>new Set(stage.assignments.map(key=>assignments[key])).size!==stage.assignments.length)){setError(new FormIssue('invalidReviewers'));return;}
  if(visibility==='restricted'&&[session.user.id,...Object.values(assignments)].some(id=>!allowed.includes(id))){setError(new FormIssue('invalidAudience'));return;}
  const expiry=new Date(expires).getTime();if(!Number.isFinite(expiry)||expiry<=Date.now()||expiry>Date.now()+366*86400_000){setError(new FormIssue('invalidExpiry'));return;}
  const publication={typePin:pin(selected.view),primaryLocale:primary,ownerId:owner,visibility,allowedIdentityIds:visibility==='tenant'?[]:[...allowed].sort(),state,
   attributes:{...serializeAttributes(extraFields,additional),translations},links};
  const parsed=parseGlossaryPublication(publication);if(!parsed.ok){setError(new ApiError(422,{code:'GLOSSARY_PUBLICATION_INVALID',issues:[...parsed.issues]}));return;}
  const checked=validateAttributes(selected.view.resolved.model,parsed.value.input.attributes);if(!checked.ok){setError(new ApiError(422,{code:'GLOSSARY_ATTRIBUTES_INVALID',detail:c.invalidCustom,issues:[...checked.issues]}));return;}
  const body:GlossaryProposalInput={requestId:crypto.randomUUID(),resourceId,resourceVersion:base?.resourceVersion??null,publication:parsed.value.input,
   workflowPin:{id:workflow.definition.id,version:workflow.definition.version,definitionHash:workflow.definitionHash},assignments:Object.fromEntries(required.map(key=>[key,assignments[key]])),expiresAt:new Date(expiry).toISOString()};
  void execute({body:JSON.stringify(body),key:crypto.randomUUID()});
 }
 return <><Link className="back-link" href={base?`/glossary/${base.resourceId}`:'/glossary'}>{c.back}</Link><Heading title={base?c.edit:c.newTerm} body={c.proposalHint}/><Notice>{base?c.existingHint:c.pinNotice}</Notice>
  <Errors error={error} retry={intent&&!busy?()=>void execute(intent):undefined}/>{intent&&!busy&&<Notice>{c.retryHint}</Notice>}{base&&error instanceof ApiError&&error.status===409&&<button type="button" className="button secondary glossary-reload" onClick={reload}>{c.reload}</button>}
  {root.error?<><Notice tone="error">{c.typeMissing}</Notice><Errors error={root.error} retry={root.reload}/></>:!root.data?<LoadingState label={c.loading}/>:null}{members.error&&<Errors error={members.error} retry={members.reload}/>}
  {members.loading&&<LoadingState label={c.loading}/>}<form className="glossary-form" onSubmit={submit}><fieldset disabled={locked||selectionBusy||workflowBusy}><legend>{c.proposal}</legend>
   {!base&&<Picker<TypeSummary> path="/asset-types" title={c.termType} selected={selected?{id:selected.view.id,label:selected.view.id}:undefined} idOf={row=>row.id} labelOf={row=>`${row.id} · ${c.version} ${row.currentVersion}`} onSelect={row=>void chooseType(row.id)}/>}
   <p className="supporting-text">{c.typeHint}</p>{selected&&<p className="glossary-pins">{c.typePin}: {selected.view.id} · {c.version} {selected.view.version} · <bdi>{selected.view.typeId}</bdi></p>}
   {selectionBusy&&<LoadingState label={c.loadingSelection}/>}<Errors error={selectionError}/>{selected&&!typeCurrent&&<Notice tone="error">{c.typeStale}</Notice>}
   {!base&&selected&&<button className="button secondary" type="button" onClick={()=>void chooseType(selected.view.id)}>{c.refreshType}</button>}
   <div className="glossary-columns"><Field title={c.owner} hint={c.ownerHint}>{(label,help)=><select required aria-labelledby={label} aria-describedby={help} value={owner} onChange={event=>setOwner(event.target.value)}><option value="">{c.choose}</option>{owner&&!activeIds.has(owner)&&<option value={owner} disabled>{owner}</option>}{members.data?.items.map(member=><option key={member.id} value={member.id}>{member.name} · {member.role}</option>)}</select>}</Field>
    <Field title={c.state}>{label=><select required aria-labelledby={label} value={state} onChange={event=>setState(event.target.value as 'active'|'deprecated')}>{!states.includes(state)&&<option value={state} disabled>{c[state]}</option>}{states.map(value=><option key={value} value={value}>{c[value as 'active'|'deprecated']}</option>)}</select>}</Field></div>
   <Field title={c.visibility}>{label=><select aria-labelledby={label} value={visibility} onChange={event=>setVisibility(event.target.value as 'tenant'|'restricted')}><option value="tenant">{c.tenant}</option><option value="restricted">{c.restricted}</option></select>}</Field>
   {visibility==='restricted'&&<fieldset><legend>{c.allowed}</legend><p>{c.restrictedHint}</p><div className="glossary-member-list">{members.data?.items.map(member=><label className="checkbox-label" key={member.id}><input type="checkbox" checked={allowed.includes(member.id)} onChange={event=>setAllowed(old=>event.target.checked?[...old,member.id]:old.filter(id=>id!==member.id))}/>{member.name}</label>)}</div>{allowed.filter(id=>!activeIds.has(id)).map(id=><p className="glossary-pins" key={id}>{id} <button className="button secondary" type="button" onClick={()=>setAllowed(old=>old.filter(value=>value!==id))}>{c.remove}</button></p>)}</fieldset>}
   <fieldset><legend>{c.translations}</legend><Field title={c.primary}>{label=><select required aria-labelledby={label} value={primary} onChange={event=>setPrimary(event.target.value)}><option value="">{c.choose}</option>{translations.map((row,index)=><option key={index} value={row.locale}>{row.locale||`${c.translation} ${index+1}`}</option>)}</select>}</Field>
    {translations.map((row,index)=><section className="glossary-translation" key={index}><h3>{c.translation} {index+1}</h3><Field title={`${c.locale} ${index+1}`} hint={c.localeHint}>{(label,help)=><input required maxLength={65536} dir="ltr" aria-labelledby={label} aria-describedby={help} value={row.locale} onChange={event=>{const locale=event.target.value;if(primary===row.locale)setPrimary(locale);editTranslation(index,{locale});}}/>}</Field>
     <Field title={`${c.name} ${index+1}`}>{label=><input required maxLength={240} dir="auto" aria-labelledby={label} value={row.name} onChange={event=>editTranslation(index,{name:event.target.value})}/>}</Field>
     <Field title={`${c.definition} ${index+1}`}>{label=><textarea required rows={5} maxLength={16384} dir="auto" aria-labelledby={label} value={row.definition} onChange={event=>editTranslation(index,{definition:event.target.value})}/>}</Field>
     <div className="glossary-columns">{(['synonyms','abbreviations'] as const).map(key=><Field key={key} title={`${c[key]} ${index+1}`} hint={c.aliasesHint}>{(label,help)=><textarea rows={3} maxLength={8192} dir="auto" aria-labelledby={label} aria-describedby={help} value={row[key].join('\n')} onChange={event=>editTranslation(index,{[key]:event.target.value===''?[]:event.target.value.split('\n')})}/>}</Field>)}</div>
     <h4>{c.examples}</h4>{row.examples.map((example,offset)=><div className="glossary-example" key={offset}><Field title={`${c.example} ${index+1}.${offset+1}`}>{label=><textarea rows={3} maxLength={4096} dir="auto" aria-labelledby={label} value={example} onChange={event=>editTranslation(index,{examples:row.examples.map((old,i)=>i===offset?event.target.value:old)})}/>}</Field><button type="button" className="button secondary" onClick={()=>editTranslation(index,{examples:row.examples.filter((_,i)=>i!==offset)})}>{c.removeExample}</button></div>)}
     <div className="glossary-actions"><button type="button" className="button secondary" disabled={row.examples.length>=16} onClick={()=>editTranslation(index,{examples:[...row.examples,'']})}>{c.addExample}</button><button type="button" className="button secondary" disabled={translations.length===1} onClick={()=>{setTranslations(old=>old.filter((_,i)=>i!==index));if(primary===row.locale)setPrimary('');}}>{c.removeTranslation}</button></div></section>)}
    <button type="button" className="button secondary" disabled={translations.length>=32} onClick={()=>setTranslations(old=>[...old,translation()])}>{c.addTranslation}</button>
   </fieldset>
   {selected&&Object.keys(extraFields).length>0&&<fieldset><legend>{c.custom}</legend><ValueFields fields={extraFields} values={additional} onChange={setAdditional} prefix="glossary"/></fieldset>}
   <fieldset><legend>{c.links}</legend>{base&&<p>{c.staleLinks}</p>}<ul className="glossary-link-list">{links.map((link,index)=><li key={`${link.kind}:${link.targetAssetId}`}><strong>{c[link.kind]}</strong> · <Link href={`/catalog/${link.targetAssetId}`}>{link.targetAssetId}</Link> · {c.targetVersion} {link.targetAssetVersion}<p className="glossary-pins">{link.typePin.relationTypeId} · {c.version} {link.typePin.version}</p><button type="button" className="button secondary" onClick={()=>setLinks(old=>old.filter((_,i)=>i!==index))}>{c.removeLink}</button></li>)}</ul>{!links.length&&<p>{c.noLinks}</p>}
    {selected&&root.data&&<LinkBuilder key={`${selected.view.id}:${selected.view.version}:${state}`} root={root.data.type} source={selected} resourceId={resourceId} resourceVersion={base?.resourceVersion??1} state={state} existing={links} add={link=>setLinks(old=>[...old,link])}/>}</fieldset>
   <fieldset><legend>{c.workflow}</legend><Picker<ApprovalDefinitionView> path="/workflow-definitions" title={c.workflow} maxQuery={120} selected={workflow?{id:workflow.definition.id,label:workflow.definition.name}:undefined} idOf={row=>row.definition.id} labelOf={row=>`${row.definition.name} · ${c.version} ${row.definition.version}`} onSelect={row=>void chooseWorkflow(row.definition.id)}/><p>{c.workflowHint}</p>
    {workflowBusy&&<LoadingState label={c.loadingSelection}/>}<Errors error={workflowError}/>{workflow&&<><p>{workflow.definition.name} · {c.version} {workflow.definition.version}</p><p className="glossary-pins">{workflow.definitionHash}</p><ol>{workflow.definition.stages.map(stage=><li key={stage.id}><strong>{stage.name}</strong><p>{c.quorum}: {stage.quorum} / {stage.assignments.length} · {c.deadlineSeconds}: {stage.deadlineSeconds}</p></li>)}</ol><p>{c.anyReject}</p><p>{c.reviewerHint}</p>{workflow.definition.separationOfDuties&&<p>{c.sod}</p>}<p>{c.distinct}</p>
     {required.map(key=><Field key={key} title={`${c.reviewer}: ${key}`}>{label=><select required aria-labelledby={label} value={assignments[key]??''} onChange={event=>setAssignments(old=>({...old,[key]:event.target.value}))}><option value="">{c.choose}</option>{members.data?.items.filter(member=>!workflow.definition.separationOfDuties||member.id!==session.user.id).map(member=><option key={member.id} value={member.id}>{member.name} · {member.role}</option>)}</select>}</Field>)}</>}
    <Field title={c.expiry} hint={c.expiryHint}>{(label,help)=><input type="datetime-local" required aria-labelledby={label} aria-describedby={help} value={expires} onChange={event=>setExpires(event.target.value)}/>}</Field>
   </fieldset>
   <button className="button primary" type="submit" disabled={!selected||!typeCurrent||!workflow||!members.data||!!members.error||!!root.error}>{busy?c.submitting:c.submit}</button>
  </fieldset></form></>;
}

function LinkBuilder({root,source,resourceId,resourceVersion,state,existing,add}:{root:PublishedAssetType;source:TypeContext;resourceId:string;resourceVersion:number;state:string;existing:GlossaryLink[];add:(link:GlossaryLink)=>void}){
 const c=useCopy(),[kind,setKind]=useState<GlossaryLink['kind']>('defines'),[target,setTarget]=useState<TargetContext|null>(null),[relation,setRelation]=useState<RelationTypeView|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null),sequence=useRef(0);
 async function chooseTarget(asset:Asset){const request=++sequence.current;setBusy(true);setError(null);setTarget(null);
  try{const [current,typed]=await Promise.all([api<{asset:Asset}>(`/assets/${asset.id}`),api<AssetTypeState>(`/assets/${asset.id}/type-state`)]);
   if(current.asset.version!==typed.assetVersion||!typed.modelId||!typed.modelVersion||current.asset.status!=='active'||asset.id===resourceId)throw new FormIssue('linkInvalid');
   const type=await loadType(typed.modelId,typed.modelVersion);if(request===sequence.current)setTarget({asset:current.asset,state:typed,type});
  }catch(caught){if(request===sequence.current)setError(caught instanceof Error?caught:new Error(c.linkInvalid));}finally{if(request===sequence.current)setBusy(false);}
 }
 async function chooseRelation(item:RelationTypeSummary){const request=++sequence.current;setBusy(true);setError(null);setRelation(null);
  try{const result=await api<{type:RelationTypeView}>(`/relation-types/${encodeURIComponent(item.id)}`);if(request===sequence.current)setRelation(result.type);}
  catch(caught){if(request===sequence.current)setError(caught instanceof Error?caught:new Error(c.linkInvalid));}finally{if(request===sequence.current)setBusy(false);}
 }
 useEffect(()=>()=>{sequence.current++;},[]);
 let eligible=false,requiresAttributes=false;
 if(target&&relation){const resolved=resolveRelationDefinition(relation.definition),definition=relation.definition;
  const semantic=kind==='defines'||target.asset.sourceId===null&&target.asset.type==='business_term'&&termType(target.type,root);
  requiresAttributes=resolved.ok&&!validateAttributes(resolved.value.model,{}).ok;
  if(resolved.ok&&!requiresAttributes&&semantic&&(kind!=='broader'||definition.direction==='directed'&&definition.cycles==='acyclic'&&definition.cardinality.outgoing.max===1)){
   const checked=validateRelationEndpoints({edge:{id:resourceId,version:1,relationTypeId:relation.relationTypeId,relationTypeVersion:relation.version,sourceAssetId:resourceId,targetAssetId:target.asset.id},policies:[{relationTypeId:relation.relationTypeId,policy:resolved.value}],
    source:{assetId:resourceId,assetVersion:resourceVersion,modelId:source.view.id,modelVersion:source.view.version,state,typeId:source.view.typeId,policy:policy(source),ancestorTypes:source.ancestors},
    target:{assetId:target.asset.id,assetVersion:target.asset.version,modelId:target.state.modelId,modelVersion:target.state.modelVersion,state:target.state.state,typeId:target.type.view.typeId,policy:policy(target.type),ancestorTypes:target.type.ancestors}});
   eligible=checked.ok&&relation.version===relation.currentVersion&&!existing.some(link=>link.kind===kind&&link.targetAssetId===target.asset.id)&&!(kind==='broader'&&existing.some(link=>link.kind==='broader'))&&existing.length<100;
  }
 }
 return <fieldset disabled={busy}><legend>{c.addLink}</legend><Field title={c.kind}>{label=><select aria-labelledby={label} value={kind} onChange={event=>{setKind(event.target.value as GlossaryLink['kind']);setTarget(null);setError(null);}}>{(['broader','related','defines'] as const).map(value=><option key={value} value={value}>{c[value]}</option>)}</select>}</Field>
  <div className="glossary-columns"><Picker<Asset> key={kind} path={kind==='defines'?'/assets':'/assets?type=business_term'} title={c.target} maxQuery={200} selected={target?{id:target.asset.id,label:target.asset.name}:undefined} idOf={row=>row.id} labelOf={row=>`${row.name} · ${row.type}`} onSelect={row=>void chooseTarget(row)}/>
   <Picker<RelationTypeSummary> path="/relation-types" title={c.relation} selected={relation?{id:relation.id,label:relation.label}:undefined} idOf={row=>row.id} labelOf={row=>`${row.label} · ${c.version} ${row.currentVersion}`} onSelect={row=>void chooseRelation(row)}/></div>
  {busy&&<LoadingState label={c.loadingSelection}/>}<Errors error={error}/><p>{c.relationHint}</p>{target&&<p>{target.asset.name} · {c.targetVersion} {target.asset.version}</p>}{relation&&<p>{relation.label} · {c.version} {relation.version}</p>}
  {target&&relation&&!eligible&&<Notice tone="error">{requiresAttributes?c.relationAttributesRequired:c.linkInvalid}</Notice>}
  <button type="button" className="button secondary" disabled={!eligible} onClick={()=>{if(!eligible||!target||!relation)return;add({kind,typePin:{relationTypeId:relation.relationTypeId,version:relation.version,definitionHash:relation.definitionHash},targetAssetId:target.asset.id,targetAssetVersion:target.asset.version});setTarget(null);setRelation(null);}}>{c.addLink}</button>
 </fieldset>;
}
