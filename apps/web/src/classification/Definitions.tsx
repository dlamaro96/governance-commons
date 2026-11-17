// SPDX-License-Identifier: Apache-2.0
import {useState,type FormEvent} from 'react';
import {EmptyState,LoadingState,Notice,StatusBadge} from '../../../../packages/ui/src';
import {CLASSIFICATION_LIMITS as limits,type ClassificationTaxonomy,type ClassificationTaxonomyView,type ClassificationRuleView,type ClassificationPredicate,type MetadataClassificationRule} from '../../../../packages/domain/src/classification-contracts';
import {useResource} from '../api';
import {PermissionDenied,RequestError} from '../components';
import {useLocale} from '../i18n';
import {usePermission,useSession} from '../session';
import type {Member} from '../types';
import {Feedback,Field,LabelPin,Panel,Picker,Pin,useCommand,useContextKey,useCopy} from './shared';
import {pinOf} from './presentation';
import './classification.css';

type Kind='taxonomies'|'rules';
type View=ClassificationTaxonomyView|ClassificationRuleView;
export function ClassificationDefinitions(){
 const c=useCopy(),context=useContextKey(),read=usePermission('classification:read'),catalog=usePermission('catalog:read');
 if(!read||!catalog)return <PermissionDenied/>;
 return <DefinitionsWorkspace key={context}/>;
}
function DefinitionsWorkspace(){
 const c=useCopy(),[kind,setKind]=useState<Kind>('taxonomies'),[editing,setEditing]=useState(false),write=usePermission('classification:write'),modelRead=usePermission('models:read'),modelWrite=usePermission('models:write'),models=modelRead&&modelWrite;
 return <section className="classification-workspace" aria-label={c.definitions}><header className="classification-heading"><div><h1 id="main-heading" tabIndex={-1}>{c.definitions}</h1><p>{c.intro}</p></div></header><Notice>{c.metadataOnly}</Notice>
  {!write&&<Notice>{c.readOnly}</Notice>}{write&&!models&&<Notice>{c.definitionReadOnly}</Notice>}
  <div className="classification-actions" role="group" aria-label={c.definitions}>{(['taxonomies','rules'] as const).map(value=><button key={value} type="button" className="button secondary" aria-pressed={kind===value} disabled={editing} onClick={()=>setKind(value)}>{c[value]}</button>)}</div>
  <DefinitionCatalogue key={kind} kind={kind} canWrite={write&&models} editing={setEditing}/>
 </section>;
}
function DefinitionCatalogue({kind,canWrite,editing}:{kind:Kind;canWrite:boolean;editing:(value:boolean)=>void}){
 const c=useCopy(),{number}=useLocale(),[selection,setSelection]=useState<{id:string;version:number|null}|null>(null),[editor,setEditor]=useState<{initial:View|null}|null>(null),[epoch,setEpoch]=useState(0),[saved,setSaved]=useState(false);
 const resource=useResource<{taxonomy?:ClassificationTaxonomyView;rule?:ClassificationRuleView}>(selection?'/classification/'+kind+'/'+selection.id+(selection.version?'?version='+selection.version:''):null);
 const returned=kind==='taxonomies'?resource.data?.taxonomy:resource.data?.rule;
 const value=returned&&returned.id===selection?.id&&(selection.version===null||returned.version===selection.version)?returned:undefined;
 function close(){setEditor(null);editing(false);}
 function edit(initial:View|null){setEditor({initial});editing(true);setSaved(false);}
 function complete(view:View){close();setSelection({id:view.id,version:view.version});setEpoch(old=>old+1);setSaved(true);resource.reload();}
 if(editor)return kind==='taxonomies'?<TaxonomyEditor initial={editor.initial as ClassificationTaxonomyView|null} close={close} saved={complete}/>:<RuleEditor initial={editor.initial as ClassificationRuleView|null} close={close} saved={complete}/>;
 return <>{saved&&<Notice tone="success">{c.saved}</Notice>}<div className="classification-actions">{canWrite&&<button className="button primary" onClick={()=>edit(null)}>{kind==='taxonomies'?c.newTaxonomy:c.newRule}</button>}</div>
  <Picker<View> key={epoch} path={'/classification/'+kind} title={c[kind]} idOf={item=>item.id} labelOf={item=>item.definition.name+' · '+c.version+' '+number(item.version)} selectedId={selection?.id} onSelect={item=>{setSelection({id:item.id,version:null});setSaved(false);}}/>
  {selection&&(resource.error?<RequestError error={resource.error} retry={resource.reload}/>:resource.loading||!value?<LoadingState label={c.loading}/>:<Panel title={value.definition.name} actions={<button className="button secondary" onClick={resource.reload}>{c.refresh}</button>}>
   <p>{c.immutable}</p><p>{c.version} {number(value.version)} · {c.currentVersion} {number(value.currentVersion)}</p>
   <div className="classification-actions"><button className="button secondary" disabled={value.version<=1} onClick={()=>setSelection({id:value.id,version:value.version-1})}>{c.previousVersion}</button><button className="button secondary" disabled={value.version>=value.currentVersion} onClick={()=>setSelection({id:value.id,version:value.version+1})}>{c.nextVersion}</button><button className="button secondary" disabled={selection.version===null} onClick={()=>setSelection({id:value.id,version:null})}>{c.latestVersion}</button>{canWrite&&value.version===value.currentVersion&&<button className="button primary" onClick={()=>edit(value)}>{c.publishVersion}</button>}</div>
   {kind==='taxonomies'?<TaxonomySummary value={value as ClassificationTaxonomyView}/>:<RuleSummary value={value as ClassificationRuleView}/>}
   <details><summary>{c.pin}</summary><Pin pin={value}/></details>
  </Panel>)}
 </>;
}
export function TaxonomySummary({value}:{value:ClassificationTaxonomyView}){
 const c=useCopy();return <><p className="classification-text">{value.definition.description}</p><ul className="classification-records">{value.definition.labels.map(label=><li key={label.key}><h4>{label.name}</h4><p><bdi className="mono">{label.key}</bdi> · <StatusBadge status={label.status==='active'?'active':'stale'} label={c[label.status]}/></p><p className="classification-text">{label.description}</p></li>)}</ul></>;
}
export function RuleSummary({value}:{value:ClassificationRuleView}){
 const c=useCopy();return <><p className="classification-text">{value.definition.purpose}</p><p><StatusBadge status={value.definition.status==='active'?'active':'stale'} label={c[value.definition.status]}/></p><p>{c.assetTypes}: {value.definition.assetTypes.map(type=>c[type]).join(', ')}</p><LabelPin label={value.definition.label}/><h4>{c.conditions}</h4><ol className="classification-conditions">{value.definition.all.map((predicate,index)=><li key={index}><p>{c[predicate.field==='name'?'fieldName':predicate.field]} · {c[predicate.operator==='starts-with'?'starts':predicate.operator==='ends-with'?'ends':predicate.operator]} · {c[predicate.comparison==='exact'?'exact':'asciiInsensitive']}</p><p className="classification-literal" dir="auto">{predicate.literal}</p></li>)}</ol></>;
}
function TaxonomyEditor({initial,close,saved}:{initial:ClassificationTaxonomyView|null;close:()=>void;saved:(value:ClassificationTaxonomyView)=>void}){
 const c=useCopy(),[id]=useState(()=>initial?.id??crypto.randomUUID()),[draft,setDraft]=useState<ClassificationTaxonomy>(()=>initial?structuredClone(initial.definition):{formatVersion:1,name:'',description:'',labels:[{key:'',name:'',description:'',status:'active'}]});
 const command=useCommand<{taxonomy:ClassificationTaxonomyView}>(result=>saved(result.taxonomy));
 const changeLabel=(index:number,patch:Partial<ClassificationTaxonomy['labels'][number]>)=>setDraft(previous=>({...previous,labels:previous.labels.map((label,i)=>i===index?{...label,...patch}:label)}));
 function submit(event:FormEvent){event.preventDefault();if(command.locked)return;command.submit('/classification/taxonomies'+(initial?'/'+id+'/versions':''),{id,expectedVersion:initial?.currentVersion??0,definition:draft});}
 return <Panel title={initial?c.publishVersion:c.newTaxonomy}><p>{c.immutable}</p><Feedback command={command}/><form className="classification-form" onSubmit={submit}><fieldset disabled={command.locked}><legend className="sr-only">{c.taxonomy}</legend>
  <Field title={c.name}>{label=><input required maxLength={limits.name} aria-labelledby={label} dir="auto" value={draft.name} onChange={event=>setDraft({...draft,name:event.target.value})}/>}</Field>
  <Field title={c.description}>{label=><textarea required maxLength={limits.description} rows={3} aria-labelledby={label} dir="auto" value={draft.description} onChange={event=>setDraft({...draft,description:event.target.value})}/>}</Field>
  {draft.labels.map((label,index)=><fieldset className="classification-card" key={index}><legend>{c.label} {index+1}</legend><div className="classification-fields"><Field title={c.labelKey}>{id=><input required pattern="[A-Za-z_][A-Za-z0-9_.-]*" maxLength={64} aria-labelledby={id} dir="ltr" value={label.key} onChange={event=>changeLabel(index,{key:event.target.value})}/>}</Field><Field title={c.labelName}>{id=><input required maxLength={limits.name} aria-labelledby={id} dir="auto" value={label.name} onChange={event=>changeLabel(index,{name:event.target.value})}/>}</Field></div>
   <Field title={c.labelDescription}>{id=><textarea required maxLength={limits.description} rows={2} aria-labelledby={id} dir="auto" value={label.description} onChange={event=>changeLabel(index,{description:event.target.value})}/>}</Field>
   <Field title={c.status}>{id=><select aria-labelledby={id} value={label.status} onChange={event=>changeLabel(index,{status:event.target.value as 'active'|'deprecated'})}><option value="active">{c.active}</option><option value="deprecated">{c.deprecated}</option></select>}</Field>
   <button className="button secondary" type="button" disabled={draft.labels.length===1} onClick={()=>setDraft({...draft,labels:draft.labels.filter((_,i)=>i!==index)})}>{c.removeLabel}</button>
  </fieldset>)}
  <button className="button secondary" type="button" disabled={draft.labels.length>=limits.labels} onClick={()=>setDraft({...draft,labels:[...draft.labels,{key:'',name:'',description:'',status:'active'}]})}>{c.addLabel}</button>
 </fieldset><div className="classification-actions"><button type="button" className="button secondary" disabled={command.locked} onClick={close}>{c.cancel}</button><button type="submit" className="button primary" disabled={command.locked}>{command.busy?c.publishing:c.publish}</button></div></form></Panel>;
}
function RuleEditor({initial,close,saved}:{initial:ClassificationRuleView|null;close:()=>void;saved:(value:ClassificationRuleView)=>void}){
 const c=useCopy(),session=useSession(),directory=usePermission('catalog:write'),[id]=useState(()=>initial?.id??crypto.randomUUID());
 const [draft,setDraft]=useState<MetadataClassificationRule>(()=>initial?structuredClone(initial.definition):{formatVersion:1,kind:'metadata-literal',name:'',purpose:'',ownerId:session.user.id,status:'active',assetTypes:['column'],label:{taxonomy:{id:'',version:1,definitionHash:''},labelKey:''},all:[{field:'name',operator:'contains',comparison:'ascii-insensitive',literal:''}]});
 const [taxonomyId,setTaxonomyId]=useState(initial?.definition.label.taxonomy.id??''),[taxonomyVersion,setTaxonomyVersion]=useState<number|null>(initial?.definition.label.taxonomy.version??null),[invalid,setInvalid]=useState(false);
 const members=useResource<{items:Member[]}>(directory?'/members':null);
 const taxonomy=useResource<{taxonomy:ClassificationTaxonomyView}>(taxonomyId?'/classification/taxonomies/'+taxonomyId+(taxonomyVersion?'?version='+taxonomyVersion:''):null);
 const returnedTaxonomy=taxonomy.data?.taxonomy,selectedTaxonomy=returnedTaxonomy?.id===taxonomyId&&(taxonomyVersion===null||returnedTaxonomy.version===taxonomyVersion)?returnedTaxonomy:undefined;
 const command=useCommand<{rule:ClassificationRuleView}>(result=>saved(result.rule));
 const ownerKnown=!!members.data?.items.some(member=>member.id===draft.ownerId),ownerAllowed=directory?ownerKnown:draft.ownerId===session.user.id||initial?.definition.ownerId===draft.ownerId;
 const labelReady=!!selectedTaxonomy&&!taxonomy.loading&&!taxonomy.error&&selectedTaxonomy.id===draft.label.taxonomy.id&&selectedTaxonomy.version===draft.label.taxonomy.version&&selectedTaxonomy.definitionHash===draft.label.taxonomy.definitionHash&&selectedTaxonomy.definition.labels.some(label=>label.key===draft.label.labelKey&&label.status==='active');
 const change=(index:number,patch:Partial<ClassificationPredicate>)=>setDraft(previous=>({...previous,all:previous.all.map((predicate,i)=>i===index?{...predicate,...patch}:predicate)}));
 function selectTaxonomy(value:ClassificationTaxonomyView){setTaxonomyId(value.id);setTaxonomyVersion(value.version);setDraft(old=>({...old,label:{taxonomy:pinOf(value),labelKey:''}}));}
 function submit(event:FormEvent){event.preventDefault();if(command.locked)return;if(!labelReady||!ownerAllowed||!draft.assetTypes.length){setInvalid(true);return;}command.submit('/classification/rules'+(initial?'/'+id+'/versions':''),{id,expectedVersion:initial?.currentVersion??0,definition:draft});}
 return <Panel title={initial?c.publishVersion:c.newRule}><Notice>{c.metadataOnly}</Notice><Feedback command={command}/>{invalid&&<Notice tone="error">{c.invalid}</Notice>}
  <form className="classification-form" onSubmit={submit}><fieldset disabled={command.locked}><legend className="sr-only">{c.rules}</legend>
   <Field title={c.name}>{label=><input required maxLength={limits.name} aria-labelledby={label} dir="auto" value={draft.name} onChange={event=>setDraft({...draft,name:event.target.value})}/>}</Field>
   <Field title={c.purpose}>{label=><textarea required maxLength={limits.description} rows={3} aria-labelledby={label} dir="auto" value={draft.purpose} onChange={event=>setDraft({...draft,purpose:event.target.value})}/>}</Field>
   {!directory&&<Notice>{c.memberPermission}</Notice>}{members.error&&<RequestError error={members.error} retry={members.reload} compact/>}
   <Field title={c.owner}>{label=><select required aria-labelledby={label} disabled={!directory||members.loading||!!members.error} value={draft.ownerId} onChange={event=>setDraft({...draft,ownerId:event.target.value})}>{!ownerKnown&&<option value={draft.ownerId}>{draft.ownerId===session.user.id?session.user.name:c.ownerUnavailable}</option>}{members.data?.items.map(member=><option key={member.id} value={member.id}>{member.name}</option>)}</select>}</Field>
   <Field title={c.status}>{label=><select aria-labelledby={label} value={draft.status} onChange={event=>setDraft({...draft,status:event.target.value as 'active'|'retired'})}><option value="active">{c.active}</option><option value="retired">{c.retired}</option></select>}</Field>
   <fieldset className="classification-card"><legend>{c.assetTypes}</legend>{(['table','view','column'] as const).map(type=><label key={type} className="checkbox-label"><input type="checkbox" checked={draft.assetTypes.includes(type)} onChange={event=>setDraft({...draft,assetTypes:event.target.checked?[...draft.assetTypes,type]:draft.assetTypes.filter(item=>item!==type)})}/>{c[type]}</label>)}</fieldset>
   <Picker<ClassificationTaxonomyView> path="/classification/taxonomies" title={c.taxonomy} idOf={value=>value.id} labelOf={value=>value.definition.name+' · '+c.version+' '+value.version} selectedId={taxonomyId} onSelect={selectTaxonomy}/>
   {taxonomy.error?<RequestError error={taxonomy.error} retry={taxonomy.reload} compact/>:taxonomy.loading?<LoadingState label={c.loading}/>:selectedTaxonomy&&<div className="classification-card"><h4>{selectedTaxonomy.definition.name} · {c.version} {selectedTaxonomy.version}</h4><Pin pin={selectedTaxonomy}/><Field title={c.label}>{label=><select required aria-labelledby={label} value={draft.label.labelKey} onChange={event=>setDraft({...draft,label:{taxonomy:pinOf(selectedTaxonomy),labelKey:event.target.value}})}><option value="">{c.choose}</option>{selectedTaxonomy.definition.labels.map(item=><option key={item.key} value={item.key} disabled={item.status!=='active'}>{item.name} · {item.key} · {c[item.status]}</option>)}</select>}</Field></div>}
   {!labelReady&&<p>{c.chooseTaxonomy}</p>}
   <fieldset className="classification-card"><legend>{c.conditions}</legend>{draft.all.map((predicate,index)=><fieldset className="classification-card" key={index}><legend>{c.condition} {index+1}</legend><div className="classification-fields">
    <Field title={c.field}>{label=><select aria-labelledby={label} value={predicate.field} onChange={event=>change(index,{field:event.target.value as ClassificationPredicate['field']})}>{(['name','qualifiedName','dataType'] as const).map(field=><option key={field} value={field}>{c[field==='name'?'fieldName':field]}</option>)}</select>}</Field>
    <Field title={c.operator}>{label=><select aria-labelledby={label} value={predicate.operator} onChange={event=>change(index,{operator:event.target.value as ClassificationPredicate['operator']})}>{(['equals','contains','starts-with','ends-with'] as const).map(operator=><option key={operator} value={operator}>{c[operator==='starts-with'?'starts':operator==='ends-with'?'ends':operator]}</option>)}</select>}</Field>
   </div><Field title={c.comparison}>{label=><select aria-labelledby={label} value={predicate.comparison} onChange={event=>change(index,{comparison:event.target.value as ClassificationPredicate['comparison']})}><option value="exact">{c.exact}</option><option value="ascii-insensitive">{c.asciiInsensitive}</option></select>}</Field>
    <Field title={c.literal} hint={c.literalHint}>{(label,hint)=><input required maxLength={limits.literal} aria-labelledby={label} aria-describedby={hint} dir="auto" value={predicate.literal} onChange={event=>change(index,{literal:event.target.value})}/>}</Field><button className="button secondary" type="button" disabled={draft.all.length===1} onClick={()=>setDraft({...draft,all:draft.all.filter((_,i)=>i!==index)})}>{c.removeCondition}</button>
   </fieldset>)}<button className="button secondary" type="button" disabled={draft.all.length>=limits.predicates} onClick={()=>setDraft({...draft,all:[...draft.all,{field:'name',operator:'contains',comparison:'exact',literal:''}]})}>{c.addCondition}</button></fieldset>
  </fieldset><div className="classification-actions"><button type="button" className="button secondary" disabled={command.locked} onClick={close}>{c.cancel}</button><button type="submit" className="button primary" disabled={command.locked||!ownerAllowed||!labelReady||!draft.assetTypes.length||!!members.error}>{command.busy?c.publishing:c.publish}</button></div></form>
 </Panel>;
}
