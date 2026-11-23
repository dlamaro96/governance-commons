// SPDX-License-Identifier: Apache-2.0
import {useState,type FormEvent} from 'react';
import {DetailDrawer,Notice} from '../../../../../packages/ui/src/index.tsx';
import type {QualityRuleView} from '../../../../../packages/domain/src/quality-contracts.ts';
import type {QualityMonitorView,MonitorWindow} from '../../../../../packages/domain/src/quality-monitoring-contracts.ts';
import {useResource} from '../../api.ts';
import {RequestError} from '../../components.tsx';
import {usePermission,useSession} from '../../session.tsx';
import type {Member} from '../../types.ts';
import {useQualityCommand} from '../commands.ts';
import {buildMonitorDefinition,monitorDraft,type MonitorDraft} from './presentation.ts';
import {Field,Feedback,useCopy} from './shared.tsx';
function Windows({kind,rows,change}:{kind:'maintenance'|'silence';rows:MonitorWindow[];change:(rows:MonitorWindow[])=>void}){
 const c=useCopy();return <fieldset className="monitor-windows"><legend>{c[kind]}</legend><p className="supporting-text">{c[kind==='maintenance'?'maintenanceHint':'silenceHint']}</p>{rows.map((row,i)=><div className="monitor-window" key={i}><Field title={c.from+' '+(i+1)}>{label=><input type="text" maxLength={24} required dir="ltr" aria-labelledby={label} value={row.from} onChange={e=>change(rows.map((v,j)=>j===i?{...v,from:e.target.value}:v))}/>}</Field><Field title={c.until+' '+(i+1)}>{label=><input type="text" maxLength={24} required dir="ltr" aria-labelledby={label} value={row.until} onChange={e=>change(rows.map((v,j)=>j===i?{...v,until:e.target.value}:v))}/>}</Field><button type="button" className="button secondary" aria-label={c.removeWindow+' '+(i+1)} onClick={()=>change(rows.filter((_,j)=>j!==i))}>{c.removeWindow}</button></div>)}<button type="button" className="button secondary" disabled={rows.length>=32} onClick={()=>change([...rows,{from:'',until:''}])}>{c.addWindow}</button></fieldset>;
}
export function MonitorEditor({rule,initial,close,saved}:{rule:QualityRuleView;initial:QualityMonitorView|null;close:()=>void;saved:(monitor:QualityMonitorView)=>void}){
 const c=useCopy(),session=useSession(),directory=usePermission('catalog:write'),members=useResource<{items:Member[]}>(directory?'/members':null);
 const [identity]=useState(()=>initial?.id??crypto.randomUUID()),[draft,setDraft]=useState(()=>monitorDraft(initial?.definition??null,rule.definition.name,session.user.id,Date.now())),[repin,setRepin]=useState(!initial),[invalid,setInvalid]=useState(false);
 const command=useQualityCommand<{monitor:QualityMonitorView}>(v=>saved(v.monitor));
 const set=<K extends keyof MonitorDraft>(key:K,value:MonitorDraft[K])=>{setDraft(v=>({...v,[key]:value}));setInvalid(false);};
 const options=new Map<string,string>([[session.user.id,session.user.name],...(members.data?.items.map(m=>[m.id,m.name] as [string,string])??[])]);
 for(const id of [...draft.recipients,draft.owner])if(id&&!options.has(id))options.set(id,c.unavailableMember);
 const current=rule.currentVersion===rule.version,pin=repin?{id:rule.id,version:rule.version,definitionHash:rule.definitionHash}:initial!.definition.rule;
 function submit(event:FormEvent){event.preventDefault();if(command.locked)return;const definition=buildMonitorDefinition(draft,pin,session.user.id,Date.now());
  if(!definition||!current||initial&&initial.definition.executorId!==session.user.id){setInvalid(true);return;}
  command.submit(initial?'/quality/monitors/'+identity+'/definitions':'/quality/monitors',{id:identity,expectedRevision:initial?.revision??0,definition});
 }
 return <DetailDrawer open onOpenChange={open=>{if(!open&&!command.locked)close();}} title={initial?c.edit:c.create} description={c.self} closeLabel={c.close}><form className="stacked-form monitor-form" onSubmit={submit}><Feedback command={command}/>{invalid&&<Notice tone="error">{c.invalid}</Notice>}{!directory&&<Notice>{c.selfOnly}</Notice>}{members.error&&<RequestError error={members.error} retry={members.reload} compact/>}
  <fieldset disabled={command.locked}><legend className="sr-only">{c.monitoring}</legend>
   <Field title={c.name}>{label=><input required maxLength={240} dir="auto" aria-labelledby={label} value={draft.name} onChange={e=>set('name',e.target.value)}/>}</Field>
   <Field title={c.purpose}>{label=><textarea required rows={3} maxLength={4096} dir="auto" aria-labelledby={label} value={draft.purpose} onChange={e=>set('purpose',e.target.value)}/>}</Field>
   {initial&&<label className="monitor-check"><input type="checkbox" checked={repin} onChange={e=>setRepin(e.target.checked)}/><span>{c.currentPin}: {rule.version}</span></label>}<p>{c.ruleVersion}: {pin.version}</p><p className="supporting-text">{c.pinHint}</p>
   <div className="monitor-grid">{(['interval','grace','ack','resolve','freshness'] as const).map(key=><Field key={key} title={c[key==='ack'?'slaAck':key==='resolve'?'slaResolve':key]}>{label=><input required type="text" inputMode="numeric" maxLength={10} dir="ltr" aria-labelledby={label} value={draft[key]} onChange={e=>set(key,e.target.value)}/>}</Field>)}</div>
   {(['starts','ends','expires'] as const).map(key=><Field key={key} title={c[key]} hint={c.utc}>{(label,description)=><input required={key!=='ends'} type="text" maxLength={24} dir="ltr" aria-labelledby={label} aria-describedby={description} value={draft[key]} placeholder="YYYY-MM-DDTHH:mm:ss.sssZ" onChange={e=>set(key,e.target.value)}/>}</Field>)}
   <Field title={c.owner}>{label=><select aria-labelledby={label} value={draft.owner} onChange={e=>{set('owner',e.target.value);setDraft(v=>({...v,owner:e.target.value,recipients:[...new Set([...v.recipients,e.target.value])].sort()}));}}>{[...options].map(([id,name])=><option key={id} value={id}>{name}</option>)}</select>}</Field>
   <fieldset><legend>{c.recipients}</legend><div className="monitor-recipients">{[...options].map(([id,name])=><label key={id} className="monitor-check"><input type="checkbox" checked={draft.recipients.includes(id)} disabled={id===draft.owner||!draft.recipients.includes(id)&&draft.recipients.length>=16} onChange={e=>set('recipients',e.target.checked?[...draft.recipients,id]:draft.recipients.filter(x=>x!==id))}/><span>{name}</span></label>)}</div></fieldset>
   <Windows kind="maintenance" rows={draft.maintenance} change={v=>set('maintenance',v)}/><Windows kind="silence" rows={draft.silences} change={v=>set('silences',v)}/><p className="supporting-text">{c.limits}</p><p>{c.timerHint}</p>
  </fieldset><div className="monitor-actions"><button type="button" className="button secondary" disabled={command.locked} onClick={close}>{c.cancel}</button><button className="button primary" disabled={command.locked||members.loading||!!members.error||!current}>{command.busy?c.sending:initial?c.save:c.publish}</button></div>
 </form></DetailDrawer>;
}
