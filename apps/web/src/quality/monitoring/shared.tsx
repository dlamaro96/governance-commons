// SPDX-License-Identifier: Apache-2.0
import {useId,type ReactNode} from 'react';
import {Notice} from '../../../../../packages/ui/src/index.tsx';
import {ApiError} from '../../api.ts';
import {RequestError} from '../../components.tsx';
import {useLocale} from '../../i18n.tsx';
import {useSession} from '../../session.tsx';
import {useQualityCommand} from '../commands.ts';
import {monitoringCopy} from './messages.ts';
export const useCopy=()=>monitoringCopy[useLocale().locale];
export function useContextKey(){const s=useSession();return JSON.stringify([s.tenant.id,s.user.id,[...s.permissions].sort()]);}
export function Field({title,hint,children}:{title:string;hint?:string;children:(label:string,description:string)=>ReactNode}){const id=useId();return <label className="form-field"><span id={id}>{title}</span>{children(id,id+'-hint')}{hint&&<small id={id+'-hint'}>{hint}</small>}</label>;}
export function Feedback({command}:{command:ReturnType<typeof useQualityCommand<unknown>>}){const c=useCopy();return <>{command.error&&<RequestError error={command.error} compact/>}{command.error instanceof ApiError&&command.error.status===409&&<Notice tone="error">{c.stale}</Notice>}{command.intent&&command.error&&<Notice><p>{c.uncertain}</p><button type="button" className="button secondary" disabled={command.busy} onClick={command.retry}>{c.retry}</button></Notice>}</>;}
export function Pager({cursor,next,change,disabled=false,label}:{cursor:string|null;next:string|null;change:(x:string|null)=>void;disabled?:boolean;label?:string}){const c=useCopy();return <nav className="monitor-actions" aria-label={label??c.pages}><button type="button" className="button secondary" disabled={disabled||!cursor} onClick={()=>change(null)}>{c.first}</button><button type="button" className="button secondary" disabled={disabled||!next} onClick={()=>change(next)}>{c.next}</button></nav>;}
export function Stamp({value}:{value:string|null}){return value?<time dateTime={value} dir="ltr" className="monitor-stamp">{value}</time>:<span>—</span>;}
