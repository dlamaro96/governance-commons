// SPDX-License-Identifier: Apache-2.0
import type {ReactNode} from 'react';
import {Notice} from '../../../../../packages/ui/src';
import type {HierarchyEdge,ReferenceReleasePin,StructureDefinition} from '../../../../../packages/domain/src/reference-structure-contracts.ts';
import type {ReferenceValue} from '../../../../../packages/domain/src/reference-data-contracts.ts';
import {useLocale} from '../../i18n.tsx';
import {Link} from '../../navigation.tsx';
import {referenceCopy} from '../messages.ts';
import {structureCopy} from './messages.ts';
import {exactTime,Field,localTime} from '../shared.tsx';
export {Field,Panel,Pager,useContextKey,useCommand,Feedback,exactTime,localTime} from '../shared.tsx';
export const useCopy=()=>{const {locale}=useLocale();return {...referenceCopy[locale],...structureCopy[locale]};};
export const API='/reference-data/structures/';
export const href=(id:string)=>'/reference-data/structures/'+id;
export function TimeField({title,value,change}:{title:string;value:string|null;change:(v:string|null)=>void}){const c=useCopy();return <Field title={title} hint={c.rowHint}>{(id,hint)=><input type="datetime-local" step="1" aria-labelledby={id} aria-describedby={hint} value={value&&Number.isFinite(Date.parse(value))?localTime(value):value??''} onChange={e=>change(e.target.value?exactTime(e.target.value)??e.target.value:null)}/>}</Field>;}
export function PinDetails({pin,title}:{pin:ReferenceReleasePin;title:string}){const c=useCopy(),{number}=useLocale();return <div className="structure-pin"><strong>{title}</strong><Link href={'/reference-data/'+pin.setId+'?version='+pin.version}>{c.version} {number(pin.version)}</Link><details><summary>{c.viewEndpoints}</summary><p><bdi>{pin.setId}</bdi></p><p className="reference-code"><bdi>{pin.publicationHash}</bdi></p></details></div>;}
export function Pins({release}:{release:Pick<StructureDefinition,'kind'>&Partial<{reference:ReferenceReleasePin;source:ReferenceReleasePin;target:ReferenceReleasePin}>}){const c=useCopy();return <div className="reference-fields">{release.kind==='reference-hierarchy'&&release.reference?<PinDetails pin={release.reference} title={c.referenceSet}/>:<>{release.source&&<PinDetails pin={release.source} title={c.sourceSet}/>} {release.target&&<PinDetails pin={release.target} title={c.targetSet}/>}</>}</div>;}
export function CodePicker({title,value,values,change}:{title:string;value:string;values:readonly ReferenceValue[];change:(v:string)=>void}){const c=useCopy(),{locale,date}=useLocale(),selected=values.find(v=>v.code===value);return <Field title={title} hint={selected?`${c.from}: ${selected.validFrom?date(selected.validFrom):c.endpointInherited} · ${c.until}: ${selected.validUntil?date(selected.validUntil):c.endpointInherited}`:undefined}>{(id,hint)=><select required aria-labelledby={id} aria-describedby={selected?hint:undefined} value={value} onChange={e=>change(e.target.value)}><option value="">{c.choose}</option>{value&&!values.some(v=>v.code===value&&v.status==='active')&&<option value={value} disabled>{value} — {c.noEndpoints}</option>}{values.filter(v=>v.status==='active').map(v=><option key={v.code} value={v.code}>{v.code} — {v.labels[locale].label}</option>)}</select>}</Field>;}
/** View-only snapshot at one instant; canonical temporal validation stays server-side.
 * Topological levels render every code once, so multi-parent graphs cannot expand exponentially. */
export function Forest({edges,codes,at,from,until}:{edges:readonly HierarchyEdge[];codes:readonly ReferenceValue[];at:string;from:string;until:string|null}){
 const c=useCopy(),{locale,date}=useLocale();const active=edges.filter(e=>(e.validFrom??from)<=at&&((e.validUntil??until)===null||at<(e.validUntil??until)!));
 const ids=new Set(codes.map(v=>v.code)),parents=new Map<string,Set<string>>(),children=new Map<string,Set<string>>();for(const e of active){ids.add(e.parentCode);ids.add(e.childCode);parents.set(e.childCode,new Set([...(parents.get(e.childCode)??[]),e.parentCode]));children.set(e.parentCode,new Set([...(children.get(e.parentCode)??[]),e.childCode]));}
 const pending=new Set(ids),levels:string[][]=[];for(let i=0;i<256&&pending.size;i++){const level=[...pending].filter(id=>![...(parents.get(id)??[])].some(parent=>pending.has(parent))).sort();if(!level.length)break;levels.push(level);for(const id of level)pending.delete(id);}
 return <section aria-label={c.forest} className="structure-forest"><h3>{c.forest}</h3><p>{c.forestAt}: <time dateTime={at}>{date(at)}</time></p>{pending.size>0?<Notice tone="error">{c.cyclePreview}</Notice>:<ol className="structure-levels">{levels.map((level,i)=><li key={i}><ul>{level.map(code=><li key={code}><bdi className="reference-code">{code}</bdi>{codes.find(v=>v.code===code)?.labels[locale].label&&<span dir="auto">{codes.find(v=>v.code===code)!.labels[locale].label}</span>}{parents.has(code)&&<small>{c.parent}: {[...parents.get(code)!].sort().join(', ')}</small>}{!parents.has(code)&&!children.has(code)&&<small>{c.isolated}</small>}</li>)}</ul></li>)}</ol>}</section>;
}
export function Cell({children}:{children:ReactNode}){return <td className="reference-text">{children}</td>;}
