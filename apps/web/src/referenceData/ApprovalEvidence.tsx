// SPDX-License-Identifier: Apache-2.0
import {Notice} from '../../../../packages/ui/src';
import type {ApprovalPayload,PublicationResult} from '../../../../packages/domain/src/reference-data-contracts';
import {useLocale} from '../i18n';
import {Link} from '../navigation';
import {Downloads,ValuesTable} from './Read';
import {useCopy} from './shared';
import './reference-data.css';
export function ReferenceApprovalEvidence({payload,result,heading=true}:{payload:ApprovalPayload;result?:PublicationResult|null;heading?:boolean}){
 const c=useCopy(),{locale,number,date}=useLocale();return <section className="reference-workspace" aria-label={c.previewTitle}>{heading&&<h2>{c.previewTitle}</h2>}<h3 dir="auto">{payload.release.labels[locale].label}</h3><p className="reference-text" dir="auto">{payload.release.labels[locale].description}</p>{!result&&<Notice>{c.notPublished}</Notice>}<dl className="detail-list reference-pins"><div><dt>{c.identifier}</dt><dd><bdi className="mono">{payload.setId}</bdi></dd></div><div><dt>{c.expected}</dt><dd>{number(payload.expectedVersion)}</dd></div><div><dt>{c.owner}</dt><dd><bdi className="mono">{payload.release.ownerId}</bdi></dd></div><div><dt>{c.status}</dt><dd>{c[payload.release.status]}</dd></div><div><dt>{c.from}</dt><dd>{payload.release.activation.kind==='at'?date(payload.release.activation.at):c.immediate}</dd></div><div><dt>{c.until}</dt><dd>{payload.release.validUntil?date(payload.release.validUntil):c.unbounded}</dd></div><div><dt>{c.audience}</dt><dd>{c[payload.audience.visibility]}{payload.audience.visibility==='restricted'&&<ul>{payload.audience.allowedIdentityIds.map(id=><li key={id}><bdi className="mono">{id}</bdi></li>)}</ul>}</dd></div></dl>
 <ValuesTable values={payload.release.values}/>{result&&<><h3>{c.result} {number(result.version)}</h3><dl className="detail-list reference-pins"><div><dt>{c.hash}</dt><dd><bdi className="mono">{result.publicationHash}</bdi></dd></div><div><dt>{c.published}</dt><dd>{date(result.publishedAt)}</dd></div><div><dt>{c.from}</dt><dd>{date(result.effectiveFrom)}</dd></div></dl><Link className="button primary" href={'/reference-data/'+result.setId}>{c.title}</Link><Downloads id={result.setId} version={result.version}/></>}
 </section>;
}
