// SPDX-License-Identifier: Apache-2.0
import {Notice} from '../../../../../packages/ui/src';
import type {StructureApprovalPayload,StructurePublicationResult} from '../../../../../packages/domain/src/reference-structure-contracts.ts';
import {useLocale} from '../../i18n.tsx';
import {Link} from '../../navigation.tsx';
import {EntriesTable} from './Tables.tsx';
import {Pins,href,useCopy} from './shared.tsx';
export function StructureApprovalEvidence({payload,result,heading=true}:{payload:StructureApprovalPayload;result?:StructurePublicationResult|null;heading?:boolean}){
 const c=useCopy(),{locale,number,date}=useLocale(),release=payload.release;
 return <section className="reference-workspace" aria-label={c.previewStructure}>{heading&&<h2>{c.previewStructure}</h2>}<h3 dir="auto">{release.labels[locale].label}</h3><p className="reference-text" dir="auto">{release.labels[locale].description}</p>{!result&&<Notice>{c.unpublished}</Notice>}<p>{c.visibilityNotice}</p><Pins release={release}/><dl className="detail-list reference-pins"><div><dt>{c.structureIdentifier}</dt><dd><bdi>{payload.structureId}</bdi></dd></div><div><dt>{c.expected}</dt><dd>{number(payload.expectedVersion)}</dd></div><div><dt>{c.owner}</dt><dd><bdi>{release.ownerId}</bdi></dd></div><div><dt>{c.status}</dt><dd>{c[release.status]}</dd></div><div><dt>{c.from}</dt><dd>{release.activation.kind==='at'?date(release.activation.at):c.immediate}</dd></div><div><dt>{c.until}</dt><dd>{release.validUntil?date(release.validUntil):c.unbounded}</dd></div>{release.kind==='reference-hierarchy'&&<div><dt>{c.multiParent}</dt><dd>{c[release.multiParent]}</dd></div>}</dl>{release.kind==='reference-hierarchy'?<EntriesTable kind={release.kind} rows={release.edges}/>:<EntriesTable kind={release.kind} rows={release.mappings}/>}{result&&<><h3>{c.result} {number(result.version)}</h3><p className="reference-code">{result.publicationHash}</p><p>{c.from}: {date(result.effectiveFrom)}</p><Link className="button primary" href={href(result.structureId)}>{c.openStructure}</Link></>}</section>;
}
