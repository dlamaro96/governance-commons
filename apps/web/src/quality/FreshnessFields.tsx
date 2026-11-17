// SPDX-License-Identifier: Apache-2.0
import type {FreshnessMeasurement,QualityFreshnessSettings} from '../../../../packages/domain/src/quality-contracts';
import {useLocale} from '../i18n';
import {qualityCopy} from './messages';
import {freshnessAgeLabel} from './presentation';
export function FreshnessSettings({binding,pinned=false}:{binding:QualityFreshnessSettings;pinned?:boolean}){
 const {locale,number}=useLocale(),c=qualityCopy[locale];
 return <><dl className="detail-list"><div><dt>{c.maximumAge}</dt><dd data-testid={pinned?'quality-pinned-age':undefined}>{number(binding.maximumAgeSeconds)}</dd></div><div><dt>{c.futureSkew}</dt><dd data-testid={pinned?'quality-pinned-skew':undefined}>{number(binding.maximumFutureSkewSeconds)}</dd></div></dl><p>{c.freshnessHint}</p></>;
}
export function FreshnessFields({measurement:m}:{measurement:FreshnessMeasurement}){
 const {locale,number}=useLocale(),c=qualityCopy[locale];
 return <>
  <div><dt>{c.nonNullRows}</dt><dd data-testid="quality-non-null-count">{number(m.rowCount-m.nullCount)}</dd></div>
  <div><dt>{c.sourceClock}</dt><dd className="break-all" data-testid="quality-source-time"><bdi dir="ltr"><time dateTime={m.sourceObservedAt}>{m.sourceObservedAt}</time></bdi></dd></div>
  <div><dt>{c.latestObserved}</dt><dd className="break-all" data-testid="quality-latest-time">{m.latestObservedAt===null?c.noFiniteTimestamp:<bdi dir="ltr"><time dateTime={m.latestObservedAt}>{m.latestObservedAt}</time></bdi>}</dd></div>
  <div><dt>{c.exactAge}</dt><dd data-testid="quality-exact-age">{m.ageMicroseconds===null?c.notEvaluated:<bdi dir="ltr">{freshnessAgeLabel(m.ageMicroseconds)}</bdi>}</dd></div>
  <div><dt>{c.nonFiniteRows}</dt><dd data-testid="quality-infinite-count">{number(m.nonFiniteCount)}</dd></div>
  <div><dt>{c.unrepresentableRows}</dt><dd data-testid="quality-unsupported-time-count">{number(m.unrepresentableCount)}</dd></div>
  <div><dt>{c.futureRows}</dt><dd data-testid="quality-future-count">{number(m.futureCount)}</dd></div>
 </>;
}
