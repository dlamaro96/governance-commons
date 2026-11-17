// SPDX-License-Identifier: Apache-2.0
import type {RangeMeasurement,RangeRuleDefinition} from '../../../../packages/domain/src/quality-contracts';
import {useLocale} from '../i18n';
import {qualityCopy} from './messages';

/** Authored bounds remain exact ASCII strings, including values beyond the
 * JavaScript safe-integer range. No observed source values are displayed. */
export function RangeBounds({binding,pinned=false}:{binding:Pick<RangeRuleDefinition,'minimum'|'maximum'>;pinned?:boolean}){
 const {locale}=useLocale(),c=qualityCopy[locale];
 return <><dl className="detail-list">
  <div><dt>{c.minimum}</dt><dd data-testid={pinned?'quality-pinned-minimum':undefined}><bdi dir="ltr">{binding.minimum}</bdi></dd></div>
  <div><dt>{c.maximum}</dt><dd data-testid={pinned?'quality-pinned-maximum':undefined}><bdi dir="ltr">{binding.maximum}</bdi></dd></div>
 </dl><p className="supporting-text">{c.rangeComparison}</p></>;
}

export function RangeFields({measurement}:{measurement:RangeMeasurement}){
 const {locale,number}=useLocale(),c=qualityCopy[locale],nonNull=measurement.rowCount-measurement.nullCount,outside=measurement.belowCount+measurement.aboveCount;
 return <>
  <div><dt>{c.nonNullRows}</dt><dd data-testid="quality-non-null-count">{number(nonNull)}</dd></div>
  <div><dt>{c.belowRows}</dt><dd data-testid="quality-below-count">{number(measurement.belowCount)}</dd></div>
  <div><dt>{c.aboveRows}</dt><dd data-testid="quality-above-count">{number(measurement.aboveCount)}</dd></div>
  <div><dt>{c.outOfRangeRows}</dt><dd data-testid="quality-out-of-range-count">{number(outside)}</dd></div>
  <div><dt>{c.outOfRangePercentage}</dt><dd data-testid="quality-out-of-range-percentage">{nonNull?new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:2}).format(outside/nonNull):c.NO_DATA}</dd></div>
 </>;
}
