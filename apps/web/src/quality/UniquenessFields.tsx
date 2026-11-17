// SPDX-License-Identifier: Apache-2.0
import type {UniquenessMeasurement} from '../../../../packages/domain/src/quality-contracts';
import {useLocale} from '../i18n';
import {qualityCopy} from './messages';

/** Counts only. Source values and duplicate-group members never enter the UI. */
export function UniquenessFields({measurement}:{measurement:UniquenessMeasurement}){
 const {locale,number}=useLocale(),c=qualityCopy[locale],nonNull=measurement.rowCount-measurement.nullCount;
 return <>
  <div><dt>{c.nonNullRows}</dt><dd data-testid="quality-non-null-count">{number(nonNull)}</dd></div>
  <div><dt>{c.distinctValues}</dt><dd data-testid="quality-distinct-count">{number(measurement.distinctCount)}</dd></div>
  <div><dt>{c.duplicateGroups}</dt><dd data-testid="quality-duplicate-group-count">{number(measurement.duplicateGroupCount)}</dd></div>
  <div><dt>{c.duplicateRows}</dt><dd data-testid="quality-duplicate-row-count">{number(measurement.duplicateRowCount)}</dd></div>
  <div><dt>{c.duplicatePercentage}</dt><dd data-testid="quality-duplicate-percentage">{nonNull?new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:2}).format(measurement.duplicateRowCount/nonNull):c.NO_DATA}</dd></div>
  <div><dt>{c.totalValueBytes}</dt><dd data-testid="quality-total-value-bytes">{number(measurement.totalValueBytes)}</dd></div>
  <div><dt>{c.largestValueBytes}</dt><dd data-testid="quality-largest-value-bytes">{number(measurement.largestValueBytes)}</dd></div>
 </>;
}
