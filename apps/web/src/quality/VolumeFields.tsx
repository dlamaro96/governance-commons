// SPDX-License-Identifier: Apache-2.0
import type {QualityVolumeSettings} from '../../../../packages/domain/src/quality-contracts.ts';
import {useLocale} from '../i18n';
import {qualityCopy} from './messages';
export function VolumeBounds({binding,pinned=false}:{binding:QualityVolumeSettings;pinned?:boolean}){
 const {locale,number}=useLocale(),c=qualityCopy[locale];
 return <section aria-label={pinned?c.volumePinned:c.volume}><dl className="quality-measurements"><div><dt>{c.minimumRows}</dt><dd data-testid="quality-volume-minimum">{number(binding.minimumRows)}</dd></div><div><dt>{c.maximumRows}</dt><dd data-testid="quality-volume-maximum">{number(binding.maximumRows)}</dd></div></dl><p>{c.volumeFormula}</p><p className="supporting-text">{c.volumeLimit}</p></section>;
}
