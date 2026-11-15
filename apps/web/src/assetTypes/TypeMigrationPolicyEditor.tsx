// SPDX-License-Identifier: Apache-2.0
import { Plus, Trash } from '@phosphor-icons/react';
import type { ResolvedAssetType } from '../../../../packages/domain/src/asset-type';
import type { AssetTypeMigrationPlan } from '../../../../packages/domain/src/asset-type-migration';
import type { TypeMigrationContext, TypePolicyChange } from '../../../../packages/domain/src/asset-type-migration-contracts';
import { useLocale } from '../i18n';
import type { Member } from '../types';
import { Link } from '../navigation';

export function TypeMigrationPolicyEditor({ plan, context, target, policyChanges, members, onChange, disabled = false }: {
  plan: AssetTypeMigrationPlan; context: TypeMigrationContext; target: ResolvedAssetType; policyChanges: readonly TypePolicyChange[]; members: Member[]; onChange: (plan: AssetTypeMigrationPlan) => void; disabled?: boolean;
}) {
  const { t, number } = useLocale();
  const overrides = plan.owner.overrides;
  const mappings = plan.lifecycle.mappings;
  function owner(assetId: string, ownerId: string | null | undefined) {
    onChange({ ...plan, owner: { default: 'preserve', overrides: [...overrides.filter(item => item.assetId !== assetId), ...(ownerId === undefined ? [] : [{ assetId, ownerId }])] } });
  }
  function mapping(index: number, value: typeof mappings[number]) { onChange({ ...plan, lifecycle: { ...plan.lifecycle, mappings: mappings.map((item, i) => i === index ? value : item) } }); }
  function options(values: readonly string[], selected: string) { return [...new Set([...values, ...(values.includes(selected) ? [] : [selected])])].map(value => <option value={value} key={value}>{value || '—'}</option>); }
  return <fieldset className="connection-fields type-migration-policy-editor" disabled={disabled}><legend>{t('typeMigrationPolicies')}</legend>
    <section className="type-migration-owners"><h3>{t('ownership')}</h3><p className="supporting-text">{t('typeMigrationOwnerHint')}</p>
      {context.assets.map(asset => {
        const override = overrides.find(item => item.assetId === asset.assetId);
        const mode = !override ? 'preserve' : override.ownerId === null ? 'clear' : 'replace';
        return <fieldset className="model-field stacked-form" key={asset.assetId}><legend><Link href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{asset.name}</Link></legend><p className="mono break-all">{asset.assetId}</p><div className="preview-counts"><span>{t('modelVersion')}: {number(asset.modelVersion)}</span><span>{t('lifecycleCurrent')}: <bdi>{asset.state || t('unknown')}</bdi></span></div><p className="supporting-text">{t('owner')}: {members.find(member => member.id === asset.ownerId)?.name || asset.ownerId || t('unassigned')}</p>
          <label className="form-field"><span>{t('typeMigrationOwnerMode')}</span><select aria-label={`${t('typeMigrationOwnerMode')} ${asset.assetId}`} value={mode} onChange={event => owner(asset.assetId, event.target.value === 'preserve' ? undefined : event.target.value === 'clear' ? null : '')}><option value="preserve">{t('typeMigrationPreserve')}</option><option value="replace">{t('typeMigrationReplace')}</option><option value="clear" disabled={target.requiredOwner}>{t('typeMigrationClear')}</option></select></label>
          {mode === 'replace' && <label className="form-field"><span>{t('typeMigrationReplacement')}</span><select aria-label={`${t('typeMigrationReplacement')} ${asset.assetId}`} value={override!.ownerId || ''} aria-invalid={!members.some(member => member.id === override!.ownerId) || undefined} onChange={event => owner(asset.assetId, event.target.value)}><option value="" disabled>{t('typeMigrationReplacement')}</option>{override!.ownerId && !members.some(member => member.id === override!.ownerId) && <option value={override!.ownerId}>{override!.ownerId}</option>}{members.map(member => <option key={member.id} value={member.id}>{member.name}</option>)}</select></label>}
          {mode === 'clear' && target.requiredOwner && <p className="field-error">{t('typeOwnerRequired')}</p>}
        </fieldset>;
      })}
      {!context.assets.length && <p>{t('noMigrationAssets')}</p>}
      {overrides.filter(item => !context.assets.some(asset => asset.assetId === item.assetId)).map(item => <div className="model-field" key={item.assetId}><code className="break-all">{item.assetId}</code><p className="field-error">{t('typeMigrationUnknownAsset')}</p><button className="text-button" type="button" onClick={() => owner(item.assetId, undefined)}>{t('typeMigrationRemoveOverride')}</button></div>)}
    </section>
    <section className="type-migration-mappings"><h3>{t('typeMigrationMappings')}</h3><p className="supporting-text">{t('typeMigrationMappingHint')}</p><label className="form-field"><span>{t('typeMigrationUnmapped')}</span><select value={plan.lifecycle.onUnmapped} onChange={event => onChange({ ...plan, lifecycle: { ...plan.lifecycle, onUnmapped: event.target.value as 'preserve' | 'error' } })}><option value="preserve">{t('typeMigrationPreserveState')}</option><option value="error">{t('typeMigrationRejectState')}</option></select></label>
      {mappings.map((item, index) => {
        const source = context.sources.find(source => source.version === item.sourceVersion);
        return <fieldset className="model-field stacked-form" key={index}><legend>{t('planMapping')} {number(index + 1)}</legend><div className="type-migration-mapping-grid">
          <label className="form-field"><span>{t('typeMigrationSourceVersion')}</span><select aria-label={`${t('typeMigrationSourceVersion')} ${index + 1}`} value={item.sourceVersion} aria-invalid={!source || undefined} onChange={event => { const version = Number(event.target.value); const next = context.sources.find(source => source.version === version); mapping(index, { ...item, sourceVersion: version, from: next?.resolution.lifecycle.states[0] || '' }); }}>{!source && <option value={item.sourceVersion}>{number(item.sourceVersion)}</option>}{context.sources.map(source => <option key={source.version} value={source.version}>{number(source.version)}</option>)}</select></label>
          <label className="form-field"><span>{t('typeMigrationSourceState')}</span><select dir="ltr" aria-label={`${t('typeMigrationSourceState')} ${index + 1}`} value={item.from} aria-invalid={!source?.resolution.lifecycle.states.includes(item.from) || undefined} onChange={event => mapping(index, { ...item, from: event.target.value })}>{options(source?.resolution.lifecycle.states || [], item.from)}</select></label>
          <label className="form-field"><span>{t('typeMigrationTargetState')}</span><select dir="ltr" aria-label={`${t('typeMigrationTargetState')} ${index + 1}`} value={item.to} aria-invalid={!target.lifecycle.states.includes(item.to) || undefined} onChange={event => mapping(index, { ...item, to: event.target.value })}>{options(target.lifecycle.states, item.to)}</select></label>
        </div><button className="text-button" type="button" aria-label={`${t('typeMigrationRemoveMapping')} ${index + 1}`} onClick={() => onChange({ ...plan, lifecycle: { ...plan.lifecycle, mappings: mappings.filter((_, i) => i !== index) } })}><Trash size={16}/>{t('typeMigrationRemoveMapping')}</button></fieldset>;
      })}
      <button type="button" className="button secondary" disabled={!context.sources.length || mappings.length >= 1000} onClick={() => { const source = context.sources[0]; if (source) onChange({ ...plan, lifecycle: { ...plan.lifecycle, mappings: [...mappings, { sourceVersion: source.version, from: source.resolution.lifecycle.states[0] || '', to: target.lifecycle.initial }] } }); }}><Plus size={16}/>{t('typeMigrationAddMapping')}</button>
    </section>
    <fieldset className="connection-fields type-migration-policy-acks"><legend>{t('typeMigrationPolicyAcks')}</legend><p className="supporting-text">{t('typeMigrationPolicyHint')}</p>{!policyChanges.length && <p>{t('typeMigrationNoPolicyChanges')}</p>}
      {policyChanges.map(code => <label key={code} className="checkbox-field"><input type="checkbox" checked={plan.acknowledgedPolicyChanges.includes(code)} onChange={event => onChange({ ...plan, acknowledgedPolicyChanges: event.target.checked ? [...plan.acknowledgedPolicyChanges, code] : plan.acknowledgedPolicyChanges.filter(item => item !== code) })}/><span>{t(`policy_${code}`)}</span></label>)}
      {plan.acknowledgedPolicyChanges.filter(code => !policyChanges.includes(code)).map(code => <div key={code}><p className="field-error">{t('typeMigrationUnknownAck')} <code>{code}</code></p><button type="button" className="text-button" onClick={() => onChange({ ...plan, acknowledgedPolicyChanges: plan.acknowledgedPolicyChanges.filter(item => item !== code) })}>{t('typeMigrationRemoveAck')}</button></div>)}
    </fieldset>
  </fieldset>;
}
