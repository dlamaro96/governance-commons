// SPDX-License-Identifier: Apache-2.0
import { useRef, useState } from 'react';
import { PencilSimple } from '@phosphor-icons/react';
import { DetailDrawer, EmptyState, LoadingState, Notice } from '../../../../packages/ui/src';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { usePermission } from '../session';
import type { AssetAttributes, PublishedModel } from './contracts';
import { AttributeReadout, draftAttributes, serializeAttributes, ValueFields } from './ValueFields';
import { ModelError } from './ModelFeedback';
import { VersionPicker } from './VersionPicker';
import { ModelBrowserControls, useModelBrowser } from './ModelBrowser';

export function AssetAttributesPanel({ assetId, onSaved }: { assetId: string; onSaved: () => void }) {
  const { t, number } = useLocale();
  const resource = useResource<AssetAttributes>(`/assets/${encodeURIComponent(assetId)}/attributes`);
  const canEdit = usePermission('catalog:write');
  const [open, setOpen] = useState(false);
  const [saved, setSaved] = useState(false);
  return <section className="panel governed-attributes"><div className="panel-heading"><div><h2>{t('attributes')}</h2><p>{t('attributesDescription')}</p></div>{canEdit && resource.data && <button className="text-button" onClick={() => { setOpen(true); setSaved(false); }}><PencilSimple size={15}/>{t(resource.data.modelId ? 'editAttributes' : 'assignModel')}</button>}</div>{resource.error ? <div className="panel-body"><RequestError error={resource.error} retry={resource.reload} compact/></div> : !resource.data ? <LoadingState label={t('loading')}/> : <div className="panel-body">{saved && <Notice tone="success">{t('attributesSaved')}</Notice>}{resource.data.definition && resource.data.modelId ? <><div className="attribute-model-pin"><Link href={`/models/${encodeURIComponent(resource.data.modelId)}?version=${resource.data.modelVersion}`}>{resource.data.modelId}</Link><span>{t('modelVersion')} {number(resource.data.modelVersion!)}</span></div><AttributeReadout fields={resource.data.definition.attributes} values={resource.data.attributes}/><p className="supporting-text">{t('attributePin')}</p></> : <EmptyState compact title={t('noAttributeModel')} description={t('noAttributeModelBody')}/>}</div>}{open && resource.data && <AttributeEditor initial={resource.data} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); setSaved(true); resource.reload(); onSaved(); }}/>}</section>;
}
function AttributeEditor({ initial, onClose, onSaved }: { initial: AssetAttributes; onClose: () => void; onSaved: () => void }) {
  const { t, number } = useLocale();
  const models = useModelBrowser();
  const [modelId, setModelId] = useState(initial.modelId || '');
  const [modelVersion, setModelVersion] = useState(initial.modelVersion || 1);
  const selected = useResource<{ model: PublishedModel }>(modelId ? `/models/${encodeURIComponent(modelId)}/versions/${modelVersion}` : null);
  const [values, setValues] = useState<Record<string, unknown>>(() => initial.definition ? draftAttributes(initial.definition.attributes, initial.attributes) : {});
  const [assetVersion, setAssetVersion] = useState(initial.assetVersion);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [conflict, setConflict] = useState(false);
  const [current, setCurrent] = useState<AssetAttributes | null>(null);
  const idempotency = useRef(crypto.randomUUID());
  const definition = selected.data?.model.definition;
  function update(next: Record<string, unknown>) { setValues(next); setError(null); idempotency.current = crypto.randomUUID(); }
  function changeBinding(id: string, version: number) { setModelId(id); setModelVersion(version); update({}); }
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!definition || saving || conflict) return;
    setSaving(true); setError(null);
    try { await api(`/assets/${encodeURIComponent(initial.assetId)}/attributes`, { method: 'PUT', headers: { 'If-Match': String(assetVersion), 'Idempotency-Key': idempotency.current }, body: JSON.stringify({ modelId, modelVersion, attributes: serializeAttributes(definition.attributes, values) }) }); onSaved(); }
    catch (caught) { setError(caught as Error); if (caught instanceof ApiError && [409, 412].includes(caught.status)) setConflict(true); }
    finally { setSaving(false); }
  }
  async function reloadCurrent() {
    setSaving(true); setError(null);
    try { setCurrent(await api<AssetAttributes>(`/assets/${encodeURIComponent(initial.assetId)}/attributes`)); }
    catch (caught) { setError(caught as Error); }
    finally { setSaving(false); }
  }
  function acceptRevision(discard: boolean) {
    if (!current) return;
    setAssetVersion(current.assetVersion); setConflict(false); setError(null); idempotency.current = crypto.randomUUID();
    if (discard) { setModelId(current.modelId || ''); setModelVersion(current.modelVersion || 1); setValues(current.definition ? draftAttributes(current.definition.attributes, current.attributes) : {}); }
    setCurrent(null);
  }
  return <DetailDrawer open onOpenChange={value => { if (!value && !saving) onClose(); }} title={t('editAttributes')} description={t('attributeWriteHint')} closeLabel={t('close')}><form className="stacked-form attribute-form" onSubmit={save} noValidate>{error && !conflict && <ModelError error={error}/ >}{conflict && <Notice tone="error"><p>{t('attributeConflict')}</p><button type="button" className="button secondary" disabled={saving} onClick={reloadCurrent}>{t('reloadVersion')}</button></Notice>}{current && <section className="conflict-comparison"><h3>{t('currentAttributes')} · {t('assetRevision')} {number(current.assetVersion)}</h3><p>{current.modelId || t('noAttributeModel')} {current.modelVersion ? `· ${number(current.modelVersion)}` : ''}</p><pre className="code-block" tabIndex={0}>{JSON.stringify(current.attributes, null, 2)}</pre><div className="conflict-actions"><button type="button" className="button secondary" onClick={() => acceptRevision(false)}>{t('keepDraft')}</button><button type="button" className="text-button" onClick={() => acceptRevision(true)}>{t('resetDraft')}</button></div></section>}<ModelBrowserControls browser={models} disabled={saving}/>{models.error && <RequestError error={models.error} retry={models.reload} compact/>}<div className="form-row"><label className="form-field"><span>{t('selectModel')}</span><select value={modelId} disabled={saving || models.loading || !!models.error} onChange={event => changeBinding(event.target.value, models.items.find(model => model.id === event.target.value)?.currentVersion || 1)}><option value="">{t('selectModel')}</option>{modelId && !models.items.some(model => model.id === modelId) && <option value={modelId}>{modelId}</option>}{models.items.map(model => <option key={model.id} value={model.id}>{model.id}</option>)}</select></label><VersionPicker value={modelVersion} maximum={selected.data?.model.currentVersion || modelVersion} label={t('modelVersion')} disabled={!modelId || saving || selected.loading} onChange={version => changeBinding(modelId, version)}/></div><p className="supporting-text">{t('bindingChange')}</p>{selected.error ? <RequestError error={selected.error} retry={selected.reload} compact/> : selected.loading ? <LoadingState label={t('loading')}/> : definition ? <ValueFields fields={definition.attributes} values={values} onChange={update}/> : <p className="text-muted">{t('noAttributeModelBody')}</p>}<p className="supporting-text">{t('assetRevision')}: {number(assetVersion)}</p><div className="form-actions"><button type="button" className="button secondary" disabled={saving} onClick={onClose}>{t('cancel')}</button><button className="button primary" disabled={!definition || selected.loading || !!selected.error || saving || conflict}>{saving ? t('saving') : t('save')}</button></div></form></DetailDrawer>;
}
