// SPDX-License-Identifier: Apache-2.0
import { useRef, useState } from 'react';
import { ArrowLeft, DownloadSimple, GitBranch, Plus } from '@phosphor-icons/react';
import type { ColumnDef } from '@tanstack/react-table';
import { DataGrid, EmptyState, EntityHeader, EvidencePanel, LoadingState, Notice } from '../../../../packages/ui/src';
import { MODEL_LIMITS } from '../../../../packages/domain/src/model';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import type { ModelDefinition, ModelPreview, ModelSummary, PublishedModel } from '../models/contracts';
import { FieldEditor } from '../models/SchemaEditor';
import { VersionPicker } from '../models/VersionPicker';
import { IssueList, ModelError } from '../models/ModelFeedback';

function exportDefinition(definition: ModelDefinition) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(definition, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `${definition.id || 'model'}.v${definition.version}.json`; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function ModelsPage() {
  const { t, date, number } = useLocale();
  const resource = useResource<{ items: ModelSummary[] }>('/models');
  const canWrite = usePermission('models:write');
  const columns: ColumnDef<ModelSummary>[] = [
    { accessorKey: 'id', header: t('modelId'), cell: ({ row }) => <Link className="asset-link" href={`/models/${encodeURIComponent(row.original.id)}`}>{row.original.id}</Link> },
    { accessorKey: 'currentVersion', header: t('currentVersion'), cell: ({ row }) => number(row.original.currentVersion) },
    { accessorKey: 'createdAt', header: t('createdAt'), cell: ({ row }) => date(row.original.createdAt) },
  ];
  return <><EntityHeader eyebrow={t('operate')} title={t('models')} description={t('modelsDescription')} actions={canWrite && <Link className="button primary" href="/models/new/definition"><Plus size={17}/>{t('newModel')}</Link>}/>{resource.error ? <RequestError error={resource.error} retry={resource.reload}/> : !resource.data ? <LoadingState label={t('loading')}/> : <section className="panel"><DataGrid caption={t('models')} columns={columns} data={resource.data.items} empty={<EmptyState icon={<GitBranch size={28}/>} title={t('noModels')} description={t('noModelsBody')} action={canWrite ? <Link className="button secondary" href="/models/new/definition">{t('newModel')}</Link> : undefined}/>}/></section>}<p className="supporting-text">{t('modelLimit')}</p><p className="supporting-text">{t('modelScopeLimit')}</p></>;
}
export function ModelPage({ id }: { id: string }) {
  const { t, number, date } = useLocale();
  const { search, go } = useNavigation();
  const version = new URLSearchParams(search).get('version');
  const resource = useResource<{ model: PublishedModel }>(`/models/${encodeURIComponent(id)}${version ? `/versions/${encodeURIComponent(version)}` : ''}`);
  const canWrite = usePermission('models:write');
  if (resource.error) return <><BackModels/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data) return <LoadingState label={t('loading')}/>;
  const model = resource.data.model;
  return <><BackModels/><EntityHeader eyebrow={t('models')} title={model.id} description={t('immutableModel')} actions={<><button className="button secondary" onClick={() => exportDefinition(model.definition)}><DownloadSimple size={16}/>{t('exportModel')}</button>{canWrite && <Link className="button primary" href={`/models/${encodeURIComponent(id)}/edit`}>{t('newModelVersion')}</Link>}</>}/>{new URLSearchParams(search).has('published') && <Notice tone="success">{t('publishedModel')}</Notice>}<div className="model-version-bar"><span>{t('modelVersionState')} <strong>{number(model.version)}</strong> / {number(model.currentVersion)}</span><VersionPicker value={model.version} maximum={model.currentVersion} label={t('viewVersion')} onChange={version => go(`/models/${encodeURIComponent(id)}?version=${version}`)}/></div><div className="model-layout"><section className="panel"><div className="panel-heading"><h2>{t('fields')} ({number(Object.keys(model.definition.attributes).length)})</h2></div><div className="panel-body">{Object.entries(model.definition.attributes).length ? <dl className="model-definition-fields">{Object.entries(model.definition.attributes).map(([key, field]) => <div key={key}><dt><strong>{field.label || key}</strong><code>{key}</code><span className="status-badge">{t(`type_${field.type}`)}</span>{field.required && <span className="required-marker">{t('required')}</span>}</dt><dd><pre className="code-block" tabIndex={0}>{JSON.stringify(field, null, 2)}</pre></dd></div>)}</dl> : <p className="text-muted">{t('noFields')}</p>}</div></section><div><EvidencePanel title={t('modelDefinition')}><dl className="detail-list"><div><dt>{t('createdAt')}</dt><dd>{date(model.createdAt)}</dd></div><div><dt>{t('createdBy')}</dt><dd className="mono break-all">{model.createdBy}</dd></div><div><dt>{t('definitionHash')}</dt><dd className="mono break-all">{model.definitionHash}</dd></div></dl></EvidencePanel><p className="supporting-text">{t('modelPinsNote')}</p></div></div></>;
}
function BackModels() { const { t } = useLocale(); return <Link className="back-link" href="/models"><ArrowLeft size={16}/>{t('backModels')}</Link>; }
export function ModelEditorPage({ id }: { id?: string }) {
  const { t } = useLocale();
  const current = useResource<{ model: PublishedModel }>(id ? `/models/${encodeURIComponent(id)}` : null);
  if (id && current.error) return <><BackModels/><RequestError error={current.error} retry={current.reload}/></>;
  if (id && !current.data) return <LoadingState label={t('loading')}/>;
  return <ModelEditor key={id || 'new'} initial={current.data?.model}/>;
}
function ModelEditor({ initial }: { initial?: PublishedModel }) {
  const { t, number } = useLocale();
  const { go } = useNavigation();
  const [definition, setDefinition] = useState<ModelDefinition>(() => initial ? { ...initial.definition, version: initial.currentVersion + 1 } : { formatVersion: 1, id: '', version: 1, attributes: {} });
  const [baseVersion, setBaseVersion] = useState(initial?.currentVersion || 0);
  const [mode, setMode] = useState<'visual' | 'json'>('visual');
  const [source, setSource] = useState('');
  const [preview, setPreview] = useState<ModelPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [message, setMessage] = useState('');
  const [stale, setStale] = useState(false);
  const idempotency = useRef(crypto.randomUUID());
  function update(next: ModelDefinition) { setDefinition(next); setPreview(null); setError(null); setMessage(''); idempotency.current = crypto.randomUUID(); }
  function changeMode(next: 'visual' | 'json') {
    if (next === mode) return;
    if (next === 'json') { setSource(JSON.stringify(definition, null, 2)); setMode(next); }
    else void validateSource();
  }
  async function parsedDraft(text = mode === 'json' ? source : JSON.stringify(definition)) {
    const result = await api<{ definition: ModelDefinition }>('/models/validate', { method: 'POST', body: JSON.stringify({ text }) });
    if (initial && (result.definition.id !== initial.id || result.definition.version !== baseVersion + 1)) throw new ApiError(422, { detail: t('staleModel'), issues: [{ code: 'model_identity', path: '/id', message: `Expected model ${initial.id}, version ${baseVersion + 1}.` }] });
    return result.definition;
  }
  async function validateSource(text = source) {
    setBusy(true); setError(null);
    try { const next = await parsedDraft(text); update(next); setMode('visual'); setMessage(t('validatedModel')); }
    catch (caught) { setError(caught as Error); }
    finally { setBusy(false); }
  }
  async function importFile(file: File | undefined) {
    if (!file) return;
    if (file.size > MODEL_LIMITS.fileLength) { setError(new ApiError(422, { detail: t('tooLargeModel') })); return; }
    const text = await file.text(); setSource(text); setMode('json'); setPreview(null); setMessage('');
    await validateSource(text);
  }
  async function previewImpact() {
    setBusy(true); setError(null); setPreview(null);
    try {
      const next = await parsedDraft(); setDefinition(next);
      const result = await api<{ preview: ModelPreview }>(`/models/${encodeURIComponent(initial!.id)}/previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: next }) });
      setPreview(result.preview); setMode('visual'); setStale(false);
    } catch (caught) { setError(caught as Error); if (caught instanceof ApiError && caught.status === 409) setStale(true); }
    finally { setBusy(false); }
  }
  async function publish() {
    if (initial && (!preview || preview.requiresExplicitMigration || stale)) return;
    setBusy(true); setError(null);
    try {
      const next = await parsedDraft();
      const result = await api<{ model: PublishedModel }>(initial ? `/models/${encodeURIComponent(initial.id)}/versions` : '/models', { method: 'POST', headers: { 'Idempotency-Key': idempotency.current, ...(initial ? { 'If-Match': String(baseVersion) } : {}) }, body: JSON.stringify(initial ? { definition: next, previewDigest: preview!.previewDigest } : { definition: next }) });
      go(`/models/${encodeURIComponent(result.model.id)}?published=1`);
    } catch (caught) { setError(caught as Error); if (caught instanceof ApiError && caught.status === 409) { setStale(true); setPreview(null); } }
    finally { setBusy(false); }
  }
  async function reloadCurrent() {
    setBusy(true); setError(null);
    try { const result = await api<{ model: PublishedModel }>(`/models/${encodeURIComponent(initial!.id)}`); setBaseVersion(result.model.currentVersion); update({ ...definition, version: result.model.currentVersion + 1 }); setMode('visual'); setStale(false); setMessage(t('copiedCurrentModel')); }
    catch (caught) { setError(caught as Error); }
    finally { setBusy(false); }
  }
  return <><BackModels/><EntityHeader eyebrow={t('models')} title={initial ? `${initial.id} · ${t('newModelVersion')}` : t('newModel')} description={t('draftOnly')}/><p className="supporting-text model-scope">{t('modelScopeLimit')}</p>{message && <Notice tone="success">{message}</Notice>}{error && <ModelError error={error}/ >}{stale && initial && <Notice tone="error"><p>{t('staleModel')}</p><button className="button secondary" disabled={busy} onClick={reloadCurrent}>{t('reloadVersion')}</button></Notice>}<fieldset className="model-editor" aria-label={t('modelDefinition')} disabled={busy}><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('modelDefinition')}><button type="button" className={mode === 'visual' ? 'selected' : ''} aria-pressed={mode === 'visual'} onClick={() => changeMode('visual')}>{t('visualEditor')}</button><button type="button" className={mode === 'json' ? 'selected' : ''} aria-pressed={mode === 'json'} onClick={() => changeMode('json')}>{t('jsonSource')}</button></div><label className="file-import button secondary">{t('importModel')}<input aria-label={t('importModel')} type="file" accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ''; }}/></label></div>{mode === 'visual' ? <><div className="model-identity"><label className="form-field"><span>{t('modelId')}</span><input value={definition.id} readOnly={!!initial} maxLength={64} onChange={event => update({ ...definition, id: event.target.value })}/><small>{t('modelIdHint')}</small></label><div className="model-version-value"><span>{t('modelVersion')}</span><strong>{number(definition.version)}</strong></div></div><FieldEditor fields={definition.attributes} onChange={attributes => update({ ...definition, attributes })}/></> : <label className="form-field model-json"><span>{t('modelJson')}</span><textarea className="mono" dir="ltr" rows={20} value={source} maxLength={MODEL_LIMITS.fileLength} onChange={event => { setSource(event.target.value); setPreview(null); idempotency.current = crypto.randomUUID(); }}/><small>{t('modelJsonHint')}</small><button type="button" className="button secondary" onClick={() => validateSource()}>{t('validateModel')}</button></label>}</fieldset>{preview && <PreviewPanel preview={preview}/>}<div className="model-publication-actions"><Link className="button secondary" href={initial ? `/models/${encodeURIComponent(initial.id)}` : '/models'}>{t('cancel')}</Link>{initial && <button className="button secondary" disabled={busy} onClick={previewImpact}>{busy ? t('previewingModel') : t('previewModel')}</button>}<button className="button primary" disabled={busy || !!initial && (!preview || preview.requiresExplicitMigration || stale)} onClick={publish}>{busy ? t('publishingModel') : t('publishModel')}</button></div></>;
}
function PreviewPanel({ preview }: { preview: ModelPreview }) {
  const { t, number } = useLocale();
  return <section className="panel model-preview" aria-label={t('previewTitle')}><div className="panel-heading"><h2>{t('previewTitle')}</h2><p>{t('previewScope')}</p></div><div className="panel-body"><div className="preview-counts"><span>{t('checkedAssets')}: <strong>{number(preview.assetCount)}</strong></span><span>{t('affectedAssets')}: <strong>{number(preview.affectedAssetIds.length)}</strong></span></div><Notice tone={preview.requiresExplicitMigration ? 'error' : 'success'}>{t(preview.requiresExplicitMigration ? 'migrationBlocked' : 'compatibleModel')}</Notice><p className="supporting-text">{t('modelPinsNote')}</p><h3>{t('changesToModel')}</h3>{preview.changes.length ? <ul className="model-changes">{preview.changes.map((change, index) => <li key={index}><span>{t(`change_${change.code}`)}</span><code>{change.path}</code>{change.requiresMigration && <strong>{t('migrationRequired')}</strong>}</li>)}</ul> : <p>{t('noModelChanges')}</p>}{preview.assets.length > 0 && <div className="preview-assets"><h3>{t('checkedAssets')}</h3>{preview.assets.map(asset => <details key={asset.assetId}><summary><code>{asset.assetId}</code><span>{asset.currentIssues.length + asset.proposedIssues.length ? t('invalidFields') : t('compatible')}</span></summary><Link className="preview-asset-link" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{t('openCatalogAsset')}</Link>{asset.currentIssues.length > 0 && <><h4>{t('currentIssues')}</h4><IssueList issues={asset.currentIssues}/></>}{asset.proposedIssues.length > 0 && <><h4>{t('proposedIssues')}</h4><IssueList issues={asset.proposedIssues}/></>}</details>)}</div>}</div></section>;
}
