// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense, useRef, useState } from 'react';
import { ArrowLeft, DownloadSimple, GitBranch, Plus } from '@phosphor-icons/react';
import type { ColumnDef } from '@tanstack/react-table';
import { DataGrid, EmptyState, EntityHeader, EvidencePanel, LoadingState, Notice } from '../../../../packages/ui/src';
import { MODEL_LIMITS } from '../../../../packages/domain/src/model';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import { ModelBrowserControls, useModelBrowser } from '../models/ModelBrowser';
import { IssueList, ModelError } from '../models/ModelFeedback';
import { VersionPicker } from '../models/VersionPicker';
import type { ModelSummary } from '../models/contracts';
import type { AssetTypeDefinition, AssetTypePreview, LifecycleDefinition, PublishedAssetType } from '../assetTypes/contracts';
import { AssetTypeDefinitionEditor, initialLifecycle } from '../assetTypes/DefinitionEditor';

const TypeMigrationWorkbench = lazy(() => import('./AssetTypeMigrations').then(module => ({ default: module.AssetTypeMigrationWorkbench })));

function exportDefinition(definition: AssetTypeDefinition) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(definition, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `${definition.id}.type.v${definition.version}.json`; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function BackTypes() { const { t } = useLocale(); return <Link className="back-link" href="/asset-types"><ArrowLeft size={16}/>{t('backAssetTypes')}</Link>; }
export function AssetTypesPage() {
  const { t, date, number } = useLocale();
  const browser = useModelBrowser(20, '/asset-types');
  const canWrite = usePermission('models:write');
  const columns: ColumnDef<ModelSummary>[] = [
    { accessorKey: 'id', header: t('typeIdentifier'), cell: ({ row }) => <Link className="asset-link" href={`/asset-types/${encodeURIComponent(row.original.id)}`}>{row.original.id}</Link> },
    { accessorKey: 'currentVersion', header: t('currentVersion'), cell: ({ row }) => number(row.original.currentVersion) },
    { accessorKey: 'createdAt', header: t('createdAt'), cell: ({ row }) => date(row.original.createdAt) },
  ];
  return <><Link className="back-link" href="/models"><ArrowLeft size={16}/>{t('backModels')}</Link><EntityHeader eyebrow={t('operate')} title={t('assetTypes')} description={t('assetTypesDescription')} actions={canWrite && <Link className="button primary" href="/asset-types/new/definition"><Plus size={17}/>{t('newAssetType')}</Link>}/><ModelBrowserControls browser={browser} assetTypes/>{browser.error ? <RequestError error={browser.error} retry={browser.reload}/> : browser.loading ? <LoadingState label={t('loading')}/> : <section className="panel"><DataGrid caption={t('assetTypes')} columns={columns} data={browser.items} empty={<EmptyState icon={<GitBranch size={28}/>} title={t('noAssetTypes')} description={t('noAssetTypesBody')}/>}/></section>}<p className="supporting-text">{t('assetTypeScope')}</p></>;
}
export function AssetTypePage({ id }: { id: string }) {
  const { t, number, date } = useLocale();
  const { search, go } = useNavigation();
  const version = new URLSearchParams(search).get('version');
  const resource = useResource<{ type: PublishedAssetType }>(`/asset-types/${encodeURIComponent(id)}${version ? `/versions/${encodeURIComponent(version)}` : ''}`);
  const canWrite = usePermission('models:write');
  const canPreview = usePermission('catalog:read');
  const canMigrate = usePermission('catalog:write');
  if (resource.error) return <><BackTypes/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (resource.loading || !resource.data) return <LoadingState label={t('loading')}/>;
  const type = resource.data.type;
  return <><BackTypes/><EntityHeader eyebrow={t('assetTypes')} title={type.id} description={t('immutableType')} actions={<><button className="button secondary" onClick={() => exportDefinition(type.definition)}><DownloadSimple size={16}/>{t('exportAssetType')}</button>{canWrite && canPreview && canMigrate && <Link className="button secondary" href={`/asset-types/${encodeURIComponent(id)}/migrate`}>{t('typeMigrationAction')}</Link>}{canWrite && canPreview && <Link className="button primary" href={`/asset-types/${encodeURIComponent(id)}/edit`}>{t('newTypeVersion')}</Link>}</>}/>{new URLSearchParams(search).has('published') && <Notice tone="success">{t('typePublished')}</Notice>}<div className="model-version-bar"><span>{t('modelVersionState')} <strong>{number(type.version)}</strong> / {number(type.currentVersion)}</span><VersionPicker value={type.version} maximum={type.currentVersion} label={t('viewVersion')} onChange={version => go(`/asset-types/${encodeURIComponent(id)}?version=${version}`)}/></div><div className="model-layout"><div><section className="panel asset-type-resolved"><div className="panel-heading"><h2>{t('resolvedFields')} ({number(Object.keys(type.resolved.model.attributes).length)})</h2></div><div className="panel-body">{Object.keys(type.resolved.model.attributes).length ? <dl className="model-definition-fields">{Object.entries(type.resolved.model.attributes).map(([key, field]) => <div key={key}><dt><strong>{field.label || key}</strong><code>{key}</code><span className="status-badge">{t(`type_${field.type}`)}</span>{field.required && <span className="required-marker">{t('required')}</span>}<span className="status-badge">{t(type.definition.overrideAttributes.includes(key) ? 'overrideOrigin' : Object.hasOwn(type.definition.attributes, key) ? 'localOrigin' : 'inheritedOrigin')}</span></dt><dd><pre className="code-block" tabIndex={0}>{JSON.stringify(field, null, 2)}</pre></dd></div>)}</dl> : <p className="text-muted">{t('noFields')}</p>}</div></section><section className="panel"><div className="panel-heading"><h2>{t('lifecycle')}</h2></div><div className="panel-body"><LifecycleReadout lifecycle={type.resolved.lifecycle}/><p><strong>{t('resolvedOwner')}:</strong> {t(type.resolved.requiredOwner ? 'yes' : 'no')}</p></div></section><details className="panel asset-type-authored"><summary>{t('authoredDefinition')}</summary><div className="panel-body"><pre className="code-block" tabIndex={0}>{JSON.stringify(type.definition, null, 2)}</pre></div></details></div><div><EvidencePanel title={t('resolvedDependencies')}><ul className="asset-type-pin-list">{type.resolved.dependencies.map(pin => <li key={`${pin.id}:${pin.version}`}><Link href={`/asset-types/${encodeURIComponent(pin.id)}?version=${pin.version}`}>{pin.id}</Link><span>{t('version')} {number(pin.version)}</span></li>)}</ul>{!type.resolved.dependencies.length && <p className="text-muted">{t('noDependencies')}</p>}<p className="supporting-text">{t('typePinsNote')}</p></EvidencePanel><EvidencePanel title={t('typeDefinition')}><dl className="detail-list"><div><dt>{t('createdAt')}</dt><dd>{date(type.createdAt)}</dd></div><div><dt>{t('createdBy')}</dt><dd className="mono break-all">{type.createdBy}</dd></div><div><dt>{t('definitionHash')}</dt><dd className="mono break-all">{type.definitionHash}</dd></div><div><dt>{t('resolutionHash')}</dt><dd className="mono break-all">{type.resolutionHash}</dd></div></dl></EvidencePanel></div></div></>;
}
export function LifecycleReadout({ lifecycle }: { lifecycle: LifecycleDefinition }) {
  const { t } = useLocale();
  return <div className="lifecycle-readout"><p>{t('lifecycleInitial')}: <strong><bdi>{lifecycle.initial}</bdi></strong></p><div className="lifecycle-states" aria-label={t('lifecycle')} role="list">{lifecycle.states.map(state => <span role="listitem" className="status-badge" key={state}><bdi>{state}</bdi></span>)}</div><h3>{t('lifecycleTransitions')}</h3>{lifecycle.transitions.length ? <ul>{lifecycle.transitions.map(({ from, to }) => <li key={`${from}:${to}`}><bdi>{from}</bdi><span className="transition-arrow" aria-label={t('transitionTo')}> → </span><bdi>{to}</bdi></li>)}</ul> : <p className="text-muted">{t('noTransitions')}</p>}</div>;
}
export function AssetTypeEditorPage({ id }: { id?: string }) {
  const { t } = useLocale();
  const current = useResource<{ type: PublishedAssetType }>(id ? `/asset-types/${encodeURIComponent(id)}` : null);
  if (id && current.error) return <><BackTypes/><RequestError error={current.error} retry={current.reload}/></>;
  if (id && !current.data) return <LoadingState label={t('loading')}/>;
  return <AssetTypeEditor key={id || 'new'} initial={current.data?.type}/>;
}
function AssetTypeEditor({ initial }: { initial?: PublishedAssetType }) {
  const { t } = useLocale();
  const { go } = useNavigation();
  const canPreview = usePermission('catalog:read');
  const canMigrate = usePermission('catalog:write');
  const [definition, setDefinition] = useState<AssetTypeDefinition>(() => initial ? { ...initial.definition, version: initial.currentVersion + 1 } : { formatVersion: 1, id: '', version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: initialLifecycle() });
  const [baseVersion, setBaseVersion] = useState(initial?.currentVersion || 0);
  const [mode, setMode] = useState<'visual' | 'json'>('visual');
  const [source, setSource] = useState('');
  const [preview, setPreview] = useState<AssetTypePreview | null>(null);
  const [reviewedDigest, setReviewedDigest] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [message, setMessage] = useState('');
  const [stale, setStale] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const idempotency = useRef(crypto.randomUUID());
  function invalidate() { setPreview(null); setReviewedDigest(null); setMessage(''); idempotency.current = crypto.randomUUID(); }
  function update(next: AssetTypeDefinition) { setDefinition(next); invalidate(); setError(null); }
  async function parsedDraft(text = mode === 'json' ? source : JSON.stringify(definition)) {
    // Raw text reaches the duplicate-key-safe server parser before any JSON.parse.
    const result = await api<{ definition: AssetTypeDefinition }>('/asset-types/validate', { method: 'POST', body: JSON.stringify({ text }) });
    if (initial && (result.definition.id !== initial.id || result.definition.version !== baseVersion + 1)) throw new ApiError(422, { detail: t('typeIdentityError') });
    return result.definition;
  }
  function handleError(caught: unknown) { setError(caught as Error); if (caught instanceof ApiError && [409, 412].includes(caught.status)) { setStale(true); setPreview(null); setReviewedDigest(null); } }
  async function validateSource(text = source) {
    setBusy(true); setError(null);
    try { update(await parsedDraft(text)); setMode('visual'); setMessage(t('typeValidated')); }
    catch (caught) { handleError(caught); }
    finally { setBusy(false); }
  }
  async function importFile(file?: File) {
    if (!file) return;
    invalidate(); setError(null);
    if (file.size > MODEL_LIMITS.fileLength) { setError(new ApiError(422, { detail: t('tooLargeModel') })); return; }
    const text = await file.text(); setSource(text); setMode('json'); await validateSource(text);
  }
  async function previewImpact() {
    if (!initial || !canPreview) return;
    setBusy(true); setError(null); invalidate();
    try { const next = await parsedDraft(); setDefinition(next); const result = await api<{ preview: AssetTypePreview }>(`/asset-types/${encodeURIComponent(initial.id)}/previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: next }) }); setPreview(result.preview); setMode('visual'); setStale(false); }
    catch (caught) { handleError(caught); }
    finally { setBusy(false); }
  }
  const publishable = !initial || !!preview && !preview.requiresExplicitMigration && preview.compatibleWithProvidedAssets && reviewedDigest === preview.previewDigest && !stale;
  async function publish() {
    if (!publishable || busy) return;
    setBusy(true); setError(null);
    try { const next = await parsedDraft(); const result = await api<{ type: PublishedAssetType }>(initial ? `/asset-types/${encodeURIComponent(initial.id)}/versions` : '/asset-types', { method: 'POST', headers: { 'Idempotency-Key': idempotency.current, ...(initial ? { 'If-Match': String(baseVersion) } : {}) }, body: JSON.stringify(initial ? { definition: next, previewDigest: preview!.previewDigest } : { definition: next }) }); go(`/asset-types/${encodeURIComponent(result.type.id)}?published=1`); }
    catch (caught) { handleError(caught); }
    finally { setBusy(false); }
  }
  async function reloadCurrent() {
    setBusy(true); setError(null);
    try { const draft = await parsedDraft(); const result = await api<{ type: PublishedAssetType }>(`/asset-types/${encodeURIComponent(initial!.id)}`); setBaseVersion(result.type.currentVersion); update({ ...draft, version: result.type.currentVersion + 1 }); setMode('visual'); setStale(false); setMessage(t('typeRefreshed')); }
    catch (caught) { handleError(caught); }
    finally { setBusy(false); }
  }
  if (migrating && initial) return <Suspense fallback={<LoadingState label={t('loading')}/>}><TypeMigrationWorkbench initial={{ ...initial, currentVersion: baseVersion }} initialDefinition={definition} onBack={next => { update(next); setBaseVersion(next.version - 1); setMigrating(false); }}/></Suspense>;
  return <><BackTypes/><EntityHeader eyebrow={t('assetTypes')} title={initial ? `${initial.id} · ${t('newTypeVersion')}` : t('newAssetType')} description={t('draftOnly')}/><p className="supporting-text">{t('assetTypeScope')}</p>{message && <Notice tone="success">{message}</Notice>}{error && <ModelError error={error}/>}{stale && initial && <Notice tone="error"><p>{t('typeStale')}</p><button className="button secondary" disabled={busy} onClick={reloadCurrent}>{t('reloadVersion')}</button></Notice>}<fieldset className="model-editor asset-type-editor" aria-label={t('typeDefinition')} disabled={busy}><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('typeDefinition')}><button type="button" className={mode === 'visual' ? 'selected' : ''} aria-pressed={mode === 'visual'} onClick={() => { if (mode !== 'visual') void validateSource(); }}>{t('visualEditor')}</button><button type="button" className={mode === 'json' ? 'selected' : ''} aria-pressed={mode === 'json'} onClick={() => { if (mode !== 'json') { setSource(JSON.stringify(definition, null, 2)); setMode('json'); } }}>{t('jsonSource')}</button></div><label className="file-import button secondary">{t('importAssetType')}<input aria-label={t('importAssetType')} type="file" accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ''; }}/></label></div>{mode === 'visual' ? <AssetTypeDefinitionEditor definition={definition} onChange={update} lockedId={!!initial}/> : <label className="form-field model-json"><span>{t('typeJson')}</span><textarea className="mono" dir="ltr" rows={20} value={source} maxLength={MODEL_LIMITS.fileLength} onChange={event => { setSource(event.target.value); invalidate(); }}/><small>{t('modelJsonHint')}</small><button type="button" className="button secondary" onClick={() => validateSource()}>{t('validateAssetType')}</button><button type="button" className="text-button" onClick={() => { invalidate(); setError(null); setMode('visual'); }}>{t('restoreTypeDraft')}</button></label>}</fieldset>{preview && <><TypePreviewPanel preview={preview}/>{initial && canMigrate && (preview.requiresExplicitMigration || !preview.compatibleWithProvidedAssets) && <div className="migration-section-actions"><button className="button primary" disabled={busy || stale} onClick={() => setMigrating(true)}>{t('typeMigrationAction')}</button></div>}{!preview.requiresExplicitMigration && preview.compatibleWithProvidedAssets && <section className="panel asset-type-approval"><div className="panel-heading"><h2>{t('typePublicationReview')}</h2></div><div className="panel-body"><label className="checkbox-field migration-approval"><input type="checkbox" disabled={busy} checked={reviewedDigest === preview.previewDigest} onChange={event => setReviewedDigest(event.target.checked ? preview.previewDigest : null)}/><span>{t('typePublicationConsent')}<code className="migration-hash">{preview.previewDigest}</code></span></label></div></section>}</>}<div className="model-publication-actions"><Link className="button secondary" href={initial ? `/asset-types/${encodeURIComponent(initial.id)}` : '/asset-types'}>{t('cancel')}</Link>{initial && canPreview && <button className="button secondary" disabled={busy} onClick={previewImpact}>{busy ? t('previewingModel') : t('previewModel')}</button>}<button className="button primary" disabled={busy || !publishable} onClick={publish}>{busy ? t('publishingModel') : t('publishAssetType')}</button></div></>;
}
function TypePreviewPanel({ preview }: { preview: AssetTypePreview }) {
  const { t, number, label } = useLocale();
  return <section className="panel asset-type-preview" aria-label={t('typePreview')}><div className="panel-heading"><h2>{t('typePreview')}</h2><p>{t('typePreviewHint')}</p></div><div className="panel-body"><p>{t('checkedAssets')}: <strong>{number(preview.assetCount)}</strong></p><Notice tone={preview.requiresExplicitMigration || !preview.compatibleWithProvidedAssets ? 'error' : 'success'}>{t(preview.requiresExplicitMigration || !preview.compatibleWithProvidedAssets ? 'typeMigrationBlocked' : 'typeCompatible')}</Notice><p className="supporting-text">{t('typePinsNote')}</p><h3>{t('changesToModel')}</h3>{preview.changes.length ? <ul className="model-changes">{preview.changes.map((change, index) => <li key={index}><span>{label(`change_${change.code}`).startsWith('change_') ? change.code : label(`change_${change.code}`)}</span><code>{change.path}</code>{change.requiresMigration && <strong>{t('migrationRequired')}</strong>}</li>)}</ul> : <p>{t('noModelChanges')}</p>}{preview.assets.length > 0 && <div className="preview-assets">{preview.assets.map(asset => <details key={asset.assetId}><summary><code>{asset.assetId}</code><span>{asset.currentIssues.length + asset.proposedIssues.length ? t('invalidFields') : t('compatible')}</span></summary><Link className="preview-asset-link" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{t('openCatalogAsset')}</Link>{asset.currentIssues.length > 0 && <><h4>{t('currentIssues')}</h4><IssueList issues={asset.currentIssues}/></>}{asset.proposedIssues.length > 0 && <><h4>{t('proposedIssues')}</h4><IssueList issues={asset.proposedIssues}/></>}</details>)}</div>}</div></section>;
}
