// SPDX-License-Identifier: Apache-2.0
import { useRef, useState } from 'react';
import { ArrowLeft, DownloadSimple } from '@phosphor-icons/react';
import { DetailDrawer, EntityHeader, LoadingState, Notice } from '../../../../packages/ui/src';
import { MODEL_LIMITS, type ModelChange, type ModelDefinition } from '../../../../packages/domain/src/model';
import type { MigrationPlan } from '../../../../packages/domain/src/model-migration';
import type { MigrationPreview, ModelMigrationReceipt } from '../../../../packages/domain/src/model-migration-service';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import type { ModelPreview, PublishedModel } from '../models/contracts';
import { FieldEditor } from '../models/SchemaEditor';
import { ModelError } from '../models/ModelFeedback';
import { MigrationPlanEditor } from '../models/MigrationPlanEditor';

interface MigrationContext { modelId: string; currentVersion: number; sourceVersions: number[]; assetCount: number }
function exportJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function ModelMigrationPage({ id }: { id: string }) {
  const { t } = useLocale();
  const model = useResource<{ model: PublishedModel }>(`/models/${encodeURIComponent(id)}`);
  if (model.error) return <><BackModel id={id}/><RequestError error={model.error} retry={model.reload}/></>;
  if (!model.data) return <LoadingState label={t('loading')}/>;
  return <MigrationWorkbench key={id} initial={model.data.model}/>;
}
export function MigrationWorkbench({ initial, initialDefinition, onBack }: { initial: PublishedModel; initialDefinition?: ModelDefinition; onBack?: (definition: ModelDefinition) => void }) {
  const { t } = useLocale();
  const context = useResource<MigrationContext>(`/models/${encodeURIComponent(initial.id)}/migration-context`);
  if (context.error) return <><BackModel id={initial.id}/><RequestError error={context.error} retry={context.reload}/></>;
  if (!context.data) return <LoadingState label={t('loading')}/>;
  return <MigrationEditor initial={initial} context={context.data} initialDefinition={initialDefinition} onBack={onBack}/>;
}
function MigrationEditor({ initial, context, initialDefinition, onBack }: { initial: PublishedModel; context: MigrationContext; initialDefinition?: ModelDefinition; onBack?: (definition: ModelDefinition) => void }) {
  const { t, number } = useLocale();
  const { go } = useNavigation();
  const [scope, setScope] = useState(context);
  const [baseVersion, setBaseVersion] = useState(initial.currentVersion);
  const [definition, setDefinition] = useState<ModelDefinition>(initialDefinition || { ...initial.definition, version: initial.currentVersion + 1 });
  const [plan, setPlan] = useState<MigrationPlan>({ formatVersion: 1, modelId: initial.id, targetVersion: initial.currentVersion + 1, sourceVersions: context.sourceVersions, acknowledgedChanges: [], operations: [] });
  const [definitionMode, setDefinitionMode] = useState<'visual' | 'json'>('visual');
  const [definitionSource, setDefinitionSource] = useState('');
  const [planMode, setPlanMode] = useState<'visual' | 'json'>('visual');
  const [planSource, setPlanSource] = useState('');
  const [changes, setChanges] = useState<readonly ModelChange[] | null>(null);
  const [acknowledgementsInvalidated, setAcknowledgementsInvalidated] = useState(false);
  const [preview, setPreview] = useState<MigrationPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [message, setMessage] = useState('');
  const [stale, setStale] = useState(context.currentVersion !== initial.currentVersion);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [approvedDigest, setApprovedDigest] = useState('');
  const idempotency = useRef(crypto.randomUUID());
  const endpoint = `/models/${encodeURIComponent(initial.id)}`;
  function invalidate() { setPreview(null); setApprovedDigest(''); setConfirmOpen(false); setMessage(''); setError(null); idempotency.current = crypto.randomUUID(); }
  function updateDefinition(next: ModelDefinition) { setDefinition(next); setChanges(null); setAcknowledgementsInvalidated(true); setPlan(previous => ({ ...previous, acknowledgedChanges: [] })); invalidate(); }
  function updatePlan(next: MigrationPlan) { setPlan(next); setAcknowledgementsInvalidated(false); invalidate(); }
  function caught(error: unknown) {
    setError(error as Error);
    if (error instanceof ApiError && ([409, 412].includes(error.status) || error.status === 422 && error.issues.some(issue => issue.path === '/plan/sourceVersions'))) { setStale(true); setPreview(null); setApprovedDigest(''); setConfirmOpen(false); }
  }
  async function parseDefinition(text = definitionMode === 'json' ? definitionSource : JSON.stringify(definition)) {
    const result = await api<{ definition: ModelDefinition }>('/models/validate', { method: 'POST', body: JSON.stringify({ text }) });
    if (result.definition.id !== initial.id || result.definition.version !== baseVersion + 1) throw new ApiError(422, { detail: t('migrationDraftIdentity') });
    return result.definition;
  }
  async function parsePlan(text = planMode === 'json' ? planSource : JSON.stringify(plan)) {
    const validated = (await api<{ plan: MigrationPlan }>('/models/migration-plans/validate', { method: 'POST', body: JSON.stringify({ text }) })).plan;
    return acknowledgementsInvalidated ? { ...validated, acknowledgedChanges: [] } : validated;
  }
  async function validateDefinition(text = definitionSource) {
    setBusy(true); setError(null);
    try { updateDefinition(await parseDefinition(text)); setDefinitionMode('visual'); setMessage(t('targetValidated')); }
    catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  async function validatePlan(text = planSource) {
    setBusy(true); setError(null);
    try { updatePlan(await parsePlan(text)); setPlanMode('visual'); setMessage(t('planValidated')); }
    catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  async function importFile(file: File | undefined, kind: 'definition' | 'plan') {
    if (!file) return;
    if (file.size > MODEL_LIMITS.fileLength) { setError(new ApiError(422, { detail: t(kind === 'plan' ? 'planFileTooLarge' : 'tooLargeModel') })); return; }
    const text = await file.text(); invalidate();
    if (kind === 'definition') { setDefinitionSource(text); setDefinitionMode('json'); await validateDefinition(text); }
    else { setPlanSource(text); setPlanMode('json'); await validatePlan(text); }
  }
  async function reviewDefinition() {
    setBusy(true); setError(null); setPreview(null); setApprovedDigest('');
    try {
      const next = await parseDefinition();
      const result = await api<{ preview: ModelPreview }>(`${endpoint}/previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: next }) });
      setDefinition(next); setDefinitionMode('visual'); setChanges(result.preview.changes); setMessage(t('targetValidated'));
    } catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  async function previewValues() {
    setBusy(true); setError(null); setPreview(null); setApprovedDigest(''); setMessage('');
    try {
      const nextDefinition = await parseDefinition(); const nextPlan = await parsePlan();
      const result = await api<{ preview: MigrationPreview }>(`${endpoint}/migration-previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: nextDefinition, plan: nextPlan }) });
      setDefinition(nextDefinition); setPlan(nextPlan); setDefinitionMode('visual'); setPlanMode('visual'); setChanges(result.preview.changes); setPreview(result.preview); setStale(false);
    } catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  async function reloadScope() {
    setBusy(true); setError(null);
    try {
      const draftDefinition = definitionMode === 'json' ? (await api<{ definition: ModelDefinition }>('/models/validate', { method: 'POST', body: JSON.stringify({ text: definitionSource }) })).definition : definition;
      const draftPlan = planMode === 'json' ? await parsePlan() : plan;
      const latest = await api<{ model: PublishedModel }>(endpoint);
      const current = await api<MigrationContext>(`${endpoint}/migration-context`);
      if (latest.model.currentVersion !== current.currentVersion) throw new ApiError(409, { detail: t('migrationScopeChanged') });
      setBaseVersion(current.currentVersion); setScope(current);
      const nextDefinition = { ...draftDefinition, version: current.currentVersion + 1 };
      const nextPlan = { ...draftPlan, targetVersion: current.currentVersion + 1, sourceVersions: current.sourceVersions, acknowledgedChanges: [] };
      setDefinition(nextDefinition); setPlan(nextPlan); setAcknowledgementsInvalidated(false);
      // Raw text is parsed by the server first; only scope metadata and prior
      // acknowledgements change. Field and operation drafts remain intact.
      if (definitionMode === 'json') setDefinitionSource(JSON.stringify(nextDefinition, null, 2));
      if (planMode === 'json') setPlanSource(JSON.stringify(nextPlan, null, 2));
      setChanges(null); invalidate(); setStale(false); setMessage(t('migrationScopeReloaded'));
    } catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  async function execute() {
    if (!preview || approvedDigest !== preview.previewDigest || stale || busy) return;
    setBusy(true); setError(null);
    try {
      const result = await api<{ model: PublishedModel; receipt: ModelMigrationReceipt }>(`${endpoint}/migrations`, { method: 'POST', headers: { 'If-Match': String(baseVersion), 'Idempotency-Key': idempotency.current }, body: JSON.stringify({ definition, plan, previewDigest: approvedDigest }) });
      go(`/models/${encodeURIComponent(initial.id)}/migrations/${encodeURIComponent(result.receipt.id)}`);
    } catch (error) { caught(error); }
    finally { setBusy(false); }
  }
  return <>
    {onBack ? <button className="back-link" disabled={busy} onClick={() => onBack(definition)}><ArrowLeft size={16}/>{t('backToDefinition')}</button> : <BackModel id={initial.id}/>}
    <EntityHeader eyebrow={initial.id} title={t('migrationTitle')} description={t('migrationIntro')}/>
    <p className="supporting-text model-scope">{t('migrationScopeNote')}</p>
    {message && <Notice tone="success">{message}</Notice>}{error && !confirmOpen && <ModelError error={error}/>}
    {stale && <Notice tone="error"><p>{t('migrationStale')}</p><button className="button secondary" disabled={busy} onClick={reloadScope}>{t('reloadMigrationScope')}</button></Notice>}
    <section className="panel migration-context" aria-label={t('migrationContext')}><div className="panel-heading"><h2>{t('migrationContext')}</h2></div><dl className="panel-body migration-scope-grid"><div><dt>{t('currentVersion')}</dt><dd>{number(baseVersion)}</dd></div><div><dt>{t('targetVersion')}</dt><dd>{number(baseVersion + 1)}</dd></div><div><dt>{t('checkedAssets')}</dt><dd>{number(scope.assetCount)}</dd></div><div><dt>{t('pinnedVersions')}</dt><dd>{scope.sourceVersions.length ? scope.sourceVersions.map(version => number(version)).join(', ') : t('noPinnedVersions')}</dd></div></dl></section>
    <fieldset className="model-editor migration-definition" aria-label={t('targetDefinition')} disabled={busy}><legend>{t('targetDefinition')}</legend><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('targetDefinition')}><button type="button" aria-pressed={definitionMode === 'visual'} className={definitionMode === 'visual' ? 'selected' : ''} onClick={() => { if (definitionMode === 'json') void validateDefinition(); }}>{t('visualEditor')}</button><button type="button" aria-pressed={definitionMode === 'json'} className={definitionMode === 'json' ? 'selected' : ''} onClick={() => { if (definitionMode !== 'json') { setDefinitionSource(JSON.stringify(definition, null, 2)); setDefinitionMode('json'); } }}>{t('jsonSource')}</button></div><label className="file-import button secondary">{t('importModel')}<input type="file" aria-label={t('importModel')} accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0], 'definition'); event.target.value = ''; }}/></label></div>{definitionMode === 'visual' ? <FieldEditor fields={definition.attributes} onChange={attributes => updateDefinition({ ...definition, attributes })}/> : <label className="form-field model-json"><span>{t('modelJson')}</span><textarea dir="ltr" className="mono" rows={16} maxLength={MODEL_LIMITS.fileLength} value={definitionSource} onChange={event => { setDefinitionSource(event.target.value); setChanges(null); setAcknowledgementsInvalidated(true); setPlan(previous => ({ ...previous, acknowledgedChanges: [] })); invalidate(); }}/><small>{t('modelJsonHint')}</small><button type="button" className="button secondary" onClick={() => validateDefinition()}>{t('validateModel')}</button></label>}<div className="migration-section-actions"><button type="button" className="button secondary" onClick={reviewDefinition}>{t('reviewDefinition')}</button></div></fieldset>
    <section className="panel migration-plan" aria-label={t('migrationPlan')}><div className="panel-heading"><h2>{t('migrationPlan')}</h2></div><div className="panel-body"><fieldset disabled={busy} className="migration-plan-fields"><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('migrationPlan')}><button type="button" aria-pressed={planMode === 'visual'} className={planMode === 'visual' ? 'selected' : ''} onClick={() => { if (planMode === 'json') void validatePlan(); }}>{t('visualEditor')}</button><button type="button" aria-pressed={planMode === 'json'} className={planMode === 'json' ? 'selected' : ''} onClick={() => { if (planMode !== 'json') { setPlanSource(JSON.stringify(plan, null, 2)); setPlanMode('json'); } }}>{t('jsonSource')}</button></div><div className="migration-file-actions"><label className="file-import button secondary">{t('importPlan')}<input type="file" aria-label={t('importPlan')} accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0], 'plan'); event.target.value = ''; }}/></label><button type="button" className="button secondary" onClick={() => { if (planMode === 'json') exportJsonRaw(planSource, `${initial.id}.migration-plan.json`); else exportJson(plan, `${initial.id}.migration-plan.json`); }}><DownloadSimple size={16}/>{t('exportPlan')}</button></div></div>{!changes && <Notice>{t('definitionReviewHint')}</Notice>}{planMode === 'visual' ? <MigrationPlanEditor plan={plan} definition={definition} destructiveChanges={changes?.filter(change => change.requiresMigration) || []} onChange={updatePlan} disabled={busy}/> : <label className="form-field model-json"><span>{t('planJson')}</span><textarea dir="ltr" className="mono" rows={16} value={planSource} maxLength={MODEL_LIMITS.fileLength} onChange={event => { setPlanSource(event.target.value); invalidate(); }}/><small>{t('planSourceHint')}</small><button type="button" className="button secondary" onClick={() => validatePlan()}>{t('validatePlan')}</button></label>}</fieldset></div></section>
    {preview && <MigrationPreviewPanel preview={preview}/>}
    <div className="model-publication-actions"><Link className="button secondary" href={`/models/${encodeURIComponent(initial.id)}`}>{t('cancel')}</Link><button className="button secondary" disabled={busy || stale} onClick={previewValues}>{busy ? t('previewingModel') : t('previewMigration')}</button><button className="button primary" disabled={busy || stale || !preview?.ready} onClick={() => { setApprovedDigest(''); setConfirmOpen(true); }}>{t('reviewExecution')}</button></div>
    {confirmOpen && preview && <DetailDrawer open onOpenChange={open => { if (!busy) { setConfirmOpen(open); setApprovedDigest(''); } }} title={t('confirmMigration')} description={t('confirmMigrationBody')} closeLabel={t('close')}><div className="stacked-form">{error && <ModelError error={error}/>}<PreviewIdentity preview={preview}/><Notice>{t('migrationAtomic')}</Notice><label className="checkbox-field migration-approval"><input type="checkbox" checked={approvedDigest === preview.previewDigest} disabled={busy} onChange={event => setApprovedDigest(event.target.checked ? preview.previewDigest : '')}/><span>{t('approveMigration')}</span></label><div className="form-actions"><button className="button secondary" disabled={busy} onClick={() => { setConfirmOpen(false); setApprovedDigest(''); }}>{t('cancel')}</button><button className="button primary" disabled={busy || approvedDigest !== preview.previewDigest} onClick={execute}>{busy ? t('executingMigration') : t('executeMigration')}</button></div></div></DetailDrawer>}
  </>;
}
function exportJsonRaw(text: string, filename: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' })); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function BackModel({ id }: { id: string }) { const { t } = useLocale(); return <Link className="back-link" href={`/models/${encodeURIComponent(id)}`}><ArrowLeft size={16}/>{t('backToModel')}</Link>; }
function PreviewIdentity({ preview }: { preview: MigrationPreview }) {
  const { t, number } = useLocale();
  return <dl className="detail-list migration-identity"><div><dt>{t('checkedAssets')}</dt><dd>{number(preview.assetCount)}</dd></div><div><dt>{t('targetVersion')}</dt><dd>{number(preview.proposedVersion)}</dd></div><div><dt>{t('planHash')}</dt><dd className="mono break-all" dir="ltr">{preview.planHash}</dd></div><div><dt>{t('previewDigest')}</dt><dd className="mono break-all" dir="ltr">{preview.previewDigest}</dd></div></dl>;
}
function MigrationPreviewPanel({ preview }: { preview: MigrationPreview }) {
  const { t, number } = useLocale();
  return <section className="panel migration-preview" aria-label={t('migrationPreviewTitle')}><div className="panel-heading"><h2>{t('migrationPreviewTitle')}</h2><p>{t('previewScope')}</p></div><div className="panel-body"><Notice tone="success">{t('migrationReady')}</Notice><PreviewIdentity preview={preview}/>{preview.changes.length ? <ul className="model-changes">{preview.changes.map((change, index) => <li key={index}><span>{t(`change_${change.code}`)}</span><code>{change.path}</code></li>)}</ul> : <p className="supporting-text">{t('migrationNoChanges')}</p>}{!preview.assets.length && <Notice>{t('noMigrationAssets')}</Notice>}<div className="migration-assets">{preview.assets.map((asset, index) => <details className="migration-asset" key={asset.assetId} open={index === 0}><summary><code>{asset.assetId}</code><span>{t('modelVersion')} {number(asset.fromModelVersion)} → {number(asset.toModelVersion)}</span></summary><Link className="preview-asset-link" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{t('openCatalogAsset')}</Link><div className="migration-values"><section aria-label={`${t('beforeValues')} ${asset.assetId}`}><h3>{t('beforeValues')}</h3><p className="supporting-text">{t('assetRevision')} {number(asset.fromAssetVersion)}</p><pre className="code-block" tabIndex={0} dir="ltr">{JSON.stringify(asset.beforeAttributes, null, 2)}</pre><p className="supporting-text">{t('beforeHash')}<code className="migration-hash" dir="ltr">{asset.beforeHash}</code></p></section><section aria-label={`${t('afterValues')} ${asset.assetId}`}><h3>{t('afterValues')}</h3><p className="supporting-text">{t('assetRevision')} {number(asset.toAssetVersion)}</p><pre className="code-block" tabIndex={0} dir="ltr">{JSON.stringify(asset.afterAttributes, null, 2)}</pre><p className="supporting-text">{t('afterHash')}<code className="migration-hash" dir="ltr">{asset.afterHash}</code></p></section></div></details>)}</div></div></section>;
}
export function ModelMigrationReceiptPage({ id, migrationId }: { id: string; migrationId: string }) {
  const { t, number, date } = useLocale();
  const resource = useResource<{ receipt: ModelMigrationReceipt }>(`/models/${encodeURIComponent(id)}/migrations/${encodeURIComponent(migrationId)}`);
  if (resource.error) return <><BackModel id={id}/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data) return <LoadingState label={t('loading')}/>;
  const { receipt } = resource.data;
  return <><BackModel id={id}/><EntityHeader eyebrow={receipt.modelId} title={t('migrationReceipt')} description={t('migrationReceiptDescription')} actions={<button className="button secondary" onClick={() => exportJson(receipt, `${receipt.modelId}.migration-${receipt.id}.json`)}><DownloadSimple size={16}/>{t('exportReceipt')}</button>}/><Notice tone="success">{t('migrationCommitted')}</Notice><section className="panel"><div className="panel-body"><dl className="detail-list migration-receipt-facts"><div><dt>{t('migrationId')}</dt><dd className="mono break-all">{receipt.id}</dd></div><div><dt>{t('executedAt')}</dt><dd>{date(receipt.executedAt)}</dd></div><div><dt>{t('executedBy')}</dt><dd className="mono break-all">{receipt.executedBy}</dd></div><div><dt>{t('previousModelVersion')}</dt><dd><Link href={`/models/${encodeURIComponent(id)}?version=${receipt.fromVersion}`}>{number(receipt.fromVersion)}</Link></dd></div><div><dt>{t('resultingModelVersion')}</dt><dd><Link href={`/models/${encodeURIComponent(id)}?version=${receipt.toVersion}`}>{number(receipt.toVersion)}</Link></dd></div><div><dt>{t('migratedAssets')}</dt><dd>{number(receipt.assetCount)}</dd></div><div><dt>{t('planHash')}</dt><dd className="mono break-all" dir="ltr">{receipt.planHash}</dd></div><div><dt>{t('previewDigest')}</dt><dd className="mono break-all" dir="ltr">{receipt.previewDigest}</dd></div></dl><p className="supporting-text">{t('receiptIntegrity')}</p></div></section><section className="panel migration-receipt-assets"><div className="panel-heading"><h2>{t('migratedAssets')} ({number(receipt.assetCount)})</h2></div><div className="panel-body">{receipt.assets.map(asset => <article className="migration-asset" key={asset.assetId}><h3><Link className="preview-asset-link mono" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{asset.assetId}</Link></h3><div className="preview-counts"><span>{t('modelVersion')}: {number(asset.fromModelVersion)} → {number(asset.toModelVersion)}</span><span>{t('assetRevision')}: {number(asset.fromAssetVersion)} → {number(asset.toAssetVersion)}</span></div><dl className="detail-list"><div><dt>{t('beforeHash')}</dt><dd className="mono break-all" dir="ltr">{asset.beforeHash}</dd></div><div><dt>{t('afterHash')}</dt><dd className="mono break-all" dir="ltr">{asset.afterHash}</dd></div></dl></article>)}{!receipt.assets.length && <p>{t('noPinnedVersions')}</p>}</div></section><section className="panel migration-receipt-plan"><div className="panel-heading"><h2>{t('recordedPlan')}</h2></div><div className="panel-body"><pre className="code-block" tabIndex={0} dir="ltr">{JSON.stringify(receipt.plan, null, 2)}</pre></div></section></>;
}
