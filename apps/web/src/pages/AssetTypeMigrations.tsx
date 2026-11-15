// SPDX-License-Identifier: Apache-2.0
import { useRef, useState } from 'react';
import { ArrowLeft, DownloadSimple } from '@phosphor-icons/react';
import { DetailDrawer, EntityHeader, LoadingState, Notice } from '../../../../packages/ui/src';
import { MODEL_LIMITS } from '../../../../packages/domain/src/model';
import type { ResolvedAssetType } from '../../../../packages/domain/src/asset-type';
import type { AssetTypeMigrationPlan } from '../../../../packages/domain/src/asset-type-migration';
import type { TypeMigrationContext, TypeMigrationPreview, TypeMigrationReceipt, TypeMigrationAssetReceipt, TypeMigrationAssetPreview, TypePolicyChange } from '../../../../packages/domain/src/asset-type-migration-contracts';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import type { Member } from '../types';
import { IssueList, ModelError } from '../models/ModelFeedback';
import { MigrationPlanEditor } from '../models/MigrationPlanEditor';
import { AssetTypeDefinitionEditor } from '../assetTypes/DefinitionEditor';
import { TypeMigrationPolicyEditor } from '../assetTypes/TypeMigrationPolicyEditor';
import type { AssetTypeDefinition, AssetTypePreview, PublishedAssetType } from '../assetTypes/contracts';

const PLAN_FILE_LIMIT = 512 * 1024;
interface TargetReview extends AssetTypePreview { target: ResolvedAssetType; policyChanges: readonly TypePolicyChange[] }
function download(value: unknown, filename: string, raw = false) {
  const url = URL.createObjectURL(new Blob([raw ? String(value) : JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function BackType({ id }: { id: string }) { const { t } = useLocale(); return <Link className="back-link" href={`/asset-types/${encodeURIComponent(id)}`}><ArrowLeft size={16}/>{t('backAssetTypes')}</Link>; }
export function AssetTypeMigrationPage({ id }: { id: string }) {
  const { t } = useLocale();
  const resource = useResource<{ type: PublishedAssetType }>(`/asset-types/${encodeURIComponent(id)}`);
  if (resource.error) return <><BackType id={id}/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data) return <LoadingState label={t('loading')}/>;
  return <AssetTypeMigrationWorkbench key={id} initial={resource.data.type}/>;
}
export function AssetTypeMigrationWorkbench({ initial, initialDefinition, onBack }: { initial: PublishedAssetType; initialDefinition?: AssetTypeDefinition; onBack?: (definition: AssetTypeDefinition) => void }) {
  const { t } = useLocale();
  const resource = useResource<TypeMigrationContext>(`/asset-types/${encodeURIComponent(initial.id)}/migration-context`);
  if (resource.error) return <><BackType id={initial.id}/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data) return <LoadingState label={t('loading')}/>;
  return <TypeMigrationEditor initial={initial} context={resource.data} initialDefinition={initialDefinition} onBack={onBack}/>;
}
function TypeMigrationEditor({ initial, context, initialDefinition, onBack }: { initial: PublishedAssetType; context: TypeMigrationContext; initialDefinition?: AssetTypeDefinition; onBack?: (definition: AssetTypeDefinition) => void }) {
  const { t, number } = useLocale(); const { go } = useNavigation();
  const members = useResource<{ items: Member[] }>('/members');
  const [scope, setScope] = useState(context);
  const [baseVersion, setBaseVersion] = useState(initial.currentVersion);
  const [definition, setDefinition] = useState<AssetTypeDefinition>(initialDefinition || { ...initial.definition, version: initial.currentVersion + 1 });
  const [plan, setPlan] = useState<AssetTypeMigrationPlan>({ formatVersion: 1, typeId: initial.typeId, attributes: { formatVersion: 1, modelId: initial.id, targetVersion: initial.currentVersion + 1, sourceVersions: context.sourceVersions, operations: [], acknowledgedChanges: [] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [] });
  const [definitionMode, setDefinitionMode] = useState<'visual' | 'json'>('visual'); const [definitionText, setDefinitionText] = useState('');
  const [planMode, setPlanMode] = useState<'visual' | 'json'>('visual'); const [planText, setPlanText] = useState('');
  const [review, setReview] = useState<TargetReview | null>(null); const [preview, setPreview] = useState<TypeMigrationPreview | null>(null);
  const [acknowledgementsInvalidated, setAcknowledgementsInvalidated] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<Error | null>(null); const [message, setMessage] = useState('');
  const [stale, setStale] = useState(context.currentVersion !== initial.currentVersion); const [confirmOpen, setConfirmOpen] = useState(false); const [approvedDigest, setApprovedDigest] = useState('');
  const idempotency = useRef(crypto.randomUUID()); const endpoint = `/asset-types/${encodeURIComponent(initial.id)}`;
  function invalidate() { setPreview(null); setApprovedDigest(''); setConfirmOpen(false); setMessage(''); setError(null); idempotency.current = crypto.randomUUID(); }
  function clearAcks(value: AssetTypeMigrationPlan): AssetTypeMigrationPlan { return { ...value, attributes: { ...value.attributes, acknowledgedChanges: [] }, acknowledgedPolicyChanges: [] }; }
  function changeDefinition(next: AssetTypeDefinition) { setDefinition(next); setReview(null); setAcknowledgementsInvalidated(true); setPlan(previous => clearAcks(previous)); invalidate(); }
  function changePlan(next: AssetTypeMigrationPlan) { setPlan(next); setAcknowledgementsInvalidated(false); invalidate(); }
  function caught(value: unknown) {
    setError(value as Error);
    if (value instanceof ApiError && ([409, 412].includes(value.status) || value.status === 422 && value.issues.some(issue => issue.path.includes('sourceVersions')))) { setStale(true); setPreview(null); setApprovedDigest(''); setConfirmOpen(false); }
  }
  async function parseDefinition(text = definitionMode === 'json' ? definitionText : JSON.stringify(definition), checkVersion = true) {
    const value = (await api<{ definition: AssetTypeDefinition }>('/asset-types/validate', { method: 'POST', body: JSON.stringify({ text }) })).definition;
    if (value.id !== initial.id || checkVersion && value.version !== baseVersion + 1) throw new ApiError(422, { detail: t('typeIdentityError') });
    return value;
  }
  async function parsePlan(text = planMode === 'json' ? planText : JSON.stringify(plan)) {
    const value = (await api<{ plan: AssetTypeMigrationPlan }>('/asset-types/migration-plans/validate', { method: 'POST', body: JSON.stringify({ text }) })).plan;
    if (value.typeId !== initial.typeId || value.attributes.modelId !== initial.id) throw new ApiError(422, { detail: t('typeMigrationPlanIdentity') });
    return acknowledgementsInvalidated ? clearAcks(value) : value;
  }
  async function validateFile(kind: 'definition' | 'plan', text: string) {
    setBusy(true); setError(null);
    try { if (kind === 'definition') { changeDefinition(await parseDefinition(text)); setDefinitionMode('visual'); setMessage(t('targetValidated')); } else { const accepted = await parsePlan(text); changePlan(accepted); setPlanText(JSON.stringify(accepted, null, 2)); setPlanMode('visual'); setMessage(t('planValidated')); } }
    catch (value) { caught(value); } finally { setBusy(false); }
  }
  async function importFile(file: File | undefined, kind: 'definition' | 'plan') {
    if (!file) return; invalidate();
    if (file.size > (kind === 'plan' ? PLAN_FILE_LIMIT : MODEL_LIMITS.fileLength)) { setError(new ApiError(422, { detail: t(kind === 'plan' ? 'typeMigrationFileTooLarge' : 'tooLargeModel') })); return; }
    const text = await file.text();
    if (kind === 'definition') { setDefinitionText(text); setDefinitionMode('json'); setReview(null); setAcknowledgementsInvalidated(true); setPlan(previous => clearAcks(previous)); }
    else { setPlanText(text); setPlanMode('json'); }
    await validateFile(kind, text);
  }
  async function targetReview(next: AssetTypeDefinition) {
    return (await api<{ preview: TargetReview }>(`${endpoint}/previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: next }) })).preview;
  }
  async function reviewDefinition() {
    setBusy(true); invalidate();
    try { const next = await parseDefinition(); const result = await targetReview(next); setDefinition(next); setDefinitionMode('visual'); setReview(result); setMessage(t('targetValidated')); }
    catch (value) { caught(value); } finally { setBusy(false); }
  }
  async function previewValues() {
    setBusy(true); invalidate();
    try {
      const next = await parseDefinition(); const proposedPlan = await parsePlan(); const target = await targetReview(next);
      const result = await api<{ preview: TypeMigrationPreview }>(`${endpoint}/migration-previews`, { method: 'POST', headers: { 'If-Match': String(baseVersion) }, body: JSON.stringify({ definition: next, plan: proposedPlan }) });
      setDefinition(next); setPlan(proposedPlan); setDefinitionMode('visual'); setPlanMode('visual'); setReview(target); setPreview(result.preview); setStale(false); setAcknowledgementsInvalidated(false);
    } catch (value) { caught(value); } finally { setBusy(false); }
  }
  async function reloadScope() {
    setBusy(true); setError(null);
    try {
      // Incomplete visual controls are drafts, not submission payloads. Scope
      // recovery must preserve them so users can finish them after re-resolution.
      const draft = definitionMode === 'json' ? await parseDefinition(definitionText, false) : definition;
      const draftPlan = planMode === 'json' ? await parsePlan(planText) : plan;
      const latest = await api<{ type: PublishedAssetType }>(endpoint); const current = await api<TypeMigrationContext>(`${endpoint}/migration-context`);
      if (latest.type.currentVersion !== current.currentVersion) throw new ApiError(409, { detail: t('migrationScopeChanged') });
      const nextDefinition = { ...draft, version: current.currentVersion + 1 };
      const nextPlan = clearAcks({ ...draftPlan, attributes: { ...draftPlan.attributes, targetVersion: current.currentVersion + 1, sourceVersions: current.sourceVersions } });
      setScope(current); setBaseVersion(current.currentVersion); setDefinition(nextDefinition); setPlan(nextPlan); setReview(null); setAcknowledgementsInvalidated(false); members.reload();
      if (definitionMode === 'json') setDefinitionText(JSON.stringify(nextDefinition, null, 2));
      if (planMode === 'json') setPlanText(JSON.stringify(nextPlan, null, 2));
      invalidate(); setStale(false); setMessage(t('migrationScopeReloaded'));
    } catch (value) { caught(value); } finally { setBusy(false); }
  }
  async function execute() {
    if (!preview || approvedDigest !== preview.previewDigest || stale || busy) return;
    setBusy(true); setError(null);
    try { const result = await api<{ type: PublishedAssetType; receipt: TypeMigrationReceipt }>(`${endpoint}/migrations`, { method: 'POST', headers: { 'If-Match': String(baseVersion), 'Idempotency-Key': idempotency.current }, body: JSON.stringify({ definition, plan, previewDigest: approvedDigest }) }); go(`${endpoint}/migrations/${encodeURIComponent(result.receipt.id)}`); }
    catch (value) { caught(value); } finally { setBusy(false); }
  }
  return <>
    {onBack ? <button className="back-link" disabled={busy} onClick={() => onBack(definition)}><ArrowLeft size={16}/>{t('backToDefinition')}</button> : <BackType id={initial.id}/>}
    <EntityHeader eyebrow={initial.id} title={t('typeMigrationTitle')} description={t('typeMigrationIntro')}/><p className="supporting-text model-scope">{t('typeMigrationScope')}</p>
    {message && <Notice tone="success">{message}</Notice>}{error && !confirmOpen && <ModelError error={error}/>}
    {stale && <Notice tone="error"><p>{t('typeMigrationStale')}</p></Notice>}
    <section className="panel migration-context" aria-label={t('migrationContext')}><div className="panel-heading"><h2>{t('migrationContext')}</h2><button className="button secondary" disabled={busy} onClick={reloadScope}>{t('reloadMigrationScope')}</button></div><dl className="panel-body migration-scope-grid"><div><dt>{t('currentVersion')}</dt><dd>{number(baseVersion)}</dd></div><div><dt>{t('targetVersion')}</dt><dd>{number(baseVersion + 1)}</dd></div><div><dt>{t('checkedAssets')}</dt><dd>{number(scope.assetCount)}</dd></div><div><dt>{t('pinnedVersions')}</dt><dd>{scope.sourceVersions.map(number).join(', ') || t('noPinnedVersions')}</dd></div></dl>{scope.sources.length > 0 && <div className="panel-body type-migration-source-policies"><h3>{t('typeMigrationSourcePolicies')}</h3>{scope.sources.map(source => <details key={source.version}><summary>{t('version')} {number(source.version)} · {t('resolvedOwner')}: {t(source.resolution.requiredOwner ? 'yes' : 'no')}</summary><p className="mono break-all" dir="ltr">{source.resolutionHash}</p><pre className="code-block" dir="ltr" tabIndex={0}>{JSON.stringify(source.resolution, null, 2)}</pre></details>)}</div>}</section>
    <fieldset className="model-editor migration-definition" disabled={busy}><legend>{t('targetDefinition')}</legend><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('targetDefinition')}><button type="button" aria-pressed={definitionMode === 'visual'} className={definitionMode === 'visual' ? 'selected' : ''} onClick={() => { if (definitionMode === 'json') void validateFile('definition', definitionText); }}>{t('visualEditor')}</button><button type="button" aria-pressed={definitionMode === 'json'} className={definitionMode === 'json' ? 'selected' : ''} onClick={() => { if (definitionMode !== 'json') { setDefinitionText(JSON.stringify(definition, null, 2)); setDefinitionMode('json'); } }}>{t('jsonSource')}</button></div><div className="migration-file-actions"><label className="file-import button secondary">{t('importAssetType')}<input type="file" aria-label={t('importAssetType')} accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0], 'definition'); event.target.value = ''; }}/></label><button type="button" className="button secondary" onClick={() => download(definitionMode === 'json' ? definitionText : definition, `${initial.id}.type-target.json`, definitionMode === 'json')}><DownloadSimple size={16}/>{t('exportAssetType')}</button></div></div>
      {definitionMode === 'visual' ? <AssetTypeDefinitionEditor key={`definition:${baseVersion}`} definition={definition} onChange={changeDefinition} lockedId/> : <div className="stacked-form"><label className="form-field model-json"><span>{t('typeJson')}</span><textarea dir="ltr" className="mono" rows={16} maxLength={MODEL_LIMITS.fileLength} value={definitionText} onChange={event => { setDefinitionText(event.target.value); setReview(null); setAcknowledgementsInvalidated(true); setPlan(previous => clearAcks(previous)); invalidate(); }}/></label><div className="migration-section-actions"><button className="button secondary" type="button" onClick={() => validateFile('definition', definitionText)}>{t('validateAssetType')}</button><button type="button" className="text-button" onClick={() => { setDefinitionMode('visual'); invalidate(); }}>{t('typeMigrationRestoreDraft')}</button></div></div>}
      <div className="migration-section-actions"><button type="button" className="button secondary" disabled={stale} onClick={reviewDefinition}>{t('typeMigrationReview')}</button></div>
    </fieldset>
    <section className="panel migration-plan" aria-label={t('migrationPlan')}><div className="panel-heading"><h2>{t('migrationPlan')}</h2></div><div className="panel-body"><fieldset className="migration-plan-fields" disabled={busy}><div className="model-toolbar"><div className="segmented-control" role="group" aria-label={t('migrationPlan')}><button type="button" aria-pressed={planMode === 'visual'} className={planMode === 'visual' ? 'selected' : ''} onClick={() => { if (planMode === 'json') void validateFile('plan', planText); }}>{t('visualEditor')}</button><button type="button" aria-pressed={planMode === 'json'} className={planMode === 'json' ? 'selected' : ''} onClick={() => { if (planMode !== 'json') { setPlanText(JSON.stringify(plan, null, 2)); setPlanMode('json'); } }}>{t('jsonSource')}</button></div><div className="migration-file-actions"><label className="file-import button secondary">{t('importPlan')}<input type="file" aria-label={t('importPlan')} accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0], 'plan'); event.target.value = ''; }}/></label><button className="button secondary" type="button" onClick={() => download(planMode === 'json' ? planText : plan, `${initial.id}.type-migration-plan.json`, planMode === 'json')}><DownloadSimple size={16}/>{t('exportPlan')}</button></div></div>
      {planMode === 'json' ? <div className="stacked-form"><label className="form-field model-json"><span>{t('planJson')}</span><textarea className="mono" dir="ltr" rows={16} maxLength={PLAN_FILE_LIMIT} value={planText} onChange={event => { setPlanText(event.target.value); invalidate(); }}/><small>{t('planSourceHint')}</small></label><div className="migration-section-actions"><button type="button" className="button secondary" onClick={() => validateFile('plan', planText)}>{t('validatePlan')}</button><button type="button" className="text-button" onClick={() => { setPlanMode('visual'); invalidate(); }}>{t('typeMigrationRestoreDraft')}</button></div></div> : !review ? <Notice>{t('typeMigrationReviewHint')}</Notice> : <><MigrationPlanEditor plan={plan.attributes} definition={review.target.model} destructiveChanges={review.changes.filter(change => change.path.startsWith('/attributes/'))} onChange={attributes => changePlan({ ...plan, attributes })}/>{members.error ? <RequestError error={members.error} retry={members.reload} compact/> : !members.data ? <LoadingState label={t('loading')}/> : <TypeMigrationPolicyEditor plan={plan} context={scope} target={review.target} policyChanges={review.policyChanges} members={members.data.items} onChange={changePlan}/>}</>}
    </fieldset></div></section>
    {preview && <TypeMigrationPreviewPanel preview={preview}/>}
    <div className="model-publication-actions"><Link className="button secondary" href={`/asset-types/${encodeURIComponent(initial.id)}`}>{t('cancel')}</Link><button className="button secondary" disabled={busy || stale} onClick={previewValues}>{busy ? t('previewingModel') : t('previewMigration')}</button><button className="button primary" disabled={busy || stale || !preview?.ready} onClick={() => { setApprovedDigest(''); setConfirmOpen(true); }}>{t('reviewExecution')}</button></div>
    {confirmOpen && preview && <DetailDrawer open onOpenChange={open => { if (!busy) { setConfirmOpen(open); setApprovedDigest(''); } }} title={t('typeMigrationConfirm')} description={t('typeMigrationConfirmBody')} closeLabel={t('close')}><div className="stacked-form">{error && <ModelError error={error}/>}<MigrationIdentity preview={preview}/><Notice>{t('typeMigrationAtomic')}</Notice><label className="checkbox-field migration-approval"><input type="checkbox" disabled={busy} checked={approvedDigest === preview.previewDigest} onChange={event => setApprovedDigest(event.target.checked ? preview.previewDigest : '')}/><span>{t('typeMigrationApprove')}</span></label><div className="form-actions"><button className="button secondary" disabled={busy} onClick={() => { setConfirmOpen(false); setApprovedDigest(''); }}>{t('cancel')}</button><button className="button primary" disabled={busy || approvedDigest !== preview.previewDigest} onClick={execute}>{busy ? t('executingMigration') : t('executeMigration')}</button></div></div></DetailDrawer>}
  </>;
}
function MigrationIdentity({ preview }: { preview: TypeMigrationPreview }) {
  const { t, number } = useLocale(); return <dl className="detail-list migration-identity"><div><dt>{t('checkedAssets')}</dt><dd>{number(preview.assetCount)}</dd></div><div><dt>{t('targetVersion')}</dt><dd>{number(preview.proposedVersion)}</dd></div><div><dt>{t('planHash')}</dt><dd className="mono break-all" dir="ltr">{preview.planHash}</dd></div><div><dt>{t('previewDigest')}</dt><dd className="mono break-all" dir="ltr">{preview.previewDigest}</dd></div><div><dt>{t('definitionHash')}</dt><dd className="mono break-all" dir="ltr">{preview.definitionHash}</dd></div><div><dt>{t('resolutionHash')}</dt><dd className="mono break-all" dir="ltr">{preview.resolutionHash}</dd></div></dl>;
}
function TupleComparison({ asset }: { asset: TypeMigrationAssetReceipt | TypeMigrationAssetPreview }) {
  const { t, number } = useLocale();
  return <><div className="preview-counts"><span>{t('modelVersion')}: {number(asset.fromModelVersion)} → {number(asset.toModelVersion)}</span><span>{t('assetRevision')}: {number(asset.fromAssetVersion)} → {number(asset.toAssetVersion)}</span></div>{'sourceIssues' in asset && asset.sourceIssues.length > 0 && <><h4>{t('typeMigrationSourceIssues')}</h4><IssueList issues={asset.sourceIssues}/></>}<div className="migration-values type-migration-tuples">{(['before', 'after'] as const).map(side => <section key={side}><h4>{t(side === 'before' ? 'typeMigrationBefore' : 'typeMigrationAfter')}</h4><dl className="detail-list"><div><dt>{t('owner')}</dt><dd className="mono break-all">{asset[side].ownerId || t('unassigned')}</dd></div><div><dt>{t('lifecycleCurrent')}</dt><dd><bdi>{asset[side].state}</bdi></dd></div></dl><pre className="code-block" dir="ltr" tabIndex={0}>{JSON.stringify(asset[side], null, 2)}</pre><p className="supporting-text">{t('typeMigrationTupleHash')}</p><p className="mono break-all" dir="ltr">{side === 'before' ? asset.beforeTupleHash : asset.afterTupleHash}</p></section>)}</div></>;
}
function TypeMigrationPreviewPanel({ preview }: { preview: TypeMigrationPreview }) {
  const { t } = useLocale();
  return <section className="panel type-migration-preview" aria-label={t('typeMigrationTuplePreview')}><div className="panel-heading"><h2>{t('typeMigrationTuplePreview')}</h2><p>{t('previewScope')}</p></div><div className="panel-body"><Notice tone="success">{t('typeMigrationReady')}</Notice><MigrationIdentity preview={preview}/><h3>{t('typeMigrationPolicyAcks')}</h3>{preview.policyChanges.length ? <ul>{preview.policyChanges.map(code => <li key={code}>{t(`policy_${code}`)}</li>)}</ul> : <p>{t('typeMigrationNoPolicyChanges')}</p>}<h3>{t('changesToModel')}</h3>{preview.changes.length ? <ul className="model-changes">{preview.changes.map((change, index) => <li key={index}><span>{t(`change_${change.code}`)}</span><code>{change.path}</code></li>)}</ul> : <p>{t('noModelChanges')}</p>}<div className="migration-assets">{preview.assets.map((asset, index) => <details className="migration-asset" key={asset.assetId} open={index === 0}><summary><code>{asset.assetId}</code></summary><Link className="preview-asset-link" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{t('openCatalogAsset')}</Link><TupleComparison asset={asset}/></details>)}</div>{!preview.assets.length && <Notice>{t('noMigrationAssets')}</Notice>}<SourceHashes sources={preview.sourceResolutions}/></div></section>;
}
function SourceHashes({ sources }: { sources: TypeMigrationPreview['sourceResolutions'] }) { const { t, number } = useLocale(); return <details className="type-migration-source-hashes"><summary>{t('typeMigrationSourceHashes')}</summary><dl className="detail-list">{sources.map(source => <div key={source.version}><dt>{t('version')} {number(source.version)}</dt><dd className="mono break-all" dir="ltr">{source.resolutionHash}</dd></div>)}</dl></details>; }
export function AssetTypeMigrationReceiptPage({ id, migrationId }: { id: string; migrationId: string }) {
  const { t, date, number } = useLocale();
  const resource = useResource<{ receipt: TypeMigrationReceipt }>(`/asset-types/${encodeURIComponent(id)}/migrations/${encodeURIComponent(migrationId)}`);
  if (resource.error) return <><BackType id={id}/><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data) return <LoadingState label={t('loading')}/>;
  const { receipt } = resource.data;
  return <><BackType id={id}/><EntityHeader eyebrow={receipt.modelId} title={t('typeMigrationReceipt')} description={t('typeMigrationReceiptBody')} actions={<button className="button secondary" onClick={() => download(receipt, `${id}.type-migration-${receipt.id}.json`)}><DownloadSimple size={16}/>{t('exportReceipt')}</button>}/><Notice tone="success">{t('migrationCommitted')}</Notice><section className="panel"><div className="panel-body"><dl className="detail-list migration-receipt-facts"><div><dt>{t('migrationId')}</dt><dd className="mono break-all">{receipt.id}</dd></div><div><dt>{t('executedAt')}</dt><dd>{date(receipt.executedAt)}</dd></div><div><dt>{t('executedBy')}</dt><dd className="mono break-all">{receipt.executedBy}</dd></div><div><dt>{t('previousModelVersion')}</dt><dd><Link href={`/asset-types/${encodeURIComponent(id)}?version=${receipt.fromVersion}`}>{number(receipt.fromVersion)}</Link></dd></div><div><dt>{t('resultingModelVersion')}</dt><dd><Link href={`/asset-types/${encodeURIComponent(id)}?version=${receipt.toVersion}`}>{number(receipt.toVersion)}</Link></dd></div><div><dt>{t('migratedAssets')}</dt><dd>{number(receipt.assetCount)}</dd></div>{(['planHash', 'previewDigest', 'definitionHash', 'resolutionHash'] as const).map(key => <div key={key}><dt>{t(key)}</dt><dd className="mono break-all" dir="ltr">{receipt[key]}</dd></div>)}</dl><SourceHashes sources={receipt.sourceResolutions}/></div></section><section className="panel type-migration-receipt-assets"><div className="panel-heading"><h2>{t('migratedAssets')} ({number(receipt.assetCount)})</h2></div><div className="panel-body">{receipt.assets.map(asset => <article className="migration-asset" key={asset.assetId}><h3><Link className="preview-asset-link mono" href={`/catalog/${encodeURIComponent(asset.assetId)}`}>{asset.assetId}</Link></h3><TupleComparison asset={asset}/></article>)}{!receipt.assets.length && <p>{t('noMigrationAssets')}</p>}</div></section><section className="panel migration-receipt-plan"><div className="panel-heading"><h2>{t('recordedPlan')}</h2></div><div className="panel-body"><pre className="code-block" dir="ltr" tabIndex={0}>{JSON.stringify(receipt.plan, null, 2)}</pre></div></section></>;
}
