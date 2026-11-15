// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react';
import { EmptyState, LoadingState, Notice } from '../../../../packages/ui/src';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { usePermission } from '../session';
import { ModelError } from '../models/ModelFeedback';
import type { AssetTypeState } from './contracts';

export function LifecyclePanel({ assetId, assetVersion, onSaved }: { assetId: string; assetVersion: number; onSaved: () => void }) {
  const { t, number } = useLocale();
  const resource = useResource<AssetTypeState>(`/assets/${encodeURIComponent(assetId)}/type-state`);
  const observedVersion = useRef(assetVersion);
  const canWrite = usePermission('catalog:write');
  const [nextState, setNextState] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [stale, setStale] = useState(false);
  const [saved, setSaved] = useState(false);
  const idempotency = useRef(crypto.randomUUID());
  useEffect(() => { if (observedVersion.current !== assetVersion) { observedVersion.current = assetVersion; resource.reload(); setNextState(''); idempotency.current = crypto.randomUUID(); } }, [assetVersion, resource.reload]);
  const state = resource.data;
  const allowed = state?.lifecycle?.transitions.filter(item => item.from === state.state).map(item => item.to) || [];
  function reload() { setStale(false); setError(null); setNextState(''); setSaved(false); idempotency.current = crypto.randomUUID(); resource.reload(); }
  async function transition(event: React.FormEvent) {
    event.preventDefault(); if (!state || busy || stale || !allowed.includes(nextState)) return;
    setBusy(true); setError(null); setSaved(false);
    try { await api<AssetTypeState>(`/assets/${encodeURIComponent(assetId)}/type-state`, { method: 'POST', headers: { 'If-Match': String(state.assetVersion), 'Idempotency-Key': idempotency.current }, body: JSON.stringify({ state: nextState }) }); setSaved(true); setNextState(''); idempotency.current = crypto.randomUUID(); resource.reload(); onSaved(); }
    catch (caught) { setError(caught as Error); if (caught instanceof ApiError && [409, 412].includes(caught.status)) setStale(true); }
    finally { setBusy(false); }
  }
  return <section className="panel asset-lifecycle"><div className="panel-heading"><h2>{t('lifecycle')}</h2></div><div className="panel-body">{resource.error ? <RequestError error={resource.error} retry={reload} compact/> : resource.loading || !state ? <LoadingState label={t('loading')}/> : !state.lifecycle || !state.modelId ? <EmptyState compact title={t('noAssetLifecycle')} description={t('noAssetLifecycleBody')}/> : <><div className="attribute-model-pin"><Link href={`/asset-types/${encodeURIComponent(state.modelId)}?version=${state.modelVersion}`}>{state.modelId}</Link><span>{t('modelVersion')} {number(state.modelVersion!)}</span></div><dl className="detail-list"><div><dt>{t('lifecycleCurrent')}</dt><dd><strong data-testid="lifecycle-current"><bdi>{state.state}</bdi></strong></dd></div><div><dt>{t('resolvedOwner')}</dt><dd>{t(state.requiredOwner ? 'yes' : 'no')}</dd></div></dl><p className="supporting-text">{t('lifecyclePin')}</p>{saved && <Notice tone="success">{t('lifecycleSaved')}</Notice>}{error && <ModelError error={error}/>}{stale && <Notice tone="error"><p>{t('lifecycleStale')}</p><button className="button secondary" disabled={busy} onClick={reload}>{t('reloadVersion')}</button></Notice>}{canWrite ? allowed.length ? <form onSubmit={transition} className="lifecycle-transition-form"><label className="form-field"><span>{t('nextLifecycleState')}</span><select value={nextState} disabled={busy || stale} onChange={event => { setNextState(event.target.value); setError(null); setSaved(false); idempotency.current = crypto.randomUUID(); }}><option value="">{t('nextLifecycleState')}</option>{allowed.map(next => <option key={next} value={next}>{next}</option>)}</select></label><button className="button secondary" disabled={busy || stale || !allowed.includes(nextState)}>{busy ? t('saving') : t('transitionAsset')}</button><p className="supporting-text">{t('transitionReview')}</p></form> : <p className="supporting-text">{t('lifecycleNoNext')}</p> : <p className="supporting-text">{t('lifecycleReadOnly')}</p>}<details className="lifecycle-rule-detail"><summary>{t('lifecycleTransitions')}</summary><ul>{state.lifecycle.transitions.map(item => <li key={`${item.from}:${item.to}`}><bdi>{item.from}</bdi> → <bdi>{item.to}</bdi></li>)}</ul>{!state.lifecycle.transitions.length && <p>{t('noTransitions')}</p>}</details></>}</div></section>;
}
