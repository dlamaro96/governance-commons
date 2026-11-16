// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react';
import { EmptyState, LoadingState, Notice } from '../../../../packages/ui/src';
import { ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { ModelError } from '../models/ModelFeedback';
import type { RelationTypeSummary } from '../../../../packages/domain/src/relation-contracts';

export function downloadJson(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const relationPath = (id: string) => `/relations/${encodeURIComponent(id)}`;
export const relationTypePath = (id: string) => `/relation-types/${encodeURIComponent(id)}`;
export function useCursorPage<T>(base: string, initialLimit = 25) {
  const [position, setPosition] = useState({ base, limit: initialLimit, cursors: [null] as (string | null)[] });
  const effective = position.base === base ? position : { ...position, base, cursors: [null] };
  const params = new URLSearchParams({ limit: String(effective.limit) });
  const cursor = effective.cursors.at(-1); if (cursor) params.set('cursor', cursor);
  const path = `${base}${base.includes('?') ? '&' : '?'}${params}`;
  const resource = useResource<{ items: T[]; nextCursor: string | null; graphRevision?: string }>(path);
  const requested = useRef(path); const changing = requested.current !== path;
  useEffect(() => { requested.current = path; if (position.base !== base) setPosition(effective); }, [path, base]);
  const data = changing || resource.error ? null : resource.data;
  const loading = changing || resource.loading;
  return { ...resource, data, loading, error: changing ? null : resource.error, items: data?.items || [], limit: effective.limit, page: effective.cursors.length,
    previous: effective.cursors.length > 1, next: !loading && !resource.error && !!data?.nextCursor,
    prevPage: () => setPosition({ ...effective, cursors: effective.cursors.slice(0, -1) }),
    nextPage: () => { if (data?.nextCursor && !loading) setPosition({ ...effective, cursors: [...effective.cursors, data.nextCursor] }); },
    setLimit: (limit: number) => setPosition({ base, limit, cursors: [null] }),
    restart: () => { setPosition({ ...effective, cursors: [null] }); resource.reload(); },
  };
}
export function CursorControls({ pager }: { pager: { limit: number; page: number; previous: boolean; next: boolean; loading: boolean; setLimit: (n: number) => void; prevPage: () => void; nextPage: () => void } }) {
  const { t, number } = useLocale();
  return <div className="model-pager"><label className="form-field"><span>{t('pageSize')}</span><select value={pager.limit} disabled={pager.loading} onChange={event => pager.setLimit(Number(event.target.value))}>{[1, 25, 50, 100].map(n => <option key={n} value={n}>{number(n)}</option>)}</select></label><span aria-live="polite">{t('page')} {number(pager.page)}</span><nav aria-label={t('page')}><button type="button" className="button secondary" disabled={pager.loading || !pager.previous} onClick={pager.prevPage}>{t('previous')}</button><button type="button" className="button secondary" disabled={pager.loading || !pager.next} onClick={pager.nextPage}>{t('more')}</button></nav></div>;
}
export function RelationTypeChooser({ selected, onSelect, allowAll = false, selectedId }: { selected: RelationTypeSummary | null; onSelect: (type: RelationTypeSummary | null) => void; allowAll?: boolean; selectedId?:string }) {
  const { t } = useLocale(); const [draft, setDraft] = useState(''); const [query, setQuery] = useState('');
  const pager = useCursorPage<RelationTypeSummary>(`/relation-types?q=${encodeURIComponent(query)}`);
  return <div className="relation-type-chooser"><div className="model-search"><label className="form-field"><span>{t('relationSearchTypes')}</span><input type="search" dir="ltr" maxLength={64} value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); setQuery(draft); pager.restart(); } }}/></label><button type="button" className="button secondary" onClick={() => { setQuery(draft); pager.restart(); }}>{t('relationSearchAction')}</button></div><CursorControls pager={pager}/>{pager.error ? <RelationError error={pager.error}/> : <label className="form-field"><span>{t(allowAll ? 'relationFilterType' : 'relationSelectType')}</span><select value={selected?.relationTypeId || selectedId || ''} disabled={pager.loading} onChange={event => onSelect(pager.items.find(item => item.relationTypeId === event.target.value) || null)}><option value="">{t(allowAll ? 'relationAllTypes' : 'relationSelectType')}</option>{!selected&&selectedId&&!pager.items.some(item=>item.relationTypeId===selectedId)&&<option value={selectedId}>{t('relationFilterCurrent')} · {selectedId}</option>}{selected && !pager.items.some(item => item.relationTypeId === selected.relationTypeId) && <option value={selected.relationTypeId}>{selected.label} · {selected.id}</option>}{pager.items.map(item => <option key={item.relationTypeId} value={item.relationTypeId}>{item.label} · {item.id}</option>)}</select></label>}</div>;
}
const codes = { VERSION_CONFLICT:'graphStaleDraft', RELATION_MIGRATION_INVALID:'graphInvalid', RELATION_PARTICIPATION_REQUIRED:'graphInvalid', RELATION_MIGRATION_PREVIEW_REQUIRED:'graphPreviewRequired', RELATION_PREPARATION_EXPIRED:'graphPreparationExpired', RELATION_PREPARATION_CONFLICT:'graphPreparationConflict', RELATION_PREPARATION_NOT_FOUND:'graphNotFound', RELATION_MIGRATION_NOT_FOUND:'graphNotFound', RELATION_OWNER_INVALID:'relationOwnerInvalid', RELATION_TRANSITION_INVALID:'relationTransitionInvalid', RELATION_PREVIEW_STALE:'graphStaleDraft', RELATION_TOMBSTONED:'relationAlreadyRemoved', RELATION_RETRY:'relationRetryError', RELATION_JSON_INVALID:'relationJsonInvalid', RELATION_PAGE_INVALID:'relationPageInvalid', RELATION_STORAGE_INVALID:'graphStorageInvalid', RELATION_VERSION_INVALID:'relationStale', RELATION_INVALID: 'relationInvalid', RELATION_DUPLICATE: 'relationDuplicate', RELATION_CARDINALITY: 'relationCardinalityError', RELATION_CYCLE: 'relationCycleError', RELATION_SCOPE_UNAVAILABLE: 'relationScopeError', RELATION_PROFILE_LIMIT: 'relationLimitError', RELATION_MIGRATION_REQUIRED: 'relationMigrationError', RELATION_MINIMUM_UNSUPPORTED: 'relationMinimumError', RELATION_GRAPH_STALE: 'relationGraphStale' } as const;
export function RelationError({ error }: { error: Error }) {
  const { t } = useLocale(); const code = error instanceof ApiError ? codes[error.code as keyof typeof codes] : undefined;
  if (!code && !(error instanceof ApiError && error.status === 503)) return <ModelError error={error}/>;
  return <div className="model-error"><Notice tone="error"><strong>{t('errorTitle')}</strong><p>{t(code || 'relationRetryError')}</p>{error instanceof ApiError && error.correlationId && <p className="mono">{t('reference')}: {error.correlationId}</p>}</Notice>{error instanceof ApiError && error.issues.length > 0 && <div className="validation-issues" role="alert"><h3>{t('invalidFields')}</h3><ul>{error.issues.map((issue, i) => <li key={i}><code>{issue.path}</code><span lang="en">{issue.message}</span></li>)}</ul></div>}</div>;
}
export function PageState({ loading, error, empty, retry }: { loading: boolean; error: Error | null; empty: boolean; retry: () => void }) { const { t } = useLocale(); return error ? <RequestError error={error} retry={retry}/> : loading ? <LoadingState label={t('loading')}/> : empty ? <EmptyState title={t('relationNoTypes')} description={t('relationNoTypesBody')}/> : null; }

/** Paging here changes presentation only; every row remains in the submitted plan. */
export function CompleteRows<T>({ rows, children }: { rows: readonly T[]; children: (rows: readonly T[]) => React.ReactNode }) {
  const [index, setIndex] = useState(0), [limit, setLimit] = useState(25);
  const page = Math.min(index, Math.max(0, Math.ceil(rows.length / limit) - 1));
  return <><CursorControls pager={{ limit, page: page + 1, previous: page > 0, next: (page + 1) * limit < rows.length, loading: false, setLimit: value => { setLimit(value); setIndex(0); }, prevPage: () => setIndex(page - 1), nextPage: () => setIndex(page + 1) }}/>{children(rows.slice(page * limit, (page + 1) * limit))}</>;
}

// In-memory handoff only: editor drafts are never written to browser storage.
export interface StagedRelationDefinition { definition: import('../../../../packages/domain/src/relation-contracts').RelationTypeDefinitionV2; relationTypeId?: string; expectedHeadVersion?: number }
let stagedDefinition: StagedRelationDefinition | null = null;
export function stageRelationDefinition(value: StagedRelationDefinition) { stagedDefinition = value; }
export function readStagedRelationDefinition() { return stagedDefinition; }
export function clearStagedRelationDefinition() { stagedDefinition = null; }
