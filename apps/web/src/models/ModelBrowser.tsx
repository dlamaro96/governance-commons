// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useResource } from '../api';
import { useLocale } from '../i18n';
import type { ModelSummary } from './contracts';

interface ModelPage { items: ModelSummary[]; nextCursor: string | null }
interface BrowsePosition { query: string; cursors: (string | null)[]; pageSize: number }
export interface ModelBrowser {
  items: ModelSummary[];
  nextCursor: string | null;
  loading: boolean;
  error: Error | null;
  reload: () => void;
  draftQuery: string;
  setDraftQuery: (value: string) => void;
  appliedQuery: string;
  page: number;
  pageSize: number;
  setPageSize: (value: number) => void;
  hasPrevious: boolean;
  hasNext: boolean;
  applySearch: () => void;
  previousPage: () => void;
  nextPage: () => void;
}
function boundedSize(value: number): number {
  return Number.isFinite(value) ? Math.max(1, Math.min(100, Math.trunc(value))) : 20;
}

/** Cursor history belongs to one applied query and page size. It is not a snapshot. */
export function useModelBrowser(limit = 20, endpoint: '/models' | '/asset-types' = '/models'): ModelBrowser {
  const [draftQuery, setDraft] = useState('');
  const [position, setPosition] = useState<BrowsePosition>(() => ({ query: '', cursors: [null], pageSize: boundedSize(limit) }));
  const params = new URLSearchParams({ limit: String(position.pageSize) });
  if (position.query !== '') params.set('q', position.query);
  const cursor = position.cursors[position.cursors.length - 1];
  if (cursor) params.set('cursor', cursor);
  const path = `${endpoint}?${params.toString()}`;
  const resource = useResource<ModelPage>(path);
  const requestedPath = useRef(path);
  const changingPath = requestedPath.current !== path;
  // useResource cancels the previous request and ignores disposed responses.
  // Mask its old data on the first render of a new path, before that effect runs.
  useEffect(() => { requestedPath.current = path; }, [path]);
  const loading = changingPath || resource.loading;
  const error = changingPath ? null : resource.error;
  const data = changingPath || resource.error ? null : resource.data;
  const nextCursor = !error && !loading ? data?.nextCursor ?? null : null;
  const setDraftQuery = useCallback((value: string) => setDraft(value.slice(0, 64)), []);
  const applySearch = useCallback(() => {
    setPosition(previous => ({ ...previous, query: draftQuery, cursors: [null] }));
    // Reapplying an unchanged search must also refresh its first page.
    resource.reload();
  }, [draftQuery, resource.reload]);
  const setPageSize = useCallback((value: number) => {
    setPosition(previous => ({ ...previous, pageSize: boundedSize(value), cursors: [null] }));
    resource.reload();
  }, [resource.reload]);
  const previousPage = useCallback(() => {
    if (loading) return;
    setPosition(previous => previous.cursors.length > 1 ? { ...previous, cursors: previous.cursors.slice(0, -1) } : previous);
  }, [loading]);
  const nextPage = useCallback(() => {
    if (loading || error || !nextCursor) return;
    setPosition(previous => ({ ...previous, cursors: [...previous.cursors, nextCursor] }));
  }, [loading, error, nextCursor]);
  return {
    items: data?.items ?? [], nextCursor, loading, error, reload: resource.reload,
    draftQuery, setDraftQuery, appliedQuery: position.query,
    page: position.cursors.length, pageSize: position.pageSize, setPageSize,
    hasPrevious: position.cursors.length > 1, hasNext: nextCursor !== null,
    applySearch, previousPage, nextPage,
  };
}

/** Explicit buttons keep this usable inside an existing asset-edit form. */
export function ModelBrowserControls({ browser, disabled = false, assetTypes = false }: { browser: ModelBrowser; disabled?: boolean; assetTypes?: boolean }) {
  const { t, number } = useLocale();
  const hintId = useId();
  const busy = disabled || browser.loading;
  const sizes = [...new Set([1, 20, 50, 100, browser.pageSize])].sort((left, right) => left - right);
  return <div className="model-browser">
    <div className="model-search">
      <label className="form-field"><span>{t(assetTypes ? 'searchAssetTypes' : 'searchModels')}</span><input type="search" dir="ltr" value={browser.draftQuery} maxLength={64} disabled={disabled} aria-describedby={hintId} onChange={event => browser.setDraftQuery(event.target.value)} onKeyDown={event => {
        if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
          event.preventDefault();
          if (!busy) browser.applySearch();
        }
      }}/></label>
      <button type="button" className="button secondary" disabled={busy} onClick={browser.applySearch}>{t(assetTypes ? 'searchAssetTypesAction' : 'searchModelsAction')}</button>
    </div>
    <p className="supporting-text" id={hintId}>{t(assetTypes ? 'assetTypeBrowseHint' : 'modelBrowseHint')}</p>
    <div className="model-pager">
      <label className="form-field"><span>{t('pageSize')}</span><select value={browser.pageSize} disabled={busy} onChange={event => browser.setPageSize(Number(event.target.value))}>{sizes.map(size => <option key={size} value={size}>{number(size)}</option>)}</select></label>
      <p className="supporting-text" aria-live="polite">{t('page')} {number(browser.page)}{!browser.error && <> · {browser.loading ? t('loading') : `${t(assetTypes ? 'assetTypePageRows' : 'modelPageRows')}: ${number(browser.items.length)}`}</>}</p>
      <nav aria-label={t(assetTypes ? 'assetTypePage' : 'modelPage')}>
        <button type="button" className="button secondary" disabled={busy || !browser.hasPrevious} onClick={browser.previousPage}>{t('previous')}</button>
        <button type="button" className="button secondary" disabled={busy || !browser.hasNext} onClick={browser.nextPage}>{t('more')}</button>
      </nav>
    </div>
  </div>;
}
