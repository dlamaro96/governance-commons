import { useEffect, useState } from 'react';
import { ArrowLeft, ArrowRight, BookOpen, Database, MagnifyingGlass } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, EmptyState, EntityHeader, FacetPanel, LoadingState, SearchBar, StatusBadge } from '../../../../packages/ui/src';
import { useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import type { Asset, AssetList } from '../types';

// This bounded browser-history hint only restores presentation/navigation. The
// API still authenticates every opaque cursor; no cursor payload is decoded here.
const MAX_PREVIOUS_PAGES = 20;
const MAX_CURSOR_LENGTH = 2048;
const MAX_CATALOG_PAGES = 2000; // 100,000 candidate limit / 50 rows per page.
type PageTrail = { page: number | null; previous: string[] };
const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
function pageTrail(state: unknown, binding: string, cursor: string): PageTrail {
  if (!cursor) return { page: 1, previous: [] };
  const fallback = { page: null, previous: [] };
  if (!record(state) || !record(state.catalogPagination)) return fallback;
  const hint = state.catalogPagination;
  if (hint.version !== 1 || hint.binding !== binding || hint.cursor !== cursor || cursor.length > MAX_CURSOR_LENGTH
    || !(hint.page === null || typeof hint.page === 'number' && Number.isInteger(hint.page) && hint.page >= 2 && hint.page <= MAX_CATALOG_PAGES)
    || !Array.isArray(hint.previous) || hint.previous.length > MAX_PREVIOUS_PAGES) return fallback;
  const previous: string[] = [];
  for (const value of hint.previous) {
    if (typeof value !== 'string' || value.length > MAX_CURSOR_LENGTH || value === cursor || previous.includes(value)
      || value === '' && previous.length > 0) return fallback;
    previous.push(value);
  }
  // A known first-page predecessor makes the label checkable without opening
  // signed cursors. Missing prefixes remain bounded, never invented.
  if (hint.page === null ? previous.includes('') : previous.length >= hint.page
    || previous[0] === '' && hint.page !== previous.length + 1) return fallback;
  return { page: hint.page, previous };
}

export function CatalogPage() {
  const { t, label, date, number } = useLocale();
  const { search, state, go } = useNavigation();
  const params = new URLSearchParams(search);
  const q = params.get('q') || '';
  const type = params.get('type') || '';
  const cursor = params.get('cursor') || '';
  const sort = params.get('sort') || 'name';
  const [query, setQuery] = useState(q);
  const binding = JSON.stringify([q, type, sort]);
  const trail = pageTrail(state, binding, cursor);
  const canConnect = usePermission('sources:write');
  useEffect(() => setQuery(q), [q]);
  const resource = useResource<AssetList>(`/assets?q=${encodeURIComponent(q)}&type=${encodeURIComponent(type)}&cursor=${encodeURIComponent(cursor)}&sort=${encodeURIComponent(sort)}&limit=50`);
  function update(values: Record<string, string>, pagination?: PageTrail) {
    const next = new URLSearchParams(search);
    for (const [key, value] of Object.entries(values)) { if (value) next.set(key, value); else next.delete(key); }
    if (!pagination) next.delete('cursor');
    const hint = pagination ? { catalogPagination: { version: 1, binding, cursor: next.get('cursor') || '', ...pagination } } : null;
    go(`/catalog${next.size ? `?${next.toString()}` : ''}`, false, hint);
  }
  const columns: ColumnDef<Asset>[] = [
    { accessorKey: 'name', header: t('name'), cell: ({ row }) => <div className="asset-name-cell"><span className="asset-type-icon"><Database size={18}/></span><div><Link className="asset-link" href={`/catalog/${row.original.id}`}>{row.original.name}</Link><span className="qualified-name" title={row.original.qualifiedName}>{row.original.qualifiedName}</span></div></div> },
    { accessorKey: 'type', header: t('kind'), cell: ({ row }) => <span className="type-label">{label(row.original.type)}</span> },
    { accessorKey: 'ownerName', header: t('owner'), cell: ({ row }) => row.original.ownerName ? <span className="owner-name"><span className="avatar small">{row.original.ownerName.slice(0, 1)}</span>{row.original.ownerName}</span> : <span className="text-muted">{t('unassigned')}</span> },
    { accessorKey: 'sourceName', header: t('source'), cell: ({ row }) => <span className="catalog-source-name" title={row.original.sourceName || undefined}>{row.original.sourceName}</span> },
    { accessorKey: 'observedAt', header: t('observed'), cell: ({ row }) => <time className="table-date" dateTime={row.original.observedAt || undefined}>{date(row.original.observedAt)}</time> },
    { accessorKey: 'status', header: t('status'), cell: ({ row }) => <StatusBadge status={row.original.status} label={label(row.original.status)}/> },
  ];
  const assets = resource.data?.items || [];
  return <><EntityHeader eyebrow={t('discover')} title={t('catalog')} description={t('catalogDescription')}/><section className="panel catalog-panel"><div className="catalog-toolbar"><SearchBar label={t('searchAssets')} value={query} onChange={setQuery} onSubmit={event => { event.preventDefault(); update({ q: query.trim() }); }}/><button className="button primary" onClick={() => update({ q: query.trim() })}><MagnifyingGlass size={17}/>{t('search')}</button><label className="sort-control"><span>{t('sortBy')}</span><select aria-label={t('sortBy')} value={sort} onChange={event => update({ sort: event.target.value })}><option value="name">{t('nameAscending')}</option><option value="name-desc">{t('nameDescending')}</option><option value="updated">{t('recentlyUpdated')}</option></select></label></div><div className="catalog-content"><aside className="catalog-facets"><FacetPanel label={t('assetType')} value={type} onChange={value => update({ type: value })} options={[{ value: '', label: t('allTypes') }, ...(resource.data?.facets || []).map(facet => ({ value: facet.type, label: label(facet.type), count: facet.count }))]}/>{type && !resource.data?.facets.some(facet => facet.type === type) && <p className="supporting-text">{label(type)}</p>}{(q || type) && <button className="text-button" onClick={() => update({ q: '', type: '' })}>{t('clearFilters')}</button>}</aside><div className="catalog-results">{resource.error ? <RequestError error={resource.error} retry={resource.reload}/> : resource.loading && !resource.data ? <LoadingState label={t('loading')}/> : resource.data && <><div className="results-meta" aria-live="polite"><span><strong>{number(resource.data.total)}</strong> {t('results')}</span><span>{resource.loading ? t('loading') : t('catalogSortScope')}</span></div><DataGrid data={assets} columns={columns} caption={t('catalog')} empty={<EmptyState icon={<BookOpen size={30}/>} title={q || type ? t('noMatches') : t('emptyCatalog')} description={q || type ? t('noMatchesBody') : t('emptyCatalogBody')} action={q || type ? <button className="button secondary" onClick={() => update({ q: '', type: '' })}>{t('clearFilters')}</button> : canConnect ? <Link href="/sources" className="button primary">{t('addSource')}</Link> : undefined}/>}/>{(resource.data.nextCursor || cursor) && <div className="pagination"><span>{trail.page === null ? t('currentPage') : <>{t('page')} {number(trail.page)}</>}</span><div>{cursor && !trail.previous.length && <button className="button secondary" disabled={resource.loading} onClick={() => update({})}>{t('catalogFirstPage')}</button>}<button className="button secondary" disabled={!trail.previous.length || resource.loading} onClick={() => { const previous = [...trail.previous]; const value = previous.pop()!; update({ cursor: value }, { previous, page: trail.page === null ? null : trail.page - 1 }); }}><ArrowLeft size={15}/>{t('previous')}</button><button className="button secondary" disabled={!resource.data.nextCursor || resource.loading} onClick={() => update({ cursor: resource.data!.nextCursor! }, { previous: [...trail.previous, cursor].slice(-MAX_PREVIOUS_PAGES), page: trail.page === null || trail.page >= MAX_CATALOG_PAGES ? null : trail.page + 1 })}>{t('more')}<ArrowRight size={15}/></button></div></div>}</>}</div></div></section></>;
}
