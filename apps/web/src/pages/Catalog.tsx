import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, ArrowRight, BookOpen, Database, MagnifyingGlass } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, EmptyState, EntityHeader, FacetPanel, LoadingState, SearchBar, StatusBadge } from '../../../../packages/ui/src';
import { useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import type { Asset, AssetList } from '../types';

export function CatalogPage() {
  const { t, label, date, number } = useLocale();
  const { search, go } = useNavigation();
  const params = new URLSearchParams(search);
  const q = params.get('q') || '';
  const type = params.get('type') || '';
  const cursor = params.get('cursor') || '';
  const sort = params.get('sort') || 'name';
  const [query, setQuery] = useState(q);
  const [previousCursors, setPreviousCursors] = useState<string[]>([]);
  const canConnect = usePermission('sources:write');
  useEffect(() => setQuery(q), [q]);
  const resource = useResource<AssetList>(`/assets?q=${encodeURIComponent(q)}&type=${encodeURIComponent(type)}&cursor=${encodeURIComponent(cursor)}&limit=50`);
  function update(values: Record<string, string>, reset = true) {
    const next = new URLSearchParams(search);
    for (const [key, value] of Object.entries(values)) { if (value) next.set(key, value); else next.delete(key); }
    if (reset) { next.delete('cursor'); setPreviousCursors([]); }
    go(`/catalog${next.size ? `?${next.toString()}` : ''}`);
  }
  const columns: ColumnDef<Asset>[] = [
    { accessorKey: 'name', header: t('name'), cell: ({ row }) => <div className="asset-name-cell"><span className="asset-type-icon"><Database size={18}/></span><div><Link className="asset-link" href={`/catalog/${row.original.id}`}>{row.original.name}</Link><span className="qualified-name" title={row.original.qualifiedName}>{row.original.qualifiedName}</span></div></div> },
    { accessorKey: 'type', header: t('kind'), cell: ({ row }) => <span className="type-label">{label(row.original.type)}</span> },
    { accessorKey: 'ownerName', header: t('owner'), cell: ({ row }) => row.original.ownerName ? <span className="owner-name"><span className="avatar small">{row.original.ownerName.slice(0, 1)}</span>{row.original.ownerName}</span> : <span className="text-muted">{t('unassigned')}</span> },
    { accessorKey: 'sourceName', header: t('source'), cell: ({ row }) => <span>{row.original.sourceName}</span> },
    { accessorKey: 'observedAt', header: t('observed'), cell: ({ row }) => <time className="table-date" dateTime={row.original.observedAt || undefined}>{date(row.original.observedAt)}</time> },
    { accessorKey: 'status', header: t('status'), cell: ({ row }) => <StatusBadge status={row.original.status} label={label(row.original.status)}/> },
  ];
  const assets = useMemo(() => [...resource.data?.items || []].sort((a, b) => sort === 'updated' ? Date.parse(b.updatedAt) - Date.parse(a.updatedAt) : sort === 'name-desc' ? b.name.localeCompare(a.name) : a.name.localeCompare(b.name)), [resource.data, sort]);
  return <><EntityHeader eyebrow={t('discover')} title={t('catalog')} description={t('catalogDescription')}/><section className="panel catalog-panel"><div className="catalog-toolbar"><SearchBar label={t('searchAssets')} value={query} onChange={setQuery} onSubmit={event => { event.preventDefault(); update({ q: query.trim() }); }}/><button className="button primary" onClick={() => update({ q: query.trim() })}><MagnifyingGlass size={17}/>{t('search')}</button><label className="sort-control"><span>{t('sortBy')}</span><select aria-label={t('sortBy')} value={sort} onChange={event => update({ sort: event.target.value }, false)}><option value="name">{t('nameAscending')}</option><option value="name-desc">{t('nameDescending')}</option><option value="updated">{t('recentlyUpdated')}</option></select></label></div><div className="catalog-content"><aside className="catalog-facets"><FacetPanel label={t('assetType')} value={type} onChange={value => update({ type: value })} options={[{ value: '', label: t('allTypes') }, ...(resource.data?.facets || []).map(facet => ({ value: facet.type, label: label(facet.type), count: facet.count }))]}/>{type && !resource.data?.facets.some(facet => facet.type === type) && <p className="supporting-text">{label(type)}</p>}{(q || type) && <button className="text-button" onClick={() => update({ q: '', type: '' })}>{t('clearFilters')}</button>}</aside><div className="catalog-results">{resource.error ? <RequestError error={resource.error} retry={resource.reload}/> : resource.loading && !resource.data ? <LoadingState label={t('loading')}/> : resource.data && <><div className="results-meta" aria-live="polite"><span><strong>{number(resource.data.total)}</strong> {t('results')}</span><span>{resource.loading ? t('loading') : t('loadedSort')}</span></div><DataGrid data={assets} columns={columns} caption={t('catalog')} empty={<EmptyState icon={<BookOpen size={30}/>} title={q || type ? t('noMatches') : t('emptyCatalog')} description={q || type ? t('noMatchesBody') : t('emptyCatalogBody')} action={q || type ? <button className="button secondary" onClick={() => update({ q: '', type: '' })}>{t('clearFilters')}</button> : canConnect ? <Link href="/sources" className="button primary">{t('addSource')}</Link> : undefined}/>}/>{(resource.data.nextCursor || previousCursors.length > 0) && <div className="pagination"><span>{t('page')} {number(previousCursors.length + 1)}</span><div><button className="button secondary" disabled={!previousCursors.length || resource.loading} onClick={() => { const previous = [...previousCursors]; const value = previous.pop() || ''; setPreviousCursors(previous); update({ cursor: value }, false); }}><ArrowLeft size={15}/>{t('previous')}</button><button className="button secondary" disabled={!resource.data.nextCursor || resource.loading} onClick={() => { setPreviousCursors([...previousCursors, cursor]); update({ cursor: resource.data!.nextCursor! }, false); }}>{t('more')}<ArrowRight size={15}/></button></div></div>}</>}</div></div></section></>;
}
