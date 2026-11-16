import { useEffect, useRef, useState } from 'react';
import { ArrowsClockwise, Database, Plus, Pulse } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, DetailDrawer, EmptyState, EntityHeader, JobProgress, LoadingState, Notice, SearchBar, SourceHealth } from '../../../../packages/ui/src';
import { api, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { usePermission } from '../session';
import { useNavigation } from '../navigation';
import { sourcePageHistory } from './source-pagination-history';
import type { Job, Source } from '../types';

export function SourcesPage() {
  const { t, label, date, number } = useLocale();
  const canWrite = usePermission('sources:write');
  const { search, go } = useNavigation();
  const params = new URLSearchParams(search), q = params.get('q') || '', cursor = params.get('cursor') || '';
  const selectedId = params.get('selected');
  const [query, setQuery] = useState(q);
  const [pageHistory] = useState(sourcePageHistory);
  const [savedSource, setSavedSource] = useState<Source | null>(null);
  useEffect(() => setQuery(q), [q]);
  const sources = useResource<{ items: Source[]; nextCursor: string | null }>(`/sources?limit=100&q=${encodeURIComponent(q)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, 5000);
  const selected = useResource<{ source: Source }>(selectedId ? `/sources/${encodeURIComponent(selectedId)}` : null, 5000);
  const selectedSource = selected.error ? null : (selected.data?.source.id === selectedId ? selected.data.source : null) || (savedSource?.id === selectedId ? savedSource : null);
  const items = selectedSource ? [selectedSource, ...(sources.data?.items || []).filter(source => source.id !== selectedSource.id)] : sources.data?.items || [];
  function navigate(nextQuery: string, nextCursor = '', selectedSourceId = '') {
    const next = new URLSearchParams();
    if (nextQuery) next.set('q', nextQuery);
    if (nextCursor) next.set('cursor', nextCursor);
    if (selectedSourceId) next.set('selected', selectedSourceId);
    go(`/sources${next.size ? `?${next}` : ''}`);
  }
  function searchSources(value: string) { setSavedSource(null); navigate(value); }
  const jobs = useResource<{ items: Job[] }>('/jobs', 3000);
  const [addOpen, setAddOpen] = useState(false);
  const [starting, setStarting] = useState<string | null>(null);
  const [notice, setNotice] = useState<'sourceRegistered' | 'scanStarted' | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const scanKeys = useRef<Record<string, string>>({});
  async function scan(source: Source) {
    if (!canWrite || starting !== null) return;
    setStarting(source.id); setError(null); setNotice(null);
    const key = scanKeys.current[source.id] ||= crypto.randomUUID();
    try { await api(`/sources/${source.id}/scans`, { method: 'POST', headers: { 'Idempotency-Key': key }, body: '{}' }); delete scanKeys.current[source.id]; setNotice('scanStarted'); jobs.reload(); sources.reload(); selected.reload(); }
    catch (caught) { setError(caught as Error); }
    finally { setStarting(null); }
  }
  const jobColumns: ColumnDef<Job>[] = [
    { accessorKey: 'id', header: t('jobId'), cell: ({ row }) => <span className="mono resource-reference" title={row.original.id}>{row.original.id}</span> },
    { accessorKey: 'sourceId', header: t('source'), cell: ({ row }) => items.find(source => source.id === row.original.sourceId)?.name || row.original.sourceId },
    { accessorKey: 'status', header: t('status'), cell: ({ row }) => <JobProgress status={row.original.status} label={label(row.original.status)}/> },
    { accessorKey: 'createdAt', header: t('started'), cell: ({ row }) => <time dateTime={row.original.createdAt}>{date(row.original.createdAt)}</time> },
    { accessorKey: 'finishedAt', header: t('finished'), cell: ({ row }) => row.original.finishedAt ? date(row.original.finishedAt) : '—' },
    { accessorKey: 'assetCount', header: t('assetsCollected'), cell: ({ row }) => row.original.assetCount === null ? '—' : number(row.original.assetCount) },
    { accessorKey: 'errorCode', header: t('failureCode'), cell: ({ row }) => <span className="mono">{row.original.errorCode || '—'}</span> },
  ];
  return <><EntityHeader eyebrow={t('operate')} title={t('sources')} description={t('sourcesDescription')} actions={canWrite && <button className="button primary" onClick={() => setAddOpen(true)}><Plus size={18}/>{t('addSource')}</button>}/>{notice && <Notice tone="success">{t(notice)}</Notice>}{error && <RequestError error={error} compact/>}<section className="panel catalog-toolbar"><SearchBar label={t('searchSources')} value={query} onChange={value => { setQuery(value); if (selectedId) { setSavedSource(null); navigate(q, cursor); } }} onSubmit={event => { event.preventDefault(); searchSources(query); }}/><button className="button primary" onClick={() => searchSources(query)}>{t('search')}</button>{q && <button className="button secondary" onClick={() => { setQuery(''); searchSources(''); }}>{t('clearFilters')}</button>}</section>{selected.error && <RequestError error={selected.error} compact/>}{sources.error ? <RequestError error={sources.error} retry={sources.reload}/> : !sources.data ? <LoadingState label={t('loading')}/> : !items.length ? <section className="panel"><EmptyState icon={<Database size={30}/>} title={t(q ? 'noMatchingSources' : 'noSources')} description={t(q ? 'noMatchesBody' : 'noSourcesBody')} action={canWrite && <button className="button primary" onClick={() => setAddOpen(true)}><Plus size={17}/>{t('addSource')}</button>}/></section> : <div className="source-list">{items.map(source => {
    const unityCatalog = source.connectorId === 'unity-catalog';
    const activeJob = jobs.data?.items.find(job => job.sourceId === source.id && ['queued', 'running'].includes(job.status));
    return <section className="panel source-card" key={source.id}><div className="source-card-heading"><div className="source-card-title"><span className="source-icon"><Database size={27}/></span><div><h2>{source.name}</h2><span className="source-engine">{unityCatalog ? 'Databricks Unity Catalog' : 'PostgreSQL'} <span aria-hidden="true">·</span> <bdi className="mono">{unityCatalog ? source.catalog : source.database}.{source.schema}</bdi></span></div></div><SourceHealth status={source.status} label={label(source.status)}/></div><dl className="source-details"><div><dt>{t(unityCatalog ? 'workspaceUrl' : 'host')}</dt><dd className="mono"><bdi>{unityCatalog ? source.workspaceUrl : `${source.host}:${source.port}`}</bdi></dd></div><div><dt>{t('credentialReference')}</dt><dd className="mono">{source.secretRef}</dd></div><div><dt>{t('lastScan')}</dt><dd>{date(source.lastSuccessfulScan)}</dd></div></dl><div className="source-card-footer"><p>{t(unityCatalog ? 'unityCatalogScopeHint' : 'sourceScopeHint')}</p>{activeJob ? <JobProgress status={activeJob.status} label={label(activeJob.status)}/> : canWrite && <button className="button secondary" disabled={starting !== null} onClick={() => scan(source)}><ArrowsClockwise size={17} className={starting === source.id ? 'spin' : ''}/>{starting === source.id ? t('scanning') : t('scan')}</button>}</div></section>;
  })}</div>}{sources.data && !sources.error && <nav className="pagination" aria-label={t('sources')}><span>{number(items.length)} {t('rows')}</span><div><button className="button secondary" disabled={!cursor || sources.loading} onClick={() => { const previous = pageHistory.previous(q, cursor); setSavedSource(null); navigate(q, previous); }}>{t('previous')}</button><button className="button secondary" disabled={!sources.data.nextCursor || sources.loading} onClick={() => { if (!sources.data?.nextCursor) return; pageHistory.remember(q, cursor, sources.data.nextCursor); setSavedSource(null); navigate(q, sources.data.nextCursor); }}>{t('more')}</button></div></nav>}<section className="panel" id="jobs"><div className="panel-heading"><div><h2>{t('jobs')}</h2><p>{t('jobsDescription')}</p></div></div>{jobs.error ? <RequestError error={jobs.error} retry={jobs.reload}/> : !jobs.data ? <LoadingState label={t('loading')}/> : <DataGrid columns={jobColumns} data={jobs.data.items} caption={t('jobs')} empty={<EmptyState compact icon={<Pulse size={27}/>} title={t('noJobs')} description={t('noJobsBody')}/>}/>}</section>{canWrite && <SourceForm open={addOpen} onOpenChange={setAddOpen} onCreated={source => { setSavedSource(source); setQuery(source.name); navigate(source.name, '', source.id); sources.reload(); setNotice('sourceRegistered'); }}/>}</>;
}
type ConnectorId = Source['connectorId'];
const postgresConnection = { host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } as const;
function SourceForm({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (value: boolean) => void; onCreated: (source: Source) => void }) {
  const { t } = useLocale();
  const canWrite = usePermission('sources:write');
  const [connectorId, setConnectorId] = useState<ConnectorId>('postgresql');
  const [form, setForm] = useState({ name: '', workspaceUrl: '', catalog: '', schema: '', secretRef: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const key = useRef(crypto.randomUUID());
  const unityCatalog = connectorId === 'unity-catalog';
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (saving || !canWrite) return;
    const name = form.name.trim();
    const body = unityCatalog
      ? { connectorId, name, workspaceUrl: form.workspaceUrl.trim(), catalog: form.catalog.trim(), schema: form.schema.trim(), secretRef: form.secretRef.trim() }
      : { connectorId, name, ...postgresConnection };
    setSaving(true); setError(null);
    try {
      const result = await api<{ source: Source }>('/sources', { method: 'POST', headers: { 'Idempotency-Key': key.current }, body: JSON.stringify(body) });
      key.current = crypto.randomUUID(); setForm(previous => ({ ...previous, name: '' })); onOpenChange(false); onCreated(result.source);
    } catch (caught) { setError(caught as Error); }
    finally { setSaving(false); }
  }
  function field(name: keyof typeof form, value: string) { setForm(previous => ({ ...previous, [name]: value })); key.current = crypto.randomUUID(); }
  const complete = form.name.trim() && (!unityCatalog || [form.workspaceUrl, form.catalog, form.schema, form.secretRef].every(value => value.trim()));
  return <DetailDrawer open={open} onOpenChange={value => { if (!saving) onOpenChange(value); }} title={t(unityCatalog ? 'addUnityCatalogTitle' : 'addSourceTitle')} description={t('addSourceBody')} closeLabel={t('close')}>
    <form className="stacked-form" onSubmit={submit}>
      <label className="form-field"><span>{t('connector')}</span><select value={connectorId} disabled={saving} onChange={event => { const value = event.target.value; if (value === 'postgresql' || value === 'unity-catalog') { setConnectorId(value); key.current = crypto.randomUUID(); setError(null); } }}><option value="postgresql">PostgreSQL</option><option value="unity-catalog">Databricks Unity Catalog</option></select></label>
      <Notice>{t(unityCatalog ? 'unityCatalogProfile' : 'localSourceProfile')}</Notice>
      {error && <RequestError error={error} compact/>}
      <label className="form-field"><span>{t('sourceName')} <span className="required-marker" aria-label={t('required')}>*</span></span><input value={form.name} onChange={event => field('name', event.target.value)} disabled={saving} required maxLength={120} autoComplete="off"/><small>{t('sourceNameHint')}</small></label>
      <fieldset className="connection-fields" disabled={saving}><legend>{t('connectionScope')}</legend>
        {unityCatalog ? <>
          <label className="form-field"><span>{t('workspaceUrl')}</span><input type="url" value={form.workspaceUrl} onChange={event => field('workspaceUrl', event.target.value)} required maxLength={255} placeholder="https://workspace.cloud.databricks.com" autoComplete="off" spellCheck={false} dir="ltr"/><small>{t('workspaceUrlHint')}</small></label>
          <div className="form-row"><label className="form-field"><span>{t('sourceCatalog')}</span><input value={form.catalog} onChange={event => field('catalog', event.target.value)} required maxLength={255} autoComplete="off" spellCheck={false} dir="auto"/></label><label className="form-field"><span>{t('schema')}</span><input value={form.schema} onChange={event => field('schema', event.target.value)} required maxLength={255} autoComplete="off" spellCheck={false} dir="auto"/></label></div>
        </> : <>
          <div className="form-row host-row"><label className="form-field"><span>{t('host')}</span><input value={postgresConnection.host} readOnly required autoComplete="off" spellCheck={false}/></label><label className="form-field"><span>{t('port')}</span><input type="number" min={1} max={65535} value={postgresConnection.port} readOnly required/></label></div>
          <div className="form-row"><label className="form-field"><span>{t('database')}</span><input value={postgresConnection.database} readOnly required autoComplete="off" spellCheck={false}/></label><label className="form-field"><span>{t('schema')}</span><input value={postgresConnection.schema} readOnly required autoComplete="off" spellCheck={false}/></label></div>
        </>}
      </fieldset>
      <label className="form-field"><span>{t('credentialReference')}</span><input value={unityCatalog ? form.secretRef : postgresConnection.secretRef} onChange={event => field('secretRef', event.target.value)} readOnly={!unityCatalog} disabled={saving} required maxLength={128} autoComplete="off" spellCheck={false} dir="ltr"/><small>{t(unityCatalog ? 'unityCatalogSecretHint' : 'secretHint')}</small></label>
      <Notice>{t(unityCatalog ? 'unityCatalogScopeHint' : 'sourceScopeHint')}</Notice>
      <div className="form-actions"><button type="button" className="button secondary" disabled={saving} onClick={() => onOpenChange(false)}>{t('cancel')}</button><button className="button primary" disabled={saving || !canWrite || !complete}>{saving ? t('registering') : t('registerSource')}</button></div>
    </form>
  </DetailDrawer>;
}
