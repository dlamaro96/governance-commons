import { useRef, useState } from 'react';
import { ArrowsClockwise, Database, Plus, Pulse } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, DetailDrawer, EmptyState, EntityHeader, JobProgress, LoadingState, Notice, SourceHealth } from '../../../../packages/ui/src';
import { api, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { usePermission } from '../session';
import type { Job, Source } from '../types';

export function SourcesPage() {
  const { t, label, date, number } = useLocale();
  const canWrite = usePermission('sources:write');
  const sources = useResource<{ items: Source[] }>('/sources', 5000);
  const jobs = useResource<{ items: Job[] }>('/jobs', 3000);
  const [addOpen, setAddOpen] = useState(false);
  const [starting, setStarting] = useState<string | null>(null);
  const [notice, setNotice] = useState<'sourceRegistered' | 'scanStarted' | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const scanKeys = useRef<Record<string, string>>({});
  async function scan(source: Source) {
    setStarting(source.id); setError(null); setNotice(null);
    const key = scanKeys.current[source.id] ||= crypto.randomUUID();
    try { await api(`/sources/${source.id}/scans`, { method: 'POST', headers: { 'Idempotency-Key': key }, body: '{}' }); delete scanKeys.current[source.id]; setNotice('scanStarted'); jobs.reload(); sources.reload(); }
    catch (caught) { setError(caught as Error); }
    finally { setStarting(null); }
  }
  const jobColumns: ColumnDef<Job>[] = [
    { accessorKey: 'id', header: t('jobId'), cell: ({ row }) => <span className="mono resource-reference" title={row.original.id}>{row.original.id}</span> },
    { accessorKey: 'sourceId', header: t('source'), cell: ({ row }) => sources.data?.items.find(source => source.id === row.original.sourceId)?.name || row.original.sourceId },
    { accessorKey: 'status', header: t('status'), cell: ({ row }) => <JobProgress status={row.original.status} label={label(row.original.status)}/> },
    { accessorKey: 'createdAt', header: t('started'), cell: ({ row }) => <time dateTime={row.original.createdAt}>{date(row.original.createdAt)}</time> },
    { accessorKey: 'finishedAt', header: t('finished'), cell: ({ row }) => row.original.finishedAt ? date(row.original.finishedAt) : '—' },
    { accessorKey: 'assetCount', header: t('assetsCollected'), cell: ({ row }) => row.original.assetCount === null ? '—' : number(row.original.assetCount) },
    { accessorKey: 'errorCode', header: t('failureCode'), cell: ({ row }) => <span className="mono">{row.original.errorCode || '—'}</span> },
  ];
  return <><EntityHeader eyebrow={t('operate')} title={t('sources')} description={t('sourcesDescription')} actions={canWrite && <button className="button primary" onClick={() => setAddOpen(true)}><Plus size={18}/>{t('addSource')}</button>}/>{notice && <Notice tone="success">{t(notice)}</Notice>}{error && <RequestError error={error} compact/>}{sources.error ? <RequestError error={sources.error} retry={sources.reload}/> : !sources.data ? <LoadingState label={t('loading')}/> : !sources.data.items.length ? <section className="panel"><EmptyState icon={<Database size={30}/>} title={t('noSources')} description={t('noSourcesBody')} action={canWrite && <button className="button primary" onClick={() => setAddOpen(true)}><Plus size={17}/>{t('addSource')}</button>}/></section> : <div className="source-list">{sources.data.items.map(source => {
    const activeJob = jobs.data?.items.find(job => job.sourceId === source.id && ['queued', 'running'].includes(job.status));
    return <section className="panel source-card" key={source.id}><div className="source-card-heading"><div className="source-card-title"><span className="source-icon"><Database size={27}/></span><div><h2>{source.name}</h2><span className="source-engine">PostgreSQL <span aria-hidden="true">·</span> <bdi className="mono">{source.database}.{source.schema}</bdi></span></div></div><SourceHealth status={source.status} label={label(source.status)}/></div><dl className="source-details"><div><dt>{t('host')}</dt><dd className="mono"><bdi>{source.host}:{source.port}</bdi></dd></div><div><dt>{t('credentialReference')}</dt><dd className="mono">{source.secretRef}</dd></div><div><dt>{t('lastScan')}</dt><dd>{date(source.lastSuccessfulScan)}</dd></div></dl><div className="source-card-footer"><p>{t('sourceScopeHint')}</p>{activeJob ? <JobProgress status={activeJob.status} label={label(activeJob.status)}/> : canWrite && <button className="button secondary" disabled={starting !== null} onClick={() => scan(source)}><ArrowsClockwise size={17} className={starting === source.id ? 'spin' : ''}/>{starting === source.id ? t('scanning') : t('scan')}</button>}</div></section>;
  })}</div>}<section className="panel" id="jobs"><div className="panel-heading"><div><h2>{t('jobs')}</h2><p>{t('jobsDescription')}</p></div></div>{jobs.error ? <RequestError error={jobs.error} retry={jobs.reload}/> : !jobs.data ? <LoadingState label={t('loading')}/> : <DataGrid columns={jobColumns} data={jobs.data.items} caption={t('jobs')} empty={<EmptyState compact icon={<Pulse size={27}/>} title={t('noJobs')} description={t('noJobsBody')}/>}/>}</section><SourceForm open={addOpen} onOpenChange={setAddOpen} onCreated={() => { sources.reload(); setNotice('sourceRegistered'); }}/></>;
}
function SourceForm({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (value: boolean) => void; onCreated: () => void }) {
  const { t } = useLocale();
  const [form, setForm] = useState({ name: '', host: 'source-postgres', port: '5432', database: 'harbor', schema: 'public', secretRef: 'demo-postgres' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const key = useRef(crypto.randomUUID());
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (saving) return;
    setSaving(true); setError(null);
    try { await api('/sources', { method: 'POST', headers: { 'Idempotency-Key': key.current }, body: JSON.stringify({ ...form, name: form.name.trim(), port: Number(form.port) }) }); key.current = crypto.randomUUID(); setForm({ ...form, name: '' }); onOpenChange(false); onCreated(); }
    catch (caught) { setError(caught as Error); }
    finally { setSaving(false); }
  }
  function field(name: keyof typeof form, value: string) { setForm(previous => ({ ...previous, [name]: value })); key.current = crypto.randomUUID(); }
  return <DetailDrawer open={open} onOpenChange={value => { if (!saving) onOpenChange(value); }} title={t('addSourceTitle')} description={t('addSourceBody')} closeLabel={t('close')}><form className="stacked-form" onSubmit={submit}><Notice>{t('localSourceProfile')}</Notice>{error && <RequestError error={error} compact/>}<label className="form-field"><span>{t('sourceName')} <span className="required-marker" aria-label={t('required')}>*</span></span><input value={form.name} onChange={event => field('name', event.target.value)} required maxLength={120} autoComplete="off"/><small>{t('sourceNameHint')}</small></label><fieldset className="connection-fields"><legend>{t('connectionScope')}</legend><div className="form-row host-row"><label className="form-field"><span>{t('host')}</span><input value={form.host} readOnly required autoComplete="off" spellCheck={false}/></label><label className="form-field"><span>{t('port')}</span><input type="number" min={1} max={65535} value={form.port} readOnly required/></label></div><div className="form-row"><label className="form-field"><span>{t('database')}</span><input value={form.database} readOnly required autoComplete="off" spellCheck={false}/></label><label className="form-field"><span>{t('schema')}</span><input value={form.schema} readOnly required autoComplete="off" spellCheck={false}/></label></div></fieldset><label className="form-field"><span>{t('credentialReference')}</span><input value={form.secretRef} readOnly required autoComplete="off" spellCheck={false}/><small>{t('secretHint')}</small></label><Notice>{t('sourceScopeHint')}</Notice><div className="form-actions"><button type="button" className="button secondary" disabled={saving} onClick={() => onOpenChange(false)}>{t('cancel')}</button><button className="button primary" disabled={saving || !form.name.trim()}>{saving ? t('registering') : t('registerSource')}</button></div></form></DetailDrawer>;
}
