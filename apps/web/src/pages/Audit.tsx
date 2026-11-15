import { useMemo, useState } from 'react';
import { ClockCounterClockwise } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, DetailDrawer, DiffViewer, EmptyState, EntityHeader, EvidencePanel, LoadingState, SearchBar, Timeline } from '../../../../packages/ui/src';
import { useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import type { Audit } from '../types';

function EventDetail({ event, onClose }: { event: Audit | null; onClose: () => void }) {
  const { t, label, date } = useLocale();
  return <DetailDrawer open={!!event} onOpenChange={open => { if (!open) onClose(); }} title={t('auditRecord')} description={event ? label(`action.${event.action}`) : ''} closeLabel={t('close')} wide>{event && <><dl className="detail-list"><div><dt>{t('eventId')}</dt><dd className="mono">{event.id}</dd></div><div><dt>{t('action')}</dt><dd>{label(`action.${event.action}`) === `action.${event.action}` ? event.action : label(`action.${event.action}`)}</dd></div><div><dt>{t('actor')}</dt><dd>{event.actorName}</dd></div><div><dt>{t('occurred')}</dt><dd>{date(event.occurredAt)}</dd></div><div><dt>{t('resource')}</dt><dd className="mono">{event.resourceId}</dd></div></dl><h3>{t('changes')}</h3><DiffViewer value={event.changes} label={t('changes')}/><EvidencePanel title={t('integrity')} note={t('hashNote')}><dl className="detail-list"><div><dt>{t('eventHash')}</dt><dd className="mono break-all">{event.hash}</dd></div><div><dt>{t('previousHash')}</dt><dd className="mono break-all">{event.previousHash || '—'}</dd></div></dl></EvidencePanel></>}</DetailDrawer>;
}
function actionName(action: string, label: (key: string) => string) { const value = label(`action.${action}`); return value.startsWith('action.') ? action : value; }
export function AuditTimeline({ events }: { events: Audit[] }) {
  const { t, label, date } = useLocale();
  const [selected, setSelected] = useState<Audit | null>(null);
  return <><Timeline label={t('recentActivity')} items={events.map(event => ({ id: event.id, title: <button className="timeline-action" onClick={() => setSelected(event)}>{actionName(event.action, label)}</button>, meta: <><span>{event.actorName}</span><span aria-hidden="true">·</span><time dateTime={event.occurredAt}>{date(event.occurredAt)}</time></> }))}/><EventDetail event={selected} onClose={() => setSelected(null)}/></>;
}
export function AuditPage() {
  const { t, label, date, number } = useLocale();
  const resource = useResource<{ items: Audit[] }>('/audit');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Audit | null>(null);
  const events = useMemo(() => (resource.data?.items || []).filter(event => `${event.action} ${event.actorName} ${event.resourceId} ${actionName(event.action, label)}`.toLowerCase().includes(query.toLowerCase())), [resource.data, query, label]);
  const columns: ColumnDef<Audit>[] = [
    { accessorKey: 'action', header: t('action'), cell: ({ row }) => <button className="text-button audit-action" onClick={() => setSelected(row.original)}>{actionName(row.original.action, label)}</button> },
    { accessorKey: 'actorName', header: t('actor') },
    { accessorKey: 'resourceId', header: t('resource'), cell: ({ row }) => <span className="mono resource-reference" title={row.original.resourceId}>{row.original.resourceId}</span> },
    { accessorKey: 'occurredAt', header: t('occurred'), cell: ({ row }) => <time dateTime={row.original.occurredAt}>{date(row.original.occurredAt)}</time> },
  ];
  return <><EntityHeader eyebrow={t('operate')} title={t('audit')} description={t('auditDescription')}/><section className="panel"><div className="catalog-toolbar"><SearchBar label={t('auditFilter')} value={query} onChange={setQuery}/></div><p className="table-scope-note">{t('auditScope')}</p>{resource.error ? <RequestError error={resource.error} retry={resource.reload}/> : !resource.data ? <LoadingState label={t('loading')}/> : <><div className="results-meta" aria-live="polite">{number(events.length)} {t('results')}</div><DataGrid data={events} columns={columns} caption={t('audit')} empty={<EmptyState icon={<ClockCounterClockwise size={28}/>} title={query ? t('noAuditMatches') : t('auditEmpty')} description={query ? t('noMatchesBody') : t('auditEmptyBody')}/>} /></>}</section><EventDetail event={selected} onClose={() => setSelected(null)}/></>;
}
