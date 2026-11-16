// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import type { ColumnDef } from '@tanstack/react-table';
import type { ParticipationItem, ParticipationRevisionView } from '../../../../packages/domain/src/relation-migration-contracts';
import { DataGrid, DetailDrawer, EmptyState, LoadingState } from '../../../../packages/ui/src';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { CursorControls, RelationError, relationTypePath, useCursorPage } from './shared';

export function Participation({ assetId }: { assetId: string }) {
  const { t, number } = useLocale();
  const [status, setStatus] = useState<'active' | 'released' | 'all'>('active');
  const [history, setHistory] = useState<string | null>(null);
  const pager = useCursorPage<ParticipationItem>(`/assets/${assetId}/relation-participation?status=${status}`);
  const columns: ColumnDef<ParticipationItem>[] = [
    { id: 'policy', header: t('relationTypePin'), cell: ({ row: { original: row } }) => <Link href={`${relationTypePath(row.policy.definition.id)}?version=${row.binding.relationTypeVersion}`}>{row.policy.definition.label} · {number(row.binding.relationTypeVersion)}</Link> },
    { id: 'side', header: t('graphSide'), cell: ({ row }) => t(row.original.binding.side === 'incident' ? 'graphIncident' : row.original.binding.side === 'source' ? 'relationSource' : 'relationTarget') },
    { id: 'degree', header: t('graphDegree'), cell: ({ row }) => number(row.original.currentDegree) },
    { accessorKey: 'minimum', header: t('graphMinimum'), cell: ({ row }) => number(row.original.minimum) },
    { id: 'maximum', header: t('relationMaximum'), cell: ({ row }) => row.original.maximum === null ? '∞' : number(row.original.maximum) },
    { id: 'status', header: t('status'), cell: ({ row }) => t(row.original.binding.status === 'active' ? 'graphActive' : 'graphReleased') },
    { id: 'revision', header: t('version'), cell: ({ row }) => <span>{number(row.original.binding.version)} · {t('graphAssetRevision')} {number(row.original.binding.assetVersion)} / {number(row.original.currentAssetVersion)}</span> },
    { id: 'history', header: t('graphBindingHistory'), cell: ({ row }) => <button className="text-button" onClick={() => setHistory(row.original.binding.id)}>{t('graphBindingHistory')}<span className="sr-only"> {row.original.binding.id}</span></button> },
  ];
  return <section className="panel"><div className="panel-heading"><h2>{t('graphParticipation')}</h2></div><div className="panel-body"><p>{t('graphParticipationHint')}</p><label className="form-field"><span>{t('status')}</span><select value={status} onChange={event => setStatus(event.target.value as typeof status)}><option value="active">{t('graphActive')}</option><option value="released">{t('graphReleased')}</option><option value="all">{t('graphAllBindings')}</option></select></label><CursorControls pager={pager}/>{pager.error ? <><RelationError error={pager.error}/><button className="button secondary" onClick={pager.restart}>{t('relationGraphRestart')}</button></> : pager.loading ? <LoadingState label={t('loading')}/> : <DataGrid caption={t('graphParticipation')} columns={columns} data={pager.items} empty={<EmptyState title={t('graphNoBindings')} compact/>}/>}</div><DetailDrawer open={!!history} onOpenChange={open => { if (!open) setHistory(null); }} title={t('graphBindingHistory')} description={t('relationHistoryHint')} closeLabel={t('close')}>{history && <BindingHistory key={history} assetId={assetId} bindingId={history}/>}</DetailDrawer></section>;
}
function BindingHistory({ assetId, bindingId }: { assetId: string; bindingId: string }) {
  const { t, number, date } = useLocale();
  const pager = useCursorPage<ParticipationRevisionView>(`/assets/${assetId}/relation-participation/${bindingId}/history`);
  return <><CursorControls pager={pager}/>{pager.error ? <><RelationError error={pager.error}/><button className="button secondary" onClick={pager.restart}>{t('relationGraphRestart')}</button></> : pager.loading ? <LoadingState label={t('loading')}/> : <ol className="relation-history-list">{pager.items.map(item => <li key={item.binding.version}><details><summary>{t('version')} {number(item.binding.version)} · {date(item.recordedAt)}</summary><p>{t('relationRecordedBy')}: <code>{item.recordedBy}</code></p><p>{t('graphAssetRevision')}: <code>{item.assetRevision.id}</code> · {number(item.assetRevision.version)}</p><Link href={`/relation-migrations/${item.operationId}`}>{t('graphOperationLink')}</Link><pre className="code-block" tabIndex={0}>{JSON.stringify(item, null, 2)}</pre></details></li>)}</ol>}</>;
}
