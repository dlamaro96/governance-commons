import { lazy, Suspense, useEffect, useState } from 'react';
import { ArrowLeft, Database, PencilSimple, Table } from '@phosphor-icons/react';
import { type ColumnDef } from '@tanstack/react-table';
import { DataGrid, DetailDrawer, DiffViewer, EmptyState, EntityHeader, EvidencePanel, LoadingState, Notice, SearchBar, StatusBadge } from '../../../../packages/ui/src';
import { api, ApiError, useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link, useNavigation } from '../navigation';
import { usePermission } from '../session';
import type { Asset, AssetDetail, Member } from '../types';
import { AuditTimeline } from './Audit';
import { AssetAttributesPanel } from '../models/AssetAttributes';
const LifecyclePanel = lazy(() => import('../assetTypes/LifecyclePanel').then(module => ({ default: module.LifecyclePanel })));
const AssetRelations = lazy(() => import('../relations/AssetRelations').then(module => ({ default: module.AssetRelations })));
import { ModelError } from '../models/ModelFeedback';

export function AssetPage({ id }: { id: string }) {
  const { t, label, date, number } = useLocale();
  const { search, go } = useNavigation();
  const resource = useResource<AssetDetail>(`/assets/${encodeURIComponent(id)}`);
  const canEdit = usePermission('catalog:write');
  const canAudit = usePermission('audit:read');
  const canRelations = usePermission('models:read');
  const [editOpen, setEditOpen] = useState(false);
  const [columnQuery, setColumnQuery] = useState('');
  const [saved, setSaved] = useState(false);
  const members = useResource<{ items: Member[] }>(editOpen && canEdit ? '/members' : null);
  const asset = resource.data?.asset;
  const requestedTab = new URLSearchParams(search).get('tab') || 'overview';
  const hasSchema = !!asset && (['table', 'view'].includes(asset.type) || !!resource.data?.columns.length);
  const tab = requestedTab === 'schema' && hasSchema || requestedTab === 'history' && canAudit || requestedTab === 'relations' && canRelations ? requestedTab : 'overview';
  const columns: ColumnDef<Asset>[] = [
    { accessorKey: 'name', header: t('name'), cell: ({ row }) => <Link className="asset-link" href={`/catalog/${row.original.id}`}>{row.original.name}</Link> },
    { id: 'dataType', header: t('dataType'), cell: ({ row }) => <span className="mono">{String(row.original.metadata.dataType ?? row.original.metadata.data_type ?? row.original.metadata.type ?? '—')}</span> },
    { id: 'nullable', header: t('nullable'), cell: ({ row }) => { const value = row.original.metadata.nullable ?? row.original.metadata.isNullable ?? row.original.metadata.is_nullable; return value === undefined ? t('unknown') : value === true || value === 'YES' ? t('yes') : t('no'); } },
    { accessorKey: 'description', header: t('description'), cell: ({ row }) => <span className={!row.original.description ? 'text-muted' : ''}>{row.original.description || '—'}</span> },
    { accessorKey: 'ownerName', header: t('owner'), cell: ({ row }) => row.original.ownerName || <span className="text-muted">{t('unassigned')}</span> },
  ];
  if (resource.error) return <><Link className="back-link" href="/catalog"><ArrowLeft size={16}/>{t('backCatalog')}</Link><RequestError error={resource.error} retry={resource.reload}/></>;
  if (!resource.data || !asset) return <LoadingState label={t('loading')}/>;
  return <><Link className="back-link" href="/catalog"><ArrowLeft size={16}/>{t('backCatalog')}</Link><EntityHeader eyebrow={<span className="asset-kind"><Database size={17}/>{label(asset.type)}<span aria-hidden="true">/</span>{asset.sourceName}</span>} title={asset.name} description={<span className="mono asset-qualified">{asset.qualifiedName}</span>} actions={<>{canEdit && <button className="button secondary" onClick={() => { setEditOpen(true); setSaved(false); }}><PencilSimple size={17}/>{t('editDetails')}</button>}</>}><div className="entity-summary"><StatusBadge status={asset.status} label={label(asset.status)}/><span>{t('owner')}: <strong>{asset.ownerName || t('unassigned')}</strong></span><span>{t('version')} <strong>{number(asset.version)}</strong></span><span>{t('collectedAt')}: <time dateTime={asset.observedAt || undefined}>{date(asset.observedAt)}</time></span></div></EntityHeader>{saved && <Notice tone="success">{t('saved')}</Notice>}<div className="entity-tabs" role="navigation" aria-label={t('details')}>{[{ key: 'overview', name: t('overviewTab'), show: true }, { key: 'schema', name: `${t('schemaTab')} (${number(resource.data.columns.length)})`, show: hasSchema }, { key: 'relations', name: t('relations'), show: canRelations }, { key: 'history', name: t('historyTab'), show: canAudit }].filter(item => item.show).map(item => <Link key={item.key} href={`/catalog/${asset.id}?tab=${item.key}`} className={tab === item.key ? 'active' : ''} aria-current={tab === item.key ? 'page' : undefined}>{item.name}</Link>)}</div>{tab === 'overview' && <div className="asset-layout"><div><section className="panel"><div className="panel-heading"><h2>{t('descriptionLabel')}</h2></div><div className="panel-body"><p className={`description-text ${asset.description ? '' : 'text-muted'}`}>{asset.description || t('noDescription')}</p>{!asset.description && canEdit && <button className="text-button" onClick={() => setEditOpen(true)}>{t('editDetails')}</button>}</div></section><section className="panel"><div className="panel-heading"><h2>{t('ownership')}</h2></div><div className="panel-body"><div className="ownership-person"><span className="avatar large">{asset.ownerName?.slice(0, 1) || '—'}</span><div><strong>{asset.ownerName || t('unassigned')}</strong><p>{t('ownerHint')}</p></div></div></div></section><AssetAttributesPanel assetId={asset.id} assetVersion={asset.version} onSaved={resource.reload}/><Suspense fallback={<LoadingState label={t('loading')}/>}><LifecyclePanel assetId={asset.id} assetVersion={asset.version} onSaved={resource.reload}/></Suspense><EvidencePanel title={t('sourceMetadata')} note={t('metadataNote')}>{Object.keys(asset.metadata || {}).length ? <DiffViewer value={asset.metadata} label={t('sourceMetadata')}/> : <p className="text-muted">{t('noMetadata')}</p>}</EvidencePanel></div><div><EvidencePanel title={t('provenance')}><dl className="detail-list"><div><dt>{t('source')}</dt><dd>{asset.sourceName}</dd></div><div><dt>{t('qualifiedName')}</dt><dd className="mono break-all">{asset.qualifiedName}</dd></div><div><dt>{t('collectedAt')}</dt><dd>{date(asset.observedAt)}</dd></div><div><dt>{t('updatedAt')}</dt><dd>{date(asset.updatedAt)}</dd></div><div><dt>{t('version')}</dt><dd>{number(asset.version)}</dd></div></dl></EvidencePanel><section className="coverage-note"><h2>{t('scanCoverage')}</h2><p>{t('scanCoverageBody')}</p></section>{!canEdit && <p className="supporting-text">{t('noOwnerPermission')}</p>}</div></div>}{tab === 'schema' && <section className="panel"><div className="catalog-toolbar"><SearchBar label={t('columnSearch')} value={columnQuery} onChange={setColumnQuery}/></div><DataGrid caption={t('schemaTab')} columns={columns} data={resource.data.columns.filter(column => column.name.toLowerCase().includes(columnQuery.toLowerCase()))} empty={<EmptyState icon={<Table size={28}/>} title={columnQuery ? t('noMatches') : t('noColumns')} description={columnQuery ? t('noMatchesBody') : t('noColumnsBody')}/>}/></section>}{tab === 'relations' && <Suspense fallback={<LoadingState label={t('loading')}/>}><AssetRelations key={asset.id} assetId={asset.id}/></Suspense>}{tab === 'history' && <section className="panel"><div className="panel-heading"><h2>{t('audit')}</h2></div>{resource.data.audit.length ? <AuditTimeline events={resource.data.audit}/> : <EmptyState compact title={t('auditEmpty')} description={t('auditEmptyBody')}/>}</section>}<EditAsset open={editOpen} onOpenChange={setEditOpen} asset={asset} members={members.data?.items || []} membersLoading={members.loading} membersError={members.error} retryMembers={members.reload} onSaved={() => { resource.reload(); setSaved(true); }} reloadAsset={resource.reload}/></>;
}
function EditAsset({ open, onOpenChange, asset, members, membersLoading, membersError, retryMembers, onSaved, reloadAsset }: { open: boolean; onOpenChange: (open: boolean) => void; asset: Asset; members: Member[]; membersLoading: boolean; membersError: Error | null; retryMembers: () => void; onSaved: () => void; reloadAsset: () => void }) {
  const { t, number } = useLocale();
  const [description, setDescription] = useState(asset.description || '');
  const [ownerId, setOwnerId] = useState(asset.ownerId || '');
  const [version, setVersion] = useState(asset.version);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [conflict, setConflict] = useState(false);
  const [currentServerAsset, setCurrentServerAsset] = useState<Asset | null>(null);
  useEffect(() => { if (open) { setDescription(asset.description || ''); setOwnerId(asset.ownerId || ''); setVersion(asset.version); setError(null); setConflict(false); setCurrentServerAsset(null); } }, [open, asset.id]);
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (saving || conflict) return;
    setSaving(true); setError(null);
    try { await api(`/assets/${asset.id}`, { method: 'PATCH', headers: { 'If-Match': String(version) }, body: JSON.stringify({ description, ownerId: ownerId || null }) }); onOpenChange(false); onSaved(); }
    catch (caught) { if (caught instanceof ApiError && [409, 412].includes(caught.status)) setConflict(true); setError(caught as Error); }
    finally { setSaving(false); }
  }
  async function reloadVersion() {
    setSaving(true); setError(null);
    try { const current = await api<AssetDetail>(`/assets/${asset.id}`); setVersion(current.asset.version); setCurrentServerAsset(current.asset); setConflict(false); reloadAsset(); }
    catch (caught) { setError(caught as Error); }
    finally { setSaving(false); }
  }
  return <DetailDrawer open={open} onOpenChange={value => { if (!saving) onOpenChange(value); }} title={t('editDetails')} description={asset.name} closeLabel={t('close')}><form onSubmit={save} className="stacked-form"><p className="supporting-text">{t('editHint')}</p>{error && !conflict && <ModelError error={error}/>}{conflict && <Notice tone="error"><p>{t('conflict')}</p><button type="button" className="button secondary" onClick={reloadVersion} disabled={saving}>{t('reloadVersion')}</button></Notice>}{currentServerAsset && <EvidencePanel title={t('currentVersion')} note={t('reviewCurrentVersion')}><dl className="detail-list"><div><dt>{t('descriptionLabel')}</dt><dd className="description-text">{currentServerAsset.description || t('noDescription')}</dd></div><div><dt>{t('owner')}</dt><dd>{currentServerAsset.ownerName || t('unassigned')}</dd></div></dl></EvidencePanel>}<label className="form-field"><span>{t('descriptionLabel')}</span><textarea aria-label={t('descriptionLabel')} rows={5} value={description} maxLength={10000} onChange={event => setDescription(event.target.value)} aria-describedby="description-hint"/><small id="description-hint">{t('descriptionHint')}</small></label><label className="form-field"><span>{t('owner')}</span><select value={ownerId} disabled={membersLoading || !!membersError} onChange={event => setOwnerId(event.target.value)}><option value="">{t('unassigned')}</option>{asset.ownerId && !members.some(member => member.id === asset.ownerId) && <option value={asset.ownerId}>{asset.ownerName || asset.ownerId}</option>}{members.map(member => <option value={member.id} key={member.id}>{member.name}</option>)}</select></label>{membersError && <RequestError error={membersError} retry={retryMembers} compact/>}<p className="supporting-text">{t('currentVersion')}: {number(version)}</p><div className="form-actions"><button type="button" className="button secondary" disabled={saving} onClick={() => onOpenChange(false)}>{t('cancel')}</button><button className="button primary" disabled={saving || conflict || membersLoading || !!membersError}>{saving ? t('saving') : t('save')}</button></div></form></DetailDrawer>;
}
