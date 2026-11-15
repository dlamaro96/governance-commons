import { ArrowRight, BookOpen, ClockCounterClockwise, Database, Users } from '@phosphor-icons/react';
import { EmptyState, EntityHeader, LoadingState } from '../../../../packages/ui/src';
import { useResource } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { useSession } from '../session';
import type { Overview } from '../types';
import { AuditTimeline } from './Audit';

export function HomePage() {
  const { t, number } = useLocale();
  const session = useSession();
  const can = (permission: string) => session.permissions.includes(permission);
  const overview = useResource<Overview>(session.permissions.length ? '/overview' : null);
  const metrics = overview.data ? [
    { key: 'totalAssets' as const, definition: 'assetsDefinition' as const, count: overview.data.assetCount, href: '/catalog', icon: BookOpen, show: can('catalog:read') },
    { key: 'ownedCount' as const, definition: 'ownedDefinition' as const, count: overview.data.ownedCount, href: '/catalog', icon: Users, show: can('catalog:read') },
    { key: 'sourceCount' as const, definition: 'sourcesDefinition' as const, count: overview.data.sourceCount, href: '/sources', icon: Database, show: can('sources:read') },
    { key: 'jobCount' as const, definition: 'jobsDefinition' as const, count: overview.data.jobCount, href: '/sources#jobs', icon: ClockCounterClockwise, show: can('sources:read') },
  ].filter(item => item.show) : [];
  return <><EntityHeader eyebrow={t('overviewEyebrow')} title={session.tenant.name} description={t('overviewDescription')} actions={can('catalog:read') && <Link className="button secondary" href="/catalog">{t('browseCatalog')}<ArrowRight size={17}/></Link>}/>{!session.permissions.length ? <EmptyState title={t('noAccess')} description={t('accessBody')}/> : overview.error ? <RequestError error={overview.error} retry={overview.reload}/> : !overview.data ? <LoadingState label={t('loading')}/> : <><div className="metric-grid">{metrics.map(({ key, definition, count, href, icon: Icon }) => <Link className="metric" href={href} key={key} title={t(definition)}><div className="metric-label"><Icon size={19}/><span>{t(key)}</span></div><div className="metric-value">{number(count)}<ArrowRight size={18}/></div><p>{t(definition)}</p></Link>)}</div>{overview.data.assetCount === 0 && can('catalog:read') && <section className="onboarding-note"><div className="onboarding-icon"><BookOpen size={30}/></div><div><h2>{t('beginTitle')}</h2><p>{t('beginBody')}</p></div>{can('sources:write') && <Link className="button primary" href="/sources">{t('manageSources')}<ArrowRight size={17}/></Link>}</section>}{can('audit:read') && <section className="panel"><div className="panel-heading"><h2>{t('recentActivity')}</h2><Link className="text-link" href="/audit">{t('viewAll')}<ArrowRight size={15}/></Link></div>{overview.data.recentAudit.length ? <AuditTimeline events={overview.data.recentAudit.slice(0, 8)}/> : <EmptyState compact icon={<ClockCounterClockwise size={27}/>} title={t('noActivity')} description={t('noActivityBody')}/>}</section>}</>}</>;
}
