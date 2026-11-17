import { lazy, Suspense, useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, BookOpen, ClockCounterClockwise, Database, GitBranch, House, List, Moon, Question, WarningCircle, SignOut, Sun, X } from '@phosphor-icons/react';
import { BrandMark, DetailDrawer, EmptyState, LoadingState, Notice, SearchBar } from '../../../packages/ui/src';
import { api, ApiError, setCsrfToken, useResource } from './api.ts';
import { useLocale } from './i18n.tsx';
import { Link, useNavigation } from './navigation.tsx';
import { SessionContext } from './session.tsx';
import { PermissionDenied, RequestError } from './components.tsx';
import type { Session } from './types.ts';
import { HomePage } from './pages/Home.tsx';
import { CatalogPage } from './pages/Catalog.tsx';
import { AssetPage } from './pages/Asset.tsx';
import { SourcesPage } from './pages/Sources.tsx';
import { AuditPage } from './pages/Audit.tsx';
import { approvalsCopy } from './pages/approvals-copy.ts';
import { glossaryCopy } from './pages/glossary-copy.ts';
import { classificationCopy } from './classification/messages.ts';
import {referenceCopy} from './referenceData/messages.ts';
import {monitoringCopy} from './quality/monitoring/messages.ts';
const QualityIssuesPage = lazy(() => import('./quality/monitoring').then(module => ({default:module.QualityIssuesPage})));
const StructuresPage = lazy(() => import('./referenceData/structures').then(module => ({default:module.StructuresPage})));
const StructurePage = lazy(() => import('./referenceData/structures').then(module => ({default:module.StructurePage})));
const StructureEditorPage = lazy(() => import('./referenceData/structures').then(module => ({default:module.StructureEditorPage})));
const ReferenceDataPage = lazy(() => import('./referenceData').then(module => ({default:module.ReferenceDataPage})));
const ReferenceSetPage = lazy(() => import('./referenceData').then(module => ({default:module.ReferenceSetPage})));
const ReferenceEditorPage = lazy(() => import('./referenceData').then(module => ({default:module.ReferenceEditorPage})));
const ClassificationDefinitions = lazy(() => import('./classification').then(module => ({ default: module.ClassificationDefinitions })));
const GlossaryPage = lazy(() => import('./pages/Glossary').then(module => ({ default: module.GlossaryPage })));
const GlossaryTermPage = lazy(() => import('./pages/Glossary').then(module => ({ default: module.GlossaryTermPage })));
const GlossaryProposalPage = lazy(() => import('./pages/Glossary').then(module => ({ default: module.GlossaryProposalPage })));
const ApprovalsPage = lazy(() => import('./pages/Approvals').then(module => ({ default: module.ApprovalsPage })));
const ApprovalPage = lazy(() => import('./pages/Approvals').then(module => ({ default: module.ApprovalPage })));
const WorkflowsPage = lazy(() => import('./pages/Approvals').then(module => ({ default: module.WorkflowsPage })));
const WorkflowPage = lazy(() => import('./pages/Approvals').then(module => ({ default: module.WorkflowPage })));
const WorkflowEditorPage = lazy(() => import('./pages/Approvals').then(module => ({ default: module.WorkflowEditorPage })));
const ModelsPage = lazy(() => import('./pages/Models').then(module => ({ default: module.ModelsPage })));
const ModelPage = lazy(() => import('./pages/Models').then(module => ({ default: module.ModelPage })));
const ModelEditorPage = lazy(() => import('./pages/Models').then(module => ({ default: module.ModelEditorPage })));
const AssetTypesPage = lazy(() => import('./pages/AssetTypes').then(module => ({ default: module.AssetTypesPage })));
const AssetTypePage = lazy(() => import('./pages/AssetTypes').then(module => ({ default: module.AssetTypePage })));
const AssetTypeEditorPage = lazy(() => import('./pages/AssetTypes').then(module => ({ default: module.AssetTypeEditorPage })));
const AssetTypeMigrationPage = lazy(() => import('./pages/AssetTypeMigrations').then(module => ({ default: module.AssetTypeMigrationPage })));
const AssetTypeMigrationReceiptPage = lazy(() => import('./pages/AssetTypeMigrations').then(module => ({ default: module.AssetTypeMigrationReceiptPage })));
const ModelMigrationPage = lazy(() => import('./pages/ModelMigrations').then(module => ({ default: module.ModelMigrationPage })));
const ModelMigrationReceiptPage = lazy(() => import('./pages/ModelMigrations').then(module => ({ default: module.ModelMigrationReceiptPage })));

const BusinessDomainsPage = lazy(() => import('./pages/BusinessDomains').then(module => ({ default: module.BusinessDomainsPage })));
const BusinessDomainPage = lazy(() => import('./pages/BusinessDomains').then(module => ({ default: module.BusinessDomainPage })));
const BusinessDomainEditorPage = lazy(() => import('./pages/BusinessDomains').then(module => ({ default: module.BusinessDomainEditorPage })));
const DomainTypesPage = lazy(() => import('./pages/DomainTypes').then(module => ({ default: module.DomainTypesPage })));
const DomainTypePage = lazy(() => import('./pages/DomainTypes').then(module => ({ default: module.DomainTypePage })));
const DomainTypeEditorPage = lazy(() => import('./pages/DomainTypes').then(module => ({ default: module.DomainTypeEditorPage })));
const DomainTypeMigrationPage = lazy(() => import('./pages/DomainTypeMigrations').then(module => ({ default: module.DomainTypeMigrationPage })));
const DomainTypeMigrationReceiptPage = lazy(() => import('./pages/DomainTypeMigrations').then(module => ({ default: module.DomainTypeMigrationReceiptPage })));

export default function App() {
  const session = useResource<Session>('/me');
  const { t, locale, setLocale } = useLocale();
  const [expired, setExpired] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('gc.theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('gc.theme', theme); }, [theme]);
  useEffect(() => { if (session.data) { setCsrfToken(session.data.csrfToken); setExpired(false); } }, [session.data]);
  useEffect(() => {
    const expire = () => { setExpired(true); setCsrfToken(''); session.reload(); };
    window.addEventListener('gc:session-expired', expire);
    return () => window.removeEventListener('gc:session-expired', expire);
  }, [session.reload]);
  const preferences = <div className="preferences"><label className="sr-only" htmlFor="language">{t('language')}</label><select id="language" aria-label={t('language')} value={locale} onChange={event => setLocale(event.target.value as 'en' | 'ar')}><option value="en">English</option><option value="ar">العربية</option></select><button className="icon-button" aria-label={`${t('theme')}: ${theme === 'dark' ? t('light') : t('dark')}`} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun size={19}/> : <Moon size={19}/>}</button></div>;
  if (session.loading && !session.data) return <div className="session-loading"><BrandMark size={36}/><LoadingState label={t('loading')}/></div>;
  if (session.error instanceof ApiError && session.error.status === 401 || expired) return <div className="sign-in"><div className="sign-in-top"><a className="brand sign-in-brand" href="/"><BrandMark size={32}/><span>Governance<br/>Commons</span></a>{preferences}</div><main className="sign-in-main"><div className="sign-in-symbol"><BrandMark size={58}/></div><div className="eyebrow">{t('workspace')}</div><h1>{t('signIn')}</h1><p className="sign-in-description">{t('signInBody')}</p>{expired && <Notice>{t('sessionExpired')}</Notice>}<a className="button primary sign-in-action" href="/auth/login">{t('signInAction')}<ArrowRight size={19}/></a><p className="supporting-text">{t('identityNote')}</p></main><footer className="sign-in-footer">{t('tagline')}</footer></div>;
  if (session.error || !session.data) return <div className="session-loading"><RequestError error={session.error || new Error(t('sessionError'))} retry={session.reload}/></div>;
  return <SessionContext.Provider value={session.data}><Shell session={session.data} reloadSession={session.reload} preferences={preferences}/></SessionContext.Provider>;
}
const RelationTypesPage = lazy(() => import('./pages/RelationTypes').then(module => ({ default: module.RelationTypesPage })));
const RelationTypePage = lazy(() => import('./pages/RelationTypes').then(module => ({ default: module.RelationTypePage })));
const RelationTypeEditorPage = lazy(() => import('./pages/RelationTypes').then(module => ({ default: module.RelationTypeEditorPage })));
const RelationMigrationPage = lazy(() => import('./pages/RelationMigrations').then(module => ({ default: module.RelationMigrationPage })));
const RelationMigrationReceiptPage = lazy(() => import('./pages/RelationMigrations').then(module => ({ default: module.RelationMigrationReceiptPage })));
const RelationPage = lazy(() => import('./pages/Relation').then(module => ({ default: module.RelationPage })));
function Shell({ session, reloadSession, preferences }: { session: Session; reloadSession: () => void; preferences: React.ReactNode }) {
  const { t, label, locale } = useLocale();
  const { path, go, search: routeSearch } = useNavigation();
  const [globalSearch, setGlobalSearch] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const can = (permission: string) => session.permissions.includes(permission);
  const approvalLabels = approvalsCopy[locale];
  const glossaryLabels = glossaryCopy[locale];
  const canReadApprovals = can('catalog:read') && (can('catalog:write') || can('classification:read') || can('reference:read'));
  const approvalContext = JSON.stringify([session.tenant.id, session.user.id, [...session.permissions].sort(), path]);
  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); document.querySelector<HTMLInputElement>('.global-search input')?.focus(); } };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, []);
  const navItems = [
    { href: '/', key: 'home' as const, icon: House, visible: true },
    { href: '/catalog', key: 'catalog' as const, icon: BookOpen, visible: can('catalog:read') },
    { href: '/domains', key: 'businessDomains' as const, icon: GitBranch, visible: can('domains:read') },
    { href: '/sources', key: 'sources' as const, icon: Database, visible: can('sources:read') },
    { href: '/models', key: 'models' as const, icon: GitBranch, visible: can('models:read') },
    { href: '/audit', key: 'audit' as const, icon: ClockCounterClockwise, visible: can('audit:read') },
  ];
  const navigation = <><Link href="/" className="brand" onClick={() => setMenuOpen(false)}><BrandMark size={30}/><span>Governance<br/>Commons</span></Link><nav aria-label={t('workspace')}><div className="nav-section-label">{t('workspace')}</div>{navItems.filter(item => item.visible).map(({ href, key, icon: Icon }) => <Link key={href} href={href} className={`nav-link ${path === href || href !== '/' && path.startsWith(href) || key === 'models' && (path.startsWith('/domain-types') || path.startsWith('/asset-types') || path.startsWith('/relation-types') || path.startsWith('/relation-migrations')) || key === 'catalog' && path.startsWith('/relations/') ? 'selected' : ''}`} aria-current={path === href || href !== '/' && path.startsWith(href) || key === 'models' && (path.startsWith('/domain-types') || path.startsWith('/asset-types') || path.startsWith('/relation-types') || path.startsWith('/relation-migrations')) || key === 'catalog' && path.startsWith('/relations/') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><Icon size={20}/>{t(key)}</Link>)}{can('catalog:read') && <Link href="/glossary" className={`nav-link ${path.startsWith('/glossary') ? 'selected' : ''}`} aria-current={path.startsWith('/glossary') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><BookOpen size={20}/>{glossaryLabels.glossary}</Link>}{can('catalog:read') && can('classification:read') && <Link href="/classifications" className={`nav-link ${path === '/classifications' ? 'selected' : ''}`} aria-current={path === '/classifications' ? 'page' : undefined} onClick={() => setMenuOpen(false)}><BookOpen size={20}/>{classificationCopy[locale].title}</Link>}{can('catalog:read') && can('reference:read') && <Link href="/reference-data" className={`nav-link ${path.startsWith('/reference-data') ? 'selected' : ''}`} aria-current={path.startsWith('/reference-data') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><BookOpen size={20}/>{referenceCopy[locale].title}</Link>}{can('catalog:read') && can('quality:read') && <Link href="/quality/issues" className={`nav-link ${path.startsWith('/quality/issues') ? 'selected' : ''}`} aria-current={path.startsWith('/quality/issues') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><WarningCircle size={20}/>{monitoringCopy[locale].issues}</Link>}{canReadApprovals && <Link href="/approvals" className={`nav-link ${path.startsWith('/approvals') ? 'selected' : ''}`} aria-current={path.startsWith('/approvals') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><ClockCounterClockwise size={20}/>{approvalLabels.approvals}</Link>}{can('models:read') && <Link href="/workflows" className={`nav-link ${path.startsWith('/workflows') ? 'selected' : ''}`} aria-current={path.startsWith('/workflows') ? 'page' : undefined} onClick={() => setMenuOpen(false)}><GitBranch size={20}/>{approvalLabels.workflows}</Link>}</nav><div className="sidebar-bottom"><button className="sidebar-help" onClick={() => { setMenuOpen(false); setHelpOpen(true); }}><Question size={20}/>{t('help')}</button><div className="sidebar-tagline">{t('tagline')}</div></div></>;
  async function switchTenant(tenantId: string) {
    setSwitching(true); setError(null);
    try { await api('/session/tenant', { method: 'POST', body: JSON.stringify({ tenantId }) }); window.location.assign('/'); }
    catch (caught) { setError(caught as Error); setSwitching(false); }
  }
  async function logout() {
    setError(null);
    try { await api('/auth/logout', { method: 'POST' }); setCsrfToken(''); reloadSession(); }
    catch (caught) { setError(caught as Error); }
  }
  function search(event: FormEvent<HTMLFormElement>) { event.preventDefault(); go(`/catalog?q=${encodeURIComponent(globalSearch)}`); setGlobalSearch(''); }
  let assetId: string | null = null;
  const assetMatch = path.match(/^\/catalog\/([^/]+)$/);
  if (assetMatch) { try { assetId = decodeURIComponent(assetMatch[1]); } catch { assetId = null; } }
  const modelMatch = path.match(/^\/models\/([^/]+)(\/edit)?$/);
  let modelId: string | null = null;
  if (modelMatch) { try { modelId = decodeURIComponent(modelMatch[1]); } catch { modelId = null; } }
  const typeMatch = path.match(/^\/asset-types\/([^/]+)(\/edit)?$/);
  let typeId: string | null = null;
  if (typeMatch) { try { typeId = decodeURIComponent(typeMatch[1]); } catch { typeId = null; } }
  const migrationMatch = path.match(/^\/models\/([^/]+)\/(migrate|migrations\/([a-f0-9-]+))$/i);
  let migrationModelId: string | null = null;
  if (migrationMatch) { try { migrationModelId = decodeURIComponent(migrationMatch[1]); } catch { migrationModelId = null; } }
  const typeMigrationMatch = path.match(/^\/asset-types\/([^/]+)\/(migrate|migrations\/([a-f0-9-]+))$/i);
  let migrationTypeId: string | null = null;
  if (typeMigrationMatch) { try { migrationTypeId = decodeURIComponent(typeMigrationMatch[1]); } catch { migrationTypeId = null; } }
  const relationTypeMatch = path.match(/^\/relation-types\/([^/]+)(\/edit)?$/);
  const relationMigrationMatch = path.match(/^\/relation-migrations\/([a-f0-9-]+)$/i);
  const relationMatch = path.match(/^\/relations\/([a-f0-9-]+)$/i);
  let relationTypeId: string | null = null;
  if (relationTypeMatch) { try { relationTypeId = decodeURIComponent(relationTypeMatch[1]); } catch { relationTypeId = null; } }
  const domainMatch = path.match(/^\/domains\/([a-f0-9-]+)(\/edit)?$/i);
  const domainTypeMatch = path.match(/^\/domain-types\/([a-f0-9-]+)(\/edit)?$/i);
  const domainMigrationMatch = path.match(/^\/domain-types\/([a-f0-9-]+)\/(migrate|migrations\/([a-f0-9-]+))$/i);
  const glossaryMatch = path.match(/^\/glossary\/([a-f0-9-]+)(\/edit)?$/i);
  const referenceMatch = path.match(/^\/reference-data\/([a-f0-9-]{36})(\/propose)?$/);
  const structureMatch = path.match(/^\/reference-data\/structures\/([a-f0-9-]{36})(\/propose)?$/);
  const canReadReference = can('catalog:read') && can('reference:read');
  const canProposeReference = canReadReference && can('reference:write');
  const canProposeGlossary = ['catalog:read','catalog:write','models:read','models:write'].every(can);
  let content;
  if (path === '/') content = <HomePage/>;
  else if (path === '/glossary') content = can('catalog:read') ? <GlossaryPage/> : <PermissionDenied/>;
  else if (path === '/glossary/new') content = canProposeGlossary ? <GlossaryProposalPage/> : <PermissionDenied/>;
  else if (glossaryMatch) content = glossaryMatch[2] ? (canProposeGlossary ? <GlossaryProposalPage key={glossaryMatch[1]} id={glossaryMatch[1]}/> : <PermissionDenied/>) : (can('catalog:read') && can('models:read') ? <GlossaryTermPage key={glossaryMatch[1]} id={glossaryMatch[1]}/> : <PermissionDenied/>);
  else if (path === '/catalog') content = can('catalog:read') ? <CatalogPage/> : <PermissionDenied/>;
  else if (assetId) content = can('catalog:read') ? <AssetPage id={assetId}/> : <PermissionDenied/>;
  else if (path === '/relation-migrations/new') content = can('models:read') && can('models:write') && can('catalog:read') && can('catalog:write') ? <RelationMigrationPage key={routeSearch}/> : <PermissionDenied/>;
  else if (relationMigrationMatch) content = can('models:read') && can('catalog:read') ? <RelationMigrationReceiptPage key={relationMigrationMatch[1]} id={relationMigrationMatch[1]}/> : <PermissionDenied/>;
  else if (path === '/relation-types') content = can('models:read') ? <RelationTypesPage/> : <PermissionDenied/>;
  else if (path === '/relation-types/new/definition') content = can('models:read') && can('models:write') ? <RelationTypeEditorPage/> : <PermissionDenied/>;
  else if (relationTypeId) content = can('models:read') && (!relationTypeMatch?.[2] || can('models:write') && can('catalog:read')) ? (relationTypeMatch?.[2] ? <RelationTypeEditorPage key={relationTypeId} id={relationTypeId}/> : <RelationTypePage key={relationTypeId} id={relationTypeId}/>) : <PermissionDenied/>;
  else if (relationMatch) content = can('models:read') && can('catalog:read') ? <RelationPage key={relationMatch[1]} id={relationMatch[1]}/> : <PermissionDenied/>;
  else if (path === '/domains') content = can('domains:read') ? <BusinessDomainsPage/> : <PermissionDenied/>;
  else if (path === '/domains/new') content = can('domains:read') && can('domains:write') ? <BusinessDomainEditorPage/> : <PermissionDenied/>;
  else if (domainMatch) content = can('domains:read') && (!domainMatch[2] || can('domains:write')) ? domainMatch[2] ? <BusinessDomainEditorPage key={domainMatch[1]} id={domainMatch[1]}/> : <BusinessDomainPage key={domainMatch[1]} id={domainMatch[1]}/> : <PermissionDenied/>;
  else if (path === '/domain-types') content = can('models:read') ? <DomainTypesPage/> : <PermissionDenied/>;
  else if (path === '/domain-types/new') content = can('models:read') && can('models:write') ? <DomainTypeEditorPage/> : <PermissionDenied/>;
  else if (domainMigrationMatch) content = can('models:read') && can('domains:read') && (domainMigrationMatch[3] || can('models:write') && can('domains:write')) ? domainMigrationMatch[3] ? <DomainTypeMigrationReceiptPage key={domainMigrationMatch[3]} id={domainMigrationMatch[1]} migrationId={domainMigrationMatch[3]}/> : <DomainTypeMigrationPage key={domainMigrationMatch[1]} id={domainMigrationMatch[1]}/> : <PermissionDenied/>;
  else if (domainTypeMatch) content = can('models:read') && (!domainTypeMatch[2] || can('models:write') && can('domains:read')) ? domainTypeMatch[2] ? <DomainTypeEditorPage key={domainTypeMatch[1]} id={domainTypeMatch[1]}/> : <DomainTypePage key={domainTypeMatch[1]} id={domainTypeMatch[1]}/> : <PermissionDenied/>;
  else if (path === '/sources') content = can('sources:read') ? <SourcesPage/> : <PermissionDenied/>;
  else if (path === '/reference-data') content = canReadReference ? <ReferenceDataPage/> : <PermissionDenied/>;
  else if (path === '/reference-data/structures') content = canReadReference ? <StructuresPage/> : <PermissionDenied/>;
  else if (path === '/reference-data/structures/new/hierarchy' || path === '/reference-data/structures/new/crosswalk') content = canProposeReference ? <StructureEditorPage key={path} kind={path.endsWith('/hierarchy') ? 'reference-hierarchy' : 'reference-crosswalk'}/> : <PermissionDenied/>;
  else if (structureMatch) content = structureMatch[2] ? (canProposeReference ? <StructureEditorPage key={path} id={structureMatch[1]}/> : <PermissionDenied/>) : (canReadReference ? <StructurePage key={structureMatch[1]} id={structureMatch[1]}/> : <PermissionDenied/>);
  else if (path === '/reference-data/new') content = canProposeReference ? <ReferenceEditorPage/> : <PermissionDenied/>;
  else if (referenceMatch) content = referenceMatch[2] ? (canProposeReference ? <ReferenceEditorPage key={path} id={referenceMatch[1]}/> : <PermissionDenied/>) : (canReadReference ? <ReferenceSetPage key={referenceMatch[1]} id={referenceMatch[1]}/> : <PermissionDenied/>);
  else if (path === '/quality/issues') content = can('catalog:read') && can('quality:read') ? <QualityIssuesPage/> : <PermissionDenied/>;
  else if (/^\/quality\/issues\/[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(path)) content = can('catalog:read') && can('quality:read') ? <QualityIssuesPage id={path.split('/')[3]}/> : <PermissionDenied/>;
  else if (path === '/classifications') content = can('catalog:read') && can('classification:read') ? <ClassificationDefinitions/> : <PermissionDenied/>;
  else if (path === '/approvals') content = canReadApprovals ? <ApprovalsPage key={approvalContext}/> : <PermissionDenied/>;
  else if (/^\/approvals\/[a-f0-9-]{36}$/.test(path)) content = canReadApprovals ? <ApprovalPage key={approvalContext} id={path.split('/')[2]}/> : <PermissionDenied/>;
  else if (path === '/workflows') content = can('models:read') ? <WorkflowsPage/> : <PermissionDenied/>;
  else if (path === '/workflows/new/definition') content = can('models:read') && can('models:write') ? <WorkflowEditorPage/> : <PermissionDenied/>;
  else if (/^\/workflows\/[A-Za-z_][A-Za-z0-9_.-]{0,63}\/edit$/.test(path)) content = can('models:read') && can('models:write') ? <WorkflowEditorPage key={path} id={path.split('/')[2]}/> : <PermissionDenied/>;
  else if (/^\/workflows\/[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(path)) content = can('models:read') ? <WorkflowPage key={path} id={path.split('/')[2]}/> : <PermissionDenied/>;
  else if (path === '/asset-types') content = can('models:read') ? <AssetTypesPage/> : <PermissionDenied/>;
  else if (path === '/asset-types/new/definition') content = can('models:write') && can('models:read') ? <AssetTypeEditorPage/> : <PermissionDenied/>;
  else if (migrationTypeId && typeMigrationMatch) content = typeMigrationMatch[3] ? (can('models:read') && can('catalog:read') ? <AssetTypeMigrationReceiptPage id={migrationTypeId} migrationId={typeMigrationMatch[3]}/> : <PermissionDenied/>) : (can('models:read') && can('models:write') && can('catalog:read') && can('catalog:write') ? <AssetTypeMigrationPage id={migrationTypeId}/> : <PermissionDenied/>);
  else if (typeId) content = can('models:read') && (!typeMatch?.[2] || can('models:write') && can('catalog:read')) ? (typeMatch?.[2] ? <AssetTypeEditorPage id={typeId}/> : <AssetTypePage id={typeId}/>) : <PermissionDenied/>;
  else if (path === '/models') content = can('models:read') ? <ModelsPage/> : <PermissionDenied/>;
  else if (path === '/models/new/definition') content = can('models:write') ? <ModelEditorPage/> : <PermissionDenied/>;
  else if (migrationModelId && migrationMatch) content = migrationMatch[3] ? (can('models:read') && can('catalog:read') ? <ModelMigrationReceiptPage id={migrationModelId} migrationId={migrationMatch[3]}/> : <PermissionDenied/>) : (can('models:read') && can('models:write') && can('catalog:read') && can('catalog:write') ? <ModelMigrationPage id={migrationModelId}/> : <PermissionDenied/>);
  else if (modelId) content = can(modelMatch?.[2] ? 'models:write' : 'models:read') ? (modelMatch?.[2] ? <ModelEditorPage id={modelId}/> : <ModelPage id={modelId}/>) : <PermissionDenied/>;
  else if (path === '/audit') content = can('audit:read') ? <AuditPage/> : <PermissionDenied/>;
  else content = <EmptyState title={t('invalidRoute')} description={t('notFoundBody')} action={<Link className="button secondary" href="/">{t('backHome')}</Link>}/>;
  return <div className="application"><a className="skip-link" href="#main-content">{t('skip')}</a><aside className="sidebar">{navigation}</aside><div className="workspace-main"><header className="topbar"><button className="icon-button mobile-menu-button" aria-label={t('openNavigation')} onClick={() => setMenuOpen(true)}><List size={23}/></button><div className="tenant-context"><span className="context-label">{t('organization')}</span>{session.tenants.length > 1 ? <><label className="sr-only" htmlFor="tenant">{t('organization')}</label><select id="tenant" value={session.tenant.id} disabled={switching} onChange={event => switchTenant(event.target.value)}>{session.tenants.map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}</select></> : <strong>{session.tenant.name}</strong>}</div>{can('catalog:read') && <SearchBar label={t('searchGlobal')} value={globalSearch} onChange={setGlobalSearch} onSubmit={search} className="global-search"/>}<div className="topbar-controls">{preferences}<div className="user-identity"><span className="avatar" aria-hidden="true">{session.user.name.slice(0, 1).toUpperCase()}</span><div><strong>{session.user.name}</strong><span>{label(`role_${session.tenant.role}`).startsWith('role_') ? session.tenant.role : label(`role_${session.tenant.role}`)}</span></div></div><button className="icon-button" title={t('signOut')} aria-label={t('signOut')} onClick={logout}><SignOut size={20}/></button></div></header>{locale === 'ar' && <p className="translation-notice">{t('translationStatus')}</p>}<main id="main-content" className="page" key={session.tenant.id} tabIndex={-1}>{error && <RequestError error={error} compact/>}{switching ? <LoadingState label={t('tenantSwitching')}/> : <Suspense fallback={<LoadingState label={t('loading')}/>}>{content}</Suspense>}</main><footer className="workspace-footer"><span>{session.tenant.name}</span><span>{t('homePermissionNote')}</span></footer></div><DetailDrawer open={menuOpen} onOpenChange={setMenuOpen} title={t('menu')} description={session.tenant.name} closeLabel={t('close')}><div className="mobile-navigation">{navigation}</div></DetailDrawer><DetailDrawer open={helpOpen} onOpenChange={setHelpOpen} title={t('helpTitle')} description={t('tagline')} closeLabel={t('close')}><div className="help-content"><p>{t('helpBody')}</p><p>{t('helpSource')}</p><p>{t('helpAudit')}</p><Notice>{t('helpScope')}</Notice></div></DetailDrawer></div>;
}
