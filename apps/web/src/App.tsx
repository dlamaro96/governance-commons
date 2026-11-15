import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, BookOpen, ClockCounterClockwise, Database, House, List, Moon, Question, SignOut, Sun, X } from '@phosphor-icons/react';
import { BrandMark, DetailDrawer, EmptyState, LoadingState, Notice, SearchBar } from '../../../packages/ui/src';
import { api, ApiError, setCsrfToken, useResource } from './api';
import { useLocale } from './i18n';
import { Link, useNavigation } from './navigation';
import { SessionContext } from './session';
import { PermissionDenied, RequestError } from './components';
import type { Session } from './types';
import { HomePage } from './pages/Home';
import { CatalogPage } from './pages/Catalog';
import { AssetPage } from './pages/Asset';
import { SourcesPage } from './pages/Sources';
import { AuditPage } from './pages/Audit';

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
function Shell({ session, reloadSession, preferences }: { session: Session; reloadSession: () => void; preferences: React.ReactNode }) {
  const { t, label, locale } = useLocale();
  const { path, go } = useNavigation();
  const [globalSearch, setGlobalSearch] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const can = (permission: string) => session.permissions.includes(permission);
  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); document.querySelector<HTMLInputElement>('.global-search input')?.focus(); } };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, []);
  const navItems = [
    { href: '/', key: 'home' as const, icon: House, visible: true },
    { href: '/catalog', key: 'catalog' as const, icon: BookOpen, visible: can('catalog:read') },
    { href: '/sources', key: 'sources' as const, icon: Database, visible: can('sources:read') },
    { href: '/audit', key: 'audit' as const, icon: ClockCounterClockwise, visible: can('audit:read') },
  ];
  const navigation = <><Link href="/" className="brand" onClick={() => setMenuOpen(false)}><BrandMark size={30}/><span>Governance<br/>Commons</span></Link><nav aria-label={t('workspace')}><div className="nav-section-label">{t('workspace')}</div>{navItems.filter(item => item.visible).map(({ href, key, icon: Icon }) => <Link key={href} href={href} className={`nav-link ${path === href || href !== '/' && path.startsWith(href) ? 'selected' : ''}`} aria-current={path === href || href !== '/' && path.startsWith(href) ? 'page' : undefined} onClick={() => setMenuOpen(false)}><Icon size={20}/>{t(key)}</Link>)}</nav><div className="sidebar-bottom"><button className="sidebar-help" onClick={() => { setMenuOpen(false); setHelpOpen(true); }}><Question size={20}/>{t('help')}</button><div className="sidebar-tagline">{t('tagline')}</div></div></>;
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
  let content;
  if (path === '/') content = <HomePage/>;
  else if (path === '/catalog') content = can('catalog:read') ? <CatalogPage/> : <PermissionDenied/>;
  else if (path.startsWith('/catalog/')) content = can('catalog:read') ? <AssetPage id={decodeURIComponent(path.split('/')[2])}/> : <PermissionDenied/>;
  else if (path === '/sources') content = can('sources:read') ? <SourcesPage/> : <PermissionDenied/>;
  else if (path === '/audit') content = can('audit:read') ? <AuditPage/> : <PermissionDenied/>;
  else content = <EmptyState title={t('invalidRoute')} description={t('notFoundBody')} action={<Link className="button secondary" href="/">{t('backHome')}</Link>}/>;
  return <div className="application"><a className="skip-link" href="#main-content">{t('skip')}</a><aside className="sidebar">{navigation}</aside><div className="workspace-main"><header className="topbar"><button className="icon-button mobile-menu-button" aria-label={t('openNavigation')} onClick={() => setMenuOpen(true)}><List size={23}/></button><div className="tenant-context"><span className="context-label">{t('organization')}</span>{session.tenants.length > 1 ? <><label className="sr-only" htmlFor="tenant">{t('organization')}</label><select id="tenant" value={session.tenant.id} disabled={switching} onChange={event => switchTenant(event.target.value)}>{session.tenants.map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}</select></> : <strong>{session.tenant.name}</strong>}</div>{can('catalog:read') && <SearchBar label={t('searchGlobal')} value={globalSearch} onChange={setGlobalSearch} onSubmit={search} className="global-search"/>}<div className="topbar-controls">{preferences}<div className="user-identity"><span className="avatar" aria-hidden="true">{session.user.name.slice(0, 1).toUpperCase()}</span><div><strong>{session.user.name}</strong><span>{label(`role_${session.tenant.role}`)}</span></div></div><button className="icon-button" title={t('signOut')} aria-label={t('signOut')} onClick={logout}><SignOut size={20}/></button></div></header>{locale === 'ar' && <p className="translation-notice">{t('translationStatus')}</p>}<main id="main-content" className="page" key={session.tenant.id} tabIndex={-1}>{error && <RequestError error={error} compact/>}{switching ? <LoadingState label={t('tenantSwitching')}/> : content}</main><footer className="workspace-footer"><span>{session.tenant.name}</span><span>{t('homePermissionNote')}</span></footer></div><DetailDrawer open={menuOpen} onOpenChange={setMenuOpen} title={t('menu')} description={session.tenant.name} closeLabel={t('close')}><div className="mobile-navigation">{navigation}</div></DetailDrawer><DetailDrawer open={helpOpen} onOpenChange={setHelpOpen} title={t('helpTitle')} description={t('tagline')} closeLabel={t('close')}><div className="help-content"><p>{t('helpBody')}</p><p>{t('helpSource')}</p><p>{t('helpAudit')}</p><Notice>{t('helpScope')}</Notice></div></DetailDrawer></div>;
}
