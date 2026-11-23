import { createContext, useContext, useEffect, useState, type AnchorHTMLAttributes, type ReactNode } from 'react';

interface Navigation { path: string; search: string; state: unknown; go: (href: string, replace?: boolean, state?: unknown) => void }
const NavigationContext = createContext<Navigation>({ path: '/', search: '', state: null, go: () => {} });
export function NavigationProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState({ path: window.location.pathname, search: window.location.search, state: window.history.state as unknown });
  useEffect(() => {
    const update = () => setLocation({ path: window.location.pathname, search: window.location.search, state: window.history.state as unknown });
    window.addEventListener('popstate', update);
    return () => window.removeEventListener('popstate', update);
  }, []);
  function go(href: string, replace = false, state: unknown = null) {
    const url = new URL(href, window.location.origin);
    if (url.origin !== window.location.origin) return;
    const changed = url.pathname !== window.location.pathname;
    window.history[replace ? 'replaceState' : 'pushState'](state, '', url.pathname + url.search + url.hash);
    setLocation({ path: url.pathname, search: url.search, state });
    if (changed) { window.scrollTo(0, 0); window.setTimeout(() => document.getElementById('main-heading')?.focus(), 0); }
    if (url.hash) window.setTimeout(() => document.getElementById(decodeURIComponent(url.hash.slice(1)))?.scrollIntoView(), 0);
  }
  return <NavigationContext.Provider value={{ ...location, go }}>{children}</NavigationContext.Provider>;
}
export const useNavigation = () => useContext(NavigationContext);
export function Link({ href = '/', onClick, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { go } = useNavigation();
  return <a {...props} href={href} onClick={event => {
    onClick?.(event);
    if (!event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && !props.target) {
      event.preventDefault(); go(href);
    }
  }}>{children}</a>;
}
