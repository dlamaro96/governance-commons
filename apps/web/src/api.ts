import { useCallback, useEffect, useRef, useState } from 'react';

export class ApiError extends Error {
  status: number;
  code?: string;
  correlationId?: string;
  browserCredentialsCleared?: boolean;
  serverRevocationConfirmed?: boolean;
  issues: readonly { code: string; path: string; message: string }[];
  constructor(status: number, body: { detail?: string; title?: string; code?: string; correlationId?: string; browserCredentialsCleared?: boolean; serverRevocationConfirmed?: boolean; issues?: { code: string; path: string; message: string }[] }) {
    super(body.detail || body.title || `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = body.code;
    this.correlationId = body.correlationId;
    this.browserCredentialsCleared = typeof body.browserCredentialsCleared === 'boolean' ? body.browserCredentialsCleared : undefined;
    this.serverRevocationConfirmed = typeof body.serverRevocationConfirmed === 'boolean' ? body.serverRevocationConfirmed : undefined;
    this.issues = Array.isArray(body.issues) ? body.issues : [];
  }
}
let csrfToken = '';
export function setCsrfToken(token: string) { csrfToken = token; }
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method || 'GET';
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (method !== 'GET' && method !== 'HEAD') headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path.startsWith('/authn/') ? path : `/api/v1${path}`, { ...options, method, headers, credentials: 'same-origin' });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401 && path !== '/me') window.dispatchEvent(new Event('gc:session-expired'));
    throw new ApiError(response.status, body);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}
function sessionVersion(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > 2_147_483_647) throw new ApiError(400, { code: 'AUTHN_REQUEST_INVALID' });
  return value;
}
export async function switchProtectedTenant(tenantId: string, expectedSessionVersion: number): Promise<void> {
  await api('/authn/tenant', { method: 'POST', body: JSON.stringify({ tenantId, expectedSessionVersion: sessionVersion(expectedSessionVersion) }) });
}
export async function revokeProtectedSession(expectedSessionVersion: number): Promise<void> {
  try {
    const result = await api<{loggedOut?: boolean; browserCredentialsCleared?: boolean; serverRevocationConfirmed?: boolean}>(
      '/authn/logout', { method: 'POST', body: JSON.stringify({ expectedSessionVersion: sessionVersion(expectedSessionVersion) }) });
    if (!result || result.loggedOut !== true || result.browserCredentialsCleared !== true || result.serverRevocationConfirmed !== true)
      throw new ApiError(503, { code: 'AUTHN_UNAVAILABLE' });
  } finally { setCsrfToken(''); }
}
export function useResource<T>(path: string | null, interval = 0) {
  const [state, setState] = useState<{ data: T | null; error: Error | null; loading: boolean }>({ data: null, error: null, loading: !!path });
  const [revision, setRevision] = useState(0);
  const lastPath = useRef(path);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    if (!path) { setState({ data: null, error: null, loading: false }); return; }
    const controller = new AbortController();
    let disposed = false;
    const changed = lastPath.current !== path;
    lastPath.current = path;
    setState(previous => ({ data: changed ? null : previous.data, error: null, loading: true }));
    api<T>(path, { signal: controller.signal })
      .then(data => { if (!disposed) setState({ data, error: null, loading: false }); })
      .catch(error => { if (!disposed && error.name !== 'AbortError') setState(previous => ({ ...previous, error, loading: false })); });
    return () => { disposed = true; controller.abort(); };
  }, [path, revision]);
  useEffect(() => {
    if (!interval || !path) return;
    const timer = window.setInterval(reload, interval);
    return () => window.clearInterval(timer);
  }, [interval, path, reload]);
  return { ...state, reload };
}
