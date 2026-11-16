// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { LoadingState, Notice } from '../../../../packages/ui/src';
import type { DomainTypePin, DomainTypeView, DomainView } from '../../../../packages/domain/src/business-domain-contracts';
import { api, ApiError, useResource } from '../api';
import { useLocale } from '../i18n';
import { Link } from '../navigation';
import { IssueList } from '../models/ModelFeedback';
import { CursorControls, useCursorPage } from '../relations/shared';
export { CompleteRows, CursorControls, downloadJson, useCursorPage } from '../relations/shared';
export const domainPath = (id: string) => `/domains/${encodeURIComponent(id)}`;
export const domainTypePath = (id: string) => `/domain-types/${encodeURIComponent(id)}`;
export function useDomainText() { const { locale } = useLocale(); return (en: string, ar: string) => locale === 'ar' ? ar : en; }
export function DomainError({ error, retry }: { error: Error; retry?: () => void }) {
  const d = useDomainText(); const code = error instanceof ApiError ? error.code || '' : '';
  const messages: Record<string, [string, string]> = {
    DOMAIN_SCOPE_UNAVAILABLE: ['The complete affected scope is unavailable. No partial preview or history can be shown.', 'النطاق المتأثر الكامل غير متاح. لا يمكن عرض معاينة أو سجل جزئي.'],
    FORBIDDEN: ['Your current permissions do not allow this action.', 'صلاحياتك الحالية لا تسمح بهذا الإجراء.'],
    DOMAIN_PAGE_STALE: ['This list changed. Restart from the first page.', 'تغيرت هذه القائمة. ابدأ من الصفحة الأولى.'],
    DOMAIN_PREVIEW_STALE: ['The reviewed scope changed. Refresh context and preview again before confirming.', 'تغير النطاق الذي تمت مراجعته. حدّث السياق وأعد المعاينة قبل التأكيد.'],
    VERSION_CONFLICT: ['The current version changed. Refresh context while keeping your draft, then review again.', 'تغير الإصدار الحالي. حدّث السياق مع الاحتفاظ بالمسودة ثم راجعها مجددًا.'],
    DOMAIN_RETRY: ['The operation rolled back. Wait five seconds, then retry this unchanged request.', 'تم التراجع عن العملية. انتظر خمس ثوانٍ ثم أعد المحاولة بالطلب نفسه.'],
    DOMAIN_STORAGE_INVALID: ['Stored evidence could not be verified. Contact a maintainer with the reference below.', 'تعذر التحقق من الأدلة المحفوظة. تواصل مع المسؤول باستخدام المرجع أدناه.'],
    DOMAIN_MIGRATION_REQUIRED: ['This change needs an explicit complete type migration.', 'يتطلب هذا التغيير ترحيلًا صريحًا وكاملًا للنوع.'],
    DOMAIN_PROFILE_LIMIT: ['The complete operation exceeds the supported profile. Nothing was changed.', 'تتجاوز العملية الكاملة الحدود المدعومة. لم يتغير شيء.'],
    DOMAIN_IN_USE: ['An active child or assigned asset prevents retirement.', 'يمنع نطاق فرعي نشط أو أصل مُعيّن عملية الإيقاف.'],
    DOMAIN_RETIRED: ['This domain is retired. Restore it before ordinary edits or assignment.', 'هذا النطاق موقوف. استعده قبل التعديل العادي أو التعيين.'],
    DOMAIN_HIERARCHY_CYCLE: ['The proposed parent would create a cycle or exceed the hierarchy limit.', 'قد ينشئ النطاق الأب المقترح دورة أو يتجاوز حد التسلسل الهرمي.'],
    DOMAIN_NO_CHANGE: ['This request makes no change.', 'لا يُحدث هذا الطلب أي تغيير.'],
    DOMAIN_JSON_INVALID: ['The JSON is invalid. Check duplicate keys, unknown fields and value types.', 'ملف JSON غير صالح. تحقق من المفاتيح المكررة والحقول غير المعروفة وأنواع القيم.'],
    DOMAIN_TYPE_EXISTS: ['This immutable type key is already in use.', 'مفتاح النوع الثابت هذا مستخدم بالفعل.'],
    DOMAIN_PREVIEW_REQUIRED: ['Generate a complete valid preview before confirming.', 'أنشئ معاينة كاملة وصالحة قبل التأكيد.'],
  };
  const missing = error instanceof ApiError && error.status === 404;
  const pair = messages[code];
  return <div className="domain-error"><Notice tone="error"><strong>{d('Unable to complete the request', 'تعذر إكمال الطلب')}</strong><p>{pair ? d(pair[0], pair[1]) : missing ? d('This resource is unavailable.', 'هذا المورد غير متاح.') : d('Check the request and your current permissions, then try again.', 'تحقق من الطلب وصلاحياتك الحالية ثم أعد المحاولة.')}</p>{code && <p><code>{code}</code></p>}{error instanceof ApiError && error.correlationId && <p className="mono break-all">{d('Reference', 'المرجع')}: {error.correlationId}</p>}</Notice>{error instanceof ApiError && error.issues.length > 0 && <IssueList issues={error.issues}/>} {retry && <button type="button" className="button secondary" onClick={retry}>{d('Refresh context', 'تحديث السياق')}</button>}</div>;
}
/** Exact unchanged requests retain a key after network/deadline failures. Draft or version changes rotate it. */
export function retryableDomainError(error: unknown) { return !(error instanceof ApiError) || error.status === 503; }
export function useDomainMutation() {
  const request = useRef<{ signature: string; key: string } | undefined>(undefined);
  return { reset: () => { request.current = undefined; }, send: async <T,>(path: string, method: string, body: unknown, version?: number): Promise<T> => {
    const signature = JSON.stringify([path, method, version, body]);
    if (request.current?.signature !== signature) request.current = { signature, key: crypto.randomUUID() };
    return api<T>(path, { method, body: JSON.stringify(body), headers: { 'Idempotency-Key': request.current.key, ...(version === undefined ? {} : { 'If-Match': String(version) }) } });
  } };
}
export function DomainSearch({ label, onSearch }: { label: string; onSearch: (q: string) => void }) {
  const d = useDomainText(), [draft, setDraft] = useState('');
  return <div className="model-search"><label className="form-field"><span>{label}</span><input type="search" value={draft} maxLength={200} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); onSearch(draft); } }}/></label><button type="button" className="button secondary" onClick={() => onSearch(draft)}>{d('Search', 'بحث')}</button></div>;
}
export function OwnerSelect({ value, onChange, label }: { value: string | null; onChange: (id: string | null) => void; label?: string }) {
  const d = useDomainText(), [q, setQ] = useState(''); const pager = useCursorPage<{ id: string; name: string }>(`/domains/owner-candidates?q=${encodeURIComponent(q)}`);
  return <fieldset className="connection-fields"><legend>{label || d('Owner', 'المالك')}</legend><p className="supporting-text">{d('Ownership records responsibility; it grants no access permissions.', 'تسجل الملكية المسؤولية ولا تمنح أي صلاحيات وصول.')}</p><DomainSearch label={d('Find an eligible owner', 'البحث عن مالك مؤهل')} onSearch={setQ}/>{pager.error ? <DomainError error={pager.error} retry={pager.restart}/> : <label className="form-field"><span>{label || d('Select owner', 'اختيار المالك')}</span><select value={value || ''} disabled={pager.loading} onChange={e => onChange(e.target.value || null)}><option value="">{d('Unassigned', 'غير مُعيّن')}</option>{value && !pager.items.some(item => item.id === value) && <option value={value}>{d('Current selection', 'الاختيار الحالي')} · {value}</option>}{pager.items.map(item => <option key={item.id} value={item.id}>{item.name} · {item.id}</option>)}</select></label>}<CursorControls pager={pager}/></fieldset>;
}
export function DomainSelect({ value, onChange, label, exclude }: { value: string | null; onChange: (value: DomainView | null) => void; label: string; exclude?: string }) {
  const d = useDomainText(), [q, setQ] = useState(''); const pager = useCursorPage<DomainView>(`/domains?status=active&q=${encodeURIComponent(q)}`);
  return <fieldset className="connection-fields"><legend>{label}</legend><DomainSearch label={d('Find a domain', 'البحث عن نطاق')} onSearch={setQ}/>{pager.error ? <DomainError error={pager.error} retry={pager.restart}/> : <label className="form-field"><span>{label}</span><select value={value || ''} disabled={pager.loading} onChange={e => onChange(pager.items.find(row => row.id === e.target.value) || null)}><option value="">{d('None / root', 'لا يوجد / الجذر')}</option>{value && !pager.items.some(row => row.id === value) && <option value={value}>{value}</option>}{pager.items.filter(row => row.id !== exclude).map(row => <option key={row.id} value={row.id}>{row.name} · {row.id}</option>)}</select></label>}<CursorControls pager={pager}/>{value && <DomainTrail id={value}/>}</fieldset>;
}
export function DomainTrail({ id }: { id: string }) {
  const d = useDomainText(); const [rows, setRows] = useState<DomainView[]>([]), [error, setError] = useState<Error | null>(null);
  useEffect(() => { const control = new AbortController(); setRows([]); setError(null); void (async () => { const found: DomainView[] = [], seen = new Set<string>(); let current: string | null = id; while (current) { if (seen.has(current) || found.length >= 32) throw new Error('Invalid hierarchy'); seen.add(current); const result: { domain: DomainView } = await api(domainPath(current), { signal: control.signal }); found.unshift(result.domain); current = result.domain.parentId; } if (!control.signal.aborted) setRows(found); })().catch(error => { if (!control.signal.aborted) setError(error); }); return () => control.abort(); }, [id]);
  return error ? <DomainError error={error}/> : <nav className="domain-breadcrumb" aria-label={d('Current domain hierarchy', 'التسلسل الهرمي الحالي للنطاق')}>{rows.map(row => <Link key={row.id} href={domainPath(row.id)} title={row.id}>{row.name}<small className="mono">{row.id}</small></Link>)}</nav>;
}
export function TypeSelect({ value, onChange, label }: { value: DomainTypePin | null; onChange: (pin: DomainTypePin | null) => void; label: string }) {
  const d = useDomainText(), [q, setQ] = useState(''); const pager = useCursorPage<{ typeId: string; key: string; label: string; currentVersion: number }>(`/domain-types?q=${encodeURIComponent(q)}`);
  const current = useResource<{ type: DomainTypeView }>(value ? `${domainTypePath(value.typeId)}/versions/${value.version}` : null);
  return <fieldset className="connection-fields"><legend>{label}</legend><DomainSearch label={d('Find a domain type', 'البحث عن نوع نطاق')} onSearch={setQ}/>{pager.error ? <DomainError error={pager.error} retry={pager.restart}/> : <label className="form-field"><span>{label}</span><select value={value?.typeId || ''} disabled={pager.loading} onChange={e => { const row = pager.items.find(row => row.typeId === e.target.value); onChange(row ? { typeId: row.typeId, version: row.currentVersion } : null); }}><option value="">{d('Choose an exact type', 'اختر نوعًا محددًا')}</option>{value && !pager.items.some(row => row.typeId === value.typeId) && <option value={value.typeId}>{value.typeId}</option>}{pager.items.map(row => <option key={row.typeId} value={row.typeId}>{row.label} · {row.key} · {row.typeId}</option>)}</select></label>}<CursorControls pager={pager}/>{value && <><label className="form-field"><span>{d('Pinned type version', 'إصدار النوع المثبّت')}</span><input type="number" min={1} max={current.data?.type.currentVersion} value={value.version} onChange={e => onChange({ ...value, version: Number(e.target.value) })}/></label>{current.error ? <DomainError error={current.error}/> : current.loading ? <LoadingState label={d('Loading policy', 'تحميل السياسة')}/> : <p className="supporting-text">{current.data?.type.definition.label} · {d('Exact immutable version; future publications do not move this pin.', 'إصدار ثابت محدد؛ لا تغيّر المنشورات اللاحقة هذا التثبيت.')}</p>}</>}</fieldset>;
}
export function Reason({ value, onChange }: { value: string; onChange: (value: string) => void }) { const d = useDomainText(), labelId = useId(); return <label className="form-field"><span id={labelId}>{d('Reason for change', 'سبب التغيير')}</span><textarea aria-labelledby={labelId} required maxLength={500} rows={2} value={value} onChange={e => onChange(e.target.value)}/></label>; }
export function JsonEvidence({ title, value }: { title: string; value: unknown }) { return <details className="domain-evidence"><summary>{title}</summary><pre className="code-block" dir="ltr" tabIndex={0}>{JSON.stringify(value, null, 2)}</pre></details>; }
export function Panel({ title, children }: { title: string; children: ReactNode }) { return <section className="panel"><div className="panel-heading"><h2>{title}</h2></div><div className="panel-body stacked-form">{children}</div></section>; }
