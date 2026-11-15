import { useRef, type FormEvent, type ReactNode } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { Check, CircleNotch, MagnifyingGlass, WarningCircle, X } from '@phosphor-icons/react';

export function BrandMark({ size = 28 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" fill="none"><path d="M5 8h10v10H5zM17 14h10v10H17z" stroke="currentColor" strokeWidth="2.4"/><path d="M15 13h5V8h7M5 24h7v-5" stroke="currentColor" strokeWidth="2.4"/></svg>;
}
export function EntityHeader({ eyebrow, title, description, actions, children }: { eyebrow?: ReactNode; title: ReactNode; description?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return <header className="entity-header"><div className="entity-header-top"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1 id="main-heading" tabIndex={-1}>{title}</h1>{description && <p className="page-description">{description}</p>}</div>{actions && <div className="header-actions">{actions}</div>}</div>{children}</header>;
}
export function SearchBar({ label, value, onChange, onSubmit, placeholder, className = '' }: { label: string; value: string; onChange: (value: string) => void; onSubmit?: (event: FormEvent<HTMLFormElement>) => void; placeholder?: string; className?: string }) {
  const input = <><MagnifyingGlass size={19} aria-hidden="true"/><input type="search" aria-label={label} placeholder={placeholder || label} value={value} onChange={event => onChange(event.target.value)} /></>;
  return onSubmit ? <form role="search" onSubmit={onSubmit} className={`search-field ${className}`}>{input}</form> : <div className={`search-field ${className}`}>{input}</div>;
}
export function DataGrid<T>({ data, columns, caption, empty }: { data: T[]; columns: ColumnDef<T, any>[]; caption: string; empty?: ReactNode }) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });
  if (!data.length && empty) return <>{empty}</>;
  return <div className="table-scroll" tabIndex={0} role="region" aria-label={caption}><table className="data-grid"><caption className="sr-only">{caption}</caption><thead>{table.getHeaderGroups().map(group => <tr key={group.id}>{group.headers.map(header => <th key={header.id} scope="col">{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead><tbody>{table.getRowModel().rows.map(row => <tr key={row.id}>{row.getVisibleCells().map(cell => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}</tbody></table></div>;
}
export function StatusBadge({ status, label }: { status: string; label: string }) {
  const known = ['succeeded', 'active', 'available', 'healthy', 'ready', 'verified'].includes(status) ? 'positive' : ['failed', 'rejected', 'blocked'].includes(status) ? 'negative' : ['queued', 'running', 'stale', 'partial', 'pending'].includes(status) ? 'attention' : 'neutral';
  return <span className={`status-badge ${known}`}><span className="status-dot" aria-hidden="true"/>{label}</span>;
}
export function SourceHealth({ status, label, collectedAt }: { status: string; label: string; collectedAt?: string }) { return <div className="source-health"><StatusBadge status={status} label={label}/>{collectedAt && <span className="text-muted">{collectedAt}</span>}</div>; }
export function JobProgress({ status, label }: { status: string; label: string }) {
  return <span className={`job-progress job-${status}`}>{status === 'running' || status === 'queued' ? <CircleNotch size={15} aria-hidden="true" className={status === 'running' ? 'spin' : ''}/> : status === 'succeeded' ? <Check size={15} aria-hidden="true"/> : status === 'failed' ? <WarningCircle size={15} aria-hidden="true"/> : null}{label}</span>;
}
export function EmptyState({ icon, title, description, action, compact = false }: { icon?: ReactNode; title: string; description?: string; action?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state ${compact ? 'compact' : ''}`}>{icon && <div className="empty-icon" aria-hidden="true">{icon}</div>}<h2>{title}</h2>{description && <p>{description}</p>}{action}</div>;
}
export function LoadingState({ label }: { label: string }) { return <div className="loading-state" role="status"><CircleNotch size={23} className="spin" aria-hidden="true"/><span>{label}</span></div>; }
export function Notice({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'success' | 'error' }) {
  return <div className={`notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>{tone === 'success' ? <Check size={19} aria-hidden="true"/> : tone === 'error' ? <WarningCircle size={19} aria-hidden="true"/> : null}<div>{children}</div></div>;
}
export function DetailDrawer({ open, onOpenChange, title, description, closeLabel, children, wide = false }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description: string; closeLabel: string; children: ReactNode; wide?: boolean }) {
  const returnFocus = useRef<HTMLElement | null>(null);
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className={`dialog-content ${wide ? 'wide' : ''}`} onOpenAutoFocus={() => { returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; }} onCloseAutoFocus={event => { if (returnFocus.current?.isConnected) { event.preventDefault(); returnFocus.current.focus(); } }}><div className="dialog-header"><div><Dialog.Title>{title}</Dialog.Title><Dialog.Description>{description}</Dialog.Description></div><Dialog.Close asChild><button className="icon-button" aria-label={closeLabel}><X size={20}/></button></Dialog.Close></div>{children}</Dialog.Content></Dialog.Portal></Dialog.Root>;
}
export function Timeline({ items, label }: { items: { id: string; title: ReactNode; meta: ReactNode; detail?: ReactNode }[]; label: string }) {
  return <ol className="timeline" aria-label={label}>{items.map(item => <li key={item.id}><span className="timeline-point" aria-hidden="true"/><div className="timeline-content"><div className="timeline-title">{item.title}</div><div className="timeline-meta">{item.meta}</div>{item.detail && <div className="timeline-detail">{item.detail}</div>}</div></li>)}</ol>;
}
export function EvidencePanel({ title, note, children }: { title: string; note?: string; children: ReactNode }) { return <section className="panel evidence-panel"><div className="panel-heading"><h2>{title}</h2></div><div className="panel-body">{children}{note && <p className="supporting-text">{note}</p>}</div></section>; }
export function FacetPanel({ label, options, value, onChange }: { label: string; options: { value: string; label: string; count?: number }[]; value: string; onChange: (value: string) => void }) {
  return <fieldset className="facet-panel"><legend>{label}</legend>{options.map(option => <label key={option.value} className={value === option.value ? 'selected' : ''}><input type="radio" name="facet-type" value={option.value} checked={value === option.value} onChange={() => onChange(option.value)}/><span>{option.label}</span>{option.count !== undefined && <span className="facet-count">{option.count}</span>}</label>)}</fieldset>;
}
export function DiffViewer({ value, label }: { value: unknown; label: string }) { return <pre className="code-block" tabIndex={0} aria-label={label}>{JSON.stringify(value, null, 2)}</pre>; }
