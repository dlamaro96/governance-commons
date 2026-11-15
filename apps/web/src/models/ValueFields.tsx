// SPDX-License-Identifier: Apache-2.0
import { Fragment } from 'react';
import { Plus, Trash } from '@phosphor-icons/react';
import { MODEL_LIMITS } from '../../../../packages/domain/src/model';
import type { AttributeDefinition, AttributeSchema } from './contracts';
import { useLocale } from '../i18n';

export function valueDraft(schema: AttributeSchema, value: unknown): unknown {
  if (value === undefined) return undefined;
  if (schema.type === 'number') return String(value);
  if (schema.type === 'list' && Array.isArray(value)) return value.map(item => valueDraft(schema.items, item));
  if (schema.type === 'object') return draftAttributes(schema.properties, object(value));
  return value;
}
function object(value: unknown): Record<string, unknown> { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
export function draftAttributes(fields: Readonly<Record<string, AttributeDefinition>>, values: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(fields).filter(([key]) => values[key] !== undefined).map(([key, schema]) => [key, valueDraft(schema, values[key])]));
}
function serializeValue(schema: AttributeSchema, value: unknown): unknown {
  if (schema.type === 'number' && typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : value;
  }
  if (schema.type === 'list' && Array.isArray(value)) return value.map(item => serializeValue(schema.items, item));
  if (schema.type === 'object') return serializeAttributes(schema.properties, object(value));
  return value;
}
export function serializeAttributes(fields: Readonly<Record<string, AttributeDefinition>>, values: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== undefined).map(([key, value]) => [key, fields[key] ? serializeValue(fields[key], value) : value]));
}
function initial(schema: AttributeSchema): unknown { return schema.type === 'object' ? {} : schema.type === 'list' ? [] : schema.type === 'boolean' ? false : ''; }
export function ValueFields({ fields, values, onChange, prefix = '' }: { fields: Readonly<Record<string, AttributeDefinition>>; values: Record<string, unknown>; onChange: (values: Record<string, unknown>) => void; prefix?: string }) {
  return <div className="value-fields">{Object.entries(fields).map(([key, schema]) => <ValueField key={key} schema={schema} value={values[key]} label={schema.label || key} path={prefix ? `${prefix}.${key}` : key} required={!!schema.required} onChange={value => onChange(value === undefined ? Object.fromEntries(Object.entries(values).filter(([name]) => name !== key)) : { ...values, [key]: value })}/>)}</div>;
}
function ValueField({ schema, value, label, path, required = true, onChange }: { schema: AttributeSchema; value: unknown; label: string; path: string; required?: boolean; onChange: (value: unknown) => void }) {
  const { t } = useLocale();
  const accessibleName = label === path ? label : `${label} (${path})`;
  const scalar = !['object', 'list'].includes(schema.type);
  return <div className="typed-field" data-attribute-path={path}><div className="typed-field-heading"><span className="typed-label">{label}{required && <span className="required-marker"> · {t('required')}</span>}<code>{path}</code></span><span className="type-caption">{t(`type_${schema.type}`)}</span></div>{value === undefined && (!required || schema.type === 'object' || schema.type === 'list') ? <div className="unset-field"><span>{t('notSet')}</span><button type="button" className="text-button" aria-label={`${t('setValue')} ${accessibleName}`} onClick={() => onChange(initial(schema))}>{t('setValue')}</button></div> : <>
    {schema.type === 'boolean' ? <select aria-required={required} aria-label={accessibleName} value={value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value === '' ? undefined : event.target.value === 'true')}><option value="">{t('selectValue')}</option><option value="true">{t('yes')}</option><option value="false">{t('no')}</option></select>
    : schema.type === 'enum' ? <select aria-required={required} aria-label={accessibleName} value={String(value ?? '')} onChange={event => onChange(event.target.value)}><option value="" disabled={!schema.values.includes('')}>{t('selectValue')}</option>{schema.values.map(item => <option key={item} value={item}>{item}</option>)}</select>
    : schema.type === 'object' ? <ValueFields fields={schema.properties} values={object(value)} prefix={path} onChange={onChange}/>
    : schema.type === 'list' ? <div className="typed-list">{(Array.isArray(value) ? value : []).map((item, index) => <div className="typed-list-item" key={index}><ValueField schema={schema.items} value={item} label={`${label} ${index + 1}`} path={`${path}[${index}]`} onChange={next => onChange((value as unknown[]).map((previous, offset) => index === offset ? next : previous))}/><button type="button" className="icon-button" aria-label={`${t('removeItem')} ${path}[${index}]`} onClick={() => onChange((value as unknown[]).filter((_, offset) => offset !== index))}><Trash size={17}/></button></div>)}{(!Array.isArray(value) || !value.length) && <p className="supporting-text">{t('listEmpty')}</p>}<button type="button" className="button secondary" aria-label={`${t('addItem')} ${path}`} disabled={Array.isArray(value) && value.length >= Math.min(schema.maxItems ?? MODEL_LIMITS.listItems, MODEL_LIMITS.listItems)} onClick={() => onChange([...(Array.isArray(value) ? value : []), initial(schema.items)])}><Plus size={16}/>{t('addItem')}</button></div>
    : schema.type === 'richText' ? <textarea aria-required={required} aria-label={accessibleName} rows={4} value={String(value ?? '')} maxLength={schema.maxLength ?? MODEL_LIMITS.stringLength} onChange={event => onChange(event.target.value)}/>
    : <input aria-required={required} aria-label={accessibleName} type={schema.type === 'number' ? 'number' : schema.type === 'date' ? 'date' : 'text'} step={schema.type === 'number' && schema.integer ? 1 : 'any'} inputMode={schema.type === 'decimal' ? 'decimal' : undefined} value={String(value ?? '')} maxLength={MODEL_LIMITS.stringLength} onChange={event => onChange(event.target.value)}/>}
    {scalar && ['decimal', 'timestamp', 'duration', 'richText'].includes(schema.type) && <p className="supporting-text">{t(schema.type === 'richText' ? 'markdownHint' : schema.type === 'decimal' ? 'decimalHint' : schema.type === 'timestamp' ? 'timestampHint' : 'durationHint')}</p>}
    {!required && <button type="button" className="text-button unset-action" aria-label={`${t('unsetValue')} ${accessibleName}`} onClick={() => onChange(undefined)}>{t('unsetValue')}</button>}
  </>}</div>;
}
export function AttributeReadout({ fields, values }: { fields: Readonly<Record<string, AttributeDefinition>>; values: Record<string, unknown> }) {
  const { t } = useLocale();
  return <dl className="attribute-readout">{Object.entries(fields).map(([key, schema]) => <Fragment key={key}><dt>{schema.label || key}<code>{key}</code></dt><dd>{values[key] === undefined ? <span className="text-muted">{t('notSet')}</span> : schema.type === 'boolean' ? (values[key] ? t('yes') : t('no')) : typeof values[key] === 'object' ? <pre className="code-block" tabIndex={0}>{JSON.stringify(values[key], null, 2)}</pre> : <span className={schema.type === 'richText' ? 'description-text' : 'break-all'}>{String(values[key])}</span>}</dd></Fragment>)}</dl>;
}
