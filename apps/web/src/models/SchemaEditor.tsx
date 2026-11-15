// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import { Plus, Trash } from '@phosphor-icons/react';
import { MODEL_LIMITS, URI_SCHEMES } from '../../../../packages/domain/src/model';
import type { AttributeDefinition, AttributeSchema } from './contracts';
import { useLocale, type MessageKey } from '../i18n';

const types: AttributeSchema['type'][] = ['text', 'richText', 'number', 'decimal', 'boolean', 'date', 'timestamp', 'duration', 'enum', 'list', 'uri', 'object'];
export function emptySchema(type: AttributeSchema['type']): AttributeSchema {
  if (type === 'list') return { type, items: { type: 'text' } };
  if (type === 'object') return { type, properties: {} };
  if (type === 'enum') return { type, values: [] };
  return { type } as AttributeSchema;
}
export function FieldEditor({ fields, onChange, depth = 1 }: { fields: Readonly<Record<string, AttributeDefinition>>; onChange: (fields: Record<string, AttributeDefinition>) => void; depth?: number }) {
  const { t } = useLocale();
  function add() {
    let index = 1;
    while (Object.hasOwn(fields, `field_${index}`)) index++;
    onChange({ ...fields, [`field_${index}`]: { type: 'text' } });
  }
  return <div className="model-fields">{Object.entries(fields).map(([key, definition]) => <FieldRow key={key} name={key} definition={definition} depth={depth} onChange={value => onChange({ ...fields, [key]: value })} onRemove={() => onChange(Object.fromEntries(Object.entries(fields).filter(([name]) => name !== key)))} onRename={name => {
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name) || ['__proto__', 'prototype', 'constructor'].includes(name) || name !== key && Object.hasOwn(fields, name)) return false;
    onChange(Object.fromEntries(Object.entries(fields).map(([existing, value]) => [existing === key ? name : existing, value])));
    return true;
  }}/>) }<button type="button" className="button secondary" onClick={add} disabled={Object.keys(fields).length >= MODEL_LIMITS.properties}><Plus size={16}/>{t('addField')}</button></div>;
}
function FieldRow({ name, definition, depth, onChange, onRemove, onRename }: { name: string; definition: AttributeDefinition; depth: number; onChange: (value: AttributeDefinition) => void; onRemove: () => void; onRename: (name: string) => boolean }) {
  const { t } = useLocale();
  const [draftName, setDraftName] = useState(name);
  const [nameError, setNameError] = useState(false);
  return <fieldset className="model-field" data-field-key={name}><legend className="mono">{name}</legend><div className="model-field-heading"><label className="form-field"><span>{t('fieldKey')}</span><input aria-label={`${t('fieldKey')} ${name}`} value={draftName} maxLength={64} aria-invalid={nameError || undefined} onChange={event => { setDraftName(event.target.value); setNameError(false); }} onBlur={() => { if (draftName !== name) setNameError(!onRename(draftName)); }}/></label><label className="form-field"><span>{t('fieldLabel')}</span><input aria-label={`${t('fieldLabel')} ${name}`} value={definition.label || ''} maxLength={256} onChange={event => onChange({ ...definition, label: event.target.value })}/></label><button type="button" className="icon-button" aria-label={`${t('removeField')} ${name}`} onClick={onRemove}><Trash size={18}/></button></div>{nameError && <p role="alert" className="field-error">{t('fieldKeyConflict')}</p>}<SchemaEditor schema={definition} onChange={value => onChange({ ...value, ...(definition.label !== undefined ? { label: definition.label } : {}), ...(definition.required !== undefined ? { required: definition.required } : {}) })} label={name} depth={depth}/><label className="checkbox-field"><input type="checkbox" checked={!!definition.required} onChange={event => onChange({ ...definition, required: event.target.checked })}/>{t('required')}</label></fieldset>;
}
function SchemaEditor({ schema, onChange, label, depth }: { schema: AttributeSchema; onChange: (schema: AttributeSchema) => void; label: string; depth: number }) {
  const { t } = useLocale();
  const record = schema as unknown as Record<string, unknown>;
  const set = (key: string, value: unknown) => {
    const entries = Object.entries(record).filter(([name]) => name !== key);
    onChange(Object.fromEntries(value === undefined ? entries : [...entries, [key, value]]) as unknown as AttributeSchema);
  };
  const numeric = (key: string, message: MessageKey, integer = false, exact = false) => <label className="form-field" key={key}><span>{t(message)}</span><input aria-label={`${t(message)} ${label}`} type={exact ? 'text' : 'number'} inputMode={exact ? 'decimal' : undefined} step={integer ? 1 : 'any'} value={String(record[key] ?? '')} onChange={event => set(key, event.target.value === '' ? undefined : exact ? event.target.value : Number(event.target.value))}/></label>;
  return <div className="schema-controls"><label className="form-field"><span>{t('fieldType')}</span><select aria-label={`${t('fieldType')} ${label}`} value={schema.type} onChange={event => onChange(emptySchema(event.target.value as AttributeSchema['type']))}>{types.filter(type => depth < MODEL_LIMITS.schemaDepth || !['list', 'object'].includes(type)).map(type => <option key={type} value={type}>{t(`type_${type}`)}</option>)}</select></label><div className="model-constraint-grid">
    {['text', 'richText'].includes(schema.type) && <>{numeric('minLength', 'minLength', true)}{numeric('maxLength', 'maxLength', true)}</>}
    {schema.type === 'uri' && numeric('maxLength', 'maxLength', true)}
    {schema.type === 'number' && <>{numeric('minimum', 'minimum')}{numeric('maximum', 'maximum')}<label className="checkbox-field"><input type="checkbox" checked={!!schema.integer} onChange={event => set('integer', event.target.checked)}/>{t('integer')}</label></>}
    {schema.type === 'decimal' && <>{numeric('precision', 'precision', true)}{numeric('scale', 'scale', true)}{numeric('minimum', 'minimum', false, true)}{numeric('maximum', 'maximum', false, true)}</>}
    {schema.type === 'list' && <>{numeric('minItems', 'minItems', true)}{numeric('maxItems', 'maxItems', true)}</>}
  </div>{schema.type === 'enum' && <label className="form-field"><span>{t('enumValues')}</span><textarea aria-label={`${t('enumValues')} ${label}`} rows={3} value={schema.values.join('\n')} onChange={event => set('values', event.target.value.split('\n'))}/></label>}
  {schema.type === 'uri' && <fieldset className="uri-schemes"><legend>{t('uriSchemes')}</legend>{URI_SCHEMES.map(scheme => <label className="checkbox-field" key={scheme}><input type="checkbox" checked={(schema.schemes || URI_SCHEMES).includes(scheme)} onChange={event => set('schemes', event.target.checked ? [...new Set([...(schema.schemes || URI_SCHEMES), scheme])] : (schema.schemes || URI_SCHEMES).filter(value => value !== scheme))}/>{scheme}</label>)}</fieldset>}
  {schema.type === 'list' && <fieldset className="nested-definition"><legend>{t('listItem')}</legend><SchemaEditor schema={schema.items} onChange={value => set('items', value)} label={`${label}[]`} depth={depth + 1}/></fieldset>}
  {schema.type === 'object' && <fieldset className="nested-definition"><legend>{t('nestedFields')}</legend><FieldEditor fields={schema.properties} onChange={value => set('properties', value)} depth={depth + 1}/></fieldset>}
  </div>;
}
