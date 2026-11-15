// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, Plus, Trash } from '@phosphor-icons/react';
import { MIGRATION_LIMITS, type MigrationAcknowledgement, type MigrationOperation, type MigrationPath, type MigrationPlan } from '../../../../packages/domain/src/model-migration';
import type { AttributeSchema, AttributeValue, ModelChange, ModelDefinition } from '../../../../packages/domain/src/model';
import { useLocale, type MessageKey } from '../i18n';
import { ValueFields, serializeAttributes, valueDraft } from './ValueFields';

const operationLabels = { rename: 'planRename', remove: 'planRemove', set: 'planSet', enumMap: 'planEnumMap', convert: 'planConvert' } as const;
const operationHints = { rename: 'planRenameHint', remove: 'planRemoveHint', set: 'planSetHint', enumMap: 'planEnumMapHint', convert: 'planConvertHint' } as const;
const safeName = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'constructor', 'prototype']);
function validPath(path: MigrationPath): boolean {
  return path.length > 0 && path.length <= MIGRATION_LIMITS.pathSegments && path.every(part => safeName.test(part) && !reserved.has(part));
}
function destination(model: ModelDefinition, path: MigrationPath): AttributeSchema | undefined {
  if (!validPath(path)) return undefined;
  let fields = model.attributes;
  let schema: AttributeSchema | undefined;
  for (let index = 0; index < path.length; index++) {
    const name = path[index]!;
    if (!Object.hasOwn(fields, name)) return undefined;
    schema = fields[name];
    if (!schema) return undefined;
    if (index < path.length - 1) {
      if (schema.type !== 'object') return undefined;
      fields = schema.properties;
    }
  }
  return schema;
}
function initialLiteral(schema?: AttributeSchema): AttributeValue {
  return schema?.type === 'boolean' ? false : schema?.type === 'object' ? {} : schema?.type === 'list' ? [] : '';
}
function newOperation(op: MigrationOperation['op']): MigrationOperation {
  if (op === 'rename') return { op, from: [], to: [], onMissing: 'error' };
  if (op === 'remove') return { op, path: [], onMissing: 'error' };
  if (op === 'set') return { op, path: [], value: '', mode: 'ifMissing' };
  if (op === 'enumMap') return { op, path: [], mappings: [], onMissing: 'error', onUnmapped: 'error' };
  return { op, path: [], conversion: 'safeIntegerToDecimal', onMissing: 'error' };
}
const acknowledgementKey = (value: { code: string; path: string }) => JSON.stringify([value.code, value.path]);
function isDestructive(change: ModelChange): change is ModelChange & MigrationAcknowledgement {
  return change.requiresMigration && ['attribute_removed', 'type_changed', 'constraints_changed'].includes(change.code);
}

export function MigrationPlanEditor({ plan, definition, destructiveChanges, onChange, disabled = false }: {
  plan: MigrationPlan; definition: ModelDefinition; destructiveChanges: readonly ModelChange[]; onChange: (plan: MigrationPlan) => void; disabled?: boolean;
}) {
  const { t, number } = useLocale();
  const [newType, setNewType] = useState<MigrationOperation['op']>('rename');
  const changes = destructiveChanges.filter(isDestructive);
  const expected = new Set(changes.map(acknowledgementKey));
  const acknowledged = new Set(plan.acknowledgedChanges.map(acknowledgementKey));
  const outdated = plan.acknowledgedChanges.filter(change => !expected.has(acknowledgementKey(change)));
  const update = (index: number, operation: MigrationOperation) => onChange({ ...plan, operations: plan.operations.map((previous, offset) => offset === index ? operation : previous) });
  const move = (index: number, direction: -1 | 1) => {
    const next = index + direction;
    if (next < 0 || next >= plan.operations.length) return;
    const operations = [...plan.operations];
    [operations[index], operations[next]] = [operations[next]!, operations[index]!];
    onChange({ ...plan, operations });
  };
  return <fieldset className="connection-fields migration-plan-editor" disabled={disabled}>
    <legend>{t('planEditor')}</legend>
    <section aria-label={t('planContext')}>
      <dl className="detail-list">
        <div><dt>{t('planModel')}</dt><dd className="break-all"><code>{plan.modelId}</code></dd></div>
        <div><dt>{t('planTarget')}</dt><dd>{number(plan.targetVersion)}</dd></div>
        <div><dt>{t('planSources')}</dt><dd>{plan.sourceVersions.length ? plan.sourceVersions.map(number).join(', ') : t('planNoSources')}</dd></div>
      </dl>
      <p className="supporting-text">{t('planContextHint')}</p>
    </section>
    <fieldset className="connection-fields"><legend>{t('planOperations')}</legend>
      <p className="supporting-text">{t('planPathHint')}</p>
      {plan.operations.length === 0 && <p className="supporting-text">{t('planNoOperations')}</p>}
      {plan.operations.map((operation, index) => <fieldset className="model-field stacked-form" key={index} data-operation-index={index}>
        <legend>{t('planOperation')} {number(index + 1)} · {t(operationLabels[operation.op])}</legend>
        <OperationFields operation={operation} index={index} definition={definition} onChange={next => update(index, next)}/>
        <div className="model-publication-actions">
          <button type="button" className="button secondary" disabled={index === 0} aria-label={`${t('planMoveUp')} ${t('planOperation')} ${number(index + 1)}`} onClick={() => move(index, -1)}><ArrowUp size={16}/>{t('planMoveUp')}</button>
          <button type="button" className="button secondary" disabled={index === plan.operations.length - 1} aria-label={`${t('planMoveDown')} ${t('planOperation')} ${number(index + 1)}`} onClick={() => move(index, 1)}><ArrowDown size={16}/>{t('planMoveDown')}</button>
          <button type="button" className="button secondary" aria-label={`${t('planRemoveOperation')} ${number(index + 1)}`} onClick={() => onChange({ ...plan, operations: plan.operations.filter((_, offset) => offset !== index) })}><Trash size={16}/>{t('planRemoveOperation')}</button>
        </div>
      </fieldset>)}
      <label className="form-field"><span>{t('planOperationType')}</span><select value={newType} onChange={event => setNewType(event.target.value as MigrationOperation['op'])}>{Object.entries(operationLabels).map(([op, key]) => <option value={op} key={op}>{t(key)}</option>)}</select></label>
      <button type="button" className="button secondary" disabled={plan.operations.length >= MIGRATION_LIMITS.operations} onClick={() => onChange({ ...plan, operations: [...plan.operations, newOperation(newType)] })}><Plus size={16}/>{t('planAddOperation')}</button>
      <p className="supporting-text">{t('planOperationLimit')}</p>
    </fieldset>
    <fieldset className="connection-fields"><legend>{t('planAcknowledgements')}</legend>
      <p className="supporting-text">{t('planAcknowledgementHint')}</p>
      {!changes.length && <p className="supporting-text">{t('planNoDestructiveChanges')}</p>}
      {changes.map(change => <label className="checkbox-field" key={acknowledgementKey(change)}>
        <input type="checkbox" checked={acknowledged.has(acknowledgementKey(change))} onChange={event => {
          const retained = plan.acknowledgedChanges.filter(previous => acknowledgementKey(previous) !== acknowledgementKey(change));
          onChange({ ...plan, acknowledgedChanges: event.target.checked ? [...retained, { code: change.code, path: change.path }] : retained });
        }}/>
        <span className="break-all">{t('planAcknowledge')} · {t(`change_${change.code}`)} <code>{change.code}</code> <code>{change.path}</code></span>
      </label>)}
      {outdated.length > 0 && <><p className="field-error">{t('planOutdatedAcknowledgements')}</p>{outdated.map(change => <div className="stacked-form" key={acknowledgementKey(change)}><code className="break-all">{change.code} {change.path}</code><button type="button" className="button secondary" aria-label={`${t('planRemoveAcknowledgement')} ${change.code} ${change.path}`} onClick={() => onChange({ ...plan, acknowledgedChanges: plan.acknowledgedChanges.filter(previous => acknowledgementKey(previous) !== acknowledgementKey(change)) })}>{t('planRemoveAcknowledgement')}</button></div>)}</>}
    </fieldset>
  </fieldset>;
}

function PathField({ label, path, onChange }: { label: string; path: MigrationPath; onChange: (path: MigrationPath) => void }) {
  const { t } = useLocale();
  const errorId = useId();
  const invalid = !validPath(path);
  return <div className="stacked-form"><label className="form-field"><span>{label}</span><input dir="ltr" value={path.join('/')} maxLength={MIGRATION_LIMITS.pathSegments * 65 - 1} aria-invalid={invalid || undefined} aria-describedby={invalid ? errorId : undefined} onChange={event => onChange(event.target.value === '' ? [] : event.target.value.split('/'))}/></label>{invalid && <p className="field-error" id={errorId}>{t('planPathInvalid')}</p>}</div>;
}

function OperationFields({ operation, index, definition, onChange }: { operation: MigrationOperation; index: number; definition: ModelDefinition; onChange: (operation: MigrationOperation) => void }) {
  const { t, number } = useLocale();
  const label = (key: MessageKey) => `${t(key)} · ${t('planOperation')} ${number(index + 1)}`;
  const schema = destination(definition, operation.op === 'rename' ? operation.to : operation.path);
  const targetOptions = schema?.type === 'enum' ? schema.values : undefined;
  const conversionMismatch = operation.op === 'convert' && schema && schema.type !== (operation.conversion === 'decimalToText' ? 'text' : 'decimal');
  return <>
    <p className="supporting-text">{t(operationHints[operation.op])}</p>
    {operation.op === 'rename' ? <div className="model-constraint-grid">
      <PathField label={label('planFromPath')} path={operation.from} onChange={from => onChange({ ...operation, from })}/>
      <PathField label={label('planToPath')} path={operation.to} onChange={to => onChange({ ...operation, to })}/>
    </div> : <PathField label={label('planPath')} path={operation.path} onChange={path => onChange(operation.op === 'set' ? { ...operation, path, value: initialLiteral(destination(definition, path)) } : { ...operation, path })}/>}
    {operation.op !== 'remove' && !schema && <p className="field-error">{t('planDestinationMissing')}</p>}
    {operation.op !== 'set' && <label className="form-field"><span>{label('planMissing')}</span><select value={operation.onMissing} onChange={event => onChange({ ...operation, onMissing: event.target.value as 'error' | 'skip' })}><option value="error">{t('planMissingError')}</option><option value="skip">{t('planMissingSkip')}</option></select></label>}
    {operation.op === 'set' && <>
      <label className="form-field"><span>{label('planSetMode')}</span><select value={operation.mode} onChange={event => onChange({ ...operation, mode: event.target.value as 'ifMissing' | 'replace' })}><option value="ifMissing">{t('planIfMissing')}</option><option value="replace">{t('planReplace')}</option></select></label>
      {schema && <LiteralEditor key={operation.path.join('/')} schema={schema} value={operation.value} label={label('planLiteral')} onChange={value => onChange({ ...operation, value })}/>}
    </>}
    {operation.op === 'enumMap' && <>
      {schema && !targetOptions && <p className="field-error">{t('planEnumDestination')}</p>}
      <fieldset className="connection-fields"><legend>{label('planMappings')}</legend>
        {!operation.mappings.length && <p className="supporting-text">{t('planMappingsEmpty')}</p>}
        {operation.mappings.map((mapping, mappingIndex) => <fieldset className="connection-fields" key={mappingIndex}>
          <legend>{t('planMapping')} {number(mappingIndex + 1)}</legend>
          <div className="model-constraint-grid">
            <label className="form-field"><span>{t('planMappingFrom')}</span><input aria-label={`${label('planMappingFrom')} · ${number(mappingIndex + 1)}`} value={mapping.from} maxLength={1024} onChange={event => onChange({ ...operation, mappings: operation.mappings.map((previous, offset) => offset === mappingIndex ? { ...previous, from: event.target.value } : previous) })}/></label>
            <label className="form-field"><span>{t('planMappingTo')}</span><select aria-label={`${label('planMappingTo')} · ${number(mappingIndex + 1)}`} value={mapping.to} disabled={!targetOptions} aria-invalid={!!targetOptions && !targetOptions.includes(mapping.to) || undefined} onChange={event => onChange({ ...operation, mappings: operation.mappings.map((previous, offset) => offset === mappingIndex ? { ...previous, to: event.target.value } : previous) })}>
              {!targetOptions?.includes('') && <option value="" disabled>{t('planChooseTarget')}</option>}
              {mapping.to !== '' && !targetOptions?.includes(mapping.to) && <option value={mapping.to} disabled>{mapping.to}</option>}
              {targetOptions?.map(value => <option value={value} key={value}>{value === '' ? '""' : value}</option>)}
            </select></label>
          </div>
          <button type="button" className="text-button" aria-label={`${label('planRemoveMapping')} · ${number(mappingIndex + 1)}`} onClick={() => onChange({ ...operation, mappings: operation.mappings.filter((_, offset) => offset !== mappingIndex) })}>{t('planRemoveMapping')}</button>
        </fieldset>)}
        <button type="button" className="button secondary" disabled={operation.mappings.length >= MIGRATION_LIMITS.enumMappings} onClick={() => onChange({ ...operation, mappings: [...operation.mappings, { from: '', to: '' }] })}><Plus size={16}/>{t('planAddMapping')}</button>
      </fieldset>
      <label className="form-field"><span>{label('planUnmapped')}</span><select value={operation.onUnmapped} onChange={event => onChange({ ...operation, onUnmapped: event.target.value as 'error' | 'keep' })}><option value="error">{t('planUnmappedError')}</option><option value="keep">{t('planUnmappedKeep')}</option></select></label>
    </>}
    {operation.op === 'convert' && <><label className="form-field"><span>{label('planConversion')}</span><select value={operation.conversion} aria-invalid={!!conversionMismatch || undefined} onChange={event => onChange({ ...operation, conversion: event.target.value as typeof operation.conversion })}><option value="safeIntegerToDecimal">{t('planIntegerDecimal')}</option><option value="decimalToText">{t('planDecimalText')}</option><option value="textToDecimal">{t('planTextDecimal')}</option></select></label>{conversionMismatch && <p className="field-error">{t('planConversionMismatch')}</p>}</>}
  </>;
}

function LiteralEditor({ schema, value, label, onChange }: { schema: AttributeSchema; value: AttributeValue; label: string; onChange: (value: AttributeValue) => void }) {
  const [draft, setDraft] = useState(() => ({ literal: valueDraft(schema, value) }));
  const schemaKey = JSON.stringify(schema);
  const previous = useRef({ schemaKey, valueKey: JSON.stringify(value) });
  useEffect(() => {
    const valueKey = JSON.stringify(value);
    if (previous.current.schemaKey !== schemaKey || previous.current.valueKey !== valueKey) {
      setDraft({ literal: valueDraft(schema, value) });
      previous.current = { schemaKey, valueKey };
    }
  }, [schema, schemaKey, value]);
  const fields = { literal: { ...schema, required: true, label } };
  return <ValueFields fields={fields} values={draft} onChange={values => {
    const next = { literal: values.literal };
    setDraft(next);
    // Required literals cannot be omitted. Keep incomplete scalar drafts as strings
    // so the shared server validator reports them instead of silently coercing them.
    const serialized = serializeAttributes(fields, next).literal ?? '';
    previous.current = { schemaKey, valueKey: JSON.stringify(serialized) };
    onChange(serialized as AttributeValue);
  }}/>;
}
