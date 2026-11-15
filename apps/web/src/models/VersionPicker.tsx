// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { useLocale } from '../i18n';
export function VersionPicker({ value, maximum, onChange, label, disabled = false }: { value: number; maximum: number; onChange: (version: number) => void; label: string; disabled?: boolean }) {
  const { t, number } = useLocale();
  const [draft, setDraft] = useState(String(value));
  const [invalid, setInvalid] = useState(false);
  useEffect(() => { setDraft(String(value)); setInvalid(false); }, [value]);
  if (maximum <= 100) return <label className="form-field"><span>{label}</span><select value={value} disabled={disabled} onChange={event => onChange(Number(event.target.value))}>{Array.from({ length: Math.max(maximum, 1) }, (_, index) => <option key={index} value={index + 1}>{number(index + 1)}</option>)}</select></label>;
  function select() {
    const next = Number(draft);
    if (!Number.isSafeInteger(next) || next < 1 || next > maximum) { setInvalid(true); return; }
    setInvalid(false); onChange(next);
  }
  return <div className="version-picker"><label className="form-field"><span>{label}</span><input type="number" min={1} max={maximum} step={1} value={draft} disabled={disabled} aria-invalid={invalid || undefined} onChange={event => { setDraft(event.target.value); setInvalid(false); }}/></label><button type="button" className="button secondary" disabled={disabled} onClick={select}>{t('viewVersion')}</button>{invalid && <p role="alert" className="field-error">{t('modelVersionUnavailable')}</p>}</div>;
}
