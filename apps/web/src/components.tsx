import { WarningCircle, ShieldCheck } from '@phosphor-icons/react';
import { EmptyState, Notice } from '../../../packages/ui/src';
import { ApiError } from './api';
import { useLocale } from './i18n';

export function RequestError({ error, retry, compact = false }: { error: Error; retry?: () => void; compact?: boolean }) {
  const { t, locale } = useLocale();
  const denied = error instanceof ApiError && error.status === 403;
  const missing = error instanceof ApiError && error.status === 404;
  const validation = error instanceof ApiError && error.code === 'VALIDATION_FAILED';
  const title = denied ? t('forbiddenTitle') : missing ? t('notFoundTitle') : t('errorTitle');
  const description = denied ? t('forbiddenBody') : missing ? t('notFoundBody') : validation ? t('validationFailedBody') : t('errorBody');
  if (compact) return <Notice tone="error"><strong>{title}</strong><p>{error instanceof ApiError && error.status < 500 && locale === 'en' ? error.message : description}</p>{error instanceof ApiError && error.correlationId && <p className="mono">{t('reference')}: {error.correlationId}</p>}{retry && !denied && <button type="button" className="button secondary" onClick={retry}>{t('retry')}</button>}</Notice>;
  return <div role="alert"><EmptyState icon={denied ? <ShieldCheck size={28}/> : <WarningCircle size={28}/>} title={title} description={description} action={retry && !denied && !missing ? <button type="button" className="button secondary" onClick={retry}>{t('retry')}</button> : undefined}/>{error instanceof ApiError && error.correlationId && <p className="error-reference">{t('reference')}: <code>{error.correlationId}</code></p>}</div>;
}
export function PermissionDenied() { return <RequestError error={new ApiError(403, {})}/>; }
