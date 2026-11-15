// SPDX-License-Identifier: Apache-2.0
import { ApiError } from '../api';
import { Notice } from '../../../../packages/ui/src';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
const localizedTypeErrors = { ASSET_TYPE_MIGRATION_INVALID: 'typeMigrationInvalid', ASSET_TYPE_MIGRATION_PREVIEW_STALE: 'typeMigrationStale', ASSET_TYPE_MIGRATION_RETRY: 'typeMigrationRetryable', ASSET_TYPE_MIGRATION_NOT_FOUND: 'typeMigrationReceiptUnavailable', ASSET_TYPE_MIGRATION_LIMIT: 'typeMigrationLimit', ASSET_TYPE_MIGRATION_STORAGE_INVALID: 'typeMigrationStorageInvalid', ASSET_TYPE_OWNER_REQUIRED: 'typeOwnerRequired', ASSET_TYPE_TRANSITION_INVALID: 'typeTransitionInvalid', ASSET_TYPE_STATE_INVALID: 'typeStateInvalid', ASSET_TYPE_PARENT_UNAVAILABLE: 'typeParentUnavailable', ASSET_TYPE_PREVIEW_STALE: 'typeStale', ASSET_TYPE_MIGRATION_REQUIRED: 'typeMigrationBlocked' } as const;
export function ModelError({ error }: { error: Error }) {
  const { t } = useLocale();
  const known = error instanceof ApiError ? localizedTypeErrors[error.code as keyof typeof localizedTypeErrors] : undefined;
  return <div className="model-error">{known ? <Notice tone="error"><strong>{t('errorTitle')}</strong><p>{t(known)}</p>{error instanceof ApiError && error.correlationId && <p className="mono">{t('reference')}: {error.correlationId}</p>}</Notice> : <RequestError error={error} compact/>}{error instanceof ApiError && error.issues.length > 0 && <div role="alert" className="validation-issues"><h3>{t('invalidFields')}</h3><ul>{error.issues.map((issue, index) => <li key={index}><code>{issue.path || '/'}</code><span lang="en">{issue.message}</span></li>)}</ul></div>}</div>;
}
export function IssueList({ issues }: { issues: readonly { code: string; path: string; message: string }[] }) {
  return <ul className="preview-issues">{issues.map((issue, index) => <li key={index}><code>{issue.path || '/'}</code><span lang="en">{issue.message}</span></li>)}</ul>;
}
