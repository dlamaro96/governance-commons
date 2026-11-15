// SPDX-License-Identifier: Apache-2.0
import { ApiError } from '../api';
import { RequestError } from '../components';
import { useLocale } from '../i18n';
export function ModelError({ error }: { error: Error }) {
  const { t } = useLocale();
  return <div className="model-error"><RequestError error={error} compact/>{error instanceof ApiError && error.issues.length > 0 && <div role="alert" className="validation-issues"><h3>{t('invalidFields')}</h3><ul>{error.issues.map((issue, index) => <li key={index}><code>{issue.path || '/'}</code><span lang="en">{issue.message}</span></li>)}</ul></div>}</div>;
}
export function IssueList({ issues }: { issues: readonly { code: string; path: string; message: string }[] }) {
  return <ul className="preview-issues">{issues.map((issue, index) => <li key={index}><code>{issue.path || '/'}</code><span lang="en">{issue.message}</span></li>)}</ul>;
}
