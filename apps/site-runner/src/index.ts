// SPDX-License-Identifier: Apache-2.0
import { NativeConnection, Worker } from '@temporalio/worker';
import { ApplicationFailure } from '@temporalio/activity';
const api = process.env.API_URL ?? 'http://api:4310';
const token = process.env.SITE_TOKEN;
const workerToken = process.env.WORKER_TOKEN;
const tenants = new Set((process.env.SITE_TENANTS ?? '').split(',').filter(Boolean));
if (!token || !workerToken || tenants.size === 0) throw new Error('Site scope and credentials are required');
async function apiRequest(tenantId: string, path: string, body: object): Promise<any> {
  const response = await fetch(`${api}${path}`, { method: 'POST', headers: { Authorization: `Bearer ${token}`,
    'X-Tenant-Id': tenantId, 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw ApplicationFailure.retryable(`API_${response.status}`, 'SITE_API_UNAVAILABLE');
  return response.json();
}
async function executeScan({ tenantId, jobId }: { tenantId: string; jobId: string }): Promise<{ status: string; assetCount?: number }> {
  if (!tenants.has(tenantId) || !/^[0-9a-f-]{36}$/i.test(jobId)) throw ApplicationFailure.nonRetryable('Site scope denied', 'SITE_SCOPE_DENIED');
  const { job, source } = await apiRequest(tenantId, `/internal/jobs/${jobId}/claim`, {});
  if (job.status === 'succeeded') return { status: 'succeeded', assetCount: job.assetCount };
  if (job.status === 'failed' || job.status === 'cancelled') return { status: job.status };
  const response = await fetch(`${process.env.PYTHON_WORKER_URL ?? 'http://python-worker:8080'}/scan`, {
    method: 'POST', headers: { Authorization: `Bearer ${workerToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenantId, source }), signal: AbortSignal.timeout(120000) });
  const payload = await response.json() as any;
  if (!response.ok) {
    const code = typeof payload.code === 'string' && /^[A-Z_]{1,64}$/.test(payload.code) ? payload.code : 'SOURCE_SCAN_FAILED';
    await apiRequest(tenantId, `/internal/jobs/${jobId}/fail`, { code });
    return { status: 'failed' };
  }
  // The payload is sent directly to the canonical API, never returned to the workflow history.
  const completed = await apiRequest(tenantId, `/internal/jobs/${jobId}/complete`, payload);
  return { status: completed.job.status, assetCount: completed.job.assetCount };
}
const connection = await NativeConnection.connect({ address: process.env.TEMPORAL_ADDRESS ?? 'temporal:7233' });
const worker = await Worker.create({ connection, namespace: process.env.TEMPORAL_NAMESPACE ?? 'default', taskQueue: 'gc-site',
  activities: { executeScan }, maxConcurrentActivityTaskExecutions: 1 });
process.once('SIGTERM', () => worker.shutdown()); process.once('SIGINT', () => worker.shutdown());
await worker.run(); await connection.close();
