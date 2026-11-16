// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { Client, Connection, WorkflowNotFoundError, type WorkflowHandle } from '@temporalio/client';
import { lockTenantLedger, scope, sql } from '../../packages/db/src/index.ts';

type Options = { tenantId: string; sourceId: string; actorId: string; fetch: typeof globalThis.fetch };
type Reservation = { jobId: string; workflowId: string; queue: string; marker: string; runId?: string };
const terminal = new Set(['succeeded', 'failed', 'cancelled']);

/**
 * Controlled worker-input tests use the real completion/failure handlers and DB.
 * They do not verify connector execution: separate source/browser tests do that.
 * Reserve the production ID on an unconsumed queue BEFORE publishing the job,
 * so the live dispatcher cannot race these deliberately supplied observations.
 * A hard-killed runner may leave an open reservation; recovery must terminalize
 * its job before terminating its exact run. Reservations expire after 30 minutes.
 */
export async function createManualScanFixture(t: TestContext, options: Options): Promise<{ job(): Promise<string> }> {
  const token = process.env.SITE_TOKEN;
  assert.ok(token, 'Manual scan fixtures require the real internal-site credential.');
  const base = process.env.TEST_BASE_URL ?? 'http://api:4310';
  const connection = await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? 'temporal:7233', connectTimeout: '10 seconds' });
  const client = new Client({ connection, namespace: process.env.TEMPORAL_NAMESPACE ?? 'default' });
  const reservations: Reservation[] = [];
  const rpc = <T>(fn: () => Promise<T>) => connection.withDeadline(Date.now() + 10_000, fn);
  const recovery = (r: Reservation, code: string, cause?: unknown) => new Error(`${code}: job=${r.jobId} workflow=${r.workflowId} run=${r.runId ?? 'unconfirmed'} queue=${r.queue}`, { cause });

  async function ownedHandle(r: Reservation): Promise<WorkflowHandle | null> {
    let current;
    try { current = await rpc(() => client.workflow.getHandle(r.workflowId).describe()); }
    catch (error) {
      if (!r.runId && error instanceof WorkflowNotFoundError) return null;
      throw recovery(r, 'MANUAL_SCAN_RESERVATION_LOOKUP_FAILED', error);
    }
    assert.equal(current.workflowId, r.workflowId);
    assert.equal(current.taskQueue, r.queue, 'Reservation task queue changed.');
    assert.equal(current.memo?.manualScanFixture, r.marker, 'Reservation ownership marker changed.');
    if (r.runId) assert.equal(current.runId, r.runId, 'Reservation is no longer the current run.');
    else r.runId = current.runId; // Resolve an ambiguous start RPC using our unique marker.
    const handle = client.workflow.getHandle(r.workflowId, r.runId);
    const exact = await rpc(() => handle.describe());
    assert.equal(exact.runId, r.runId);
    assert.equal(exact.taskQueue, r.queue);
    assert.equal(exact.memo?.manualScanFixture, r.marker);
    return handle;
  }

  async function assertUnexecuted(handle: WorkflowHandle, terminated = false): Promise<void> {
    const history = await rpc(() => handle.fetchHistory());
    assert.ok(history.events?.some(event => event.workflowExecutionStartedEventAttributes), 'Reservation must have real Temporal history.');
    // Reject even a workflow-task start, including failed/retried execution;
    // absence of completed activities alone would not prove isolation.
    assert.ok(history.events?.every(event => event.workflowExecutionStartedEventAttributes || event.workflowTaskScheduledEventAttributes ||
      (terminated && event.workflowExecutionTerminatedEventAttributes)), 'The reserved workflow must never execute a workflow task.');
  }

  async function jobStatus(r: Reservation): Promise<string | undefined> {
    return scope(options.tenantId, options.actorId, async tx => {
      await sql`select set_config('statement_timeout','10000',true), set_config('lock_timeout','10000',true)`.execute(tx);
      const job = await tx.selectFrom('jobs').select(['status', 'source_id', 'actor_id']).where('id', '=', r.jobId).executeTakeFirst();
      if (!job) return undefined;
      assert.equal(job.source_id, options.sourceId); assert.equal(job.actor_id, options.actorId);
      return job.status as string;
    });
  }

  t.after(async () => {
    const failures: Error[] = [];
    try {
      for (const r of [...reservations].reverse()) {
        // Fail closed: no Temporal release until the actual DB says terminal
        // (or confirms insertion never committed). Never rely on the HTTP body.
        try {
          const status = await jobStatus(r);
          if (status !== undefined && !terminal.has(status)) {
            const result: Response = await options.fetch(`${base}/internal/jobs/${r.jobId}/fail`, { method: 'POST',
              headers: { Authorization: `Bearer ${token}`, 'X-Tenant-Id': options.tenantId, 'Content-Type': 'application/json' },
              body: JSON.stringify({ code: 'SYNTHETIC_MANUAL_SCAN_CLEANUP' }), signal: AbortSignal.timeout(10_000) });
            await result.body?.cancel();
            assert.equal(result.status, 200, 'Manual fixture cleanup must use the real failure handler.');
          }
          const confirmed = await jobStatus(r);
          assert.ok(confirmed === undefined || terminal.has(confirmed), 'Manual job remains runnable.');
        } catch (error) {
          failures.push(recovery(r, 'MANUAL_SCAN_JOB_NOT_PROVEN_TERMINAL_RESERVATION_RETAINED', error)); continue;
        }
        try {
          const handle = await ownedHandle(r);
          if (!handle) continue; // Failed start and no committed job.
          const state = await rpc(() => handle.describe());
          try { assert.equal(state.status.name, 'RUNNING'); await assertUnexecuted(handle); }
          catch (error) { failures.push(recovery(r, 'MANUAL_SCAN_RESERVATION_ISOLATION_FAILED', error)); }
          if (state.status.name === 'RUNNING') {
            await rpc(() => handle.terminate('Controlled handler fixture finished; database job is terminal.'));
            assert.equal((await rpc(() => handle.describe())).status.name, 'TERMINATED');
            await assertUnexecuted(handle, true);
          }
        } catch (error) { failures.push(recovery(r, 'MANUAL_SCAN_RESERVATION_CLEANUP_FAILED', error)); }
      }
    } finally {
      try { await connection.close(); }
      catch (error) { failures.push(new Error('MANUAL_SCAN_TEMPORAL_CONNECTION_CLOSE_FAILED', { cause: error })); }
    }
    // Hook failures remain visible alongside, rather than replacing or swallowing,
    // any original test assertion failure.
    if (failures.length) throw new AggregateError(failures, 'Manual scan fixture cleanup or isolation failed.');
  });

  return { async job() {
    const jobId = randomUUID(), marker = randomUUID();
    const r: Reservation = { jobId, workflowId: `scan:${options.tenantId}:${jobId}`, queue: `gc-manual-scan-${marker}`, marker };
    reservations.push(r);
    try {
      const started = await rpc(() => client.workflow.start('scanSourceWorkflow', { workflowId: r.workflowId, taskQueue: r.queue,
        args: [{ tenantId: options.tenantId, jobId }], workflowExecutionTimeout: '30 minutes',
        workflowIdReusePolicy: 'REJECT_DUPLICATE', workflowIdConflictPolicy: 'FAIL', memo: { manualScanFixture: marker } }));
      r.runId = started.firstExecutionRunId;
      const handle = await ownedHandle(r); assert.ok(handle);
      assert.equal((await rpc(() => handle.describe())).status.name, 'RUNNING');
      await assertUnexecuted(handle);
      await scope(options.tenantId, options.actorId, async tx => {
        await sql`select set_config('statement_timeout','10000',true), set_config('lock_timeout','10000',true)`.execute(tx);
        await lockTenantLedger(tx, options.tenantId);
        await tx.insertInto('jobs').values({ tenant_id: options.tenantId, id: jobId, source_id: options.sourceId, actor_id: options.actorId, status: 'running' }).execute();
      });
      return jobId;
    } catch (error) { throw recovery(r, 'MANUAL_SCAN_RESERVATION_OR_JOB_CREATION_FAILED', error); }
  } };
}
