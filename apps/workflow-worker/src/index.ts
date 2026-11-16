// SPDX-License-Identifier: Apache-2.0
import { createServer } from 'node:http';
import { Client, Connection, WorkflowExecutionAlreadyStartedError } from '@temporalio/client';
import { NativeConnection, Worker } from '@temporalio/worker';
import { fileURLToPath } from 'node:url';
import {createApprovalActivities,dispatchApprovalEvent} from './approval-activities.ts';
const address = process.env.TEMPORAL_ADDRESS ?? 'temporal:7233';
const namespace = process.env.TEMPORAL_NAMESPACE ?? 'default';
const api = process.env.API_URL ?? 'http://api:4310';
const token = process.env.SITE_TOKEN;
const tenants = (process.env.SITE_TENANTS ?? '').split(',').filter(Boolean);
if (!token || tenants.length === 0) throw new Error('SITE_TOKEN and SITE_TENANTS are required');
const approvals=createApprovalActivities({apiUrl:api,token});
const connection = await Connection.connect({ address });
const client = new Client({ connection, namespace });
const workerConnection = await NativeConnection.connect({ address });
const worker = await Worker.create({ connection: workerConnection, namespace, taskQueue: 'gc-workflow',
  workflowsPath: fileURLToPath(new URL('./workflows.ts', import.meta.url)), maxConcurrentWorkflowTaskExecutions: 8,
  activities:{tickApproval:approvals.tickApproval},maxConcurrentActivityTaskExecutions:8 });
const health = createServer((request, response) => {
  const ready = request.url === '/health' && worker.getState() === 'RUNNING';
  response.writeHead(ready ? 200 : 503, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify({ status: ready ? 'ready' : 'starting' }));
}).listen(8081, '0.0.0.0');
let stopping = false;
const stop = () => { stopping = true; health.close(); worker.shutdown(); };
process.once('SIGINT', stop); process.once('SIGTERM', stop);
async function dispatch() {
  while (!stopping) {
    for (const tenantId of tenants) {
      if (stopping) break;
      try {
        const response = await fetch(`${api}/internal/jobs/pending`, { headers: { Authorization: `Bearer ${token}`, 'X-Tenant-Id': tenantId }, signal: AbortSignal.timeout(10000) });
        if (!response.ok) throw new Error(`API_${response.status}`);
        const body = await response.json() as { items: { id: string; tenantId: string }[] };
        for (const job of body.items) {
          if (job.tenantId !== tenantId) throw new Error('JOB_TENANT_MISMATCH');
          try {
            await client.workflow.start('scanSourceWorkflow', { taskQueue: 'gc-workflow', workflowId: `scan:${tenantId}:${job.id}`,
              args: [{ tenantId, jobId: job.id }], workflowExecutionTimeout: '30 minutes' });
          } catch (error) {
            if (!(error instanceof WorkflowExecutionAlreadyStartedError)) throw error;
          }
        }
      } catch (error) {
        console.error(JSON.stringify({ event: 'dispatcher_retry', code: error instanceof Error && /^API_\d+$/.test(error.message) ? error.message : 'DISPATCH_FAILED' }));
      }
      if(stopping)break;
      try{
        const pending=await approvals.pendingApprovals(tenantId);
        for(const event of pending.items){
          if(stopping)break;
          try{
            await dispatchApprovalEvent(event,approvals,async(input,eventId)=>{
              try{
                await connection.withDeadline(Date.now()+10_000,()=>client.workflow.signalWithStart('approvalWorkflow',{
                  taskQueue:'gc-workflow',workflowId:`approval:${input.tenantId}:${input.requestId}`,args:[input],
                  signal:'approvalChanged',signalArgs:[eventId],workflowIdReusePolicy:'REJECT_DUPLICATE',workflowIdConflictPolicy:'USE_EXISTING',
                }));
                return 'accepted';
              }catch(error){if(error instanceof WorkflowExecutionAlreadyStartedError)return 'closed';throw error;}
            });
          }catch(error){
            console.error(JSON.stringify({event:'approval_dispatch_retry',code:error instanceof Error&&error.message==='APPROVAL_CLOSED_PENDING'?'APPROVAL_CLOSED_PENDING':'APPROVAL_DISPATCH_FAILED'}));
          }
        }
      }catch{console.error(JSON.stringify({event:'approval_dispatch_retry',code:'APPROVAL_DISPATCH_FAILED'}));}
    }
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
}
await Promise.all([worker.run(), dispatch()]);
health.close(); await connection.close(); await workerConnection.close();
