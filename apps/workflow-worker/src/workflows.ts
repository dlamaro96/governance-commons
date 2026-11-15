// SPDX-License-Identifier: Apache-2.0
import { proxyActivities } from '@temporalio/workflow';
export interface ScanInput { tenantId: string; jobId: string }
const { executeScan } = proxyActivities<{ executeScan(input: ScanInput): Promise<{ status: string; assetCount?: number }> }>({
  taskQueue: 'gc-site', startToCloseTimeout: '3 minutes', scheduleToCloseTimeout: '20 minutes',
  retry: { initialInterval: '2 seconds', maximumInterval: '30 seconds', maximumAttempts: 5 },
});
export async function scanSourceWorkflow(input: ScanInput): Promise<{ status: string; assetCount?: number }> {
  // IDs only in Temporal history; metadata and credentials stay at the execution site.
  return executeScan(input);
}
