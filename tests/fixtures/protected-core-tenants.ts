// SPDX-License-Identifier: Apache-2.0
/** Dedicated protected fixtures. The older nonlogin search tuples are untouched. */
export const PROTECTED_SEARCH_FIXTURE=Object.freeze({
 tenant:'71d70000-0000-4000-8000-000000000001',foreign:'71d70000-0000-4000-8000-000000000002',
 steward:'72d70000-0000-4000-8000-000000000001',consumer:'72d70000-0000-4000-8000-000000000002',
 summit:'72d70000-0000-4000-8000-000000000003',membershipLoss:'72d70000-0000-4000-8000-000000000004',
 expired:'72d70000-0000-4000-8000-000000000005',
});
export const PROTECTED_AUDIT_FIXTURE=Object.freeze({
 tenant:'73d70000-0000-4000-8000-000000000001',steward:'74d70000-0000-4000-8000-000000000001',
 consumer:'74d70000-0000-4000-8000-000000000002',assetId:'75d70000-0000-4000-8000-000000000001',
 correlationId:'76d70000-0000-4000-8000-000000000001',eventCount:10002,name:'Synthetic protected audit reader',
});
