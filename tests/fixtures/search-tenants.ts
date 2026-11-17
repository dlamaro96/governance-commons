// SPDX-License-Identifier: Apache-2.0
/** Dedicated synthetic qualification identities. Their issuer has no login
 * configuration. Explicit owner preparation never resets existing authority.
 * Tenant/member tombstones are retained; tests remove only their owned assets,
 * index documents and sessions. No demonstration persona belongs here. */
export const SEARCH_TEST_FIXTURE=Object.freeze({
  tenant:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  foreign:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  steward:'70000000-0000-4000-8000-000000000001',
  consumer:'70000000-0000-4000-8000-000000000002',
  summit:'70000000-0000-4000-8000-000000000003',
});
