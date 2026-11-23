// SPDX-License-Identifier: Apache-2.0
import { db, sql, type Tx } from '../../../packages/db/src/index.ts';
import { Problem, requirePermission, type Principal } from '../../../packages/authz/src/index.ts';
import { verifyAuditChain } from './audit.ts';
import { visibleAudit } from './repository.ts';
import { readProtectedSessionSnapshot, requireLiveProtectedSession } from './security.ts';

const maximumAuditRows = 10_000;

/** The caller owns this bounded RR READ ONLY transaction. Authentication,
 * current permissions and the complete visible ledger share its snapshot. */
export async function verifyAuditIntegritySnapshot(tx: Tx, principal: Principal, sessionHash: string) {
  await sql`SELECT set_config('statement_timeout','5000',true),set_config('lock_timeout','2000',true),
    set_config('idle_in_transaction_session_timeout','5000',true)`.execute(tx);
  const session = await readProtectedSessionSnapshot(tx, sessionHash);
  if (session.identityId !== principal.id || session.selectedTenantId !== principal.tenantId)
    throw new Problem(401, 'SESSION_EXPIRED', 'Your session has expired. Sign in again.');
  await sql`SELECT set_config('gc.tenant_id', ${session.selectedTenantId}, true),
    set_config('gc.actor_id', ${session.identityId}, true)`.execute(tx);
  const identity = await tx.selectFrom('identities').select('name').where('id', '=', session.identityId)
    .where('active', '=', true).executeTakeFirst();
  if (!identity) throw new Problem(401, 'SESSION_EXPIRED', 'Your session has expired. Sign in again.');
  const membership = await tx.selectFrom('memberships').select('permissions')
    .where('tenant_id', '=', principal.tenantId).where('identity_id', '=', principal.id)
    .where('active', '=', true).executeTakeFirst();
  if (!membership) throw new Problem(401, 'MEMBERSHIP_REVOKED', 'Access to this organization has been revoked.');
  const current: Principal = { id: session.identityId, tenantId: session.selectedTenantId,
    name: identity.name, permissions: membership.permissions };
  requirePermission(current, 'audit:read');

  // Complete current resource visibility precedes any size-dependent response.
  // Select only an identity here, not hidden journal payloads or a partial chain.
  const permitted = visibleAudit(tx, current).clearSelect().select('audit.id')
    .where(sql<boolean>`audit.id = ledger.id`);
  const hidden = await tx.selectFrom('audit as ledger').select('ledger.id')
    .where('ledger.tenant_id', '=', current.tenantId)
    .where(sql<boolean>`NOT EXISTS (${permitted})`).limit(1).executeTakeFirst();
  if (hidden) throw new Problem(403, 'AUDIT_SCOPE_UNAVAILABLE', 'The complete audit scope is unavailable for this operation.');
  const rows = await tx.selectFrom('audit').selectAll().orderBy('sequence').limit(maximumAuditRows + 1).execute();
  if (rows.length > maximumAuditRows) throw new Problem(422, 'AUDIT_PROFILE_LIMIT',
    'This development verifier is limited to 10,000 entries. Verification of larger audit chains is not yet implemented.');
  const result = verifyAuditChain(rows);
  await requireLiveProtectedSession(tx, session);
  return result;
}

/** Principal, visibility and bounded chain all use one MVCC snapshot. */
export async function readAuditIntegrity(principal: Principal, sessionHash: string) {
  return db.transaction().setIsolationLevel('repeatable read').setAccessMode('read only')
    .execute(tx => verifyAuditIntegritySnapshot(tx, principal, sessionHash));
}
