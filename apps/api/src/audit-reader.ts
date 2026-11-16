// SPDX-License-Identifier: Apache-2.0
import { db, sql, type Tx } from '../../../packages/db/src/index.ts';
import { Problem, requirePermission, type Principal } from '../../../packages/authz/src/index.ts';
import { verifyAuditChain } from './audit.ts';
import { visibleAudit } from './repository.ts';

const maximumAuditRows = 10_000;

/** Runs the same reader inside an existing repeatable-read transaction. The
 * caller owns its lifetime; the public reader below always uses read-only mode. */
export async function verifyAuditIntegritySnapshot(tx: Tx, principal: Principal, sessionHash: string) {
  await sql`SELECT set_config('gc.tenant_id', ${principal.tenantId}, true),
    set_config('gc.actor_id', ${principal.id}, true)`.execute(tx);
  const session = await tx.selectFrom('sessions').innerJoin('identities', 'identities.id', 'sessions.identity_id')
    .select('identities.name').where('sessions.id_hash', '=', sessionHash)
    .where('sessions.identity_id', '=', principal.id).where('sessions.tenant_id', '=', principal.tenantId)
    .where('sessions.expires_at', '>', sql<Date>`transaction_timestamp()`)
    .where('identities.active', '=', true).executeTakeFirst();
  if (!session) throw new Problem(401, 'SESSION_EXPIRED', 'Your session has expired. Sign in again.');
  const membership = await tx.selectFrom('memberships').select('permissions')
    .where('tenant_id', '=', principal.tenantId).where('identity_id', '=', principal.id)
    .where('active', '=', true).executeTakeFirst();
  if (!membership) throw new Problem(401, 'MEMBERSHIP_REVOKED', 'Access to this organization has been revoked.');
  const current: Principal = { id: principal.id, tenantId: principal.tenantId,
    name: session.name, permissions: membership.permissions };
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
  return verifyAuditChain(rows);
}

/** Principal, visibility and bounded chain all use one MVCC snapshot. */
export async function readAuditIntegrity(principal: Principal, sessionHash: string) {
  return db.transaction().setIsolationLevel('repeatable read').setAccessMode('read only')
    .execute(tx => verifyAuditIntegritySnapshot(tx, principal, sessionHash));
}
