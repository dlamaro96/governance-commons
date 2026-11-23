// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {after,before,test} from 'node:test';
import {createHash} from 'node:crypto';
import {db,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {verifyAuditIntegritySnapshot} from '../../apps/api/src/audit-reader.ts';
import {verifyAuditChain} from '../../apps/api/src/audit.ts';
import {visibleAudit} from '../../apps/api/src/repository.ts';
import {PROTECTED_AUDIT_FIXTURE as fixture} from '../fixtures/protected-core-tenants.ts';
import {createProtectedCoreSession,closeProtectedCoreSessions} from '../fixtures/protected-core-authentication.ts';

const {tenant,steward,consumer}=fixture;
const principal:Principal={id:steward,tenantId:tenant,name:fixture.name,permissions:['audit:read','catalog:read','models:read']};
before(async()=>{
 assert.ok(process.env.DATABASE_URL,'A real runtime DATABASE_URL is required; no audit reader cases ran.');
 assert.deepEqual((await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user AS name,
  rolsuper AS superuser,rolbypassrls AS bypass FROM pg_roles WHERE rolname=current_user`.execute(db)).rows,[{name:'gc_app',superuser:false,bypass:false}]);
});
after(async()=>{await closeProtectedCoreSessions();await db.destroy();});
async function readOnly<T>(work:(tx:Tx)=>Promise<T>){
 return db.transaction().setIsolationLevel('repeatable read').setAccessMode('read only').execute(async tx=>{
  await sql`SELECT set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${steward},true)`.execute(tx);
  assert.deepEqual((await sql<{isolation:string;read_only:string}>`SELECT current_setting('transaction_isolation') isolation,current_setting('transaction_read_only') read_only`.execute(tx)).rows,[{isolation:'repeatable read',read_only:'on'}]);
  return work(tx);
 });
}
function problem(status:number,code:string){return(error:unknown)=>{
 assert.ok(error instanceof Problem);assert.equal(error.status,status);assert.equal(error.code,code);
 for(const key of ['checked','head','failedId','count','total'])assert.equal(Object.hasOwn(error,key),false);return true;
};}
async function fixtureSnapshot(tx:Tx){
 const rows=await tx.selectFrom('audit').selectAll().orderBy('sequence').execute();
 const assets=await tx.selectFrom('assets').selectAll().orderBy('id').execute();
 const revisions=await tx.selectFrom('asset_revisions').selectAll().orderBy('asset_id').orderBy('version').execute();
 return {rows,assets,revisions,digest:createHash('sha256').update(JSON.stringify({rows,assets,revisions})).digest('hex')};
}

test('audit integrity rejects hidden scope before the 10000-row profile using a committed dedicated real ledger',async()=>{
 const session=await createProtectedCoreSession(steward,tenant);
 const before=await readOnly(async tx=>{
  const snapshot=await fixtureSnapshot(tx);assert.equal(snapshot.rows.length,fixture.eventCount);assert.ok(snapshot.rows.length>10000);
  assert.equal(snapshot.rows.filter(row=>row.correlation_id===fixture.correlationId).length,10002);
  const chain=verifyAuditChain(snapshot.rows);assert.equal(chain.valid,true);assert.equal(chain.checked,10002);
  assert.equal(snapshot.assets.length,1);assert.equal(snapshot.assets[0]!.id,fixture.assetId);assert.equal(snapshot.revisions.length,1);
  assert.equal(await visibleAudit(tx,principal).where('audit.resource_id','=',fixture.assetId).executeTakeFirst(),undefined);
  assert.equal((await visibleAudit(tx,principal).execute()).length,10001);
  await assert.rejects(()=>verifyAuditIntegritySnapshot(tx,principal,session.sessionHash),problem(403,'AUDIT_SCOPE_UNAVAILABLE'));
  return snapshot.digest;
 });
 assert.equal(await readOnly(async tx=>(await fixtureSnapshot(tx)).digest),before,'Read-only denial preserves the complete dedicated ledger and asset history');
});

test('audit integrity reloads current membership permissions and binds the exact active session before reading the ledger',async()=>{
 const limited=await createProtectedCoreSession(consumer,tenant),current=await createProtectedCoreSession(steward,tenant);
 await readOnly(async tx=>{
  const actual=await tx.selectFrom('memberships').select('permissions').where('tenant_id','=',tenant).where('identity_id','=',consumer).where('active','=',true).executeTakeFirstOrThrow();
  assert.equal(actual.permissions.includes('audit:read'),false);
  // The caller's stale grant cannot replace the current membership read.
  await assert.rejects(()=>verifyAuditIntegritySnapshot(tx,{...principal,id:consumer},limited.sessionHash),problem(403,'FORBIDDEN'));
 });
 await assert.rejects(()=>readOnly(tx=>verifyAuditIntegritySnapshot(tx,principal,limited.sessionHash)),problem(401,'SESSION_EXPIRED'));
 await assert.rejects(()=>readOnly(tx=>verifyAuditIntegritySnapshot(tx,{...principal,tenantId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},current.sessionHash)),problem(401,'SESSION_EXPIRED'));
 // A native rejection aborts PostgreSQL; assert outside the transaction so its
 // rollback completes before the expected application denial is inspected.
 await current.revoke();
 await assert.rejects(()=>readOnly(tx=>verifyAuditIntegritySnapshot(tx,principal,current.sessionHash)),problem(401,'SESSION_EXPIRED'));
});
