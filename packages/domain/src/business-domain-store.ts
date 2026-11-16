// SPDX-License-Identifier: Apache-2.0
import { createHmac } from 'node:crypto';
import { lockTenantLedger, sql, type Tx } from '../../db/src/index.ts';
import type { OperationNodeSource } from 'kysely';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { typeHash } from './asset-type-policy.ts';
import { parseDomainTypeDefinition, resolveDomainType, domainTypeAttributeModel } from './business-domain-type.ts';
import { validateAttributes, type ValidationIssue } from './model.ts';
import type { DomainTypeDefinition, DomainTypeView, DomainView, DomainTuple, DomainPlacementView } from './business-domain-contracts.ts';

export type DomainRow = Record<string, any>;
export const DOMAIN_READ = ['domains:read'] as const;
export const DOMAIN_WRITE = ['domains:read', 'domains:write'] as const;
export const DOMAIN_TYPE_READ = ['models:read'] as const;
export const DOMAIN_TYPE_WRITE = ['models:read', 'models:write'] as const;
export const DOMAIN_PLACEMENT_READ = ['catalog:read', 'domains:read'] as const;
export const DOMAIN_PLACEMENT_WRITE = [...DOMAIN_PLACEMENT_READ, 'catalog:write', 'domains:assign'] as const;
export const domainUUID = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
export const domainVersion = (value: unknown, zero = false): value is number => typeof value === 'number' && Number.isInteger(value) && value >= (zero ? 0 : 1) && value <= 2147483647;
export const domainMissing = () => new Problem(404, 'DOMAIN_NOT_FOUND', 'The domain is unavailable.');
export const domainTypeMissing = () => new Problem(404, 'DOMAIN_TYPE_NOT_FOUND', 'The domain type is unavailable.');
export const domainScopeMissing = () => new Problem(403, 'DOMAIN_SCOPE_UNAVAILABLE', 'The complete scope is unavailable for this operation.');
export const domainStorage = () => new Problem(500, 'DOMAIN_STORAGE_INVALID', 'Stored domain evidence could not be verified.');
export const domainLimit = () => new Problem(422, 'DOMAIN_PROFILE_LIMIT', 'The complete authorized scope exceeds this development profile.');
export const domainRetry = () => new Problem(503, 'DOMAIN_RETRY', 'A stable execution window was unavailable. Retry with the same idempotency key.');
export const domainStale = () => new Problem(409, 'DOMAIN_PREVIEW_STALE', 'The complete scope changed. Load it again and run a fresh preview.');
export const domainConflict = () => new Problem(409, 'VERSION_CONFLICT', 'The expected current version has changed.');
export function domainValidation(code: string, issues?: readonly ValidationIssue[]): Problem {
  if (issues?.some(issue => issue.code === 'limit')) return domainLimit();
  return new Problem(422, code, 'The proposed domain change does not satisfy its policy.', issues);
}
export function domainISO(value: string | Date): string {
  const date = new Date(value); if (!Number.isFinite(date.valueOf())) throw domainStorage(); return date.toISOString();
}
export function domainText(value: unknown, maximum: number, required = false): value is string {
  return typeof value === 'string' && [...value].length <= maximum && (!required || value.trim().length > 0)
    && !/\p{Cc}|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
}

interface BudgetState { deadline: number }
const deadlines = new WeakMap<Tx, BudgetState>();
export function checkDomainDeadline(tx: Tx): number {
  const state = deadlines.get(tx); if (!state) throw domainStorage();
  const remaining = Math.floor(state.deadline - performance.now()); if (remaining < 1) throw domainRetry(); return remaining;
}
/** Every statement has a separately armed timer. The database's original,
 * full-precision transaction clock includes waits before this module is entered.
 * The monotonic application deadline and previous positive timers only shorten it. */
export async function configureDomainTransaction(tx: Tx): Promise<void> {
  const started = performance.now();
  if (deadlines.has(tx)) checkDomainDeadline(tx);
  const clock = await sql<{ remaining: number; statement_ms: number; lock_ms: number }>`select
    floor(extract(epoch from (transaction_timestamp()+interval '30 seconds'-clock_timestamp()))*1000)::integer as remaining,
    (extract(epoch from current_setting('statement_timeout')::interval)*1000)::integer as statement_ms,
    (extract(epoch from current_setting('lock_timeout')::interval)*1000)::integer as lock_ms`.execute(tx);
  const row = clock.rows[0];
  if (!row || !Number.isFinite(row.remaining) || row.remaining < 1) throw domainRetry();
  const previous = deadlines.get(tx)?.deadline ?? started + 30000;
  deadlines.set(tx, { deadline: Math.min(previous, started + row.remaining) });
  const remaining = checkDomainDeadline(tx);
  const statement = Math.min(remaining, row.statement_ms > 0 ? row.statement_ms : remaining);
  const lock = Math.min(5000, remaining, row.lock_ms > 0 ? row.lock_ms : remaining);
  if (statement < 1 || lock < 1) throw domainRetry();
  await sql`select set_config('statement_timeout',${String(statement)},true),set_config('lock_timeout',${String(lock)},true)`.execute(tx);
  checkDomainDeadline(tx);
}
export async function domainQuery<T>(tx: Tx, work: () => Promise<T>): Promise<T> {
  await configureDomainTransaction(tx); const result = await work(); checkDomainDeadline(tx); return result;
}
export function domainFailure(error: unknown): unknown {
  if (error instanceof Problem) return error;
  if (!error || typeof error !== 'object' || !('code' in error)) return error;
  const e = error as { code: string; message?: string; constraint?: string };
  if (['55P03','57014','40P01','40001'].includes(e.code)) return domainRetry();
  if (e.code === '42501' && e.message === 'FORBIDDEN') return new Problem(403, 'FORBIDDEN', 'Your current permissions do not allow this action.');
  if (e.code === '42501' && e.message === 'DOMAIN_SCOPE_UNAVAILABLE') return domainScopeMissing();
  const missing = ['DOMAIN_NOT_FOUND','DOMAIN_TYPE_NOT_FOUND','DOMAIN_MIGRATION_NOT_FOUND','ASSET_NOT_FOUND'];
  if (['P0002','23514'].includes(e.code) && missing.includes(e.message ?? '')) return new Problem(404, e.message!, 'The resource is unavailable.');
  if (e.code === '23514' && e.message === 'VERSION_CONFLICT') return domainConflict();
  if (e.code === '23514' && e.message === 'DOMAIN_PREVIEW_STALE') return domainStale();
  const validation = ['DOMAIN_INVALID','DOMAIN_TYPE_INVALID','DOMAIN_MIGRATION_INVALID','DOMAIN_HIERARCHY_CYCLE','DOMAIN_IN_USE','DOMAIN_RETIRED','DOMAIN_NO_CHANGE','DOMAIN_MIGRATION_REQUIRED'];
  if (e.code === '23514' && validation.includes(e.message ?? '')) return domainValidation(e.message!);
  if (e.code === '54000' && e.message === 'DOMAIN_PROFILE_LIMIT') return domainLimit();
  if (e.code === '23505' && e.constraint === 'domain_types_tenant_id_key_key') return new Problem(409, 'DOMAIN_TYPE_EXISTS', 'The domain type key already exists.');
  if (['23502','23503','23505','23514','42501','P0001'].includes(e.code)) return domainStorage();
  return error;
}
export async function authorizeDomain(tx: Tx, p: Principal, actions: readonly string[]): Promise<Principal> {
  if (!domainUUID(p.id) || !domainUUID(p.tenantId)) throw new Problem(403, 'FORBIDDEN', 'Your current permissions do not allow this action.');
  const row = await domainQuery(tx, () => tx.selectFrom('memberships as m').innerJoin('identities as i','i.id','m.identity_id')
    .select(['m.permissions','i.name']).where('m.tenant_id','=',p.tenantId).where('m.identity_id','=',p.id)
    .where('m.active','=',true).where('i.active','=',true).executeTakeFirst());
  if (!row || !Array.isArray(row.permissions) || row.permissions.some(value => typeof value !== 'string') || actions.some(action => !row.permissions.includes(action)))
    throw new Problem(403, 'FORBIDDEN', 'Your current permissions do not allow this action.');
  return { id: p.id, tenantId: p.tenantId, name: row.name, permissions: [...row.permissions] };
}
export async function lockDomainScope(tx: Tx, p: Principal, actions: readonly string[]): Promise<Principal> {
  await authorizeDomain(tx,p,actions);
  await domainQuery(tx, () => lockTenantLedger(tx,p.tenantId));
  await domainQuery(tx, () => sql`select pg_advisory_xact_lock(hashtextextended(${`governance-models:${p.tenantId}`},0))`.execute(tx));
  await domainQuery(tx, () => sql`select pg_advisory_xact_lock(hashtextextended(${`governance-domains:${p.tenantId}`},0))`.execute(tx));
  return authorizeDomain(tx,p,actions);
}
export async function lockDomainPrincipals(tx: Tx, p: Principal, owners: readonly (string | null)[], actions: readonly string[]): Promise<Principal> {
  const ids = [...new Set([p.id,...owners.filter((id): id is string => id !== null)])].sort();
  if (ids.length > 2001) throw domainLimit();
  if (ids.some(id => !domainUUID(id))) throw domainValidation('DOMAIN_INVALID');
  await domainQuery(tx, () => sql`select public.gc_lock_type_migration_principals(${ids}::uuid[])`.execute(tx));
  return authorizeDomain(tx,p,actions);
}
export async function domainOwnerActivity(tx: Tx,p: Principal, owners: readonly (string|null)[]) {
  const ids = [...new Set(owners.filter((id): id is string => id !== null))].sort(); if (ids.length > 2001) throw domainLimit();
  const rows = ids.length ? await domainQuery(tx, () => tx.selectFrom('memberships as m').innerJoin('identities as i','i.id','m.identity_id')
    .select(['i.id','i.active as identity_active','m.active as member_active']).where('m.tenant_id','=',p.tenantId).where('i.id','in',ids).execute()) : [];
  const activity = new Map(rows.map(row => [row.id,row.identity_active === true && row.member_active === true]));
  return ids.map(identityId => ({ identityId, active: activity.get(identityId) === true }));
}
/** Called only after complete current scope authorization. Charge both JSONB
 * storage expansion and serialized values before retaining complete documents. */
export async function domainPhysicalBudget(tx: Tx, value: unknown): Promise<number> {
  checkDomainDeadline(tx); const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 524288) throw domainLimit();
  let nodes = 0;
  const visit = (v: unknown, depth: number): void => { if (++nodes > 100000 || depth > 32) throw domainLimit();
    if (v && typeof v === 'object') for (const child of Object.values(v)) visit(child,depth+1); };
  visit(value,0); checkDomainDeadline(tx);
  const rows = await domainQuery(tx, () => sql<{ bytes: number }>`select octet_length(${encoded}::jsonb::text) as bytes`.execute(tx));
  if (rows.rows[0].bytes > 524288) throw domainLimit();
  return rows.rows[0].bytes;
}
/** Preflight exactly the authorized rows about to cross the database boundary.
 * The subquery retains the caller's keyset/order/limit and returns only a scalar;
 * opaque legacy payloads are never serialized in JavaScript to discover size. */
export async function domainRowsBudget(tx: Tx, query: OperationNodeSource, retainedBytes = 0): Promise<number> {
  if (!Number.isSafeInteger(retainedBytes) || retainedBytes < 0) throw domainStorage();
  const result = await domainQuery(tx, () => sql<{ bytes: number }>`select
    coalesce(sum(octet_length(to_jsonb(domain_read_row)::text)),0)::double precision as bytes
    from (${query}) as domain_read_row`.execute(tx));
  const bytes = result.rows[0]?.bytes;
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw domainStorage();
  if (retainedBytes + bytes > 524288) throw domainLimit();
  return retainedBytes + bytes;
}
export async function domainScopeFence(tx: Tx,p: Principal): Promise<string> {
  const epoch = await domainQuery(tx, () => sql<{ epoch: string }>`select public.gc_domain_scope_epoch()::text as epoch`.execute(tx));
  return Buffer.from(domainConsent('page-scope',{ tenantId:p.tenantId,actorId:p.id,epoch:epoch.rows[0].epoch }), 'hex').toString('base64url');
}
export function domainConsent(purpose: string,value: unknown): string {
  const secret = process.env.SESSION_KEY;
  if (!secret || Buffer.byteLength(secret) < 32) throw new Problem(500,'CURSOR_CONFIGURATION_INVALID','Domain consent is temporarily unavailable.');
  return createHmac('sha256',secret).update(`governance-commons:domain:${purpose}\0`).update(typeHash(value)).digest('hex');
}
export function domainTuple(view: DomainView): DomainTuple {
  return { name:view.name,description:view.description,parentId:view.parentId,type:view.type,attributes:view.attributes,
    ownerId:view.ownerId,state:view.state,status:view.status };
}
export function domainView(row: DomainRow): DomainView {
  if (!domainUUID(row.id) || !domainVersion(row.version) || !domainText(row.name,200,true) || !domainText(row.description,4000)
    || row.parent_id !== null && !domainUUID(row.parent_id) || !domainUUID(row.type_id) || !domainVersion(row.type_version)
    || row.owner_id !== null && !domainUUID(row.owner_id) || !['active','retired'].includes(row.status)
    || !domainUUID(row.created_by) || !domainUUID(row.updated_by)) throw domainStorage();
  return { id:row.id,version:row.version,name:row.name,description:row.description,parentId:row.parent_id,
    type:{typeId:row.type_id,version:row.type_version},attributes:row.attributes,ownerId:row.owner_id,state:row.state,status:row.status,
    createdAt:domainISO(row.created_at),createdBy:row.created_by,updatedAt:domainISO(row.updated_at),updatedBy:row.updated_by };
}
export function placementView(assetId: string,row?: DomainRow): DomainPlacementView {
  if (!row) return { assetId,version:0,domainId:null,recordedAssetVersion:null,recordedDomainVersion:null,recordedAt:null,recordedBy:null };
  if (row.asset_id !== assetId || !domainVersion(row.version) || !domainVersion(row.recorded_asset_version)
    || !domainUUID(row.recorded_by) || (row.domain_id === null ? row.recorded_domain_version !== null : !domainUUID(row.domain_id) || !domainVersion(row.recorded_domain_version))) throw domainStorage();
  return { assetId,version:row.version,domainId:row.domain_id,recordedAssetVersion:row.recorded_asset_version,
    recordedDomainVersion:row.recorded_domain_version,recordedAt:domainISO(row.recorded_at),recordedBy:row.recorded_by };
}
export async function storedDomain(tx: Tx,p: Principal,id: string,retainedBytes = 0): Promise<DomainView> {
  if (!domainUUID(id)) throw domainMissing();
  const query = tx.selectFrom('domains as d').leftJoin('domain_revisions as r',j=>j.onRef('r.tenant_id','=','d.tenant_id')
    .onRef('r.domain_id','=','d.id').onRef('r.version','=','d.version')).selectAll('d').select('r.snapshot as revision')
    .where('d.tenant_id','=',p.tenantId).where('d.id','=',id);
  const loadedBytes = await domainRowsBudget(tx,query,retainedBytes);
  const row = await domainQuery(tx, () => query.executeTakeFirst());
  if (!row) throw domainMissing(); const view = domainView(row);
  const policy = await storedDomainType(tx,p,view.type.typeId,view.type.version,loadedBytes);
  await domainPhysicalBudget(tx,{row,policy});
  if (!validateAttributes(domainTypeAttributeModel(policy.definition,policy.resolved),view.attributes).ok || !policy.resolved.lifecycle.states.includes(view.state)) throw domainStorage();
  if (!row.revision || typeHash(row.revision.domain) !== typeHash(view)) throw domainStorage(); return view;
}
export async function domainAsset(tx: Tx,p: Principal,id: string): Promise<DomainRow> {
  if (!domainUUID(id)) throw new Problem(404,'ASSET_NOT_FOUND','The asset is unavailable.');
  // Placement reads need identity/version only. Visibility is evaluated inside
  // SQL, so arbitrary legacy metadata, descriptions and ACL arrays stay there.
  const row = await domainQuery(tx, () => tx.selectFrom('assets').select(['id','version'])
    .where('tenant_id','=',p.tenantId).where('id','=',id)
    .where(sql<boolean>`visibility='tenant' OR allowed_identities @> ${JSON.stringify([p.id])}::jsonb`).executeTakeFirst());
  if (!row) throw new Problem(404,'ASSET_NOT_FOUND','The asset is unavailable.');
  return row;
}
/** Immutable exact-version reads verify authored hashes and independently resolve
 * the closure. The normalized closure must match; stored resolution is not trusted. */
export async function storedDomainType(tx: Tx,p: Principal,id: string,version?: number,retainedBytes = 0): Promise<DomainTypeView> {
  if (!domainUUID(id) || version !== undefined && !domainVersion(version)) throw domainTypeMissing();
  const head = await domainQuery(tx, () => tx.selectFrom('domain_types').selectAll().where('tenant_id','=',p.tenantId).where('id','=',id).executeTakeFirst());
  if (!head) throw domainTypeMissing();
  const load = async (typeId: string,v: number) => {
    const q = tx.selectFrom('domain_type_versions').where('tenant_id','=',p.tenantId).where('type_id','=',typeId).where('version','=',v);
    const physical = await domainQuery(tx, () => q.select(sql<number>`octet_length(definition::text)+octet_length(resolved::text)`.as('bytes')).executeTakeFirst());
    if (!physical) throw domainTypeMissing(); if (physical.bytes > 524288) throw domainLimit();
    retainedBytes = await domainRowsBudget(tx,q.selectAll(),retainedBytes);
    const row = await domainQuery(tx, () => q.selectAll().executeTakeFirstOrThrow());
    const parsed = parseDomainTypeDefinition(row.definition);
    if (!parsed.ok || parsed.value.version !== v || typeHash(parsed.value) !== row.definition_hash || typeHash(row.resolved) !== row.resolution_hash) throw domainStorage();
    return {row,definition:parsed.value};
  };
  const root = await load(id,version ?? head.current_version); if (root.definition.id !== head.key) throw domainStorage();
  const found = new Map<string,{typeId:string;definition:DomainTypeDefinition}>();
  const visit = async (definition: DomainTypeDefinition,depth:number,active:Set<string>): Promise<void> => {
    if (depth > 8) throw domainStorage();
    for (const pin of definition.parents) {
      if (active.has(pin.typeId)) throw domainStorage();
      const old = found.get(pin.typeId); if (old) { if (old.definition.version !== pin.version) throw domainStorage(); continue; }
      if (found.size >= 64) throw domainLimit();
      const parent = await load(pin.typeId,pin.version); found.set(pin.typeId,{typeId:pin.typeId,definition:parent.definition});
      await visit(parent.definition,depth+1,new Set([...active,pin.typeId]));
    }
  };
  await visit(root.definition,0,new Set([id]));
  const dependencies = [...found.values()]; await domainPhysicalBudget(tx,{definition:root.definition,dependencies,resolved:root.row.resolved});
  const resolved = resolveDomainType(id,root.definition,dependencies);
  if (!resolved.ok || typeHash(resolved.value) !== root.row.resolution_hash) throw domainStorage();
  const pins = await domainQuery(tx, () => tx.selectFrom('domain_type_dependencies').select(['parent_type_id','parent_version'])
    .where('tenant_id','=',p.tenantId).where('type_id','=',id).where('version','=',root.definition.version).orderBy('parent_type_id').orderBy('parent_version').limit(65).execute());
  if (typeHash(pins.map(pin => ({typeId:pin.parent_type_id,version:pin.parent_version}))) !== typeHash(resolved.value.dependencies)) throw domainStorage();
  return { typeId:id,key:head.key,version:root.definition.version,currentVersion:head.current_version,definition:root.definition,resolved:resolved.value,
    definitionHash:root.row.definition_hash,resolutionHash:root.row.resolution_hash,createdAt:domainISO(root.row.created_at),createdBy:root.row.created_by };
}
