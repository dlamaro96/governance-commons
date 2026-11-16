// SPDX-License-Identifier: Apache-2.0
/** Synthetic browser setup through authenticated real HTTP; no response interception. */
import { expect, type APIResponse, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { DomainTypeDefinition, DomainTypeView, DomainView } from '../../packages/domain/src/business-domain-contracts.ts';
const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
export const domainBrowserOrigin = new URL(process.env.GC_BROWSER_BASE_URL || 'http://localhost:4310').origin;
export const stewardIdentity = '10000000-0000-4000-8000-000000000001';
const csrf = new WeakMap<Page, string>();
export async function domainLogin(page: Page, username = 'steward') {
  await page.goto('/auth/login'); await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(credentials.personas[username]);
  await page.getByRole('button', { name: 'Sign In', exact: true }).click(); await expect(page).toHaveURL(`${domainBrowserOrigin}/`);
  await expect(page.getByRole('heading', { level: 1, name: username === 'summit' ? 'Summit Logistics' : 'Harbor Retail' })).toBeVisible();
}
export async function domainHeaders(page: Page, version?: number) {
  if (!csrf.has(page)) { const result = await domainBody<{ csrfToken: string }>(await page.request.get('/api/v1/me')); csrf.set(page, result.csrfToken); }
  return { 'X-CSRF-Token': csrf.get(page)!, Origin: domainBrowserOrigin, 'Idempotency-Key': crypto.randomUUID(), ...(version === undefined ? {} : { 'If-Match': String(version) }) };
}
export async function domainBody<T = any>(response: APIResponse, status = 200): Promise<T> { expect(response.status(), await response.text()).toBe(status); return response.json(); }
export function domainDefinition(key: string): DomainTypeDefinition { return { formatVersion: 1, kind: 'domain-type', id: key, version: 1, label: `Synthetic ${key}`, parents: [], attributes: { amount: { type: 'number', integer: true, required: true } }, overrideAttributes: [], requiredOwner: true, lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } }; }
export async function createDomainType(page: Page, definition: DomainTypeDefinition): Promise<DomainTypeView> { return (await domainBody<{ type: DomainTypeView }>(await page.request.post('/api/v1/domain-types', { headers: await domainHeaders(page), data: { definition, reason: 'Synthetic browser policy setup' } }), 201)).type; }
export async function createDomain(page: Page, type: DomainTypeView, name: string): Promise<DomainView> { return (await domainBody<{ domain: DomainView }>(await page.request.post('/api/v1/domains', { headers: await domainHeaders(page), data: { name, description: 'Independent synthetic browser domain', parentId: null, type: { typeId: type.typeId, version: type.version }, attributes: { amount: 7 }, ownerId: stewardIdentity, reason: 'Synthetic browser domain setup' } }), 201)).domain; }
export async function readDomain(page: Page, id: string): Promise<DomainView> { return (await domainBody<{ domain: DomainView }>(await page.request.get(`/api/v1/domains/${id}`))).domain; }
export async function editDomain(page: Page, row: DomainView, name: string): Promise<DomainView> { return (await domainBody<{ domain: DomainView }>(await page.request.patch(`/api/v1/domains/${row.id}`, { headers: await domainHeaders(page, row.version), data: { name, description: row.description, attributes: row.attributes, ownerId: row.ownerId, reason: 'Concurrent synthetic version change' } }))).domain; }
export async function hierarchy(page: Page, row: DomainView, kind: 'retire' | 'restore' | 'move', parentId = row.parentId): Promise<DomainView> {
  const change = { kind, domainId: row.id, expectedVersion: row.version, parentId, reason: 'Synthetic hierarchy preparation' }, headers = await domainHeaders(page, row.version);
  const { preview } = await domainBody(await page.request.post(`/api/v1/domains/${row.id}/hierarchy-previews`, { headers, data: { change } })); expect(preview.ready).toBe(true);
  return (await domainBody<{ domain: DomainView }>(await page.request.post(`/api/v1/domains/${row.id}/hierarchy-changes`, { headers: await domainHeaders(page, row.version), data: { change, previewDigest: preview.previewDigest } }))).domain;
}
export async function scanDomainBrowserAsset(page: Page, name: string) {
  const { source } = await domainBody(await page.request.post('/api/v1/sources', { headers: await domainHeaders(page), data: { name, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } }), 201);
  const { job } = await domainBody(await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: await domainHeaders(page), data: {} }), 202);
  await expect.poll(async () => (await domainBody(await page.request.get(`/api/v1/jobs/${job.id}`))).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  let assetId: string | undefined;
  await expect.poll(async () => { let cursor: string | null = null; for (let i = 0; i < 30; i++) { const result: { items: { id: string; name: string; sourceId: string }[]; nextCursor: string | null } = await domainBody(await page.request.get(`/api/v1/assets?q=orders&type=table&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`)); assetId = result.items.find(row => row.sourceId === source.id && row.name === 'orders')?.id; cursor = result.nextCursor; if (assetId || !cursor) break; } return !!assetId; }, { timeout: 30_000 }).toBe(true);
  return (await domainBody(await page.request.get(`/api/v1/assets/${assetId}`))).asset as { id: string; version: number; name: string; sourceId: string };
}
