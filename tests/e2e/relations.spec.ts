// SPDX-License-Identifier: Apache-2.0
import { test, expect, type Browser, type Page, type APIResponse, type Response as BrowserResponse } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { RelationCreate, RelationEdit, RelationGraphPage, RelationTypeDefinition, RelationTypeView, RelationView } from '../../packages/domain/src/relation-contracts.ts';

const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
const life = { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };
async function login(page: Page, username = 'steward') {
  page.on('response', response => { if (response.status() === 429 || response.status() >= 500) console.info(JSON.stringify({ diagnostic: response.status() === 429 ? 'browser_request_budget' : 'browser_server_response', method: response.request().method(), status: response.status(), path: new URL(response.url()).pathname })); });
  await page.goto('/auth/login'); await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(credentials.personas[username]);
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page).toHaveURL('http://localhost:4310/');
  await expect(page.getByRole('heading', { level: 1, name: username === 'summit' ? 'Summit Logistics' : 'Harbor Retail' })).toBeVisible();
}
function waitResponse(page: Page, predicate: (response: BrowserResponse) => boolean) { return page.waitForResponse(predicate, { timeout: 40_000 }); }
async function headers(page: Page) {
  const response = await page.request.get('/api/v1/me'); expect(response.status()).toBe(200);
  const me = await response.json(); return { 'X-CSRF-Token': me.csrfToken, Origin: 'http://localhost:4310', 'Idempotency-Key': crypto.randomUUID() };
}
async function paceRequestBudget({ browser }: { browser: Browser }) {
  test.setTimeout(75_000); const context = await browser.newContext(); const response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']), remaining = Number(response.headers()['x-ratelimit-remaining']); await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 220) {
    console.info(`Relation fixture pacing: waiting ${reset + 1}s for the configured request budget to reset`);
    await new Promise(resolve => setTimeout(resolve, (reset + 1) * 1000));
  }
}
test.beforeAll(paceRequestBudget); test.beforeEach(paceRequestBudget); test.afterAll(paceRequestBudget);
async function capture(page: Page, name: string, selector?: string, widths = [1440, 390]) {
  mkdirSync('docs/verification/screenshots', { recursive: true });
  for (const width of widths) {
    await page.setViewportSize({ width, height: 960 });
    await page.evaluate(selector => {
      if (selector) document.querySelector(selector)?.scrollIntoView({ block: 'start', behavior: 'instant' }); else window.scrollTo({ top: 0, behavior: 'instant' });
      document.querySelector('.dialog-content')?.scrollTo({ top: 0, behavior: 'instant' });
    }, selector);
    console.info(`Relation capture: ${name} at ${width}px`);
    // Only playing finite transitions need to settle. Animation.finished can stay
    // unresolved for idle/paused animations and zero-rate or unbounded timelines.
    await expect.poll(() => page.evaluate(() => document.getAnimations().filter(animation =>
      animation.playState === 'running' && animation.playbackRate !== 0 && Number.isFinite(animation.effect?.getComputedTiming().endTime)
    ).map(animation => ({ state: animation.playState, rate: animation.playbackRate, currentTime: animation.currentTime,
      endTime: animation.effect?.getComputedTiming().endTime, target: (animation.effect as KeyframeEffect | null)?.target?.nodeName }))),
    { timeout: 5_000, message: `Finite animations settle before ${name} at ${width}px` }).toEqual([]);
    if (name.startsWith('graph-')) {
      // The loaded three-node cohort must remain complete and readable after
      // desktop/mobile resize. DOM presence alone missed off-canvas cards.
      await expect(page.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(3);
      await expect.poll(() => page.locator('.relation-graph-canvas').evaluate(canvas => {
        const bounds = canvas.getBoundingClientRect();
        return [...canvas.querySelectorAll('.react-flow__node')].flatMap(node => {
          const box = node.getBoundingClientRect();
          const fits = box.left >= bounds.left && box.right <= bounds.right && box.top >= bounds.top && box.bottom <= bounds.bottom && box.width >= 210;
          return fits ? [] : [{ canvas: bounds.toJSON(), node: box.toJSON(), text: (node as HTMLElement).innerText }];
        });
      }), { timeout: 5_000, message: `All loaded graph cards fit at readable size after resize to ${width}px` }).toEqual([]);
      const expandName = name.includes('-ar-') ? 'الاستكشاف من هذا الأصل' : 'Explore from this asset';
      await expect(page.locator('.relation-graph-canvas').getByRole('link', { name: expandName, exact: true })).toHaveCount(3);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    if (name.startsWith('graph-')) await expect(page.locator('.relation-graph-canvas').getByRole('link', { name: name.includes('-ar-') ? 'الاستكشاف من هذا الأصل' : 'Explore from this asset', exact: true })).toHaveCount(3);
    await page.screenshot({ path: `docs/verification/screenshots/m2-relation-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function asset(page: Page, id: string) {
  const response = await page.request.get(`/api/v1/assets/${id}`); expect(response.status()).toBe(200); return (await response.json()).asset;
}
async function relation(page: Page, id: string): Promise<RelationView> {
  const response = await page.request.get(`/api/v1/relations/${id}`); expect(response.status()).toBe(200); return (await response.json()).relation;
}
async function changeDescription(page: Page, id: string, description: string) {
  const current = await asset(page, id);
  const response = await page.request.patch(`/api/v1/assets/${id}`, { headers: { ...await headers(page), 'If-Match': String(current.version) }, data: { description } });
  expect(response.status()).toBe(200); return (await response.json()).asset;
}
async function fixture(page: Page, prefix: string) {
  const definition: AssetTypeDefinition = { formatVersion: 1, id: `${prefix}_asset`, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: life };
  const response = await page.request.post('/api/v1/asset-types', { headers: await headers(page), data: { definition } });
  expect(response.status()).toBe(201); const base = (await response.json()).type;
  const childResponse = await page.request.post('/api/v1/asset-types', { headers: await headers(page), data: { definition: { ...definition, id: `${prefix}_child`, parents: [{ id: definition.id, version: 1 }], lifecycle: null } } });
  expect(childResponse.status()).toBe(201); const child = (await childResponse.json()).type;
  const sourceResponse = await page.request.post('/api/v1/sources', { headers: await headers(page), data: { name: `Synthetic relations browser ${prefix}`, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } });
  expect(sourceResponse.status()).toBe(201); const { source } = await sourceResponse.json();
  const scan = await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: await headers(page), data: {} });
  expect(scan.status()).toBe(202); const { job } = await scan.json();
  await expect.poll(async () => (await (await page.request.get(`/api/v1/jobs/${job.id}`)).json()).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  const assets: { id: string; search: string }[] = [];
  for (const [index, name] of ['orders', 'customers', 'products', 'order_lines'].entries()) {
    let id: string | undefined;
    await expect.poll(async () => {
      let cursor: string | null = null;
      for (let count = 0; count < 30; count++) {
        const response: APIResponse = await page.request.get(`/api/v1/assets?q=${name}&type=table&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
        expect(response.status()).toBe(200); const body: {items:{id:string;name:string;sourceId:string}[];nextCursor:string|null} = await response.json();
        id = body.items.find((item: { name: string; sourceId: string }) => item.sourceId === source.id && item.name === name)?.id;
        cursor = body.nextCursor; if (id || !cursor) break;
      }
      return !!id;
    }, { timeout: 25_000 }).toBeTruthy();
    const before = await asset(page, id!);
    const assigned = await page.request.put(`/api/v1/assets/${id}/attributes`, { headers: { ...await headers(page), 'If-Match': String(before.version) }, data: { modelId: index === 1 ? child.id : base.id, modelVersion: 1, attributes: {} } });
    expect(assigned.status()).toBe(200);
    const search = crypto.randomUUID().replaceAll('-', '');
    await changeDescription(page, id!, `Synthetic relation endpoint ${search}`); assets.push({ id: id!, search });
  }
  // Unique random description terms avoid dependence on inventory size/order.
  await expect.poll(async () => {
    const response = await page.request.get(`/api/v1/assets?q=${assets[1].search}&limit=25`); expect(response.status()).toBe(200);
    return (await response.json()).items.some((item: { id: string }) => item.id === assets[1].id);
  }, { timeout: 25_000 }).toBeTruthy();
  return { base, child, assets, sourceId: source.id as string };
}
function simpleDefinition(id: string, typeId: string): RelationTypeDefinition {
  return { formatVersion: 1, id, version: 1, label: 'Supports', inverseLabel: 'Supported by', direction: 'directed', sourceTypes: [{ typeId, includeDescendants: true }], targetTypes: [{ typeId, includeDescendants: true }], sourceStates: null, targetStates: null, cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } }, allowSelf: false, cycles: 'allow', attributes: {}, requiredOwner: false, lifecycle: life };
}
async function createEdge(page: Page, type: RelationTypeView, sourceId: string, targetId: string, overrides: Partial<RelationCreate> = {}, status = 201) {
  const [a, b] = await Promise.all([asset(page, sourceId), asset(page, targetId)]);
  const data: RelationCreate = { relationTypeId: type.relationTypeId, relationTypeVersion: type.currentVersion, sourceAssetId: sourceId, targetAssetId: targetId, sourceAssetVersion: a.version, targetAssetVersion: b.version, attributes: {}, ownerId: null, validFrom: null, validTo: null, visibility: 'tenant', allowedIdentityIds: [], ...overrides };
  const response = await page.request.post('/api/v1/relations', { headers: await headers(page), data }); expect(response.status()).toBe(status); return response.json();
}
function editData(value: RelationView): RelationEdit {
  return { sourceAssetVersion: value.source.assetVersion, targetAssetVersion: value.target.assetVersion, attributes: value.attributes, ownerId: value.ownerId, validFrom: value.validFrom, validTo: value.validTo, visibility: value.visibility, allowedIdentityIds: value.allowedIdentityIds };
}
async function previewType(page: Page, id: string) {
  const response = waitResponse(page, response => response.url().endsWith(`/relation-types/${id}/previews`) && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview relation impact', exact: true }).click(); const result = await response; expect(result.status()).toBe(200); return (await result.json()).preview;
}

test('MOD: authored relations preserve exact values and pins, enforce constraints, and recover stale edits and graph pages', async ({ page }) => {
  test.setTimeout(480_000); await login(page);
  const prefix = `relation_${Date.now()}`, { base, assets, sourceId } = await fixture(page, prefix);
  const [first, second, third, fourth] = assets; const id = `${prefix}_supports`;
  const members = (await (await page.request.get('/api/v1/members')).json()).items;
  const owner = members.find((member: { name: string }) => member.name === 'Harbor Owner'); expect(owner).toBeTruthy();
  await page.goto('/relation-types'); await page.getByRole('link', { name: 'New relation type', exact: true }).click();
  await page.getByRole('textbox', { name: /^Relation type identifier/ }).fill(id);
  await page.getByRole('textbox', { name: 'Forward label', exact: true }).fill('Supports');
  await page.getByRole('textbox', { name: 'Inverse label', exact: true }).fill('Supported by');
  for (const scope of ['Allowed source types', 'Allowed target types']) {
    const group = page.getByRole('group', { name: scope, exact: true });
    await group.locator('summary').click();
    await group.getByRole('searchbox', { name: 'Search asset types by identifier', exact: true }).fill(base.id);
    await group.getByRole('button', { name: 'Search types', exact: true }).click();
    const picker = group.getByRole('combobox', { name: `Asset type · ${scope}`, exact: true });
    await expect(picker).toBeEnabled(); await picker.selectOption(base.typeId);
    await group.getByRole('button', { name: 'Add allowed type', exact: true }).click();
    await group.getByRole('checkbox', { name: 'Include descendants at their actual assigned parent pins', exact: true }).check();
    await group.locator('summary').click();
  }
  await page.getByRole('combobox', { name: 'Allowed source states', exact: true }).selectOption('listed');
  await page.getByRole('textbox', { name: 'Only these states · Allowed source states', exact: true }).fill('draft');
  await page.getByRole('combobox', { name: 'Maximum outgoing relations', exact: true }).selectOption('bounded');
  await page.getByRole('spinbutton', { name: 'Maximum · Maximum outgoing relations', exact: true }).fill('2');
  await page.getByRole('combobox', { name: 'Cycles', exact: true }).selectOption('acyclic');
  await expect(page.getByRole('checkbox', { name: 'Allow an asset to relate to itself', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Add field', exact: true }).click();
  await page.getByRole('textbox', { name: 'Field identifier field_1', exact: true }).fill('amount'); await page.keyboard.press('Tab');
  await page.getByRole('textbox', { name: 'Display label amount', exact: true }).fill('Exact amount');
  await page.getByRole('combobox', { name: 'Field type amount', exact: true }).selectOption('decimal');
  await page.getByRole('spinbutton', { name: 'Precision amount', exact: true }).fill('30');
  await page.getByRole('spinbutton', { name: 'Scale amount', exact: true }).fill('10');
  await page.locator('[data-field-key="amount"]').getByRole('checkbox', { name: 'Required', exact: true }).check();
  await page.getByRole('checkbox', { name: 'Require an active owner', exact: true }).check();
  await capture(page, 'type-editor-en', '.relation-definition', [1440, 1024, 768, 390]);
  mkdirSync('.local/evidence', { recursive: true });
  console.info('Relation stage: export and validate definition');
  const download = page.waitForEvent('download', { timeout: 40_000 }); await page.getByRole('button', { name: 'Export relation type JSON', exact: true }).click();
  const exported = `.local/evidence/${id}.relation-type.json`; await (await download).saveAs(exported);
  const definition = JSON.parse(readFileSync(exported, 'utf8')) as RelationTypeDefinition;
  expect(definition).toMatchObject({ sourceTypes: [{ typeId: base.typeId, includeDescendants: true }], targetTypes: [{ typeId: base.typeId, includeDescendants: true }], attributes: { amount: { type: 'decimal', precision: 30, scale: 10, required: true } } });
  await page.getByLabel('Import relation type JSON', { exact: true }).setInputFiles({ name: 'duplicate.json', mimeType: 'application/json', buffer: Buffer.from('{"id":"a","id":"b"}') });
  await expect(page.locator('.validation-issues')).toContainText('Duplicate');
  await page.getByRole('button', { name: 'Return to last valid draft', exact: true }).click();
  await page.getByLabel('Import relation type JSON', { exact: true }).setInputFiles(exported);
  await expect(page.getByText('Definition validated. Existing relations still require a complete impact preview.', { exact: true })).toBeVisible();
  const createTypeResponse = waitResponse(page, response => response.url().endsWith('/relation-types') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Publish relation type', exact: true }).click(); const published = await createTypeResponse; expect(published.status()).toBe(201);
  console.info('Relation stage: published type and create form');
  const type: RelationTypeView = (await published.json()).type; expect(type.definition).toEqual(definition);
  await expect(page.getByRole('heading', { level: 1, name: 'Supports', exact: true })).toBeVisible();
  await page.goto(`/catalog/${first.id}?tab=relations`); await page.getByRole('button', { name: 'Add relation', exact: true }).click();
  const form = page.getByRole('dialog', { name: 'Create asserted relation', exact: true });
  await form.getByRole('searchbox', { name: 'Search relation types by identifier', exact: true }).fill(id);
  await form.getByRole('button', { name: 'Search relation types', exact: true }).click();
  await expect(form.getByRole('combobox', { name: 'Select relation type', exact: true })).toBeEnabled();
  await form.getByRole('combobox', { name: 'Select relation type', exact: true }).selectOption(type.relationTypeId);
  const target = form.getByRole('group', { name: 'Target asset', exact: true }); await target.locator('summary').click();
  await target.getByRole('searchbox', { name: 'Search assets · Target asset', exact: true }).fill(second.search);
  await target.getByRole('button', { name: 'Search assets', exact: true }).click();
  await expect(target.getByRole('combobox', { name: 'Select an asset · Target asset', exact: true })).toBeEnabled();
  await target.getByRole('combobox', { name: 'Select an asset · Target asset', exact: true }).selectOption(second.id); await target.locator('summary').click();
  const exact = '12345678901234567890.123456789';
  await form.getByRole('textbox', { name: 'Exact amount (amount)', exact: true }).fill(exact);
  await form.getByRole('textbox', { name: 'Valid from (UTC)', exact: true }).fill('2020-01-01T00:00:00.000Z');
  await form.getByRole('textbox', { name: 'Valid until (UTC)', exact: true }).fill('2099-01-01T00:00:00.000Z');
  const invalidOwner = waitResponse(page, response => response.url().endsWith('/relations') && response.request().method() === 'POST');
  await form.getByRole('button', { name: 'Create asserted relation', exact: true }).click(); expect((await invalidOwner).status()).toBe(422);
  expect((await (await page.request.get(`/api/v1/assets/${first.id}/relations`)).json()).items).toEqual([]);
  await form.getByRole('combobox', { name: 'Owner · Required', exact: true }).selectOption(owner.id);
  await capture(page, 'form-en');
  const createResponse = waitResponse(page, response => response.url().endsWith('/relations') && response.request().method() === 'POST');
  await form.getByRole('button', { name: 'Create asserted relation', exact: true }).click(); const createdResponse = await createResponse; expect(createdResponse.status()).toBe(201);
  const created: RelationView = (await createdResponse.json()).relation; await expect(form).toBeHidden();
  expect(created).toMatchObject({ attributes: { amount: exact }, relationTypeVersion: 1, state: 'draft', ownerId: owner.id, provenance: { origin: 'asserted', sourceObservedAt: null, confidence: null } });
  const overrides = { ownerId: owner.id, attributes: { amount: exact } };
  expect((await createEdge(page, type, first.id, second.id, overrides, 422)).code).toBe('RELATION_DUPLICATE');
  const extra: RelationView = (await createEdge(page, type, first.id, third.id, overrides)).relation;
  expect((await createEdge(page, type, first.id, fourth.id, overrides, 422)).code).toBe('RELATION_CARDINALITY');
  expect((await createEdge(page, type, third.id, first.id, overrides, 422)).code).toBe('RELATION_CYCLE');
  const endpointBefore = await asset(page, first.id);
  const deniedState = await page.request.post(`/api/v1/assets/${first.id}/type-state`, { headers: { ...await headers(page), 'If-Match': String(endpointBefore.version) }, data: { state: 'active' } });
  expect(deniedState.status()).toBe(422); expect((await deniedState.json()).code).toBe('RELATION_MIGRATION_REQUIRED');
  expect(await asset(page, first.id)).toEqual(endpointBefore);
  console.info('Relation stage: constraint failures and stale edit recovery');
  // A changed endpoint invalidates the edit, but not the user's decimal draft.
  await page.getByRole('button', { name: 'Edit relation', exact: true }).click();
  const edit = page.getByRole('dialog', { name: 'Edit relation', exact: true }); const changedExact = '99999999999999999999.000000001';
  await edit.getByRole('textbox', { name: 'Exact amount (amount)', exact: true }).fill(changedExact);
  await changeDescription(page, first.id, `Synthetic concurrent endpoint edit ${crypto.randomUUID()}`);
  const staleEdit = waitResponse(page, response => response.url().endsWith(`/relations/${created.id}`) && response.request().method() === 'PATCH');
  await edit.getByRole('button', { name: 'Save changes', exact: true }).click(); expect((await staleEdit).status()).toBe(409);
  expect((await relation(page, created.id)).attributes.amount).toBe(exact);
  await edit.getByRole('button', { name: 'Reload relation and endpoint revisions', exact: true }).click();
  await expect(edit.getByText('Current revisions loaded. Your editable fields are preserved; review before saving.', { exact: true })).toBeVisible();
  await expect(edit.getByRole('textbox', { name: 'Exact amount (amount)', exact: true })).toHaveValue(changedExact);
  await edit.getByRole('button', { name: 'Save changes', exact: true }).click(); await expect(edit).toBeHidden();
  expect((await relation(page, created.id)).attributes.amount).toBe(changedExact);
  await page.getByRole('combobox', { name: 'Next lifecycle state', exact: true }).selectOption('active');
  await page.getByRole('button', { name: 'Transition relation', exact: true }).click(); await expect(page.getByTestId('relation-current-state')).toHaveText('active');
  await capture(page, 'detail-en');
  await page.getByRole('link', { name: 'Relation history', exact: true }).click();
  await page.locator('.relation-history-list summary').first().click(); await capture(page, 'history-en', '.relation-history-list');
  const revisions = await (await page.request.get(`/api/v1/relations/${created.id}/revisions`)).json();
  expect(revisions.items.map((item: { version: number }) => item.version)).toEqual([1, 2, 3]);
  expect(revisions.items[0].snapshot.attributes.amount).toBe(exact); expect(revisions.items[0].snapshot.source.assetVersion).toBe(created.source.assetVersion);
  console.info('Relation stage: type preview and stale publication');
  // Whole-cohort preview is fenced against a concurrent relation revision.
  await page.goto(`/relation-types/${id}/edit`); await page.getByRole('textbox', { name: 'Forward label', exact: true }).fill('Supports reviewed');
  const initialPreview = await previewType(page, id); expect(initialPreview).toMatchObject({ relationCount: 2, pinsPreserved: true, requiresExplicitMigration: false });
  await page.getByRole('button', { name: 'Publish relation type', exact: true }).click();
  const confirmation = page.getByRole('dialog', { name: 'Publish relation type', exact: true });
  await expect(confirmation.getByRole('button', { name: 'Publish relation type', exact: true })).toBeDisabled();
  const consent = confirmation.getByRole('checkbox', { name: 'I reviewed these exact relation changes and this preview digest.', exact: true }); await consent.focus(); await page.keyboard.press('Space');
  const oldExtra = await relation(page, extra.id);
  const changedExtra = await page.request.patch(`/api/v1/relations/${extra.id}`, { headers: { ...await headers(page), 'If-Match': String(oldExtra.version) }, data: { ...editData(oldExtra), validFrom: '2020-01-01T00:00:00.000Z' } }); expect(changedExtra.status()).toBe(200);
  const stalePublish = waitResponse(page, response => response.url().endsWith(`/relation-types/${id}/versions`) && response.request().method() === 'POST');
  await confirmation.getByRole('button', { name: 'Publish relation type', exact: true }).click(); expect((await stalePublish).status()).toBe(409);
  await expect(confirmation).toBeHidden(); expect((await (await page.request.get(`/api/v1/relation-types/${id}`)).json()).type.currentVersion).toBe(1);
  await page.getByRole('button', { name: 'Reload current version and preserve draft', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Forward label', exact: true })).toHaveValue('Supports reviewed'); await previewType(page, id);
  await page.getByRole('button', { name: 'Publish relation type', exact: true }).click(); await consent.check();
  await confirmation.getByRole('button', { name: 'Publish relation type', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Supports reviewed', exact: true })).toBeVisible();
  expect((await relation(page, created.id)).relationTypeVersion).toBe(1); await capture(page, 'type-detail-en');
  await page.goto(`/relation-types/${id}/edit`); await page.getByRole('button', { name: 'Remove field amount', exact: true }).click();
  expect((await previewType(page, id)).requiresExplicitMigration).toBeTruthy();
  await expect(page.getByRole('button', { name: 'Publish relation type', exact: true })).toBeDisabled();
  console.info('Relation stage: table and graph pagination');
  // Table pages are bound to the current graph fence, not blindly appended.
  await page.goto(`/catalog/${first.id}?tab=relations&relationTypeId=${type.relationTypeId}`);
  await page.locator('.asset-relations > .model-pager').getByRole('combobox', { name: 'Rows per page', exact: true }).selectOption('1');
  await expect(page.locator('.asset-relations .relation-table tbody tr')).toHaveCount(1);
  await changeDescription(page, first.id, `Synthetic stale graph fence ${crypto.randomUUID()}`);
  const stalePage = waitResponse(page, response => response.url().includes(`/assets/${first.id}/relations?`) && new URL(response.url()).searchParams.has('cursor'));
  await page.locator('.asset-relations > .model-pager').getByRole('button', { name: 'Next page', exact: true }).click(); expect((await stalePage).status()).toBe(409);
  await expect(page.locator('.asset-relations .relation-table')).toHaveCount(0);
  await page.getByRole('button', { name: 'Restart this graph query', exact: true }).click();
  await expect(page.locator('.asset-relations .relation-table tbody tr')).toHaveCount(1);
  await page.locator('.asset-relations > .model-pager').getByRole('combobox', { name: 'Rows per page', exact: true }).selectOption('25');
  await expect(page.locator('.asset-relations .relation-table tbody tr')).toHaveCount(2); await capture(page, 'table-en', '.asset-relations');
  await page.getByRole('link', { name: 'Relations graph', exact: true }).click();
  await expect(page.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(3);
  await page.getByRole('combobox', { name: 'Relations per graph page', exact: true }).selectOption('1');
  await expect(page.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(2);
  await changeDescription(page, first.id, `Synthetic graph expansion fence ${crypto.randomUUID()}`);
  const staleExpansion = waitResponse(page, response => response.url().includes(`/assets/${first.id}/graph?`) && new URL(response.url()).searchParams.has('cursor'));
  await page.getByRole('button', { name: 'Load next graph page', exact: true }).click(); expect((await staleExpansion).status()).toBe(409);
  await expect(page.locator('.relation-graph-canvas')).toHaveCount(0); await expect(page.locator('.relation-graph-section .relation-table')).toHaveCount(0);
  const restartGraph = waitResponse(page, response => response.url().includes(`/assets/${first.id}/graph?`) && !new URL(response.url()).searchParams.has('cursor'));
  await page.getByRole('button', { name: 'Restart this graph query', exact: true }).click();
  const firstGraphResponse = await restartGraph; expect(firstGraphResponse.status()).toBe(200); const firstGraph: RelationGraphPage = await firstGraphResponse.json();
  expect(firstGraph.edges).toHaveLength(1); expect(firstGraph.nextCursor).toBeTruthy();
  await expect(page.locator('.relation-graph-section .relation-table tbody tr')).toHaveCount(1);
  const expandGraph = waitResponse(page, response => response.url().includes(`/assets/${first.id}/graph?`) && new URL(response.url()).searchParams.has('cursor'));
  await page.getByRole('button', { name: 'Load next graph page', exact: true }).click();
  const secondGraphResponse = await expandGraph; expect(secondGraphResponse.status()).toBe(200);
  expect(new URL(secondGraphResponse.url()).searchParams.get('validAt')).toBe(firstGraph.validAt);
  const secondGraph: RelationGraphPage = await secondGraphResponse.json();
  expect(secondGraph.validAt).toBe(firstGraph.validAt); expect(secondGraph.graphRevision).toBe(firstGraph.graphRevision);
  expect(new Set([...firstGraph.edges, ...secondGraph.edges].map(edge=>edge.id))).toEqual(new Set([created.id,extra.id]));
  await expect(page.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(3);
  await expect(page.locator('.relation-graph-section .relation-table tbody tr')).toHaveCount(2);
  await expect(page.getByRole('button', { name: 'Load next graph page', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Zoom in', exact: true }).focus(); await page.keyboard.press('Enter');
  await page.getByRole('button', { name: 'Fit graph', exact: true }).click(); await capture(page, 'graph-en', '.relation-graph-section');
  await page.getByRole('button', { name: 'Colour theme: Dark', exact: true }).click(); await page.locator('#language').selectOption('ar');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl'); await capture(page, 'graph-ar-dark', '.relation-graph-section');
  await page.locator('#language').selectOption('en'); await page.getByRole('button', { name: 'Colour theme: Light', exact: true }).click();
  console.info('Relation stage: post-assertion real connector rescan');
  // Run the actual connector again after governed assertions exist. Connector
  // observations may advance endpoint revisions, but cannot rewrite assertions
  // or any previously recorded relation snapshot.
  const assertion = (value: RelationView) => ({
    id:value.id, relationTypeId:value.relationTypeId, relationTypeKey:value.relationTypeKey, relationTypeVersion:value.relationTypeVersion,
    sourceAssetId:value.source.assetId, targetAssetId:value.target.assetId, version:value.version, attributes:value.attributes,
    ownerId:value.ownerId, state:value.state, validFrom:value.validFrom, validTo:value.validTo, visibility:value.visibility,
    allowedIdentityIds:value.allowedIdentityIds, status:value.status, provenance:value.provenance,
    createdAt:value.createdAt, createdBy:value.createdBy, updatedAt:value.updatedAt, updatedBy:value.updatedBy,
  });
  const beforeRescan = [];
  for (const edgeId of [created.id, extra.id]) {
    const live = await relation(page, edgeId); const historyResponse = await page.request.get(`/api/v1/relations/${edgeId}/revisions`);
    expect(historyResponse.status()).toBe(200); beforeRescan.push({ edgeId, live, history:await historyResponse.json() });
  }
  const rescan = await page.request.post(`/api/v1/sources/${sourceId}/scans`, { headers:await headers(page), data:{} });
  expect(rescan.status()).toBe(202); const rescanJob = (await rescan.json()).job;
  await expect.poll(async () => {
    const response = await page.request.get(`/api/v1/jobs/${rescanJob.id}`); expect(response.status()).toBe(200);
    return (await response.json()).job.status;
  }, { timeout:100_000, intervals:[1000,2000] }).toBe('succeeded');
  for (const before of beforeRescan) {
    const after = await relation(page, before.edgeId);
    expect(assertion(after)).toEqual(assertion(before.live));
    expect(after.source.assetVersion).toBeGreaterThanOrEqual(before.live.source.assetVersion);
    expect(after.target.assetVersion).toBeGreaterThanOrEqual(before.live.target.assetVersion);
    const historyResponse = await page.request.get(`/api/v1/relations/${before.edgeId}/revisions`);
    expect(historyResponse.status()).toBe(200); expect(await historyResponse.json()).toEqual(before.history);
  }
  await page.goto(`/relations/${created.id}`); await page.getByRole('button', { name: 'Remove relation', exact: true }).click();
  const removal = page.getByRole('dialog', { name: 'Remove this asserted relation?', exact: true }); await capture(page, 'removal-en');
  await removal.getByRole('button', { name: 'Remove relation', exact: true }).click(); await expect(removal).toBeHidden();
  expect((await relation(page, created.id)).status).toBe('tombstoned');
  await expect(page.getByRole('button', { name: 'Edit relation', exact: true })).toHaveCount(0);
  const historyAfter = await (await page.request.get(`/api/v1/relations/${created.id}/revisions`)).json();
  expect(historyAfter.items.map((item: { version: number }) => item.version)).toEqual([1, 2, 3, 4]); expect(historyAfter.items[3].snapshot.status).toBe('tombstoned');
  const audit = await (await page.request.get('/api/v1/audit')).json();
  expect(audit.items.some((event: { action: string; resourceId: string }) => event.action === 'relation.tombstoned' && event.resourceId === created.id)).toBeTruthy();
});

test('MOD: restricted relation bridges, current permissions and independent tenants bound graph and history access', async ({ browser }) => {
  test.setTimeout(240_000); const steward = await browser.newContext(); const page = await steward.newPage(); await login(page);
  const prefix = `relation_access_${Date.now()}`, { base, assets } = await fixture(page, prefix);
  const [root, privateNode, visibleNode, unreachable] = assets; const definition = simpleDefinition(`${prefix}_supports`, base.typeId);
  const published = await page.request.post('/api/v1/relation-types', { headers: await headers(page), data: { definition } }); expect(published.status()).toBe(201);
  console.info('Relation stage: published type and create form');
  const type: RelationTypeView = (await published.json()).type;
  const hidden: RelationView = (await createEdge(page, type, root.id, privateNode.id)).relation;
  const visible: RelationView = (await createEdge(page, type, root.id, visibleNode.id)).relation;
  await createEdge(page, type, privateNode.id, unreachable.id);
  const consumer = await browser.newContext(); const readPage = await consumer.newPage(); await login(readPage, 'consumer');
  const graphUrl = `/catalog/${root.id}?tab=relations&view=graph&depth=3&relationTypeId=${type.relationTypeId}`;
  await readPage.goto(graphUrl); await expect(readPage.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(4);
  await expect(readPage.getByRole('button', { name: 'Add relation', exact: true })).toHaveCount(0);
  // Real UI narrows the edge ACL. Refresh must remove both its inaccessible hop
  // and the otherwise visible downstream node, without phantom placeholders.
  await page.goto(`/relations/${hidden.id}`); await page.getByRole('button', { name: 'Edit relation', exact: true }).click();
  const edit = page.getByRole('dialog', { name: 'Edit relation', exact: true });
  await edit.getByRole('combobox', { name: 'Relation visibility', exact: true }).selectOption('restricted');
  const me = await (await page.request.get('/api/v1/me')).json();
  await expect(edit.locator('.relation-member-list input:checked')).toHaveCount(1);
  await edit.getByRole('button', { name: 'Save changes', exact: true }).click(); await expect(edit).toBeHidden();
  expect((await relation(page, hidden.id)).allowedIdentityIds).toEqual([me.user.id]);
  const refresh = waitResponse(readPage, response => response.url().includes(`/assets/${root.id}/graph?`));
  await readPage.getByRole('button', { name: 'Restart this graph query', exact: true }).click(); expect((await refresh).status()).toBe(200);
  await expect(readPage.locator('.relation-graph-canvas .react-flow__node')).toHaveCount(2);
  await expect(readPage.locator(`.relation-graph-canvas a[href="/catalog/${privateNode.id}"]`)).toHaveCount(0);
  await expect(readPage.locator(`.relation-graph-canvas a[href="/catalog/${unreachable.id}"]`)).toHaveCount(0);
  const graphResponse = await readPage.request.get(`/api/v1/assets/${root.id}/graph?depth=3&relationTypeId=${type.relationTypeId}`); expect(graphResponse.status()).toBe(200);
  const graph: RelationGraphPage = await graphResponse.json(); expect(graph.nodes.map(node => node.assetId).sort()).toEqual([root.id, visibleNode.id].sort()); expect(graph.edges.map(edge => edge.id)).toEqual([visible.id]);
  expect((await readPage.request.get(`/api/v1/relations/${hidden.id}`)).status()).toBe(404);
  expect((await readPage.request.get(`/api/v1/relations/${hidden.id}/revisions`)).status()).toBe(403); // Consumer has no audit permission, independent of relation existence.
  await readPage.goto(`/relations/${visible.id}`); await expect(readPage.getByRole('heading', { level: 1, name: 'Supports', exact: true })).toBeVisible();
  await expect(readPage.getByRole('button', { name: 'Edit relation', exact: true })).toHaveCount(0); await expect(readPage.getByRole('button', { name: 'Transition relation', exact: true })).toHaveCount(0);
  const before = await relation(page, visible.id);
  const denied = await readPage.request.patch(`/api/v1/relations/${visible.id}`, { headers: { ...await headers(readPage), 'If-Match': String(before.version) }, data: editData(before) }); expect(denied.status()).toBe(403);
  expect(await relation(page, visible.id)).toEqual(before);
  await readPage.goto(`/relation-types/${definition.id}`); await expect(readPage.getByRole('link', { name: 'Publish a new relation type version', exact: true })).toHaveCount(0);
  expect((await readPage.request.post('/api/v1/relation-types', { headers: await headers(readPage), data: { definition: { ...definition, id: `${prefix}_denied` } } })).status()).toBe(403);
  const summit = await browser.newContext(); const other = await summit.newPage(); await login(other, 'summit');
  expect((await other.request.get(`/api/v1/relations/${visible.id}`)).status()).toBe(404);
  expect((await other.request.get(`/api/v1/relations/${visible.id}/revisions`)).status()).toBe(404);
  expect((await other.request.get(`/api/v1/relation-types/${definition.id}`)).status()).toBe(404);
  expect((await other.request.get(`/api/v1/assets/${root.id}/graph`)).status()).toBe(404);
  await other.goto(`/relations/${visible.id}`); await expect(other.getByRole('heading', { level: 1, name: 'Supports', exact: true })).toHaveCount(0);
  await steward.close(); await consumer.close(); await summit.close();
});
