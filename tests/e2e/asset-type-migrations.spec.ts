// SPDX-License-Identifier: Apache-2.0
import { test, expect, type Page, type Browser } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { AssetTypeMigrationPlan } from '../../packages/domain/src/asset-type-migration.ts';
import type { TypeMigrationPreview, TypeMigrationReceipt } from '../../packages/domain/src/asset-type-migration-contracts.ts';

const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
async function login(page: Page, username = 'steward') {
  page.on('response', response => { if (response.status() === 429) console.info(JSON.stringify({ diagnostic: 'browser_request_budget', method: response.request().method(), status: response.status(), path: new URL(response.url()).pathname })); });
  await page.goto('/auth/login');
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(credentials.personas[username]);
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page).toHaveURL('http://localhost:4310/');
  await expect(page.getByRole('heading', { level: 1, name: username === 'summit' ? 'Summit Logistics' : 'Harbor Retail' })).toBeVisible();
}
async function headers(page: Page) {
  const me = await (await page.request.get('/api/v1/me')).json();
  return { 'X-CSRF-Token': me.csrfToken, Origin: 'http://localhost:4310', 'Idempotency-Key': crypto.randomUUID() };
}
async function paceRequestBudget({ browser }: { browser: Browser }) {
  test.setTimeout(75_000); const context = await browser.newContext(); const response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']), remaining = Number(response.headers()['x-ratelimit-remaining']); await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 220) {
    console.info(`Type migration fixture pacing: waiting ${reset + 1}s for the configured request budget to reset`);
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
    await page.evaluate(async () => { await Promise.all(document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity).map(animation => animation.finished.catch(() => undefined))); });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await page.screenshot({ path: `docs/verification/screenshots/m2-type-migration-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function createType(page: Page, definition: AssetTypeDefinition) {
  const response = await page.request.post('/api/v1/asset-types', { headers: await headers(page), data: { definition } });
  expect(response.status()).toBe(201); return (await response.json()).type;
}
async function publishType(page: Page, definition: AssetTypeDefinition) {
  const h = { ...await headers(page), 'If-Match': String(definition.version - 1) };
  const preview = await page.request.post(`/api/v1/asset-types/${definition.id}/previews`, { headers: h, data: { definition } });
  expect(preview.status()).toBe(200);
  const response = await page.request.post(`/api/v1/asset-types/${definition.id}/versions`, { headers: h, data: { definition, previewDigest: (await preview.json()).preview.previewDigest } });
  expect(response.status()).toBe(201); return (await response.json()).type;
}
async function scannedAssets(page: Page) {
  const h = await headers(page);
  const response = await page.request.post('/api/v1/sources', { headers: h, data: { name: `Synthetic type migration browser ${Date.now()}`, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } });
  expect(response.status()).toBe(201); const { source } = await response.json();
  const scan = await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: { ...h, 'Idempotency-Key': crypto.randomUUID() }, data: {} });
  expect(scan.status()).toBe(202); const { job } = await scan.json();
  await expect.poll(async () => (await (await page.request.get(`/api/v1/jobs/${job.id}`)).json()).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  const result: string[] = [];
  for (const name of ['orders', 'customers', 'products', 'order_lines']) {
    let id: string | undefined;
    await expect.poll(async () => {
      let cursor: string | null = null;
      for (let count = 0; count < 20; count++) {
        const response = await page.request.get(`/api/v1/assets?q=${name}&type=table&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
        expect(response.status()).toBe(200); const body: { items: { id: string; name: string; sourceId: string }[]; nextCursor: string | null } = await response.json();
        id = body.items.find((item: { name: string; sourceId: string }) => item.sourceId === source.id && item.name === name)?.id;
        cursor = body.nextCursor; if (id || !cursor) break;
      }
      return !!id;
    }, { timeout: 25_000 }).toBeTruthy(); result.push(id!);
  }
  return result;
}
async function assign(page: Page, assetId: string, modelId: string, modelVersion: number, attributes: Record<string, unknown>) {
  const before = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  const response = await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(before.assetVersion) }, data: { modelId, modelVersion, attributes } });
  expect(response.status()).toBe(200); return response.json();
}
async function acknowledge(page: Page) {
  const attributeChecks = page.getByRole('checkbox', { name: /^I acknowledge this change/ });
  await expect(attributeChecks).toHaveCount(1); await attributeChecks.check();
  for (const name of ['Parent version pins change', 'Required ownership changes', 'Resolved lifecycle changes']) await page.getByRole('checkbox', { name, exact: true }).check();
}
async function preview(page: Page, id: string, status = 200) {
  const response = page.waitForResponse(response => response.url().endsWith(`/asset-types/${id}/migration-previews`) && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview transformed values', exact: true }).click(); const result = await response; expect(result.status()).toBe(status); return result.json();
}
const life = { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };

test('MOD: complete typed migration handles mixed pins, explicit owners and states, stale consent and immutable tuples', async ({ page }) => {
  test.setTimeout(360_000); await login(page);
  const prefix = `type_move_${Date.now()}`, id = `${prefix}_subject`, oldParent = `${prefix}_old`, newParent = `${prefix}_new`, childId = `${prefix}_child`;
  const amount = { type: 'decimal' as const, precision: 30, scale: 10, required: true, label: 'Exact amount' };
  const base: AssetTypeDefinition = { formatVersion: 1, id: oldParent, version: 1, parents: [], attributes: { amount }, overrideAttributes: [], requiredOwner: false, lifecycle: life };
  await createType(page, base);
  await createType(page, { ...base, id: newParent, requiredOwner: true, lifecycle: { initial: 'review', states: ['review', 'live', 'done'], transitions: [{ from: 'review', to: 'live' }, { from: 'live', to: 'done' }] } });
  const subject: AssetTypeDefinition = { ...base, id, parents: [{ id: oldParent, version: 1 }], attributes: { legacy: { type: 'text', label: 'Legacy note' } }, lifecycle: null };
  const created = await createType(page, subject);
  await publishType(page, { ...subject, version: 2, attributes: { ...subject.attributes, note: { type: 'text', label: 'Note' } } });
  const child = await createType(page, { ...subject, id: childId, parents: [{ id, version: 1 }], attributes: {} });
  const [first, second, descendant, late] = await scannedAssets(page);
  const exact = '12345678901234567890.123456789';
  const firstBefore = await assign(page, first, id, 1, { amount: exact, legacy: 'Synthetic retired annotation' });
  const secondBefore = await assign(page, second, id, 2, { amount: exact, legacy: 'Synthetic second annotation', note: 'Preserved note' });
  const descendantBefore = await assign(page, descendant, childId, 1, { amount: exact, legacy: 'Child keeps old policy' });
  await page.goto(`/asset-types/${id}`); await page.getByRole('link', { name: 'Plan type migration', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Migrate asset type', exact: true })).toBeVisible();
  await page.getByRole('button', { name: `Remove parent ${oldParent}`, exact: true }).click();
  await page.locator('.asset-type-parent-browser > summary').click();
  await page.getByRole('searchbox', { name: 'Search asset types by identifier', exact: true }).fill(newParent);
  await page.getByRole('button', { name: 'Search types', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Select parent type', exact: true })).toBeEnabled();
  await page.getByRole('combobox', { name: 'Select parent type', exact: true }).selectOption(newParent);
  await page.getByRole('button', { name: 'Add pinned parent', exact: true }).click();
  await page.getByRole('button', { name: 'Remove field legacy', exact: true }).click();
  await capture(page, 'definition-en', '.migration-definition', [1440, 1024, 768, 390]);
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Operation type', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Operation type', exact: true }).selectOption('remove');
  await page.getByRole('button', { name: 'Add operation', exact: true }).click();
  await page.getByRole('textbox', { name: 'Field path · Operation 1', exact: true }).fill('legacy');
  await acknowledge(page);
  await preview(page, id, 422);
  await expect(page.locator('.validation-issues')).toContainText('/assets/');
  expect(await (await page.request.get(`/api/v1/assets/${first}/attributes`)).json()).toEqual(firstBefore);
  expect(await (await page.request.get(`/api/v1/assets/${second}/attributes`)).json()).toEqual(secondBefore);
  expect((await (await page.request.get(`/api/v1/asset-types/${id}`)).json()).type.currentVersion).toBe(2);
  const members = (await (await page.request.get('/api/v1/members')).json()).items;
  const owner = members.find((member: { name: string }) => member.name === 'Harbor Owner'); expect(owner).toBeTruthy();
  // Scope recovery must keep an unfinished visual owner choice even when its
  // controls disappear after a target edit and a concurrent head publication.
  await page.getByRole('combobox', { name: `Ownership action ${first}`, exact: true }).selectOption('replace');
  await expect(page.getByRole('combobox', { name: `Replacement owner ${first}`, exact: true })).toHaveValue('');
  await page.getByRole('textbox', { name: 'Display label note', exact: true }).fill('Reviewed note');
  await publishType(page, { ...subject, version: 3, attributes: { ...subject.attributes, note: { type: 'text', label: 'Note' } } });
  const staleTarget = page.waitForResponse(response => response.url().endsWith(`/asset-types/${id}/previews`) && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click(); expect((await staleTarget).status()).toBe(409);
  await page.getByRole('button', { name: 'Reload scope and current version', exact: true }).click();
  await expect(page.getByText('Current scope reloaded. Draft fields and operations are preserved; review changes and preview again.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Field path · Operation 1', exact: true })).toHaveValue('legacy');
  await expect(page.getByRole('combobox', { name: `Replacement owner ${first}`, exact: true })).toHaveValue('');
  await expect(page.getByRole('textbox', { name: 'Display label note', exact: true })).toHaveValue('Reviewed note');
  for (const asset of [first, second]) {
    await page.getByRole('combobox', { name: `Ownership action ${asset}`, exact: true }).selectOption('replace');
    await page.getByRole('combobox', { name: `Replacement owner ${asset}`, exact: true }).selectOption(owner.id);
  }
  for (const [index, sourceVersion, state] of [[1, '1', 'review'], [2, '2', 'live']] as const) {
    await page.getByRole('button', { name: 'Add state mapping', exact: true }).click();
    await page.getByRole('combobox', { name: `Source model version ${index}`, exact: true }).selectOption(sourceVersion);
    await page.getByRole('combobox', { name: `Source lifecycle state ${index}`, exact: true }).selectOption('draft');
    await page.getByRole('combobox', { name: `Target lifecycle state ${index}`, exact: true }).selectOption(state);
  }
  await acknowledge(page);
  // A new asset on an already included source version changes the cohort but
  // not sourceVersions. Its owner error must still have a usable refresh path.
  await assign(page, late, id, 2, { amount: exact, legacy: 'Late same-version asset' });
  await preview(page, id, 422);
  await expect(page.getByRole('combobox', { name: `Ownership action ${late}`, exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Reload scope and current version', exact: true }).click();
  await expect(page.getByText('Current scope reloaded. Draft fields and operations are preserved; review changes and preview again.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click();
  await expect(page.getByRole('combobox', { name: `Replacement owner ${first}`, exact: true })).toHaveValue(owner.id);
  await expect(page.getByRole('combobox', { name: `Ownership action ${late}`, exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: `Ownership action ${late}`, exact: true }).selectOption('replace');
  await page.getByRole('combobox', { name: `Replacement owner ${late}`, exact: true }).selectOption(owner.id);
  await acknowledge(page);
  // A JSON/visual mode toggle is not a fresh acknowledgement after target edits.
  const planSection = page.getByRole('region', { name: 'Transformation plan', exact: true });
  await planSection.getByRole('button', { name: 'JSON source', exact: true }).click();
  const stalePlanText = await page.getByRole('textbox', { name: /^Migration plan JSON(?:\s|$)/ }).inputValue();
  expect(JSON.parse(stalePlanText).acknowledgedPolicyChanges).toHaveLength(3);
  await page.getByRole('textbox', { name: 'Display label note', exact: true }).fill('Final reviewed note');
  await planSection.getByRole('button', { name: 'Visual editor', exact: true }).click();
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click();
  for (const box of await page.getByRole('checkbox', { name: /^I acknowledge this change/ }).all()) await expect(box).not.toBeChecked();
  for (const box of await page.locator('.type-migration-policy-acks input[type=checkbox]').all()) await expect(box).not.toBeChecked();
  await acknowledge(page);
  await capture(page, 'policy-en', '.type-migration-policy-editor');
  const planDownload = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export plan JSON', exact: true }).click();
  const planFile = `.local/evidence/${id}.typed-plan.json`; await (await planDownload).saveAs(planFile);
  const plan = JSON.parse(readFileSync(planFile, 'utf8')) as AssetTypeMigrationPlan;
  expect(plan.typeId).toBe(created.typeId); expect(plan.attributes.sourceVersions).toEqual([1, 2]); expect(plan.owner.overrides).toHaveLength(3); expect(plan.lifecycle.mappings).toEqual([{ sourceVersion: 1, from: 'draft', to: 'review' }, { sourceVersion: 2, from: 'draft', to: 'live' }]);
  await page.getByLabel('Import plan JSON', { exact: true }).setInputFiles({ name: 'duplicate-plan.json', mimeType: 'application/json', buffer: Buffer.from('{"typeId":"first","typeId":"second"}') });
  await expect(page.locator('.validation-issues')).toContainText('Duplicate');
  await page.getByRole('button', { name: 'Return to last valid draft', exact: true }).click();
  await page.getByLabel('Import plan JSON', { exact: true }).setInputFiles(planFile);
  await expect(page.getByText('Plan syntax validated. Preview is still required to validate all affected values.', { exact: true })).toBeVisible();
  const initialPreview = (await preview(page, id)).preview as TypeMigrationPreview;
  expect(initialPreview.assetCount).toBe(3); expect(initialPreview.policyChanges).toEqual(['lifecycle_changed', 'parents_changed', 'required_owner_changed']);
  expect(initialPreview.assets.find(asset => asset.assetId === first)).toMatchObject({ before: { modelVersion: 1, ownerId: null, state: 'draft' }, after: { modelVersion: 4, ownerId: owner.id, state: 'review', attributes: { amount: exact } } });
  expect(initialPreview.assets.find(asset => asset.assetId === second)).toMatchObject({ after: { state: 'live', attributes: { amount: exact, note: 'Preserved note' } } });
  expect(initialPreview.assets.every(asset => !Object.hasOwn(asset.after.attributes, 'legacy'))).toBeTruthy();
  await capture(page, 'preview-en', '.type-migration-preview');
  await capture(page, 'values-en', '.type-migration-tuples');
  await page.getByRole('button', { name: 'Review execution', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Confirm asset-type migration', exact: true });
  await expect(dialog.getByRole('button', { name: 'Execute migration', exact: true })).toBeDisabled();
  const consent = dialog.getByRole('checkbox', { name: 'I reviewed these exact asset tuples, policy changes and migration digest.', exact: true });
  await consent.focus(); await page.keyboard.press('Space'); await expect(consent).toBeChecked();
  const edit = await page.request.patch(`/api/v1/assets/${first}`, { headers: { ...await headers(page), 'If-Match': String(firstBefore.assetVersion) }, data: { description: 'Synthetic concurrent edit after typed preview' } });
  expect(edit.status()).toBe(200);
  const concurrent = await (await page.request.get(`/api/v1/assets/${first}/attributes`)).json();
  const stale = page.waitForResponse(response => response.url().endsWith(`/asset-types/${id}/migrations`) && response.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Execute migration', exact: true }).click(); expect((await stale).status()).toBe(409);
  await expect(dialog).toBeHidden(); await expect(page.getByRole('button', { name: 'Review execution', exact: true })).toBeDisabled();
  expect(await (await page.request.get(`/api/v1/assets/${first}/attributes`)).json()).toEqual(concurrent);
  expect((await (await page.request.get(`/api/v1/asset-types/${id}`)).json()).type.currentVersion).toBe(3);
  await page.getByRole('button', { name: 'Reload scope and current version', exact: true }).click();
  await expect(page.getByText('Current scope reloaded. Draft fields and operations are preserved; review changes and preview again.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Review resolved target', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Field path · Operation 1', exact: true })).toHaveValue('legacy');
  await expect(page.getByRole('combobox', { name: `Replacement owner ${first}`, exact: true })).toHaveValue(owner.id);
  for (const box of await page.locator('.type-migration-policy-acks input[type=checkbox]').all()) await expect(box).not.toBeChecked();
  await acknowledge(page); const finalPreview = (await preview(page, id)).preview as TypeMigrationPreview;
  expect(finalPreview.previewDigest).not.toBe(initialPreview.previewDigest);
  await page.getByRole('button', { name: 'Review execution', exact: true }).click(); await expect(consent).not.toBeChecked();
  await capture(page, 'confirmation-en'); await consent.focus(); await page.keyboard.press('Space');
  const executed = page.waitForResponse(response => response.url().endsWith(`/asset-types/${id}/migrations`) && response.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Execute migration', exact: true }).click(); const result = await executed; expect(result.status()).toBe(201); const { receipt } = await result.json() as { receipt: TypeMigrationReceipt };
  await expect(page).toHaveURL(`http://localhost:4310/asset-types/${id}/migrations/${receipt.id}`);
  await expect(page.getByRole('heading', { name: 'Asset-type migration receipt', exact: true })).toBeVisible(); await page.reload();
  await expect(page.getByText(receipt.id, { exact: true })).toBeVisible(); expect(receipt.assets.map(asset => asset.after)).toEqual(finalPreview.assets.map(asset => asset.after));
  expect(await (await page.request.get(`/api/v1/assets/${descendant}/attributes`)).json()).toEqual(descendantBefore);
  expect((await (await page.request.get(`/api/v1/asset-types/${childId}`)).json()).type).toEqual(child);
  for (const asset of receipt.assets) {
    const current = await (await page.request.get(`/api/v1/assets/${asset.assetId}`)).json();
    expect(current.asset).toMatchObject({ modelId: id, modelVersion: 4, ownerId: owner.id, typeState: asset.after.state, attributes: asset.after.attributes, version: asset.toAssetVersion });
    expect(asset.after.attributes.amount).toBe(exact);
  }
  const receiptDownload = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export receipt JSON', exact: true }).click(); const receiptFile = `.local/evidence/${id}.typed-receipt.json`; await (await receiptDownload).saveAs(receiptFile); expect(JSON.parse(readFileSync(receiptFile, 'utf8'))).toEqual(receipt);
  expect((await (await page.request.get(`/api/v1/asset-types/${id}/migrations/${receipt.id}`)).json()).receipt).toEqual(receipt);
  await capture(page, 'receipt-en');
  await page.goto(`/catalog/${first}?tab=history`); await page.getByRole('button', { name: 'Asset type and policies migrated', exact: true }).click();
  await page.getByRole('dialog').getByRole('link', { name: 'Asset-type migration receipt', exact: true }).click();
  await expect(page).toHaveURL(`http://localhost:4310/asset-types/${id}/migrations/${receipt.id}`);
  await expect(page.getByRole('heading', { name: 'Asset-type migration receipt', exact: true })).toBeVisible();
  await page.locator('#language').selectOption('ar'); await page.getByRole('button', { name: 'نمط الألوان: داكن', exact: true }).click(); await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await capture(page, 'receipt-ar-dark', undefined, [390]);
  await page.goto(`/asset-types/${id}/migrate`); await expect(page.getByRole('heading', { name: 'ترحيل نوع الأصل', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'مراجعة الهدف المحسوم', exact: true }).click(); await expect(page.locator('.type-migration-policy-editor')).toBeVisible();
  await capture(page, 'editor-ar-dark', '.type-migration-policy-editor', [390]);
});

test('MOD: typed migration ingress and immutable receipts enforce permissions and tenant scope', async ({ browser }) => {
  test.setTimeout(240_000); const setup = await browser.newContext(); const page = await setup.newPage(); await login(page);
  const id = `type_move_scope_${Date.now()}`;
  const definition: AssetTypeDefinition = { formatVersion: 1, id, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: life };
  const type = await createType(page, definition); const target = { ...definition, version: 2 };
  const plan: AssetTypeMigrationPlan = { formatVersion: 1, typeId: type.typeId, attributes: { formatVersion: 1, modelId: id, targetVersion: 2, sourceVersions: [], operations: [], acknowledgedChanges: [] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [] };
  const previewResult = await page.request.post(`/api/v1/asset-types/${id}/migration-previews`, { headers: { ...await headers(page), 'If-Match': '1' }, data: { definition: target, plan } }); expect(previewResult.status()).toBe(200); const { preview } = await previewResult.json();
  const executed = await page.request.post(`/api/v1/asset-types/${id}/migrations`, { headers: { ...await headers(page), 'If-Match': '1' }, data: { definition: target, plan, previewDigest: preview.previewDigest } }); expect(executed.status()).toBe(201); const { receipt } = await executed.json();
  const consumerContext = await browser.newContext(); const consumer = await consumerContext.newPage(); await login(consumer, 'consumer');
  await consumer.goto(`/asset-types/${id}`); await expect(consumer.getByRole('heading', { name: id, exact: true })).toBeVisible(); await expect(consumer.getByRole('link', { name: 'Plan type migration', exact: true })).toHaveCount(0);
  await consumer.goto(`/asset-types/${id}/migrate`); await expect(consumer.getByRole('heading', { name: 'You do not have access to this view', exact: true })).toBeVisible();
  const denied = await consumer.request.post(`/api/v1/asset-types/${id}/migrations`, { headers: { ...await headers(consumer), 'If-Match': '1' }, data: { definition: target, plan, previewDigest: preview.previewDigest } }); expect(denied.status()).toBe(403);
  expect((await consumer.request.get(`/api/v1/asset-types/${id}/migration-context`)).status()).toBe(403);
  await consumer.goto(`/asset-types/${id}/migrations/${receipt.id}`); await expect(consumer.getByRole('heading', { name: 'Asset-type migration receipt', exact: true })).toBeVisible(); await capture(consumer, 'readonly-en', undefined, [390]);
  const foreignContext = await browser.newContext(); const foreign = await foreignContext.newPage(); await login(foreign, 'summit');
  expect((await foreign.request.get(`/api/v1/asset-types/${id}/migrations/${receipt.id}`)).status()).toBe(404);
  expect((await foreign.request.get(`/api/v1/asset-types/${id}/migration-context`)).status()).toBe(404);
  await foreign.goto(`/asset-types/${id}/migrations/${receipt.id}`); await expect(foreign.getByRole('heading', { name: 'This item is not available', exact: true })).toBeVisible();
  expect((await (await page.request.get(`/api/v1/asset-types/${id}`)).json()).type.currentVersion).toBe(2);
  await setup.close(); await consumerContext.close(); await foreignContext.close();
});
