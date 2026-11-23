// SPDX-License-Identifier: Apache-2.0
import {domainLogin} from '../fixtures/business-domains-browser.ts';
import { test, expect, type Page, type Browser } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { ModelDefinition } from '../../packages/domain/src/model.ts';
import type { MigrationPlan } from '../../packages/domain/src/model-migration.ts';

async function login(page: Page, username = 'steward') {
  await domainLogin(page, username);
}
async function headers(page: Page) {
  const me = await (await page.request.get('/api/v1/me')).json();
  return { 'X-CSRF-Token': me.csrfToken, Origin: 'http://127.0.0.1:4310', 'Idempotency-Key': crypto.randomUUID() };
}
async function paceRequestBudget({ browser }: { browser: Browser }) {
  test.setTimeout(75_000);
  const context = await browser.newContext();
  const response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']);
  const remaining = Number(response.headers()['x-ratelimit-remaining']);
  await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 200) {
    console.info(`Migration fixture pacing: waiting ${reset + 1}s for the configured request budget to reset`);
    await new Promise(resolve => setTimeout(resolve, (reset + 1) * 1000));
  }
}
test.beforeAll(paceRequestBudget);
test.afterAll(paceRequestBudget);
async function accessible(page: Page) {
  await page.evaluate(async () => { await Promise.all(document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity).map(animation => animation.finished.catch(() => undefined))); });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
}
async function capture(page: Page, name: string, selector?: string, widths = [1440, 390]) {
  mkdirSync('docs/verification/screenshots', { recursive: true });
  for (const width of widths) {
    await page.setViewportSize({ width, height: 960 });
    await page.evaluate(selector => {
      if (selector) document.querySelector(selector)?.scrollIntoView({ block: 'start', behavior: 'instant' });
      else window.scrollTo({ top: 0, behavior: 'instant' });
      document.querySelector('.dialog-content')?.scrollTo({ top: 0, behavior: 'instant' });
    }, selector);
    await accessible(page);
    await page.screenshot({ path: `docs/verification/screenshots/m2-migration-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function scannedAsset(page: Page) {
  const h = await headers(page);
  const response = await page.request.post('/api/v1/sources', { headers: h, data: { name: `Synthetic migration browser ${Date.now()}`, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } });
  expect(response.status()).toBe(201); const { source } = await response.json();
  const scan = await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: { ...h, 'Idempotency-Key': crypto.randomUUID() }, data: {} });
  expect(scan.status()).toBe(202); const { job } = await scan.json();
  await expect.poll(async () => (await (await page.request.get(`/api/v1/jobs/${job.id}`)).json()).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  let asset: { id: string } | undefined;
  await expect.poll(async () => {
    // Existing synthetic sources can place this scan beyond the first page.
    // Traverse the actual cursor protocol; a successful scan is not proof that
    // its projection is present, and unrelated same-name assets cannot satisfy it.
    let cursor: string | null = null;
    const visited = new Set<string>();
    for (let count = 0; count < 20; count++) {
      const response = await page.request.get(`/api/v1/assets?q=orders&type=table&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
      expect(response.status()).toBe(200);
      const result: { items: { id: string; sourceId: string; name: string }[]; nextCursor: string | null } = await response.json();
      asset = result.items.find(item => item.sourceId === source.id && item.name === 'orders');
      cursor = result.nextCursor;
      if (asset || !cursor) break;
      expect(visited.has(cursor)).toBe(false); visited.add(cursor);
    }
    return !!asset;
  }, { timeout: 25_000 }).toBeTruthy();
  return asset!.id;
}
async function addOperation(page: Page, op: string) {
  await page.getByRole('combobox', { name: 'Operation type', exact: true }).selectOption(op);
  await page.getByRole('button', { name: 'Add operation', exact: true }).click();
}
async function acknowledge(page: Page) {
  const boxes = page.getByRole('checkbox', { name: /^I acknowledge this change/ });
  await expect(boxes.first()).toBeVisible();
  expect(await boxes.count()).toBeGreaterThan(0);
  for (const box of await boxes.all()) await box.check();
}

test('MOD: explicit visual migration rejects invalid and stale plans, commits exact values and an immutable receipt', async ({ page }) => {
  test.setTimeout(240_000);
  await login(page);
  const inventory = await (await page.request.get('/api/v1/models')).json();
  console.info(`Migration model first page: ${inventory.items.length} models; another page: ${!!inventory.nextCursor}; no total inferred`);
  const modelId = `migration_browser_${Date.now()}`;
  const definition: ModelDefinition = { formatVersion: 1, id: modelId, version: 1, attributes: {
    amount: { type: 'decimal', precision: 30, scale: 10, required: true, label: 'Exact budget' },
    legacy: { type: 'text', label: 'Retired note' },
    quantity: { type: 'number', integer: true, required: true, label: 'Quantity' },
    state: { type: 'enum', values: ['draft', 'approved'], required: true, label: 'Review state' },
    title: { type: 'text', required: true, label: 'Business title' },
    metadata: { type: 'object', required: true, properties: { region: { type: 'text', required: true } } },
  } };
  const created = await page.request.post('/api/v1/models', { headers: await headers(page), data: { definition } });
  expect(created.status()).toBe(201);
  const assetId = await scannedAsset(page);
  const unbound = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  const exact = '12345678901234567890.123456789';
  const attributes = { amount: exact, legacy: 'Synthetic obsolete annotation', quantity: 42, state: 'draft', title: 'Synthetic migration asset', metadata: { region: 'Gulf' } };
  const assigned = await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(unbound.assetVersion) }, data: { modelId, modelVersion: 1, attributes } });
  expect(assigned.status()).toBe(200);
  const before = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  await page.goto(`/models/${modelId}`);
  await page.getByRole('link', { name: 'Plan migration', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Migrate model and values', exact: true })).toBeVisible();
  const rename = page.getByRole('textbox', { name: 'Field identifier amount', exact: true });
  await rename.fill('budget'); await rename.blur();
  await page.getByRole('button', { name: 'Remove field legacy', exact: true }).click();
  await page.getByRole('combobox', { name: 'Field type quantity', exact: true }).selectOption('decimal');
  await page.getByRole('spinbutton', { name: 'Precision quantity', exact: true }).fill('20');
  await page.getByRole('spinbutton', { name: 'Scale quantity', exact: true }).fill('0');
  await page.getByRole('textbox', { name: 'Allowed values, one per line state', exact: true }).fill('review\napproved');
  await page.locator('.migration-definition > .model-fields > button').click();
  const newKey = page.getByRole('textbox', { name: 'Field identifier field_1', exact: true });
  await newKey.fill('approved'); await newKey.blur();
  await page.getByRole('combobox', { name: 'Field type approved', exact: true }).selectOption('boolean');
  await page.locator('[data-field-key="approved"]').getByRole('checkbox', { name: 'Required', exact: true }).check();
  await page.getByRole('button', { name: 'Review definition changes', exact: true }).click();
  await expect(page.getByRole('checkbox', { name: /I acknowledge this change.*attribute_removed.*\/attributes\/amount/ })).toBeVisible();
  await addOperation(page, 'rename');
  await page.getByRole('textbox', { name: 'Source path · Operation 1', exact: true }).fill('missing_amount');
  await page.getByRole('textbox', { name: 'Destination path · Operation 1', exact: true }).fill('budget');
  await addOperation(page, 'remove');
  await page.getByRole('textbox', { name: 'Field path · Operation 2', exact: true }).fill('legacy');
  await addOperation(page, 'convert');
  await page.getByRole('textbox', { name: 'Field path · Operation 3', exact: true }).fill('quantity');
  await addOperation(page, 'enumMap');
  await page.getByRole('textbox', { name: 'Field path · Operation 4', exact: true }).fill('state');
  await page.getByRole('button', { name: 'Add mapping', exact: true }).click();
  await page.getByRole('textbox', { name: 'Existing value · Operation 4 · 1', exact: true }).fill('draft');
  await page.getByRole('combobox', { name: 'Target value · Operation 4 · 1', exact: true }).selectOption('review');
  await addOperation(page, 'set');
  await page.getByRole('textbox', { name: 'Field path · Operation 5', exact: true }).fill('approved');
  await expect(page.getByRole('combobox', { name: 'Literal value · Operation 5 (literal)', exact: true })).toHaveValue('false');

  const missingConsent = page.waitForResponse(response => response.url().endsWith('/migration-previews') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview transformed values', exact: true }).click();
  expect((await missingConsent).status()).toBe(422);
  await expect(page.locator('.validation-issues')).toContainText('/plan/acknowledgedChanges');
  expect(await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json()).toEqual(before);
  expect((await (await page.request.get(`/api/v1/models/${modelId}`)).json()).model.currentVersion).toBe(1);
  await acknowledge(page);
  const invalidTransform = page.waitForResponse(response => response.url().endsWith('/migration-previews') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview transformed values', exact: true }).click();
  expect((await invalidTransform).status()).toBe(422);
  await expect(page.locator('.validation-issues')).toContainText('/assets/0');
  expect(await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json()).toEqual(before);
  await page.getByRole('textbox', { name: 'Source path · Operation 1', exact: true }).fill('amount');
  await capture(page, 'plan-en', '.migration-plan');

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export plan JSON', exact: true }).click();
  const file = await download; const planFile = `.local/evidence/${modelId}.plan.json`; await file.saveAs(planFile);
  const plan = JSON.parse(readFileSync(planFile, 'utf8')) as MigrationPlan;
  expect(plan.sourceVersions).toEqual([1]); expect(plan.operations.map(operation => operation.op)).toEqual(['rename', 'remove', 'convert', 'enumMap', 'set']);
  expect(plan.operations[4]).toMatchObject({ value: false });
  await page.getByLabel('Import plan JSON', { exact: true }).setInputFiles({ name: 'duplicate-plan.json', mimeType: 'application/json', buffer: Buffer.from('{"modelId":"first","modelId":"second"}') });
  await expect(page.locator('.validation-issues')).toContainText('Duplicate');
  await page.getByLabel('Import plan JSON', { exact: true }).setInputFiles(planFile);
  await expect(page.getByText('Plan syntax validated. Preview is still required to validate all affected values.', { exact: true })).toBeVisible();
  const previewResponse = page.waitForResponse(response => response.url().endsWith('/migration-previews') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview transformed values', exact: true }).click();
  const firstPreview = await (await previewResponse).json();
  expect(firstPreview.preview.assets[0]).toMatchObject({ assetId, beforeAttributes: attributes, afterAttributes: { budget: exact, quantity: '42', state: 'review', approved: false, metadata: { region: 'Gulf' } } });
  expect(firstPreview.preview.assets[0].afterAttributes).not.toHaveProperty('amount');
  expect(firstPreview.preview.assets[0].afterAttributes).not.toHaveProperty('legacy');
  await capture(page, 'preview-en', '.migration-preview');
  await capture(page, 'values-en', '.migration-values', [390]);
  await page.getByRole('button', { name: 'Colour theme: Dark', exact: true }).click();
  await capture(page, 'preview-dark', '.migration-preview', [390]);
  await page.getByRole('button', { name: 'Colour theme: Light', exact: true }).click();
  await page.getByRole('button', { name: 'Review execution', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Confirm migration', exact: true });
  await expect(dialog.getByRole('button', { name: 'Execute migration', exact: true })).toBeDisabled();
  await expect(dialog).toContainText(firstPreview.preview.previewDigest);
  await dialog.getByRole('checkbox', { name: 'I approve this exact preview and the changes to all listed assets.', exact: true }).check();
  const external = await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(before.assetVersion) }, data: { modelId, modelVersion: 1, attributes: { ...attributes, title: 'Changed after migration preview' } } });
  expect(external.status()).toBe(200);
  const concurrent = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  const stale = page.waitForResponse(response => response.url().endsWith(`/models/${modelId}/migrations`) && response.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Execute migration', exact: true }).click();
  expect((await stale).status()).toBe(409); await expect(dialog).toBeHidden();
  await expect(page.getByRole('button', { name: 'Review execution', exact: true })).toBeDisabled();
  expect(await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json()).toEqual(concurrent);
  expect((await (await page.request.get(`/api/v1/models/${modelId}`)).json()).model.currentVersion).toBe(1);
  await page.getByRole('button', { name: 'Reload scope and current version', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Source path · Operation 1', exact: true })).toHaveValue('amount');
  await page.getByRole('button', { name: 'Review definition changes', exact: true }).click();
  await expect(page.getByRole('checkbox', { name: /^I acknowledge this change/ }).first()).toBeVisible();
  for (const box of await page.getByRole('checkbox', { name: /^I acknowledge this change/ }).all()) await expect(box).not.toBeChecked();
  await acknowledge(page);
  await page.getByRole('button', { name: 'Preview transformed values', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Review execution', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Review execution', exact: true }).click();
  await expect(dialog.getByRole('checkbox', { name: 'I approve this exact preview and the changes to all listed assets.', exact: true })).not.toBeChecked();
  await capture(page, 'confirmation-en');
  await dialog.getByRole('checkbox', { name: 'I approve this exact preview and the changes to all listed assets.', exact: true }).check();
  const executed = page.waitForResponse(response => response.url().endsWith(`/models/${modelId}/migrations`) && response.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Execute migration', exact: true }).click();
  const committed = await executed; expect(committed.status()).toBe(201); const { receipt } = await committed.json();
  await expect(page).toHaveURL(`http://127.0.0.1:4310/models/${modelId}/migrations/${receipt.id}`);
  await expect(page.getByRole('heading', { name: 'Migration receipt', exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText(receipt.id, { exact: true })).toBeVisible();
  const after = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  expect(after).toMatchObject({ modelVersion: 2, assetVersion: concurrent.assetVersion + 1, attributes: { budget: exact, quantity: '42', approved: false, state: 'review', title: 'Changed after migration preview', metadata: { region: 'Gulf' } } });
  expect(after.attributes).not.toHaveProperty('legacy'); expect(after.attributes).not.toHaveProperty('amount');
  expect((await (await page.request.get(`/api/v1/models/${modelId}/versions/1`)).json()).model.definition).toEqual(definition);
  expect((await (await page.request.get(`/api/v1/models/${modelId}/migrations/${receipt.id}`)).json()).receipt).toEqual(receipt);
  const receiptDownload = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export receipt JSON', exact: true }).click();
  const receiptFile = `.local/evidence/${modelId}.receipt.json`; await (await receiptDownload).saveAs(receiptFile);
  expect(JSON.parse(readFileSync(receiptFile, 'utf8'))).toEqual(receipt);
  await capture(page, 'receipt-en');
  await page.locator('#language').selectOption('ar'); await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await capture(page, 'receipt-ar', undefined, [390]);
});

test('MOD: migration execution is permission-scoped and receipts remain tenant-scoped', async ({ browser }) => {
  const setup = await browser.newContext(); const page = await setup.newPage(); await login(page);
  const modelId = `migration_isolation_${Date.now()}`;
  const original = { formatVersion: 1, id: modelId, version: 1, attributes: {} };
  expect((await page.request.post('/api/v1/models', { headers: await headers(page), data: { definition: original } })).status()).toBe(201);
  const definition = { ...original, version: 2 };
  const plan = { formatVersion: 1, modelId, targetVersion: 2, sourceVersions: [], acknowledgedChanges: [], operations: [] };
  const previewResponse = await page.request.post(`/api/v1/models/${modelId}/migration-previews`, { headers: { ...await headers(page), 'If-Match': '1' }, data: { definition, plan } });
  expect(previewResponse.status()).toBe(200); const { preview } = await previewResponse.json();
  const execution = await page.request.post(`/api/v1/models/${modelId}/migrations`, { headers: { ...await headers(page), 'If-Match': '1' }, data: { definition, plan, previewDigest: preview.previewDigest } });
  expect(execution.status()).toBe(201); const { receipt } = await execution.json(); await setup.close();
  const consumer = await browser.newContext(); const reader = await consumer.newPage(); await login(reader, 'consumer');
  await reader.goto(`/models/${modelId}`); await expect(reader.getByRole('link', { name: 'Plan migration', exact: true })).toHaveCount(0);
  await reader.goto(`/models/${modelId}/migrate`); await expect(reader.getByRole('heading', { name: 'You do not have access to this view', exact: true })).toBeVisible();
  expect((await reader.request.get(`/api/v1/models/${modelId}/migration-context`)).status()).toBe(403);
  expect((await reader.request.post(`/api/v1/models/${modelId}/migration-previews`, { headers: { ...await headers(reader), 'If-Match': '2' }, data: { definition, plan } })).status()).toBe(403);
  await reader.goto(`/models/${modelId}/migrations/${receipt.id}`); await expect(reader.getByRole('heading', { name: 'Migration receipt', exact: true })).toBeVisible();
  await expect(reader.getByRole('button', { name: 'Execute migration', exact: true })).toHaveCount(0); await consumer.close();
  const summit = await browser.newContext(); const other = await summit.newPage(); await login(other, 'summit');
  expect((await other.request.get(`/api/v1/models/${modelId}/migrations/${receipt.id}`)).status()).toBe(404);
  await other.goto(`/models/${modelId}/migrations/${receipt.id}`); await expect(other.getByRole('heading', { name: 'This item is not available', exact: true })).toBeVisible();
  await summit.close();
});
