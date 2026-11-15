// SPDX-License-Identifier: Apache-2.0
import { test, expect, type Page, type Browser } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { ModelDefinition } from '../../packages/domain/src/model.ts';

const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
async function login(page: Page, username = 'steward') {
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
async function accessible(page: Page) {
  await page.evaluate(async () => { await Promise.all(document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity).map(animation => animation.finished.catch(() => undefined))); });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  expect(result.violations).toEqual([]);
}
async function capture(page: Page, name: string) {
  mkdirSync('docs/verification/screenshots', { recursive: true });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 960 });
    await page.evaluate(screen => {
      const selector = screen === 'preview-en' ? '.model-preview' : screen === 'typed-asset-en' ? '.governed-attributes' : null;
      if (selector) document.querySelector(selector)?.scrollIntoView({ block: 'start', behavior: 'instant' });
      else window.scrollTo({ top: 0, behavior: 'instant' });
      document.querySelector('.dialog-content')?.scrollTo({ top: 0, behavior: 'instant' });
    }, name);
    await accessible(page);
    await page.screenshot({ path: `docs/verification/screenshots/m2-model-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function scannedAsset(page: Page) {
  const h = await headers(page);
  const created = await page.request.post('/api/v1/sources', { headers: h, data: { name: `Synthetic typed model browser ${Date.now()}`, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } });
  expect(created.status()).toBe(201);
  const { source } = await created.json();
  const response = await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: { ...h, 'Idempotency-Key': crypto.randomUUID() }, data: {} });
  expect(response.status()).toBe(202);
  const { job } = await response.json();
  await expect.poll(async () => (await (await page.request.get(`/api/v1/jobs/${job.id}`)).json()).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  let asset: { id: string } | undefined;
  await expect.poll(async () => {
    const results = await (await page.request.get('/api/v1/assets?q=orders&type=table&limit=100')).json();
    asset = results.items.find((item: { sourceId: string }) => item.sourceId === source.id);
    return !!asset;
  }, { timeout: 25_000 }).toBeTruthy();
  return asset!.id;
}

// This suite performs many real navigations. Leave the server's global request
// budget available for the following core journey; do not relax production
// limits or silently retry failed requests inside an acceptance assertion.
async function paceRequestBudget({ browser }: { browser: Browser }) {
  test.setTimeout(75_000);
  const context = await browser.newContext();
  const response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']);
  const remaining = Number(response.headers()['x-ratelimit-remaining']);
  await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 200) {
    console.info(`Browser fixture pacing: waiting ${reset + 1}s for the configured request budget to reset`);
    await new Promise(resolve => setTimeout(resolve, (reset + 1) * 1000));
  }
}
test.beforeAll(paceRequestBudget);
test.afterAll(paceRequestBudget);

test('MOD: visual model, import/export, real typed assets, immutable versions and migration protection', async ({ page }) => {
  test.setTimeout(180_000);
  await login(page);
  const inventory = await (await page.request.get('/api/v1/models')).json();
  console.info(`Browser model inventory: ${inventory.items.length} of the API's 100-model bound`);
  const modelId = `browser_model_${Date.now()}`;
  await page.goto('/models');
  await page.getByRole('link', { name: 'Create model', exact: true }).first().click();
  await page.getByLabel('Model identifier', { exact: false }).fill(modelId);
  await page.getByRole('button', { name: 'Add field', exact: true }).click();
  const key = page.getByRole('textbox', { name: 'Field identifier field_1', exact: true });
  await key.fill('amount'); await key.blur();
  await page.getByRole('combobox', { name: 'Field type amount', exact: true }).selectOption('decimal');
  await page.getByRole('textbox', { name: 'Display label amount', exact: true }).fill('Approved budget');
  await page.getByRole('spinbutton', { name: 'Precision amount', exact: true }).fill('30');
  await page.getByRole('spinbutton', { name: 'Scale amount', exact: true }).fill('10');
  await page.getByRole('checkbox', { name: 'Required', exact: true }).check();
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  const authored = JSON.parse(await page.getByRole('textbox', { name: 'Model JSON', exact: false }).inputValue());
  expect(authored.attributes.amount).toMatchObject({ type: 'decimal', precision: 30, scale: 10, required: true });
  const definition: ModelDefinition = { ...authored, attributes: {
    ...authored.attributes,
    title: { type: 'text', required: true, minLength: 2, label: 'Business title' },
    summary: { type: 'richText', required: true, label: 'Business notes' },
    quantity: { type: 'number', required: true, integer: true, minimum: 0, label: 'Record estimate' },
    approved: { type: 'boolean', required: true, label: 'Approved' },
    asOf: { type: 'date', required: true, label: 'As of date' },
    updatedAt: { type: 'timestamp', required: true, label: 'Business timestamp' },
    retention: { type: 'duration', required: true, label: 'Retention duration' },
    status: { type: 'enum', required: true, values: ['draft', 'approved'], label: 'Business status' },
    tags: { type: 'list', required: true, minItems: 1, items: { type: 'text', minLength: 1 }, label: 'Tags' },
    details: { type: 'object', required: true, properties: { currency: { type: 'enum', required: true, values: ['AED', 'USD'], label: 'Currency' }, note: { type: 'text', label: 'Optional note' } }, label: 'Business details' },
    reference: { type: 'uri', required: true, schemes: ['https'], label: 'Reference URI' },
  } };
  await page.getByRole('textbox', { name: 'Model JSON', exact: false }).fill(JSON.stringify(definition));
  await page.getByRole('button', { name: 'Validate JSON', exact: true }).click();
  await expect(page.getByText('Definition validated. Review the visual fields before publishing.', { exact: true })).toBeVisible();
  await capture(page, 'editor-en');
  const published = page.waitForResponse(response => response.url().endsWith('/api/v1/models') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Publish model', exact: true }).click();
  expect((await published).status()).toBe(201);
  await expect(page.getByRole('heading', { name: modelId, exact: true })).toBeVisible();
  const exported = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON', exact: true }).click();
  const file = await exported;
  const exportPath = `.local/evidence/${modelId}.json`;
  await file.saveAs(exportPath);
  expect(JSON.parse(readFileSync(exportPath, 'utf8'))).toEqual(definition);
  await capture(page, 'version-en');

  // Import goes through the raw-text parser; duplicate keys cannot disappear in JSON.parse.
  await page.goto('/models/new/definition');
  await page.getByLabel('Import JSON file', { exact: true }).setInputFiles({ name: 'duplicate.json', mimeType: 'application/json', buffer: Buffer.from('{"formatVersion":1,"id":"first","id":"second","version":1,"attributes":{}}') });
  await expect(page.getByText('Review these validation issues', { exact: true })).toBeVisible();
  await expect(page.locator('.validation-issues')).toContainText('Duplicate');
  await page.getByLabel('Import JSON file', { exact: true }).setInputFiles(exportPath);
  await expect(page.getByText('Definition validated. Review the visual fields before publishing.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  expect(JSON.parse(await page.getByRole('textbox', { name: 'Model JSON', exact: false }).inputValue())).toEqual(definition);

  const assetId = await scannedAsset(page);
  await page.goto(`/catalog/${assetId}`);
  await page.getByRole('button', { name: 'Assign a model', exact: true }).click();
  const form = page.getByRole('dialog', { name: 'Edit attributes', exact: true });
  await form.getByRole('combobox', { name: 'Choose a model', exact: true }).selectOption(modelId);
  await form.getByRole('textbox', { name: 'Approved budget (amount)', exact: true }).fill('not-a-decimal');
  const invalid = page.waitForResponse(response => response.url().endsWith(`/assets/${assetId}/attributes`) && response.request().method() === 'PUT');
  await form.getByRole('button', { name: 'Save changes', exact: true }).click();
  expect((await invalid).status()).toBe(422);
  await expect(form.locator('.validation-issues')).toContainText('/amount');
  const amount = '12345678901234567890.123456789';
  await form.getByRole('textbox', { name: 'Approved budget (amount)', exact: true }).fill(amount);
  await form.getByRole('textbox', { name: 'Business title (title)', exact: true }).fill('Synthetic governed commerce');
  await form.getByRole('textbox', { name: 'Business notes (summary)', exact: true }).fill('**Synthetic notes** <script>not executable</script>');
  await form.getByRole('spinbutton', { name: 'Record estimate (quantity)', exact: true }).fill('42');
  await form.getByRole('combobox', { name: 'Approved (approved)', exact: true }).selectOption('false');
  await form.getByLabel('As of date (asOf)', { exact: true }).fill('2026-11-15');
  await form.getByRole('textbox', { name: 'Business timestamp (updatedAt)', exact: true }).fill('2026-11-15T12:00:00Z');
  await form.getByRole('textbox', { name: 'Retention duration (retention)', exact: true }).fill('PT30M');
  await form.getByRole('combobox', { name: 'Business status (status)', exact: true }).selectOption('approved');
  await form.getByRole('button', { name: 'Set value Tags (tags)', exact: true }).click();
  await form.getByRole('button', { name: 'Add item tags', exact: true }).click();
  await form.getByRole('textbox', { name: 'Tags 1 (tags[0])', exact: true }).fill('synthetic');
  await form.getByRole('button', { name: 'Set value Business details (details)', exact: true }).click();
  await form.getByRole('combobox', { name: 'Currency (details.currency)', exact: true }).selectOption('AED');
  await form.getByRole('textbox', { name: 'Reference URI (reference)', exact: true }).fill('https://example.org/synthetic');
  await capture(page, 'typed-form-en');
  await form.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(form).toBeHidden();
  await expect(page.getByText(amount, { exact: true })).toBeVisible();
  await page.reload();
  const binding = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  expect(binding).toMatchObject({ modelId, modelVersion: 1, attributes: { amount, quantity: 42, approved: false, details: { currency: 'AED' }, tags: ['synthetic'] } });
  expect(binding.attributes.details).not.toHaveProperty('note');
  await capture(page, 'typed-asset-en');

  // Server-side concurrent edit must not silently overwrite the preserved form draft.
  await page.getByRole('button', { name: 'Edit attributes', exact: true }).click();
  const conflictForm = page.getByRole('dialog', { name: 'Edit attributes', exact: true });
  await conflictForm.getByRole('textbox', { name: 'Business title (title)', exact: true }).fill('Preserved browser draft');
  const external = await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(binding.assetVersion) }, data: { modelId, modelVersion: 1, attributes: { ...binding.attributes, title: 'Concurrent saved title' } } });
  expect(external.status()).toBe(200);
  await conflictForm.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(conflictForm.getByText('This asset changed. Your values are preserved. Reload the current saved values and compare before trying again.', { exact: true })).toBeVisible();
  await conflictForm.getByRole('button', { name: 'Reload current version', exact: true }).click();
  await expect(conflictForm.locator('.conflict-comparison')).toContainText('Concurrent saved title');
  await expect(conflictForm.getByRole('textbox', { name: 'Business title (title)', exact: true })).toHaveValue('Preserved browser draft');
  await conflictForm.getByRole('button', { name: 'Keep draft and use current revision', exact: true }).click();
  await conflictForm.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(conflictForm).toBeHidden();

  await page.goto(`/models/${modelId}/edit`);
  await page.getByRole('textbox', { name: 'Display label amount', exact: true }).fill('Approved budget value');
  await page.getByRole('button', { name: 'Preview impact', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Publication impact', exact: true })).toContainText('1');
  await expect(page.getByText('The proposed definition is compatible with the checked values.', { exact: true })).toBeVisible();
  await page.locator('.preview-assets summary').click();
  await expect(page.getByRole('link', { name: 'Open catalog asset', exact: true })).toHaveAttribute('href', `/catalog/${assetId}`);
  await capture(page, 'preview-en');
  const latestBinding = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  const changedBinding = await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(latestBinding.assetVersion) }, data: { modelId, modelVersion: 1, attributes: { ...latestBinding.attributes, title: 'Changed after preview' } } });
  expect(changedBinding.status()).toBe(200);
  const stalePreview = page.waitForResponse(response => response.url().endsWith(`/models/${modelId}/versions`) && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Publish model', exact: true }).click();
  expect((await stalePreview).status()).toBe(409);
  await expect(page.getByRole('textbox', { name: 'Display label amount', exact: true })).toHaveValue('Approved budget value');
  await page.getByRole('button', { name: 'Reload current version', exact: true }).click();
  await page.getByRole('button', { name: 'Preview impact', exact: true }).click();
  await expect(page.getByText('The proposed definition is compatible with the checked values.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Publish model', exact: true }).click();
  await expect(page.getByRole('heading', { name: modelId, exact: true })).toBeVisible();
  const old = await (await page.request.get(`/api/v1/models/${modelId}/versions/1`)).json();
  expect(old.model.definition).toEqual(definition);
  expect((await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json()).modelVersion).toBe(1);
  await page.getByRole('combobox', { name: 'View version', exact: true }).selectOption('1');
  await expect(page.getByText('Approved budget', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Create next version', exact: true }).click();
  await page.getByRole('button', { name: 'Remove field amount', exact: true }).click();
  await page.getByRole('button', { name: 'Preview impact', exact: true }).click();
  await expect(page.getByText('Publication blocked. These changes require an explicit migration, which is not yet supported in this development increment.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Publish model', exact: true })).toBeDisabled();
  expect((await (await page.request.get(`/api/v1/models/${modelId}`)).json()).model.currentVersion).toBe(2);
  await page.setViewportSize({ width: 390, height: 960 });
  await page.locator('#language').selectOption('ar');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  await accessible(page);
  await page.screenshot({ path: 'docs/verification/screenshots/m2-model-editor-ar-390.png', fullPage: false });
});

test('MOD: consumer cannot publish models and tenant definitions remain isolated', async ({ browser }) => {
  const steward = await browser.newContext(); const page = await steward.newPage();
  await login(page);
  const modelId = `browser_isolation_${Date.now()}`;
  const definition = { formatVersion: 1, id: modelId, version: 1, attributes: {} };
  const created = await page.request.post('/api/v1/models', { headers: await headers(page), data: { definition } });
  expect(created.status()).toBe(201);
  await steward.close();
  const consumer = await browser.newContext(); const consumerPage = await consumer.newPage();
  await login(consumerPage, 'consumer');
  await consumerPage.goto('/models');
  await expect(consumerPage.getByRole('heading', { name: 'Operating models', exact: true })).toBeVisible();
  await expect(consumerPage.getByRole('link', { name: 'Create model', exact: true })).toHaveCount(0);
  await consumerPage.goto('/models/new/definition');
  await expect(consumerPage.getByRole('heading', { name: 'You do not have access to this view', exact: true })).toBeVisible();
  expect((await consumerPage.request.post('/api/v1/models', { headers: await headers(consumerPage), data: { definition: { ...definition, id: `${modelId}_denied` } } })).status()).toBe(403);
  await consumer.close();
  const summit = await browser.newContext(); const summitPage = await summit.newPage();
  await login(summitPage, 'summit');
  expect((await summitPage.request.get(`/api/v1/models/${modelId}`)).status()).toBe(404);
  await summitPage.goto(`/models/${modelId}`);
  await expect(summitPage.getByRole('heading', { name: 'This item is not available', exact: true })).toBeVisible();
  await summit.close();
});
