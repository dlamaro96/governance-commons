// SPDX-License-Identifier: Apache-2.0
import { test, expect, type Page, type Browser } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';

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
  test.setTimeout(75_000);
  const context = await browser.newContext();
  const response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']);
  const remaining = Number(response.headers()['x-ratelimit-remaining']);
  await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 200) {
    console.info(`Asset-type fixture pacing: waiting ${reset + 1}s for the configured request budget to reset`);
    await new Promise(resolve => setTimeout(resolve, (reset + 1) * 1000));
  }
}
test.beforeAll(paceRequestBudget);
// Each journey performs enough real navigations to need its own shared-IP budget.
// Wait before execution using actual headers; never retry a failed assertion.
test.beforeEach(paceRequestBudget);
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
    await page.screenshot({ path: `docs/verification/screenshots/m2-asset-type-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function scannedAsset(page: Page) {
  const h = await headers(page);
  const response = await page.request.post('/api/v1/sources', { headers: h, data: { name: `Synthetic inherited type browser ${Date.now()}`, host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } });
  expect(response.status()).toBe(201); const { source } = await response.json();
  const scan = await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: { ...h, 'Idempotency-Key': crypto.randomUUID() }, data: {} });
  expect(scan.status()).toBe(202); const { job } = await scan.json();
  await expect.poll(async () => (await (await page.request.get(`/api/v1/jobs/${job.id}`)).json()).job.status, { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  let asset: { id: string } | undefined;
  await expect.poll(async () => {
    const results = await (await page.request.get('/api/v1/assets?q=orders&type=table&limit=100')).json();
    asset = results.items.find((item: { sourceId: string }) => item.sourceId === source.id);
    return !!asset;
  }, { timeout: 25_000 }).toBeTruthy();
  return asset!.id;
}
async function addField(page: Page, key: string, label: string) {
  await page.getByRole('button', { name: 'Add field', exact: true }).click();
  const input = page.getByRole('textbox', { name: 'Field identifier field_1', exact: true });
  await input.fill(key); await input.blur();
  await page.getByRole('textbox', { name: `Display label ${key}`, exact: true }).fill(label);
}
async function assignThroughUi(page: Page, modelId: string, exact: string) {
  await page.getByRole('button', { name: 'Assign a model', exact: true }).click();
  const form = page.getByRole('dialog', { name: 'Edit attributes', exact: true });
  await form.getByLabel('Search model identifiers', { exact: true }).fill(modelId);
  await form.getByRole('button', { name: 'Search models', exact: true }).click();
  await expect(form.getByRole('combobox', { name: 'Choose a model', exact: true })).toBeEnabled();
  await form.getByRole('combobox', { name: 'Choose a model', exact: true }).selectOption(modelId);
  await form.getByRole('textbox', { name: 'Child budget (amount)', exact: true }).fill(exact);
  return form;
}
async function previewAndApprove(page: Page) {
  await page.getByRole('button', { name: 'Preview impact', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Type impact preview', exact: true })).toBeVisible();
  const consent = page.getByRole('checkbox', { name: /I reviewed this exact type preview/ });
  await expect(consent).toBeVisible();
  await consent.focus(); await page.keyboard.press('Space');
  await expect(page.getByRole('button', { name: 'Publish asset type', exact: true })).toBeEnabled();
}

test('MOD: authored inheritance pins, required ownership, lifecycle and stale preview survive parent upgrades', async ({ page }) => {
  test.setTimeout(300_000);
  await login(page);
  const prefix = `type_browser_${Date.now()}`, parentId = `${prefix}_parent`, childId = `${prefix}_child`;
  const exact = '12345678901234567890.123456789';
  await page.goto('/models');
  await page.getByRole('link', { name: 'Asset types', exact: true }).click();
  await page.getByRole('link', { name: 'Create asset type', exact: true }).click();
  await page.getByRole('textbox', { name: 'Type identifier', exact: false }).fill(parentId);
  await addField(page, 'amount', 'Parent budget');
  await page.getByRole('combobox', { name: 'Field type amount', exact: true }).selectOption('decimal');
  await page.getByRole('spinbutton', { name: 'Precision amount', exact: true }).fill('30');
  await page.getByRole('spinbutton', { name: 'Scale amount', exact: true }).fill('10');
  await page.locator('[data-field-key="amount"]').getByRole('checkbox', { name: 'Required', exact: true }).check();
  await page.getByRole('checkbox', { name: 'Require an active owner', exact: true }).check();
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  const authored = JSON.parse(await page.getByRole('textbox', { name: 'Asset type JSON', exact: false }).inputValue()) as AssetTypeDefinition;
  await page.getByLabel('Import type JSON', { exact: true }).setInputFiles({ name: 'duplicate-type.json', mimeType: 'application/json', buffer: Buffer.from('{"id":"first","id":"second"}') });
  await expect(page.locator('.validation-issues')).toContainText('Duplicate');
  await page.getByRole('button', { name: 'Return to last valid draft', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Type identifier', exact: false })).toHaveValue(parentId);
  await page.getByLabel('Import type JSON', { exact: true }).setInputFiles({ name: 'parent-type.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(authored)) });
  await expect(page.getByText('Type syntax validated. Parent resolution and publication constraints are checked by the server.', { exact: true })).toBeVisible();
  await capture(page, 'editor-en', '.asset-type-editor', [1440, 1024, 768, 390]);
  await capture(page, 'lifecycle-editor-en', '.lifecycle-editor');
  await page.getByRole('button', { name: 'Publish asset type', exact: true }).click();
  await expect(page.getByRole('heading', { name: parentId, exact: true })).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export type JSON', exact: true }).click();
  const file = await download; const filename = `.local/evidence/${parentId}.json`; await file.saveAs(filename);
  expect(JSON.parse(readFileSync(filename, 'utf8'))).toEqual(authored);

  await page.goto('/asset-types/new/definition');
  await page.getByRole('textbox', { name: 'Type identifier', exact: false }).fill(childId);
  await page.locator('.asset-type-parent-browser > summary').click();
  await page.getByLabel('Search asset types by identifier', { exact: true }).fill(parentId);
  await page.getByRole('button', { name: 'Search types', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Select parent type', exact: true })).toBeEnabled();
  await page.getByRole('combobox', { name: 'Select parent type', exact: true }).selectOption(parentId);
  await page.getByRole('button', { name: 'Add pinned parent', exact: true }).click();
  await page.locator('.asset-type-parent > details > summary').click();
  await page.getByRole('button', { name: 'Override field amount', exact: true }).click();
  await page.getByRole('textbox', { name: 'Display label amount', exact: true }).fill('Child budget');
  await expect(page.getByRole('checkbox', { name: 'Replaces inherited field amount', exact: true })).toBeChecked();
  await page.getByRole('combobox', { name: 'Lifecycle definition', exact: true }).selectOption('inherit');
  await expect(page.getByRole('checkbox', { name: 'Require an active owner', exact: true })).not.toBeChecked();
  await capture(page, 'inheritance-en', '.asset-type-parent');
  await page.getByRole('button', { name: 'Publish asset type', exact: true }).click();
  await expect(page.getByRole('heading', { name: childId, exact: true })).toBeVisible();
  const originalChild = (await (await page.request.get(`/api/v1/asset-types/${childId}`)).json()).type;
  expect(originalChild.resolved.requiredOwner).toBe(true);
  expect(originalChild.resolved.dependencies).toEqual([{ id: parentId, version: 1 }]);
  await capture(page, 'resolved-en');

  const assetId = await scannedAsset(page);
  await page.goto(`/catalog/${assetId}`);
  const deniedForm = await assignThroughUi(page, childId, exact);
  const deniedAssignment = page.waitForResponse(response => response.url().endsWith(`/assets/${assetId}/attributes`) && response.request().method() === 'PUT');
  await deniedForm.getByRole('button', { name: 'Save changes', exact: true }).click();
  expect((await deniedAssignment).status()).toBe(422);
  await expect(deniedForm).toContainText('This asset type requires an active owner in this organization.');
  expect((await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json()).modelId).toBeNull();
  await deniedForm.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(deniedForm).toBeHidden();
  await page.getByRole('button', { name: 'Edit details', exact: true }).first().click();
  const ownerForm = page.getByRole('dialog', { name: 'Edit details', exact: true });
  await ownerForm.getByRole('combobox', { name: 'Owner', exact: true }).selectOption({ label: 'Harbor Owner' });
  await ownerForm.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(ownerForm).toBeHidden();
  await expect(page.locator('.ownership-person')).toContainText('Harbor Owner');
  const form = await assignThroughUi(page, childId, exact);
  await form.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(form).toBeHidden();
  await expect(page.getByTestId('lifecycle-current')).toHaveText('draft');
  await page.getByRole('combobox', { name: 'Next lifecycle state', exact: true }).selectOption('active');
  await page.getByRole('button', { name: 'Apply transition', exact: true }).click();
  await expect(page.getByTestId('lifecycle-current')).toHaveText('active');
  const pinnedState = await (await page.request.get(`/api/v1/assets/${assetId}/type-state`)).json();
  expect(pinnedState).toMatchObject({ modelId: childId, modelVersion: 1, state: 'active', requiredOwner: true });
  const invalidTransition = await page.request.post(`/api/v1/assets/${assetId}/type-state`, { headers: { ...await headers(page), 'If-Match': String(pinnedState.assetVersion) }, data: { state: 'draft' } });
  expect(invalidTransition.status()).toBe(422);
  expect(await (await page.request.get(`/api/v1/assets/${assetId}/type-state`)).json()).toEqual(pinnedState);
  await page.getByRole('button', { name: 'Edit details', exact: true }).first().click();
  const removeOwner = page.getByRole('dialog', { name: 'Edit details', exact: true });
  await removeOwner.getByRole('combobox', { name: 'Owner', exact: true }).selectOption('');
  const ownerDenied = page.waitForResponse(response => response.url().endsWith(`/assets/${assetId}`) && response.request().method() === 'PATCH');
  await removeOwner.getByRole('button', { name: 'Save changes', exact: true }).click();
  expect((await ownerDenied).status()).toBe(422);
  await expect(removeOwner).toContainText('This asset type requires an active owner in this organization.');
  await removeOwner.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(removeOwner).toBeHidden();

  await page.goto(`/asset-types/${parentId}/edit`);
  await addField(page, 'comment', 'Inherited note');
  await previewAndApprove(page);
  await page.getByRole('button', { name: 'Publish asset type', exact: true }).click();
  await expect(page.getByRole('heading', { name: parentId, exact: true })).toBeVisible();
  const unchangedChild = (await (await page.request.get(`/api/v1/asset-types/${childId}`)).json()).type;
  expect(unchangedChild.definition).toEqual(originalChild.definition);
  expect(unchangedChild.resolutionHash).toEqual(originalChild.resolutionHash);
  expect(unchangedChild.resolved.model.attributes.comment).toBeUndefined();
  expect((await (await page.request.get(`/api/v1/assets/${assetId}/type-state`)).json()).modelVersion).toBe(1);
  await page.goto(`/asset-types/${childId}/edit`);
  await page.getByRole('combobox', { name: `Parent version ${parentId}`, exact: true }).selectOption('2');
  await previewAndApprove(page);
  await expect(page.getByRole('region', { name: 'Type impact preview', exact: true })).toContainText('Checked assets: 1');
  await capture(page, 'preview-en', '.asset-type-preview');
  const beforeStale = (await (await page.request.get(`/api/v1/assets/${assetId}`)).json()).asset;
  const concurrent = await page.request.patch(`/api/v1/assets/${assetId}`, { headers: { ...await headers(page), 'If-Match': String(beforeStale.version) }, data: { description: 'Synthetic concurrent change after type preview', ownerId: beforeStale.ownerId } });
  expect(concurrent.status()).toBe(200);
  const stalePublication = page.waitForResponse(response => response.url().endsWith(`/asset-types/${childId}/versions`) && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Publish asset type', exact: true }).click();
  expect((await stalePublication).status()).toBe(409);
  await expect(page.getByRole('combobox', { name: `Parent version ${parentId}`, exact: true })).toHaveValue('2');
  await expect(page.getByRole('button', { name: 'Publish asset type', exact: true })).toBeDisabled();
  expect((await (await page.request.get(`/api/v1/asset-types/${childId}`)).json()).type.currentVersion).toBe(1);
  await page.getByRole('button', { name: 'Reload current version', exact: true }).click();
  await previewAndApprove(page);
  await page.getByRole('button', { name: 'Publish asset type', exact: true }).click();
  await expect(page.getByRole('heading', { name: childId, exact: true })).toBeVisible();
  await expect(page.locator('.asset-type-resolved')).toContainText('Inherited note');
  await page.getByRole('combobox', { name: 'View version', exact: true }).selectOption('1');
  await expect(page.locator('.asset-type-resolved')).not.toContainText('Inherited note');
  expect((await (await page.request.get(`/api/v1/asset-types/${childId}/versions/1`)).json()).type.definition).toEqual(originalChild.definition);
  await page.goto(`/catalog/${assetId}`);
  await expect(page.getByTestId('lifecycle-current')).toHaveText('active');
  await page.getByRole('button', { name: 'Edit attributes', exact: true }).click();
  const reassignment = page.getByRole('dialog', { name: 'Edit attributes', exact: true });
  await reassignment.getByRole('combobox', { name: 'Model version', exact: true }).selectOption('2');
  await reassignment.getByRole('textbox', { name: 'Child budget (amount)', exact: true }).fill(exact);
  await reassignment.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(reassignment).toBeHidden();
  await expect(page.getByTestId('lifecycle-current')).toHaveText('active');
  const assigned = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  expect(assigned).toMatchObject({ modelId: childId, modelVersion: 2, attributes: { amount: exact } });
  await capture(page, 'lifecycle-en', '.asset-lifecycle');
  await page.getByRole('button', { name: 'Colour theme: Dark', exact: true }).click();
  await page.locator('#language').selectOption('ar');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await capture(page, 'lifecycle-ar-dark', '.asset-lifecycle', [390]);
  await page.goto(`/asset-types/${childId}/edit`);
  await expect(page.locator('.asset-type-editor')).toBeVisible();
  await capture(page, 'editor-ar-dark', '.asset-type-editor', [390]);
});

test('MOD: type authoring and transitions enforce permissions and tenant isolation, and legacy editors stay closed', async ({ browser }) => {
  test.setTimeout(180_000);
  const steward = await browser.newContext(); const page = await steward.newPage();
  await login(page);
  const typeId = `type_isolation_${Date.now()}`;
  const definition: AssetTypeDefinition = { formatVersion: 1, id: typeId, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } };
  const created = await page.request.post('/api/v1/asset-types', { headers: await headers(page), data: { definition } });
  expect(created.status()).toBe(201);
  const assetId = await scannedAsset(page);
  const before = await (await page.request.get(`/api/v1/assets/${assetId}/attributes`)).json();
  expect((await page.request.put(`/api/v1/assets/${assetId}/attributes`, { headers: { ...await headers(page), 'If-Match': String(before.assetVersion) }, data: { modelId: typeId, modelVersion: 1, attributes: {} } })).status()).toBe(200);
  await page.goto('/models');
  await page.getByLabel('Search model identifiers', { exact: true }).fill(typeId);
  await page.getByRole('button', { name: 'Search models', exact: true }).click();
  await expect(page.getByRole('link', { name: typeId, exact: true })).toHaveAttribute('href', `/asset-types/${typeId}`);
  for (const suffix of ['', '/edit', '/migrate']) {
    await page.goto(`/models/${typeId}${suffix}`);
    await expect(page.getByRole('link', { name: 'Open asset type', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Plan migration', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Publish model', exact: true })).toHaveCount(0);
  }
  await steward.close();
  const consumer = await browser.newContext(); const readPage = await consumer.newPage();
  await login(readPage, 'consumer');
  await readPage.goto(`/asset-types/${typeId}`);
  await expect(readPage.getByRole('heading', { name: typeId, exact: true })).toBeVisible();
  await expect(readPage.getByRole('link', { name: 'Create next type version', exact: true })).toHaveCount(0);
  await readPage.goto('/asset-types/new/definition');
  await expect(readPage.getByRole('heading', { name: 'You do not have access to this view', exact: true })).toBeVisible();
  expect((await readPage.request.post('/api/v1/asset-types', { headers: await headers(readPage), data: { definition: { ...definition, id: `${typeId}_denied` } } })).status()).toBe(403);
  await readPage.goto(`/catalog/${assetId}`);
  await expect(readPage.getByTestId('lifecycle-current')).toHaveText('draft');
  await expect(readPage.getByRole('button', { name: 'Apply transition', exact: true })).toHaveCount(0);
  const state = await (await readPage.request.get(`/api/v1/assets/${assetId}/type-state`)).json();
  expect((await readPage.request.post(`/api/v1/assets/${assetId}/type-state`, { headers: { ...await headers(readPage), 'If-Match': String(state.assetVersion) }, data: { state: 'active' } })).status()).toBe(403);
  expect(await (await readPage.request.get(`/api/v1/assets/${assetId}/type-state`)).json()).toEqual(state);
  await capture(readPage, 'readonly-en', '.asset-lifecycle', [390]);
  await consumer.close();
  const summit = await browser.newContext(); const otherPage = await summit.newPage();
  await login(otherPage, 'summit');
  expect((await otherPage.request.get(`/api/v1/asset-types/${typeId}`)).status()).toBe(404);
  expect((await otherPage.request.get(`/api/v1/assets/${assetId}/type-state`)).status()).toBe(404);
  await otherPage.goto('/asset-types');
  await otherPage.getByLabel('Search asset types by identifier', { exact: true }).fill(typeId);
  await otherPage.getByRole('button', { name: 'Search types', exact: true }).click();
  await expect(otherPage.getByRole('link', { name: typeId, exact: true })).toHaveCount(0);
  await expect(otherPage.getByRole('heading', { name: 'No asset types found', exact: true })).toBeVisible();
  await otherPage.goto(`/asset-types/${typeId}`);
  await expect(otherPage.getByRole('heading', { name: 'This item is not available', exact: true })).toBeVisible();
  const independent = await otherPage.request.post('/api/v1/asset-types', { headers: await headers(otherPage), data: { definition: { ...definition, lifecycle: { initial: 'private', states: ['private'], transitions: [] } } } });
  expect(independent.status()).toBe(201);
  await otherPage.goto(`/asset-types/${typeId}`);
  await expect(otherPage.locator('.lifecycle-readout')).toContainText('private');
  await summit.close();
});
