// SPDX-License-Identifier: Apache-2.0
import { test, expect, type Page, type APIResponse } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import AxeBuilder from '@axe-core/playwright';

const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
async function login(page: Page, username: string) {
  await page.goto('/');
  await page.getByRole('link', { name: 'Continue with your identity provider' }).click();
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(credentials.personas[username]);
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page).toHaveURL('http://localhost:4310/');
  await expect(page.getByRole('heading', { level: 1, name: username === 'summit' ? 'Summit Logistics' : 'Harbor Retail' })).toBeVisible();
}

test('E2E-02/03: real OIDC, UI source registration, scan, discovery, ownership and audit', async ({ page }) => {
  test.setTimeout(180_000);
  await login(page, 'steward');
  console.info('Browser step: authenticated through Keycloak');
  const sourceName = `Harbor commerce browser ${Date.now()}`;
  await page.getByRole('link', { name: 'Sources & scans', exact: true }).click();
  await page.getByRole('button', { name: 'Connect a source', exact: true }).first().click();
  const connection = page.getByRole('dialog', { name: 'Connect PostgreSQL' });
  await connection.getByLabel('Connection name', { exact: false }).fill(sourceName);
  const createdResponse = page.waitForResponse(response => response.url().endsWith('/api/v1/sources') && response.request().method() === 'POST');
  await connection.getByRole('button', { name: 'Register source', exact: true }).click();
  const created = await createdResponse;
  expect(created.status()).toBe(201);
  const { source } = await created.json();
  console.info('Browser step: source registered through UI');
  await expect(connection).toBeHidden();
  const sourceCard = page.locator('.source-card').filter({ has: page.getByRole('heading', { name: sourceName, exact: true }) });
  await expect(sourceCard).toBeVisible();
  const submittedResponse = page.waitForResponse(response => response.url().endsWith(`/api/v1/sources/${source.id}/scans`) && response.request().method() === 'POST');
  await sourceCard.getByRole('button', { name: 'Run scan', exact: true }).click();
  const submitted = await submittedResponse;
  expect(submitted.status()).toBe(202);
  const { job } = await submitted.json();
  await expect(page.getByRole('status').filter({ hasText: 'Scan queued.' })).toBeVisible();
  await expect.poll(async () => {
    const response = await page.request.get(`/api/v1/jobs/${job.id}`);
    expect(response.ok()).toBeTruthy();
    return (await response.json()).job.status;
  }, { timeout: 100_000, intervals: [1_000, 2_000, 3_000] }).toBe('succeeded');
  console.info('Browser step: source scan succeeded');
  const jobRow = page.locator('#jobs tbody tr').filter({ hasText: sourceName });
  await expect(jobRow.getByText('Completed', { exact: true })).toBeVisible({ timeout: 10_000 });
  await expect.poll(async () => {
    let cursor: string | null = null;
    const seen = new Set<string>();
    do {
      const response: APIResponse = await page.request.get(`/api/v1/assets?q=orders&type=table${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
      expect(response.ok()).toBeTruthy();
      const result: { items: { sourceId: string }[]; nextCursor: string | null } = await response.json();
      if (result.items.some((asset: { sourceId: string }) => asset.sourceId === source.id)) return true;
      cursor = result.nextCursor;
      if (cursor) { expect(seen.has(cursor)).toBe(false); seen.add(cursor); expect(seen.size).toBeLessThan(200); }
    } while (cursor);
    return false;
  }, { timeout: 25_000 }).toBeTruthy();
  console.info('Browser step: search projection available');
  await page.getByRole('link', { name: 'Data catalog', exact: true }).click();
  const search = page.getByRole('searchbox', { name: 'Search names, descriptions and qualified names' });
  await search.fill('orders');
  await search.press('Enter');
  await expect(page).toHaveURL(/q=orders/);
  await page.getByRole('radio', { name: /^Table/ }).check();
  const assetRow = page.locator('tbody tr').filter({ hasText: sourceName }).filter({ has: page.getByRole('link', { name: 'orders', exact: true }) });
  // Repeated real scans retain independent sources. Exercise the actual catalog
  // pagination instead of assuming this source sorts into the first fifty rows.
  for (let visited = 0; await assetRow.count() === 0; visited += 1) {
    expect(visited).toBeLessThan(199);
    const more = page.locator('.pagination').getByRole('button').last();
    await expect(more).toBeEnabled();
    const loaded = page.waitForResponse(response => response.url().includes('/api/v1/assets?') && response.request().method() === 'GET');
    await more.click();
    expect((await loaded).ok()).toBeTruthy();
    await expect(page.locator('.pagination').getByRole('button').first()).toBeEnabled();
    await expect(page.locator('.catalog-results [aria-busy="true"]')).toHaveCount(0);
  }
  await assetRow.getByRole('link', { name: 'orders', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'orders', exact: true })).toBeVisible();
  console.info('Browser step: discovered orders in catalog');
  await page.getByRole('link', { name: /^Columns \(/ }).click();
  await expect(page.getByRole('link', { name: 'order_id', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Edit details', exact: true }).click();
  const editor = page.getByRole('dialog', { name: 'Edit details' });
  const description = 'Synthetic Harbor orders used for the verified browser acceptance journey.';
  await editor.getByRole('textbox', { name: /^Business description/ }).fill(description);
  await editor.getByRole('combobox', { name: 'Owner', exact: true }).selectOption({ label: 'Harbor Owner' });
  const savedResponse = page.waitForResponse(response => response.url().includes('/api/v1/assets/') && response.request().method() === 'PATCH');
  await editor.getByRole('button', { name: 'Save changes', exact: true }).click();
  expect((await savedResponse).status()).toBe(200);
  await expect(editor).toBeHidden();
  await page.getByRole('link', { name: 'Overview', exact: true }).last().click();
  await expect(page.getByText(description, { exact: true })).toBeVisible();
  await expect(page.locator('.ownership-person').getByText('Harbor Owner', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText(description, { exact: true })).toBeVisible();
  mkdirSync('docs/verification/screenshots', { recursive: true });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 960 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
    const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
    expect(accessibility.violations).toEqual([]);
    await page.screenshot({ path: `docs/verification/screenshots/asset-en-light-${width}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.getByRole('link', { name: 'History', exact: true }).click();
  await page.getByRole('button', { name: 'Asset details updated', exact: true }).first().click();
  const audit = page.getByRole('dialog', { name: 'Audit record' });
  await expect(audit.getByLabel('Recorded changes')).toContainText(description);
  await expect(audit.getByText('Harbor Steward', { exact: true })).toBeVisible();
  await audit.getByRole('button', { name: 'Close', exact: true }).click();
  mkdirSync('docs/verification/screenshots', { recursive: true });
  await page.screenshot({ path: 'docs/verification/screenshots/catalog-history.png', fullPage: true });
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace', exact: true })).toBeVisible();
});

test('E2E-03: consumer restrictions and cross-tenant catalog isolation use real identity', async ({ browser }) => {
  const consumer = await browser.newContext();
  const page = await consumer.newPage();
  await login(page, 'consumer');
  const me = await (await page.request.get('/api/v1/me')).json();
  expect(me.permissions).not.toContain('sources:write');
  await expect(page.getByRole('link', { name: 'Sources & scans', exact: true })).toHaveCount(0);
  const denied = await page.request.post('/api/v1/sources', {
    headers: { 'X-CSRF-Token': me.csrfToken, Origin: 'http://localhost:4310', 'Idempotency-Key': crypto.randomUUID() },
    data: { name: 'Forbidden synthetic source', host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' },
  });
  expect(denied.status()).toBe(403);
  await page.goto('/sources');
  await expect(page.getByRole('heading', { name: 'You do not have access to this view', exact: true })).toBeVisible();
  await consumer.close();
  const summit = await browser.newContext();
  const summitPage = await summit.newPage();
  await login(summitPage, 'summit');
  const assets = await (await summitPage.request.get('/api/v1/assets?q=orders')).json();
  expect(assets.total).toBe(0);
  expect(assets.facets).toEqual([]);
  await summitPage.goto('/catalog?q=orders');
  await expect(summitPage.getByRole('heading', { name: 'No matching assets', exact: true })).toBeVisible();
  await summit.close();
});
