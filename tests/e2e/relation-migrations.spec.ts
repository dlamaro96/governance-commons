// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, source scan, REST and rendered UI journeys. No response stubs. */
import { test, expect, type APIResponse, type Browser, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import type { RelationView } from '../../packages/domain/src/relation-contracts.ts';
import type { GraphChangeSet, RelationMigrationContext, RelationMigrationPreview, RelationMigrationReceipt,
  RelationPreparationView } from '../../packages/domain/src/relation-migration-contracts.ts';
import { authoredDefinition, contextRequest, emptyChange, exactAmount, jointCreation, plan, positiveDefinition,
  repairChange, samePairReplacement, type Endpoint } from '../fixtures/relation-migration-api.ts';

const credentials = JSON.parse(readFileSync('.local/bootstrap.json', 'utf8'));
const base = process.env.GC_BROWSER_BASE_URL || 'http://localhost:4310', origin = new URL(base).origin;
const actor = '10000000-0000-4000-8000-000000000001';
const csrf = new WeakMap<Page, string>();
const consent = 'I reviewed the complete affected graph, zero-degree assets, owner and state changes, dispositions and this exact preview digest.';
async function login(page: Page, username = 'steward') {
  page.on('response', response => { if (response.status() === 429 || response.status() >= 500)
    console.info(JSON.stringify({ diagnostic: 'graph_browser_http', method: response.request().method(), status: response.status(), path: new URL(response.url()).pathname })); });
  await page.goto('/auth/login'); await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(credentials.personas[username]);
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page).toHaveURL(`${origin}/`);
  await expect(page.getByRole('heading', { level: 1, name: username === 'summit' ? 'Summit Logistics' : 'Harbor Retail' })).toBeVisible();
}
async function headers(page: Page) {
  if (!csrf.has(page)) { const response = await page.request.get('/api/v1/me'); expect(response.status()).toBe(200); csrf.set(page, (await response.json()).csrfToken); }
  return { 'X-CSRF-Token': csrf.get(page)!, Origin: origin, 'Idempotency-Key': crypto.randomUUID() };
}
async function body<T = any>(response: APIResponse, status = 200): Promise<T> {
  expect(response.status(), await response.text()).toBe(status); return response.json();
}
async function pacing({ browser }: { browser: Browser }) {
  test.setTimeout(75_000); const context = await browser.newContext(), response = await context.request.get('/api/v1/me');
  const reset = Number(response.headers()['x-ratelimit-reset']), remaining = Number(response.headers()['x-ratelimit-remaining']); await context.close();
  if (Number.isFinite(reset) && reset >= 0 && reset <= 60 && Number.isFinite(remaining) && remaining < 220)
    await new Promise(resolve => setTimeout(resolve, Math.min(60, reset + 1) * 1000));
}
test.beforeAll(pacing); test.beforeEach(pacing); test.afterAll(pacing);
async function capture(page: Page, name: string, selector?: string) {
  mkdirSync('docs/verification/screenshots', { recursive: true });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 960 });
    await page.evaluate(selector => { if (selector) document.querySelector(selector)?.scrollIntoView({ block: 'start', behavior: 'instant' }); else window.scrollTo(0, 0); }, selector);
    await expect.poll(() => page.evaluate(() => document.getAnimations().filter(animation => animation.playState === 'running' && animation.playbackRate !== 0 &&
      Number.isFinite(animation.effect?.getComputedTiming().endTime)).length), { timeout: 5000 }).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBeTruthy();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await page.screenshot({ path: `docs/verification/screenshots/m2-relation-migration-${name}-${width}.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
}
async function asset(page: Page, id: string): Promise<Endpoint> { return (await body(await page.request.get(`/api/v1/assets/${id}`))).asset; }
async function fixture(page: Page) {
  const prefix = `browser_graph_${Date.now()}_${crypto.randomUUID().slice(0, 6)}`;
  const route = await page.request.get(`/api/v1/assets/${crypto.randomUUID()}/relation-participation`);
  expect((await body(route, 404)).code, 'The matching graph API must be installed; an old image is not a qualification target.').toBe('RELATION_NOT_FOUND');
  const { type } = await body(await page.request.post('/api/v1/asset-types', { headers: await headers(page), data: { definition: authoredDefinition(`${prefix}_asset`) } }), 201);
  const { source } = await body(await page.request.post('/api/v1/sources', { headers: await headers(page), data: { name: `Synthetic graph browser ${prefix}`,
    host: 'source-postgres', port: 5432, database: 'harbor', schema: 'public', secretRef: 'demo-postgres' } }), 201);
  const { job } = await body(await page.request.post(`/api/v1/sources/${source.id}/scans`, { headers: await headers(page), data: {} }), 202);
  await expect.poll(async () => (await body(await page.request.get(`/api/v1/jobs/${job.id}`))).job.status,
    { timeout: 100_000, intervals: [1000, 2000] }).toBe('succeeded');
  const endpoints: Endpoint[] = [];
  for (const name of ['orders', 'customers']) {
    let found: string | undefined;
    await expect.poll(async () => {
      let cursor: string | null = null;
      for (let count = 0; count < 30; count++) {
        const result: { items: { id: string; name: string; sourceId: string }[]; nextCursor: string | null } = await body(await page.request.get(
          `/api/v1/assets?q=${name}&type=table&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`));
        found = result.items.find(row => row.sourceId === source.id && row.name === name)?.id;
        cursor = result.nextCursor; if (found || !cursor) break;
      }
      return !!found;
    }, { timeout: 25_000 }).toBeTruthy();
    const endpoint = await asset(page, found!); expect(endpoint.modelId).toBeNull(); endpoints.push(endpoint);
  }
  const definition = positiveDefinition(`${prefix}_required`, type.typeId), preparationHeaders = await headers(page);
  const { preparation } = await body<{ preparation: RelationPreparationView }>(await page.request.post('/api/v1/relation-migrations/preparations',
    { headers: preparationHeaders, data: { definition } }), 201);
  const replay = await body<{ preparation: RelationPreparationView }>(await page.request.post('/api/v1/relation-migrations/preparations',
    { headers: preparationHeaders, data: { definition } }), 201);
  expect(replay.preparation).toEqual(preparation); expect(Date.parse(preparation.expiresAt) - Date.parse(preparation.createdAt)).toBe(900000);
  return { type, endpoints, definition, preparation, change: jointCreation(preparation, definition, type.id, endpoints) };
}
async function importDraft(page: Page, change: GraphChangeSet) {
  await page.getByLabel('Import change set JSON', { exact: true }).setInputFiles({ name: 'synthetic.graph-change.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(change, null, 2)) });
  await expect(page.getByRole('textbox', { name: 'Change set draft', exact: true })).toHaveValue(JSON.stringify(change, null, 2));
  const response = page.waitForResponse(response => response.url().endsWith('/relation-migrations/validate') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Validate and open visual editor', exact: true }).click(); expect((await response).status()).toBe(200);
  await expect(page.getByRole('button', { name: 'Visual editor', exact: true })).toHaveAttribute('aria-pressed', 'true');
}
async function loadContext(page: Page): Promise<RelationMigrationContext> {
  const response = page.waitForResponse(response => response.url().endsWith('/relation-migrations/context') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Load complete context', exact: true }).click();
  const result = await response; expect(result.status()).toBe(200); return (await result.json()).context;
}
async function preview(page: Page): Promise<RelationMigrationPreview> {
  const response = page.waitForResponse(response => response.url().endsWith('/relation-migrations/previews') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Preview complete graph', exact: true }).click();
  const result = await response; expect(result.status()).toBe(200); return (await result.json()).preview;
}
async function executeAttempt(page: Page) {
  const response = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/relation-migrations' && response.request().method() === 'POST', { timeout: 45_000 });
  await page.getByRole('button', { name: 'Execute reviewed graph change', exact: true }).click();
  const result = await response; return { status: result.status(), body: await result.json() };
}
async function execute(page: Page): Promise<RelationMigrationReceipt> {
  const control = page.getByRole('checkbox', { name: consent, exact: true }); await control.focus(); await page.keyboard.press('Space'); await expect(control).toBeChecked();
  const result = await executeAttempt(page); expect(result.status, JSON.stringify(result.body)).toBe(201);
  await expect(page.getByRole('heading', { name: 'Graph change receipt', level: 1 })).toBeVisible(); return result.body.receipt;
}
async function apiContext(page: Page, typeId: string, receiptId: string | null = null): Promise<RelationMigrationContext> {
  const change: GraphChangeSet = { ...emptyChange(), repairsReceiptId: receiptId, relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: plan(typeId) }] };
  return (await body<{ context: RelationMigrationContext }>(await page.request.post('/api/v1/relation-migrations/context', { headers: await headers(page), data: contextRequest(change) }))).context;
}
async function apiExecute(page: Page, changeSet: GraphChangeSet): Promise<RelationMigrationReceipt> {
  const { preview } = await body<{ preview: RelationMigrationPreview }>(await page.request.post('/api/v1/relation-migrations/previews', { headers: await headers(page), data: { changeSet } }));
  expect(preview.ready, JSON.stringify(preview.targetIssues)).toBe(true);
  return (await body<{ receipt: RelationMigrationReceipt }>(await page.request.post('/api/v1/relation-migrations', { headers: await headers(page), data: { changeSet, previewDigest: preview.previewDigest } }), 201)).receipt;
}

test('MOD: complete graph draft repairs positive participation, jointly assigns first endpoints, round-trips exact intent and follows receipt/history into same-pair repair', async ({ page }) => {
  test.setTimeout(420_000); await login(page); const f = await fixture(page);
  const initial = structuredClone(f.change); initial.relationTargets[0].plan.creations = [];
  await page.goto('/relation-migrations/new'); await importDraft(page, initial);
  const before = await loadContext(page); expect(before.before.endpoints).toHaveLength(2); expect(before.before.edges).toHaveLength(0);
  expect(before.proposedEndpoints?.every(row => row.assetVersion === f.endpoints.find(endpoint => endpoint.id === row.assetId)!.version + 1)).toBe(true);
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  const draft = page.getByRole('textbox', { name: 'Change set draft', exact: true }); await draft.fill('{"formatVersion":1,');
  await loadContext(page); await expect(draft).toHaveValue('{"formatVersion":1,');
  await expect(page.getByRole('button', { name: 'Execute reviewed graph change', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Restore last structured draft', exact: true }).click(); await loadContext(page);
  const blocked = await preview(page); expect(blocked.ready).toBe(false); expect(blocked.previewDigest).toBeNull(); expect(blocked.projection).not.toBeNull();
  await expect(page.getByText('This proposal cannot execute. Correct the target issues and preview again.', { exact: true })).toBeVisible();
  await capture(page, 'invalid-minimum-en', '.graph-preview');
  const creations = page.locator('.graph-plan-editor > section').filter({ has: page.getByRole('heading', { name: 'New assertions', exact: true }) });
  for (const [index, source] of f.endpoints.entries()) {
    await creations.getByRole('button', { name: 'Add assertion proposal', exact: true }).click();
    const group = creations.getByRole('group', { name: `New assertions ${index + 1}`, exact: true });
    await group.getByRole('textbox', { name: 'Creation key', exact: true }).fill(`required_${index}`);
    await group.getByRole('combobox', { name: 'Source asset', exact: true }).selectOption(source.id);
    await group.getByRole('combobox', { name: 'Target asset', exact: true }).selectOption(f.endpoints[1 - index].id);
    await group.getByRole('textbox', { name: 'amount', exact: true }).fill(exactAmount);
  }
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  const authored = JSON.parse(await page.getByRole('textbox', { name: 'Change set draft', exact: true }).inputValue()) as GraphChangeSet;
  for (const creation of authored.relationTargets[0].plan.creations) {
    expect(creation.sourceAssetVersion).toBe(f.endpoints.find(row => row.id === creation.sourceAssetId)!.version);
    expect(creation.targetAssetVersion).toBe(f.endpoints.find(row => row.id === creation.targetAssetId)!.version);
    expect(creation.values.attributes.amount).toBe(exactAmount);
  }
  const downloaded = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export change set JSON', exact: true }).click();
  const file = await downloaded, text = readFileSync((await file.path())!, 'utf8');
  expect(JSON.parse(text)).toEqual(authored);
  await importDraft(page, JSON.parse(text)); await loadContext(page); const reviewed = await preview(page);
  expect(reviewed.ready).toBe(true); expect(reviewed.projection?.participation).toHaveLength(4);
  expect(reviewed.projection?.participation.every(row => row.beforeDegree === 0 && row.proposedDegree === 1)).toBe(true);
  await expect(page.getByRole('button', { name: 'Execute reviewed graph change', exact: true })).toBeDisabled();
  await capture(page, 'joint-preview-en', '.graph-preview');
  await page.getByRole('button', { name: 'Colour theme: Dark', exact: true }).click(); await page.locator('#language').selectOption('ar');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl'); await expect(page.locator('.graph-preview').getByRole('heading', { name: 'معاينة الرسم الكامل', exact: true })).toBeVisible();
  await capture(page, 'joint-preview-ar-dark', '.graph-preview');
  await page.locator('#language').selectOption('en'); await page.getByRole('button', { name: 'Colour theme: Light', exact: true }).click();
  const receipt = await execute(page); expect(receipt.creations).toHaveLength(2); expect(receipt.enrollments).toHaveLength(4);
  expect(receipt.assetRevisions.every(row => row.after.version === row.before.version + 1)).toBe(true);
  expect(receipt.after.edges.every(row => row.sourceAssetVersion === f.endpoints.find(endpoint => endpoint.id === row.sourceAssetId)!.version + 1)).toBe(true);
  await capture(page, 'joint-receipt-en');
  await page.getByRole('link', { name: 'Start forward repair', exact: true }).click();
  const repairContext = await loadContext(page); await page.getByRole('button', { name: 'Capture every source edge and binding in the plan', exact: true }).click();
  const replacement = samePairReplacement(repairContext, f.preparation.relationTypeId, receipt.id);
  await importDraft(page, replacement); await loadContext(page); expect((await preview(page)).ready).toBe(true);
  const repaired = await execute(page); expect(repaired.repairsReceiptId).toBe(receipt.id); expect(repaired.replacements).toHaveLength(1);
  const mapping = repaired.replacements[0]; expect(mapping.predecessorId).not.toBe(mapping.successorId);
  expect((await body(await page.request.get(`/api/v1/relations/${mapping.predecessorId}`))).relation.status).toBe('tombstoned');
  expect((await body(await page.request.get(`/api/v1/relations/${mapping.successorId}`))).relation.status).toBe('active');
  await capture(page, 'forward-repair-receipt-en');
  await page.goto(`/catalog/${f.endpoints[0].id}?tab=relations`);
  const participation = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: 'Required participation', level: 2, exact: true }) });
  await expect(participation.getByRole('table')).toBeVisible(); await participation.getByRole('combobox', { name: 'Rows per page', exact: true }).selectOption('1');
  await expect(participation.getByRole('row')).toHaveCount(2); await participation.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(participation.getByText('Page 2', { exact: true })).toBeVisible();
  await participation.getByRole('button', { name: /^Participation history/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Participation history', exact: true }); await expect(dialog).toBeVisible();
  await dialog.locator('summary').first().click(); await expect(dialog.getByRole('link', { name: 'Originating graph change', exact: true })).toHaveAttribute('href', `/relation-migrations/${receipt.id}`);
  await capture(page, 'participation-history-en', '.dialog-content');
  await page.keyboard.press('Escape'); await expect(dialog).toBeHidden();
});

test('MOD: edits clear consent, concurrent reviews recover from stale execution, participation cursors and private receipt/history scope remain enforced', async ({ page, browser }) => {
  test.setTimeout(420_000); await login(page); const f = await fixture(page), receipt = await apiExecute(page, f.change);
  const captured = await apiContext(page, f.preparation.relationTypeId, receipt.id), change = repairChange(captured, f.preparation.relationTypeId, receipt.id);
  const edge = captured.before.edges[0]; expect(edge.key.kind).toBe('existing'); if (edge.key.kind !== 'existing') throw Error('Missing actual edge');
  const edgeId = edge.key.relationId;
  change.relationTargets[0].plan = { ...change.relationTargets[0].plan, edges: change.relationTargets[0].plan.edges.map(row => row.relationId === edgeId
    ? { ...row, action: 'repair', values: { ...edge.values, attributes: { ...edge.values.attributes, note: 'Synthetic browser repair' } } } : row) };
  await page.goto('/relation-migrations/new'); await importDraft(page, change); await loadContext(page); expect((await preview(page)).ready).toBe(true);
  await page.getByRole('checkbox', { name: consent, exact: true }).check();
  await page.getByRole('button', { name: 'JSON source', exact: true }).click();
  await page.getByRole('textbox', { name: 'Change set draft', exact: true }).fill(JSON.stringify(change, null, 2) + '\n');
  await expect(page.getByRole('checkbox', { name: consent, exact: true })).toHaveCount(0);
  await importDraft(page, change); await loadContext(page); expect((await preview(page)).ready).toBe(true);
  await page.getByRole('checkbox', { name: consent, exact: true }).check();
  const current = await asset(page, f.endpoints[0].id);
  await body(await page.request.patch(`/api/v1/assets/${current.id}`, { headers: { ...await headers(page), 'If-Match': String(current.version) }, data: { description: 'Synthetic late metadata update' } }));
  const stale = await executeAttempt(page); expect(stale.status).toBe(409); expect(stale.body.code).toBe('RELATION_PREVIEW_STALE');
  await expect(page.getByRole('checkbox', { name: consent, exact: true })).toHaveCount(0);
  await capture(page, 'stale-review-en');
  await loadContext(page); expect((await preview(page)).ready).toBe(true); await page.getByRole('checkbox', { name: consent, exact: true }).check();
  const competing = await page.context().newPage();
  try {
    await competing.goto('/relation-migrations/new'); await importDraft(competing, change); await loadContext(competing); expect((await preview(competing)).ready).toBe(true);
    await competing.getByRole('checkbox', { name: consent, exact: true }).check();
    const attempts = await Promise.all([executeAttempt(page), executeAttempt(competing)]), winnerIndex = attempts.findIndex(result => result.status === 201);
    expect(winnerIndex).not.toBe(-1); const loserIndex = 1 - winnerIndex, loser = loserIndex === 0 ? page : competing;
    expect([409, 503]).toContain(attempts[loserIndex].status);
    expect(['VERSION_CONFLICT', 'RELATION_PREVIEW_STALE', 'RELATION_RETRY']).toContain(attempts[loserIndex].body.code);
    if (attempts[loserIndex].status === 503) {
      const retried = loser.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/relation-migrations' && response.request().method() === 'POST');
      await loser.getByRole('button', { name: 'Retry', exact: true }).click(); expect((await retried).status()).toBe(409);
    }
    await expect(loser.getByRole('checkbox', { name: consent, exact: true })).toHaveCount(0);
  } finally { await competing.close(); }
  await page.goto(`/catalog/${f.endpoints[0].id}?tab=relations`);
  const participation = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: 'Required participation', level: 2, exact: true }) });
  await participation.getByRole('combobox', { name: 'Rows per page', exact: true }).selectOption('1');
  await expect(participation.getByRole('button', { name: 'Next page', exact: true })).toBeEnabled();
  const latest = await asset(page, f.endpoints[0].id);
  await body(await page.request.patch(`/api/v1/assets/${latest.id}`, { headers: { ...await headers(page), 'If-Match': String(latest.version) }, data: { description: 'Synthetic participation page invalidation' } }));
  const stalePage = page.waitForResponse(response => response.url().includes('/relation-participation?') && response.url().includes('cursor='));
  await participation.getByRole('button', { name: 'Next page', exact: true }).click(); expect((await stalePage).status()).toBe(409);
  await expect(participation.getByRole('table')).toHaveCount(0); await participation.getByRole('button', { name: 'Restart this graph query', exact: true }).click();
  await expect(participation.getByRole('table')).toBeVisible();
  const restricted = (await body(await page.request.get(`/api/v1/relations/${edgeId}`))).relation as RelationView;
  await body(await page.request.patch(`/api/v1/relations/${edgeId}`, { headers: { ...await headers(page), 'If-Match': String(restricted.version) }, data: {
    attributes: restricted.attributes, ownerId: restricted.ownerId, validFrom: restricted.validFrom, validTo: restricted.validTo,
    sourceAssetVersion: restricted.source.assetVersion, targetAssetVersion: restricted.target.assetVersion,
    visibility: 'restricted', allowedIdentityIds: [actor] } }));
  const analystContext = await browser.newContext();
  try {
    const analystPage = await analystContext.newPage(); await login(analystPage, 'consumer'); await analystPage.goto(`/catalog/${f.endpoints[0].id}?tab=relations`);
    const hidden = analystPage.locator('section.panel').filter({ has: analystPage.getByRole('heading', { name: 'Required participation', level: 2, exact: true }) });
    await expect(hidden.getByText('The complete validation scope is not available with your current access.', { exact: true })).toBeVisible();
    await expect(hidden.getByRole('table')).toHaveCount(0); await capture(analystPage, 'private-participation-en', '.asset-relations');
    const forbidden = await analystPage.request.get(`/api/v1/relation-migrations/${receipt.id}`); expect((await body(forbidden, 404)).code).toBe('RELATION_MIGRATION_NOT_FOUND');
    const binding = receipt.enrollments.find(row => row.assetId === f.endpoints[0].id)!;
    expect((await body(await analystPage.request.get(`/api/v1/assets/${binding.assetId}/relation-participation/${binding.bindingId}/history?limit=1`), 403)).code).toBe('RELATION_SCOPE_UNAVAILABLE');
    await analystPage.goto(`/relation-migrations/${receipt.id}`); await expect(analystPage.getByText('The requested graph operation or preparation is unavailable.', { exact: true })).toBeVisible();
    await expect(analystPage.getByRole('heading', { name: 'Graph change receipt', level: 1 })).toHaveCount(0);
  } finally { await analystContext.close(); }
  const foreignContext = await browser.newContext();
  try {
    const foreignPage = await foreignContext.newPage(); await login(foreignPage, 'summit');
    expect((await body(await foreignPage.request.get(`/api/v1/assets/${f.endpoints[0].id}/relation-participation`), 404)).code).toBe('RELATION_NOT_FOUND');
    await foreignPage.goto(`/relation-migrations/${receipt.id}`); await expect(foreignPage.getByText('The requested graph operation or preparation is unavailable.', { exact: true })).toBeVisible();
  } finally { await foreignContext.close(); }
});
