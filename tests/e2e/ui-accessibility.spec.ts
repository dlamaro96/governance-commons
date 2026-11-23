// SPDX-License-Identifier: Apache-2.0
import {domainLogin} from '../fixtures/business-domains-browser.ts';
import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync } from 'node:fs';

async function login(page: Page) {
  await domainLogin(page);
}
async function accessible(page: Page) {
  // Theme changes animate button backgrounds. Audit the settled rendered state,
  // without hiding elements, disabling transitions, or excluding any axe rules.
  await page.evaluate(async () => {
    const finiteAnimations = document.getAnimations().filter(animation =>
      animation.effect?.getComputedTiming().iterations !== Infinity);
    await Promise.all(finiteAnimations.map(animation => animation.finished.catch(() => undefined)));
  });
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  expect(result.violations).toEqual([]);
}
async function fitsViewport(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
}

test('UX-04/AT-UX-01: real catalog layouts, light/dark, RTL and automated accessibility', async ({ page }) => {
  test.setTimeout(180_000);
  mkdirSync('docs/verification/screenshots', { recursive: true });
  await login(page);
  for (const width of [390, 768, 1024, 1280, 1440]) {
    await page.setViewportSize({ width, height: 960 });
    await page.goto('/catalog');
    await expect(page.getByRole('heading', { name: 'Data catalog', exact: true })).toBeVisible();
    await expect(page.getByText('Loading…', { exact: true })).toHaveCount(0);
    await fitsViewport(page);
    await accessible(page);
    await page.screenshot({ path: `docs/verification/screenshots/catalog-en-light-${width}.png`, fullPage: false });
  }
  for (const screen of [
    { path: '/', heading: 'Harbor Retail', name: 'overview' },
    { path: '/sources', heading: 'Sources & scans', name: 'sources' },
    { path: '/audit', heading: 'Audit history', name: 'audit' },
  ]) {
    await page.goto(screen.path);
    await expect(page.getByRole('heading', { level: 1, name: screen.heading, exact: true })).toBeVisible();
    await expect(page.getByText('Loading…', { exact: true })).toHaveCount(0);
    await fitsViewport(page);
    await accessible(page);
    await page.screenshot({ path: `docs/verification/screenshots/${screen.name}-en-light-1440.png`, fullPage: false });
  }
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto('/catalog');
  await expect(page.getByRole('heading', { name: 'Data catalog', exact: true })).toBeVisible();
  await expect(page.getByText('Loading…', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Colour theme: Dark', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await accessible(page);
  await page.screenshot({ path: 'docs/verification/screenshots/catalog-en-dark-1440.png', fullPage: false });
  await page.locator('#language').selectOption('ar');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await expect(page.getByRole('heading', { name: 'كتالوج البيانات', exact: true })).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 960 });
    await fitsViewport(page);
    await accessible(page);
    await page.screenshot({ path: `docs/verification/screenshots/catalog-ar-dark-${width}.png`, fullPage: false });
  }
});

test('UX-30: connection form keyboard focus, dismissal and accessible labels', async ({ page }) => {
  await login(page);
  await page.goto('/sources');
  const opener = page.getByRole('button', { name: 'Connect a source', exact: true }).first();
  await opener.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: 'Connect PostgreSQL' });
  await expect(dialog).toBeVisible();
  await accessible(page);
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press('Tab');
    expect(await dialog.evaluate(element => element.contains(document.activeElement))).toBeTruthy();
  }
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
});
