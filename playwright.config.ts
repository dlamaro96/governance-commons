// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: process.env.GC_BROWSER_BASE_URL || 'http://localhost:4310',
    headless: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    colorScheme: 'light',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    // A locally installed Chrome can avoid an unnecessary browser download.
    // The evidence manifest must record the actual browser version used.
    launchOptions: process.env.GC_BROWSER_EXECUTABLE ? { executablePath: process.env.GC_BROWSER_EXECUTABLE } : undefined,
  },
  reporter: [['list'], ['json', { outputFile: '.local/evidence/playwright-results.json' }]],
  outputDir: '.local/test-results',
});
