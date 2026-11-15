// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from '@playwright/test';
import base from '../playwright.config';

// Never collect login form values, network headers or cookies into CI artifacts.
// Tests may explicitly save reviewed authenticated synthetic-data screenshots only.
export default defineConfig({
  ...base,
  testDir: '../tests/e2e',
  // Reporter paths resolve relative to this config directory, unlike the root
  // config. Keep the raw report private at the collector's exact input path.
  reporter: [['list'], ['json', { outputFile: '../.local/evidence/playwright-results.json' }]],
  use: { ...base.use, trace: 'off', video: 'off', screenshot: 'off' },
  outputDir: '../.local/ci-test-results',
  projects: [
    { name: 'vertical-slice', testMatch: /vertical-slice\.spec\.ts/ },
    { name: 'accessibility', testMatch: /ui-accessibility\.spec\.ts/, dependencies: ['vertical-slice'] },
    { name: 'models', testMatch: /models\.spec\.ts/, dependencies: ['vertical-slice'] },
    { name: 'model-migrations', testMatch: /model-migrations\.spec\.ts/, dependencies: ['models'] },
    { name: 'asset-types', testMatch: /asset-types\.spec\.ts/, dependencies: ['model-migrations'] },
    { name: 'asset-type-migrations', testMatch: /asset-type-migrations\.spec\.ts/, dependencies: ['asset-types'] },
    { name: 'relations', testMatch: /relations\.spec\.ts/, dependencies: ['asset-type-migrations'] },
    { name: 'relation-migrations', testMatch: /relation-migrations\.spec\.ts/, dependencies: ['relations'] },
  ],
});
