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
    { name: 'business-domains', testMatch: /business-domains\.spec\.ts/, dependencies: ['relation-migrations'] },
    { name: 'source-connectors', testMatch: /source-connectors\.spec\.ts/, dependencies: ['business-domains'] },
    { name: 'postgres-configuration', testMatch: /postgres-configuration\.spec\.ts/, dependencies: ['source-connectors'] },
    { name: 'approvals', testMatch: /approvals\.spec\.ts/, dependencies: ['postgres-configuration'] },
    { name: 'glossary', testMatch: /glossary\.spec\.ts/, dependencies: ['approvals'] },
    { name: 'quality', testMatch: /(^|[/\\])quality\.spec\.ts$/, dependencies: ['glossary'] },
    { name: 'lineage', testMatch: /lineage\.spec\.ts/, dependencies: ['quality'] },
    { name: 'classification', testMatch: /classification\.spec\.ts/, dependencies: ['lineage'] },
    { name: 'reference-data', testMatch: /reference-data\.spec\.ts/, dependencies: ['classification'] },
    { name: 'reference-quality', testMatch: /reference-quality\.spec\.ts/, dependencies: ['reference-data'] },
    { name: 'reference-structures', testMatch: /reference-structures\.spec\.ts/, dependencies: ['reference-quality'] },
    { name: 'reference-import', testMatch: /reference-import\.spec\.ts/, dependencies: ['reference-structures'] },
    { name: 'quality-uniqueness', testMatch: /quality-uniqueness\.spec\.ts/, dependencies: ['reference-import'] },
    { name: 'quality-range', testMatch: /quality-range\.spec\.ts/, dependencies: ['quality-uniqueness'] },
    { name: 'quality-monitoring', testMatch: /quality-monitoring\.spec\.ts/, dependencies: ['quality-range'] },
    { name: 'quality-freshness', testMatch: /quality-freshness\.spec\.ts/, dependencies: ['quality-monitoring'] },
    { name: 'quality-freshness-monitoring', testMatch: /quality-freshness-monitoring\.spec\.ts/, dependencies: ['quality-freshness'] },
  ],
});
