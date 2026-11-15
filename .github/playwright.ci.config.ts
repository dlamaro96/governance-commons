// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from '@playwright/test';
import base from '../playwright.config';

// Never collect login form values, network headers or cookies into CI artifacts.
// Tests may explicitly save the reviewed authenticated catalog screenshots only.
export default defineConfig({
  ...base,
  testDir: '../tests/e2e',
  use: { ...base.use, trace: 'off', video: 'off', screenshot: 'off' },
  outputDir: '../.local/ci-test-results',
  projects: [
    { name: 'vertical-slice', testMatch: /vertical-slice\.spec\.ts/ },
    { name: 'accessibility', testMatch: /ui-accessibility\.spec\.ts/, dependencies: ['vertical-slice'] },
  ],
});
