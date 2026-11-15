// SPDX-License-Identifier: Apache-2.0
import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests/e2e',fullyParallel:false,workers:1,timeout:120000,expect:{timeout:15000},use:{baseURL:'http://localhost:4310',headless:true,trace:'retain-on-failure',screenshot:'only-on-failure'},reporter:[['list'],['json',{outputFile:'.local/evidence/playwright-results.json'}]],outputDir:'.local/test-results'});
