// SPDX-License-Identifier: Apache-2.0
import {defineConfig} from '@playwright/test';
if(!process.env.AUTHN_BROWSER_CONFIG||!process.env.AUTHN_BROWSER_OUTPUT||!process.env.GC_BROWSER_EXECUTABLE)throw Error('Explicit isolated browser inputs required');
export default defineConfig({testDir:'.',testMatch:'*.spec.ts',fullyParallel:false,workers:1,retries:0,maxFailures:1,timeout:120_000,expect:{timeout:15_000},
 use:{baseURL:'http://127.0.0.1:4314',headless:true,actionTimeout:15_000,navigationTimeout:30_000,colorScheme:'light',trace:'off',video:'off',screenshot:'off',launchOptions:{executablePath:process.env.GC_BROWSER_EXECUTABLE}},
 reporter:[['list'],['json',{outputFile:process.env.AUTHN_BROWSER_OUTPUT+'/results.json'}]],outputDir:process.env.AUTHN_BROWSER_OUTPUT+'/test-results'});
