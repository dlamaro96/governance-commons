// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, source registration and Temporal/site/Python failure path; no mocks or vendor credentials. */
import {test,expect,type Browser,type Locator,type Page} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {mkdirSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {domainLogin,domainHeaders,domainBody} from '../fixtures/business-domains-browser.ts';
import type {Job,Source} from '../../apps/web/src/types.ts';

async function pacing({browser}:{browser:Browser}) {
  test.setTimeout(75_000);
  const context=await browser.newContext();
  try {
    const response=await context.request.get('/api/v1/me');
    const remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
    if(Number.isFinite(remaining)&&remaining<100&&Number.isFinite(reset)&&reset>=0&&reset<=60)
      await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
  } finally {await context.close();}
}
test.beforeAll(pacing);

// Same settled-animation, real axe and viewport evidence convention as the
// existing domain/accessibility journeys. Screenshots contain synthetic data only.
async function capture(page:Page,name:string,width:number,anchor?:Locator) {
  await page.setViewportSize({width,height:960});
  if(anchor)await anchor.scrollIntoViewIfNeeded();
  else await page.evaluate(()=>window.scrollTo(0,0));
  await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>
    animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
  mkdirSync('docs/verification/screenshots',{recursive:true});
  await page.screenshot({path:`docs/verification/screenshots/m8-source-connectors-${name}-${width}.png`,fullPage:false});
}
async function language(page:Page,value:'en'|'ar') {
  await page.locator('#language').selectOption(value);
  await expect(page.locator('html')).toHaveAttribute('lang',value);
  await expect(page.locator('html')).toHaveAttribute('dir',value==='ar'?'rtl':'ltr');
}
async function sources(page:Page,q:string):Promise<Source[]> {return (await domainBody<{items:Source[]}>(await page.request.get('/api/v1/sources?q='+encodeURIComponent(q)))).items;}
async function readSource(page:Page,id:string):Promise<Source> {return (await domainBody<{source:Source}>(await page.request.get(`/api/v1/sources/${id}`))).source;}
async function readJob(page:Page,id:string):Promise<Job> {return (await domainBody<{job:Job}>(await page.request.get(`/api/v1/jobs/${id}`))).job;}

// One independent journey keeps the read-only probes bound to the actual source
// just created by its steward, rather than an unrelated or nonexistent resource.
test('CX-005: Unity Catalog registration, missing-credential scan failure and read-only denial through real services',async({page,browser})=>{
  test.setTimeout(240_000);
  await page.setViewportSize({width:1440,height:960});await domainLogin(page);
  const unique=randomUUID(),name=`00 UC browser ${Number.MAX_SAFE_INTEGER-Date.now()} ${unique.slice(0,8)}`;
  const secretRef=`missing-browser-uc-${unique}`;
  const input={connectorId:'unity-catalog',name,workspaceUrl:'https://synthetic-browser.cloud.databricks.com',catalog:'harbor_browser',schema:'commerce',secretRef};
  await page.getByRole('link',{name:'Sources & scans',exact:true}).click();
  await page.getByRole('button',{name:'Connect a source',exact:true}).first().click();
  const dialog=page.getByRole('dialog');
  await expect(dialog).toHaveAccessibleName('Connect PostgreSQL');
  await expect(dialog.getByRole('combobox',{name:/^Connector/})).toHaveValue('postgresql');
  await dialog.getByRole('combobox',{name:/^Connector/}).selectOption('unity-catalog');
  await expect(dialog).toHaveAccessibleName('Connect Unity Catalog');
  const register=dialog.getByRole('button',{name:'Register source',exact:true});
  await expect(register).toBeDisabled();
  await dialog.getByLabel(/^Connection name/).fill(name);
  await dialog.getByLabel(/^Workspace URL/).fill('https://unsupported.example.invalid');
  await dialog.getByLabel('Catalog',{exact:true}).fill(input.catalog);
  await dialog.getByLabel('Schema',{exact:true}).fill(input.schema);
  await expect(register).toBeDisabled();
  await dialog.getByLabel(/^Credential reference/).fill(secretRef);
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  await expect(register).toBeEnabled();
  const invalidResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/sources'&&response.request().method()==='POST');
  await register.click();const invalid=await invalidResponse;
  expect(invalid.status()).toBe(400);expect((await invalid.json()).code).toBe('VALIDATION_FAILED');
  await expect(dialog).toBeVisible();await expect(dialog.getByText('We could not complete this request',{exact:true})).toBeVisible();
  expect((await sources(page,name)).some(source=>source.name===name)).toBe(false);
  await dialog.getByLabel(/^Workspace URL/).fill(input.workspaceUrl);
  await capture(page,'form-en',1440);
  // Dismiss with the real accessible control before changing language outside
  // the modal; opening it again must retain the entered registration draft.
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await language(page,'ar');
  await page.getByRole('button',{name:'ربط مصدر',exact:true}).first().click();
  await expect(dialog).toHaveAccessibleName('ربط Unity Catalog');
  await expect(dialog.getByLabel(/^رابط مساحة العمل/)).toHaveValue(input.workspaceUrl);
  await capture(page,'form-ar',390);
  const createdResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/sources'&&response.request().method()==='POST');
  await dialog.getByRole('button',{name:'تسجيل المصدر',exact:true}).click();
  const created=await createdResponse;expect(created.status()).toBe(201);
  expect(created.request().postDataJSON()).toEqual(input);
  const source=(await created.json()).source as Source;
  expect(source).toMatchObject(input);expect(source.lastSuccessfulScan).toBeNull();expect(source.status).toBe('unconfigured');
  expect(Object.hasOwn(source,'password')).toBe(false);expect(Object.hasOwn(source,'clientSecret')).toBe(false);
  await expect(dialog).toBeHidden();
  const card=page.locator('.source-card').filter({has:page.getByRole('heading',{name,exact:true})});
  await expect(card).toBeVisible();await expect(card.getByText('Databricks Unity Catalog',{exact:false})).toBeVisible();
  await expect(card.getByText(input.workspaceUrl,{exact:true})).toBeVisible();await expect(card.getByText(secretRef,{exact:true})).toBeVisible();
  await capture(page,'registered-ar',390,card);
  await page.setViewportSize({width:1440,height:960});await language(page,'en');await page.reload();
  await expect(card).toBeVisible();expect(await readSource(page,source.id)).toEqual(source);
  expect(new URL(page.url()).searchParams.get('selected')).toBe(source.id);
  await capture(page,'registered-en',1440,card);

  // Search changes use the actual API and URL; a selected registration is
  // cleared on manual search while its canonical source remains available.
  await page.getByRole('searchbox',{name:'Search source names',exact:true}).fill('absent-'+unique);
  await page.getByRole('button',{name:'Search',exact:true}).click();
  await expect(page).toHaveURL(url=>url.searchParams.get('q')==='absent-'+unique&&!url.searchParams.has('selected'));
  await expect(page.getByRole('heading',{name:'No matching sources',exact:true})).toBeVisible();
  await expect(card).toHaveCount(0);
  await page.getByRole('button',{name:'Clear filters',exact:true}).click();
  await expect(page).toHaveURL(url=>!url.searchParams.has('q')&&!url.searchParams.has('cursor'));
  await page.getByRole('searchbox',{name:'Search source names',exact:true}).fill(name);
  const searchedResponse=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/sources'&&url.searchParams.get('q')===name&&response.request().method()==='GET';});
  await page.getByRole('button',{name:'Search',exact:true}).click();
  const searched=await searchedResponse;expect(searched.status()).toBe(200);
  const searchedBody=await searched.json();expect(searchedBody.items.map((item:Source)=>item.id)).toEqual([source.id]);expect(searchedBody.nextCursor).toBeNull();
  await expect(page).toHaveURL(url=>url.searchParams.get('q')===name&&!url.searchParams.has('cursor'));
  await expect(card).toBeVisible();
  await expect(page.getByRole('button',{name:'Previous page',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Next page',exact:true})).toBeDisabled();

  // The unique reference is intentionally absent from the provider. The real
  // worker must reject it before adapter/OAuth/vendor network execution.
  const submittedResponse=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/v1/sources/${source.id}/scans`&&response.request().method()==='POST');
  await card.getByRole('button',{name:'Run scan',exact:true}).click();const submitted=await submittedResponse;
  expect(submitted.status()).toBe(202);const submittedJob=(await submitted.json()).job as Job;
  expect(submittedJob.sourceId).toBe(source.id);expect(submittedJob.status).toBe('queued');
  await expect.poll(async()=>{
    const job=await readJob(page,submittedJob.id);
    expect(job.status).not.toBe('succeeded');expect(job.status).not.toBe('cancelled');
    return job.status;
  },{timeout:100_000,intervals:[1000,2000,3000]}).toBe('failed');
  const failed=await readJob(page,submittedJob.id);
  expect(failed.errorCode).toBe('SECRET_REFERENCE_DENIED');expect(failed.assetCount).toBeNull();
  expect(failed.finishedAt).not.toBeNull();expect(Number.isFinite(Date.parse(failed.finishedAt!))).toBe(true);
  const jobRow=page.locator('#jobs tbody tr').filter({hasText:submittedJob.id});
  await expect(jobRow.getByText('Failed',{exact:true})).toBeVisible({timeout:10_000});
  await expect(jobRow.getByText('SECRET_REFERENCE_DENIED',{exact:true})).toBeVisible();
  await expect(jobRow.getByText('Completed',{exact:true})).toHaveCount(0);
  await capture(page,'failure-en',1440,jobRow);
  await language(page,'ar');await expect(jobRow.getByText('فشل',{exact:true})).toBeVisible();
  await capture(page,'failure-ar',390,jobRow);
  await page.reload();await expect(jobRow.getByText('SECRET_REFERENCE_DENIED',{exact:true})).toBeVisible();
  expect(await readJob(page,submittedJob.id)).toEqual(failed);
  const after=await readSource(page,source.id);
  expect(after).toEqual({...source,status:'failed'});expect(after.lastSuccessfulScan).toBeNull();expect(after.status).toBe('failed');

  const context=await browser.newContext({viewport:{width:1440,height:960}});
  try {
    const reader=await context.newPage();await domainLogin(reader,'consumer');
    const me=await domainBody<{permissions:string[]}>(await reader.request.get('/api/v1/me'));
    expect(me.permissions).not.toContain('sources:write');
    await expect(reader.getByRole('link',{name:'Sources & scans',exact:true})).toHaveCount(0);
    const forbiddenName=`00 UC forbidden ${unique}`;
    const deniedCreate=await reader.request.post('/api/v1/sources',{headers:await domainHeaders(reader),data:{...input,name:forbiddenName}});
    expect(deniedCreate.status()).toBe(403);expect((await deniedCreate.json()).code).toBe('FORBIDDEN');
    const deniedScan=await reader.request.post(`/api/v1/sources/${source.id}/scans`,{headers:await domainHeaders(reader),data:{}});
    expect(deniedScan.status()).toBe(403);expect((await deniedScan.json()).code).toBe('FORBIDDEN');
    await reader.goto('/sources');await expect(reader.getByRole('heading',{name:'You do not have access to this view',exact:true})).toBeVisible();
    await expect(reader.getByRole('button',{name:'Connect a source',exact:true})).toHaveCount(0);
    await expect(reader.getByRole('button',{name:'Run scan',exact:true})).toHaveCount(0);
    await expect(reader.getByText(name,{exact:true})).toHaveCount(0);await expect(reader.getByText(secretRef,{exact:true})).toHaveCount(0);
    await capture(reader,'denial-en',1440);
    await language(reader,'ar');await expect(reader.getByRole('heading',{name:'ليس لديك إذن لعرض هذه الصفحة',exact:true})).toBeVisible();
    await capture(reader,'denial-ar',390);
    expect((await sources(page,forbiddenName)).some(row=>row.name===forbiddenName)).toBe(false);
    const jobs=await domainBody<{items:Job[]}>(await page.request.get('/api/v1/jobs'));
    expect(jobs.items.filter(job=>job.sourceId===source.id)).toEqual([failed]);
  } finally {await context.close();}
});
