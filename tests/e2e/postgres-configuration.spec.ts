// SPDX-License-Identifier: Apache-2.0
/** Real Keycloak/API/Temporal/site/Python acceptance. The custom source has no
 * credential; successful external TLS extraction is a separate native gate. */
import {test,expect,type Browser,type Locator,type Page} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {mkdirSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {domainLogin,domainBody,scanDomainBrowserAsset} from '../fixtures/business-domains-browser.ts';
import type {AssetDetail,Job,Source} from '../../apps/web/src/types.ts';

test.beforeAll(async({browser}:{browser:Browser})=>{
  test.setTimeout(75_000);const context=await browser.newContext();
  try {
    const response=await context.request.get('/api/v1/me');
    const remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
    if(Number.isFinite(remaining)&&remaining<100&&Number.isFinite(reset)&&reset>=0&&reset<=60)
      await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
  } finally {await context.close();}
});
async function language(page:Page,value:'en'|'ar'){
  await page.locator('#language').selectOption(value);await expect(page.locator('html')).toHaveAttribute('lang',value);
  await expect(page.locator('html')).toHaveAttribute('dir',value==='ar'?'rtl':'ltr');
}
async function capture(page:Page,name:string,width:number,anchor?:Locator){
  await page.setViewportSize({width,height:960});
  if(anchor)await anchor.scrollIntoViewIfNeeded();else await page.evaluate(()=>window.scrollTo(0,0));
  await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'
    &&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
  mkdirSync('docs/verification/screenshots',{recursive:true});
  await page.screenshot({path:`docs/verification/screenshots/m8-postgres-configuration-${name}-${width}.png`,fullPage:false});
}
async function source(page:Page,id:string){return (await domainBody<{source:Source}>(await page.request.get('/api/v1/sources/'+id))).source;}
async function job(page:Page,id:string){return (await domainBody<{job:Job}>(await page.request.get('/api/v1/jobs/'+id))).job;}

test('INT-001/003: editable PostgreSQL configuration survives connector switching and a real missing-reference scan preserves catalog state',async({page})=>{
  test.setTimeout(300_000);await page.setViewportSize({width:1440,height:960});await domainLogin(page,'engineer');
  const me=await domainBody<{user:{id:string};permissions:string[]}>(await page.request.get('/api/v1/me'));
  expect(me.user.id).toBe('10000000-0000-4000-8000-000000000006');expect(me.permissions).toContain('sources:write');
  const unique=randomUUID(),name=`00 PG browser ${Number.MAX_SAFE_INTEGER-Date.now()} ${unique.slice(0,8)}`;
  // A genuinely successful bundled scan supplies the state-preservation oracle;
  // no direct worker handler, source fixture mutation or mock creates this state.
  const existing=await scanDomainBrowserAsset(page,'00 PG preserved '+unique);
  const priorAsset=await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+existing.id));
  const priorSource=await source(page,existing.sourceId),priorJob=await job(page,existing.metadata.scanId!);
  expect(priorSource.status).toBe('healthy');expect(priorSource.lastSuccessfulScan).not.toBeNull();expect(priorJob.status).toBe('succeeded');
  const input={connectorId:'postgresql',name,host:'warehouse.example.invalid',port:6432,
    database:'Analytics archive',schema:'Reporting',secretRef:'missing-browser-pg-'+unique};
  await page.getByRole('link',{name:'Sources & scans',exact:true}).click();
  await page.getByRole('button',{name:'Connect a source',exact:true}).first().click();
  const dialog=page.getByRole('dialog'),connector=dialog.getByRole('combobox',{name:/^Connector/});
  await expect(dialog).toHaveAccessibleName('Connect PostgreSQL');await expect(connector).toHaveValue('postgresql');
  for(const [label,value] of [['Host','source-postgres'],['Port','5432'],['Database','harbor'],['Schema','public'],['Credential reference','demo-postgres']])
    await expect(dialog.getByLabel(label!,{exact:true})).toHaveValue(value!);
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  const register=dialog.getByRole('button',{name:'Register source',exact:true});await expect(register).toBeDisabled();
  await dialog.getByLabel(/^Connection name/).fill(name);
  for(const [label,value] of [['Host',input.host],['Database',input.database],['Schema',input.schema],['Credential reference',input.secretRef]]){
    await expect(dialog.getByLabel(label!,{exact:true})).toBeEditable();await dialog.getByLabel(label!,{exact:true}).fill(value!);
  }
  await dialog.getByLabel('Port',{exact:true}).fill('0');await expect(register).toBeDisabled();
  await dialog.getByLabel('Port',{exact:true}).fill(String(input.port));await expect(register).toBeEnabled();
  await connector.selectOption('unity-catalog');await expect(dialog).toHaveAccessibleName('Connect Unity Catalog');
  await expect(dialog.getByLabel('Schema',{exact:true})).toHaveValue('');await expect(dialog.getByLabel('Credential reference',{exact:true})).toHaveValue('');
  await dialog.getByLabel('Workspace URL',{exact:true}).fill('https://synthetic.cloud.databricks.com');
  await dialog.getByLabel('Catalog',{exact:true}).fill('independent_catalog');
  await dialog.getByLabel('Schema',{exact:true}).fill('independent_schema');
  await dialog.getByLabel('Credential reference',{exact:true}).fill('independent-uc-reference');
  await connector.selectOption('postgresql');await expect(dialog).toHaveAccessibleName('Connect PostgreSQL');
  for(const [label,value] of [['Host',input.host],['Port',String(input.port)],['Database',input.database],['Schema',input.schema],['Credential reference',input.secretRef]])
    await expect(dialog.getByLabel(label!,{exact:true})).toHaveValue(value!);
  await connector.selectOption('unity-catalog');
  await expect(dialog.getByLabel('Schema',{exact:true})).toHaveValue('independent_schema');
  await expect(dialog.getByLabel('Credential reference',{exact:true})).toHaveValue('independent-uc-reference');
  await connector.selectOption('postgresql');await capture(page,'form-en',1440);
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await language(page,'ar');
  await page.getByRole('button',{name:'ربط مصدر',exact:true}).first().click();
  await expect(dialog).toHaveAccessibleName('ربط PostgreSQL');await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  await capture(page,'form-ar',390);
  const createdResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/sources'&&response.request().method()==='POST');
  await dialog.getByRole('button',{name:'تسجيل المصدر',exact:true}).click();
  const created=await createdResponse;expect(created.status()).toBe(201);expect(created.request().postDataJSON()).toEqual(input);
  const registered=(await created.json()).source as Source;expect(registered).toMatchObject(input);
  expect(registered.status).toBe('unconfigured');expect(registered.lastSuccessfulScan).toBeNull();
  for(const field of ['password','username','token','clientSecret','credentials','tls','allowedCidrs'])expect(Object.hasOwn(registered,field)).toBe(false);
  await expect(dialog).toBeHidden();await page.setViewportSize({width:1440,height:960});await language(page,'en');await page.reload();
  const card=page.locator('.source-card').filter({has:page.getByRole('heading',{name,exact:true})});
  await expect(card).toBeVisible();await expect(card.getByText(input.host+':'+input.port,{exact:true})).toBeVisible();
  await expect(card.getByText(input.database+'.'+input.schema,{exact:true})).toBeVisible();await expect(card.getByText(input.secretRef,{exact:true})).toBeVisible();
  expect(await source(page,registered.id)).toEqual(registered);expect(new URL(page.url()).searchParams.get('selected')).toBe(registered.id);
  // Unique missing reference is rejected by the real provider before DNS/TLS;
  // merely registering this custom destination never enables network access.
  const submittedResponse=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/v1/sources/${registered.id}/scans`&&response.request().method()==='POST');
  await card.getByRole('button',{name:'Run scan',exact:true}).click();const submitted=await submittedResponse;
  expect(submitted.status()).toBe(202);const queued=(await submitted.json()).job as Job;
  expect(queued.sourceId).toBe(registered.id);expect(queued.status).toBe('queued');
  await expect.poll(async()=>{const current=await job(page,queued.id);expect(current.status).not.toBe('succeeded');expect(current.status).not.toBe('cancelled');return current.status;},
    {timeout:100_000,intervals:[1000,2000,3000]}).toBe('failed');
  const failed=await job(page,queued.id);expect(failed.errorCode).toBe('SECRET_REFERENCE_DENIED');expect(failed.assetCount).toBeNull();
  expect(failed.finishedAt).not.toBeNull();expect(Number.isFinite(Date.parse(failed.finishedAt!))).toBe(true);
  await expect(card.getByText('Failed',{exact:true})).toBeVisible();
  const failureNotice=page.getByRole('alert').filter({hasText:'Your scan failed. The last successful catalog state is preserved.'});
  await expect(failureNotice).toHaveCount(1);await expect(failureNotice).toBeVisible();
  await expect(failureNotice).toContainText('Your scan failed. The last successful catalog state is preserved.');
  await expect(failureNotice.getByText('SECRET_REFERENCE_DENIED',{exact:true})).toBeVisible();
  const row=page.locator('#jobs tbody tr').filter({hasText:queued.id});
  await expect(row.getByText('Failed',{exact:true})).toBeVisible();await expect(row.getByText('SECRET_REFERENCE_DENIED',{exact:true})).toBeVisible();
  await capture(page,'failure-en',1440,row.locator('td').first());
  await language(page,'ar');await expect(row.getByText('فشل',{exact:true})).toBeVisible();
  await capture(page,'failure-ar',390,row.locator('td').first());
  await page.reload();await expect(row.getByText('SECRET_REFERENCE_DENIED',{exact:true})).toBeVisible();
  expect(await job(page,queued.id)).toEqual(failed);
  expect(await source(page,registered.id)).toEqual({...registered,status:'failed'});
  expect(await source(page,existing.sourceId)).toEqual(priorSource);
  expect(await job(page,priorJob.id)).toEqual(priorJob);
  expect(await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+existing.id))).toEqual(priorAsset);
});
