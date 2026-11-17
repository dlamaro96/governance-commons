// SPDX-License-Identifier: Apache-2.0
/** Real OIDC and canonical workflow APIs. No response interception, approval
 * submission, decision fixture, or inferred resource-publication outcome. */
import {test,expect,type Browser,type Page,type Response} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {mkdirSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {domainBody,domainHeaders,domainLogin} from '../fixtures/business-domains-browser.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import type {ApprovalDefinitionView} from '../../packages/domain/src/approval-service.ts';

test.beforeAll(async({browser}:{browser:Browser})=>{
 test.setTimeout(75_000);const context=await browser.newContext();
 try{const response=await context.request.get('/api/v1/me'),remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
  if(Number.isFinite(remaining)&&remaining<100&&Number.isFinite(reset)&&reset>=0&&reset<=60)await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
 }finally{await context.close();}
});
async function language(page:Page,locale:'en'|'ar'){
 await page.locator('#language').selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');
}
async function capture(page:Page,name:string,width:number){
 await page.setViewportSize({width,height:960});await page.evaluate(()=>window.scrollTo(0,0));
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 mkdirSync('docs/verification/screenshots',{recursive:true});await page.screenshot({path:`docs/verification/screenshots/m5-approvals-${name}-${width}.png`,fullPage:false});
}
const responseFor=(page:Page,path:string,method:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()===method);
async function workflowResponse(response:Response,status=201):Promise<ApprovalDefinitionView>{expect(response.status()).toBe(status);return (await response.json()).workflow;}

test('WF: real visual workflow publication, immutable versions, search, empty inbox and read-only boundaries',async({page,browser})=>{
 test.setTimeout(240_000);await page.setViewportSize({width:1440,height:960});await domainLogin(page);
 const unique=randomUUID().replaceAll('-',''),id=`browser_approval_${unique}`,name=`Synthetic approval ${unique.slice(0,12)}`;
 const definition:ApprovalDefinition={formatVersion:1,id,version:1,name,separationOfDuties:true,stages:[
  {id:'review',name:'Parallel meaning review',assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'},
  {id:'final_review',name:'Final review',assignments:['custodian'],quorum:1,deadlineSeconds:7200,rejection:'any'},
 ]};
 await page.getByRole('link',{name:'Workflows',exact:true}).click();
 await expect(page.getByRole('heading',{level:1,name:'Workflows',exact:true})).toBeVisible();
 await page.getByRole('link',{name:'Create workflow',exact:true}).click();await expect(page).toHaveURL(/\/workflows\/new\/definition$/);
 await page.getByLabel('Workflow name',{exact:true}).fill(name);await page.getByLabel('Workflow identifier',{exact:true}).fill(id);
 const first=page.getByRole('group',{name:'Stage 1',exact:true});
 await first.getByLabel('Stage name',{exact:true}).fill(definition.stages[0].name);await first.getByLabel('Stage identifier',{exact:true}).fill('review');
 await first.getByLabel('Assignment keys',{exact:true}).fill('steward,steward');await first.getByLabel('Approvals required',{exact:true}).fill('2');await first.getByLabel('Stage deadline (seconds)',{exact:true}).fill('3600');
 await page.getByRole('button',{name:'Add stage',exact:true}).click();const second=page.getByRole('group',{name:'Stage 2',exact:true});
 await second.getByLabel('Stage name',{exact:true}).fill(definition.stages[1].name);await second.getByLabel('Stage identifier',{exact:true}).fill('final_review');
 await second.getByLabel('Assignment keys',{exact:true}).fill('custodian');await second.getByLabel('Stage deadline (seconds)',{exact:true}).fill('7200');
 await second.getByRole('button',{name:'Move stage up: Final review',exact:true}).click();await expect(first.getByLabel('Stage identifier',{exact:true})).toHaveValue('final_review');
 await first.getByRole('button',{name:'Move stage down: Final review',exact:true}).click();await expect(first.getByLabel('Stage identifier',{exact:true})).toHaveValue('review');
 const publicationRequests:string[]=[];page.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname==='/api/v1/workflow-definitions')publicationRequests.push(request.url());});
 await page.getByRole('button',{name:'Publish workflow',exact:true}).click();await expect(page.getByText('Duplicate stage assignment.',{exact:false})).toBeVisible();expect(publicationRequests).toEqual([]);
 await first.getByLabel('Assignment keys',{exact:true}).fill('steward,owner');await expect(page.getByRole('checkbox',{name:'Separate requester and reviewers',exact:true})).toBeChecked();
 await capture(page,'editor-en',1440);await language(page,'ar');await capture(page,'editor-ar',390);await language(page,'en');
 const createdPromise=responseFor(page,'/api/v1/workflow-definitions','POST');await page.getByRole('button',{name:'Publish workflow',exact:true}).click();const createdResponse=await createdPromise,created=await workflowResponse(createdResponse);
 expect(createdResponse.request().postDataJSON()).toEqual({definition});expect(created.definition).toEqual(definition);expect(created.currentVersion).toBe(1);expect(created.definitionHash).toMatch(/^[a-f0-9]{64}$/);
 await expect(page).toHaveURL(url=>url.pathname===`/workflows/${id}`&&url.searchParams.get('version')==='1');await expect(page.getByRole('heading',{level:1,name,exact:true})).toBeVisible();
 const originalKey=createdResponse.request().headers()['idempotency-key'];expect(originalKey).toMatch(/^[a-f0-9-]{36}$/);
 const replay=await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.post('/api/v1/workflow-definitions',{headers:{...await domainHeaders(page),'Idempotency-Key':originalKey},data:{definition}}),201);expect(replay.workflow).toEqual(created);

 await page.getByRole('link',{name:'Publish a new version',exact:true}).click();await expect(page.getByLabel('Workflow identifier',{exact:true})).toHaveValue(id);await expect(page.getByLabel('Workflow identifier',{exact:true})).toHaveAttribute('readonly','');
 const next:ApprovalDefinition={...definition,version:2,name:`${name} revised`,stages:[{...definition.stages[0],quorum:1},definition.stages[1]]};
 await page.getByLabel('Workflow name',{exact:true}).fill(next.name);await page.getByRole('group',{name:'Stage 1',exact:true}).getByLabel('Approvals required',{exact:true}).fill('1');
 const nextPromise=responseFor(page,`/api/v1/workflow-definitions/${id}/versions`,'POST');await page.getByRole('button',{name:'Publish workflow',exact:true}).click();const nextResponse=await nextPromise,published=await workflowResponse(nextResponse);
 expect(nextResponse.request().postDataJSON()).toEqual({definition:next,expectedVersion:1});expect(published.definition).toEqual(next);expect(published.currentVersion).toBe(2);expect(published.definitionHash).not.toBe(created.definitionHash);
 await expect(page.getByRole('heading',{level:1,name:next.name,exact:true})).toBeVisible();
 await page.getByLabel('View immutable version',{exact:true}).fill('1');const oldPromise=responseFor(page,`/api/v1/workflow-definitions/${id}/versions/1`,'GET');await page.getByRole('button',{name:'View version',exact:true}).click();const old=await workflowResponse(await oldPromise,200);
 expect(old).toEqual({...created,currentVersion:2});await expect(page.getByRole('heading',{level:1,name,exact:true})).toBeVisible();await expect(page.getByRole('heading',{level:1,name:next.name,exact:true})).toHaveCount(0);
 await capture(page,'pinned-en',1440);await language(page,'ar');await capture(page,'pinned-ar',390);await language(page,'en');
 await page.getByRole('link',{name:'Back to workflows',exact:true}).click();await page.getByLabel('Search workflows',{exact:true}).fill(name);
 const searchedPromise=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/workflow-definitions'&&url.searchParams.get('q')===name&&response.request().method()==='GET';});
 await page.getByRole('button',{name:'Search',exact:true}).click();const searched=await searchedPromise;expect(searched.status()).toBe(200);expect(await searched.json()).toEqual({items:[published],nextCursor:null});
 await expect(page).toHaveURL(url=>url.searchParams.get('q')===name&&!url.searchParams.has('cursor'));await expect(page.getByRole('link',{name:next.name,exact:true})).toBeVisible();

 // No request is created by this initial workflow-definition journey. Assert
 // the actual participant-scoped empty response before recording empty UI.
 const emptyPromise=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/approval-requests'&&url.searchParams.get('status')==='failed'&&url.searchParams.get('assignedToMe')==='true'&&response.request().method()==='GET';});
 await page.goto('/approvals?status=failed&assignedToMe=true');const empty=await emptyPromise;expect(empty.status()).toBe(200);expect(await empty.json()).toEqual({items:[],nextCursor:null});await expect(page.getByRole('heading',{name:'No approval requests',exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Submit proposal',exact:true})).toHaveCount(0);await capture(page,'empty-en',1440);await language(page,'ar');await capture(page,'empty-ar',390);

 const context=await browser.newContext({viewport:{width:1440,height:960}});
 try{
  const reader=await context.newPage();await domainLogin(reader,'consumer');const me=await domainBody<{permissions:string[]}>(await reader.request.get('/api/v1/me'));
  expect(me.permissions).toContain('models:read');expect(me.permissions).not.toContain('models:write');expect(me.permissions).not.toContain('catalog:write');
  expect(me.permissions).toContain('reference:read');expect(me.permissions).not.toContain('reference:write');expect(me.permissions).not.toContain('reference:approve');
  await reader.goto(`/workflows/${id}?version=1`);await expect(reader.getByRole('heading',{level:1,name,exact:true})).toBeVisible();await expect(reader.getByRole('link',{name:'Publish a new version',exact:true})).toHaveCount(0);
  const read=await domainBody<{workflow:ApprovalDefinitionView}>(await reader.request.get(`/api/v1/workflow-definitions/${id}/versions/1`));expect(read.workflow).toEqual(old);
  await capture(reader,'readonly-en',1440);await language(reader,'ar');await capture(reader,'readonly-ar',390);await language(reader,'en');
  const refused=await reader.request.post(`/api/v1/workflow-definitions/${id}/versions`,{headers:await domainHeaders(reader),data:{definition:{...next,version:3},expectedVersion:2}});expect(refused.status()).toBe(403);expect((await refused.json()).code).toBe('FORBIDDEN');
  const deniedName=`Denied workflow ${unique}`;
  const refusedCreate=await reader.request.post('/api/v1/workflow-definitions',{headers:await domainHeaders(reader),data:{definition:{...definition,id:`denied_${unique}`,name:deniedName}}});expect(refusedCreate.status()).toBe(403);expect((await refusedCreate.json()).code).toBe('FORBIDDEN');
  await reader.goto(`/workflows/${id}/edit`);await expect(reader.getByRole('heading',{name:'You do not have access to this view',exact:true})).toBeVisible();await expect(reader.getByRole('button',{name:'Publish workflow',exact:true})).toHaveCount(0);
  // Reference readers may inspect their participant-scoped inbox. This reader
  // has no assigned proposals and cannot author, cancel, or approve a request.
  const inbox=await reader.request.get('/api/v1/approval-requests');expect(inbox.status()).toBe(200);expect(await inbox.json()).toEqual({items:[],nextCursor:null});
  await reader.setViewportSize({width:1440,height:960});await reader.goto('/approvals');await expect(reader.getByRole('heading',{name:'No approval requests',exact:true})).toBeVisible();await expect(reader.getByRole('link',{name:'Approvals',exact:true})).toHaveCount(1);await expect(reader.locator('.approval-list')).toHaveCount(0);
  for(const action of ['Submit proposal','Approve','Reject','Cancel request'])await expect(reader.getByRole('button',{name:action,exact:true})).toHaveCount(0);
  await capture(reader,'readonly-inbox-en',1440);await language(reader,'ar');await capture(reader,'readonly-inbox-ar',390);
  expect((await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.get(`/api/v1/workflow-definitions/${id}`))).workflow).toEqual(published);
  expect((await domainBody<{items:ApprovalDefinitionView[]}>(await page.request.get(`/api/v1/workflow-definitions?q=${encodeURIComponent(deniedName)}`))).items).toEqual([]);
 }finally{await context.close();}
});
