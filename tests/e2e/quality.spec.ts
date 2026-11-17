// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, PostgreSQL scan, versioned rules and Temporal/source-worker runs.
 * No mocked responses, internal completion calls or test-side database writes. */
import {test,expect,type Page,type Browser,type TestInfo} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID} from 'node:crypto';
import {domainBody,domainHeaders,domainLogin,stewardIdentity} from '../fixtures/business-domains-browser.ts';
import type {Asset,AssetDetail,AssetList,Session} from '../../apps/web/src/types.ts';
import type {QualityAssetView,QualityPublishInput,QualityRuleView,QualityRunInput,QualityRunView} from '../../packages/domain/src/quality-contracts.ts';

const responseFor=(page:Page,path:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()==='POST');
async function readRun(page:Page,id:string){return (await domainBody<{run:QualityRunView}>(await page.request.get('/api/v1/quality/runs/'+id))).run;}
async function readRule(page:Page,id:string,version?:number){return (await domainBody<{rule:QualityRuleView}>(await page.request.get('/api/v1/quality/rules/'+id+(version?'?version='+version:'')))).rule;}
async function language(page:Page,locale:'en'|'ar'){
 await page.locator('#language').selectOption(locale);
 await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');
}
async function historyMatches(page:Page,run:QualityRunView){
 const arabic=await page.locator('html').getAttribute('lang')==='ar';
 const table=page.getByRole('table',{name:arabic?'سجل التنفيذ':'Run history',exact:true});
 const row=table.getByRole('row').filter({has:page.getByRole('button',{name:(arabic?'عرض التنفيذ':'View run')+' '+run.id,exact:true})});
 await expect(row).toHaveCount(1);
 const version=await page.evaluate(value=>new Intl.NumberFormat(document.documentElement.lang).format(value),run.ruleVersion);
 await expect(row.getByRole('cell').nth(1)).toHaveText(version);
 expect(run.status).toBe('succeeded');expect(['PASS','FAIL']).toContain(run.verdict);
 await expect(row.getByText(arabic?'مكتمل':'Completed',{exact:true})).toBeVisible();
 await expect(row.getByText(run.verdict==='PASS'?(arabic?'ناجح':'Pass'):(arabic?'غير ناجح':'Fail'),{exact:true})).toBeVisible();
 await expect(row.getByText(arabic?'في الانتظار':'Queued',{exact:true})).toHaveCount(0);
 await expect(row.getByText(arabic?'لم يُقيّم':'Not evaluated',{exact:true})).toHaveCount(0);
}
async function capture(page:Page,info:TestInfo,name:string,width:number,run:QualityRunView){
 // Bind the displayed terminal outcome to this exact persisted run, including
 // its immutable rule version, before recording either locale's screenshot.
 await historyMatches(page,run);
 const arabic=await page.locator('html').getAttribute('lang')==='ar';
 const evidence=page.getByRole('region',{name:arabic?'أدلة التنفيذ':'Run evidence',exact:true});
 await expect(evidence.getByText(run.id,{exact:true})).toHaveCount(1);
 await expect(evidence.getByText(arabic?'مكتمل':'Completed',{exact:true})).toBeVisible();
 await expect(evidence.getByText(run.verdict==='PASS'?(arabic?'ناجح':'Pass'):(arabic?'غير ناجح':'Fail'),{exact:true})).toBeVisible();
 await expect(evidence.getByTestId('quality-pinned-threshold')).toBeVisible();
 await page.setViewportSize({width,height:960});await page.locator('.quality-run-inspector').evaluate(element=>element.scrollIntoView({block:'start'}));
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 await page.screenshot({path:info.outputPath('quality-'+name+'-'+width+'.png'),fullPage:false});
}
test.beforeAll(async({browser}:{browser:Browser})=>{
 test.setTimeout(75_000);const context=await browser.newContext();
 try{const response=await context.request.get('/api/v1/me'),remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
  if(Number.isFinite(remaining)&&remaining<180&&Number.isFinite(reset)&&reset>=0&&reset<=60)await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
 }finally{await context.close();}
});
async function scannedColumn(page:Page){
 const {source}=await domainBody<{source:{id:string}}>(await page.request.post('/api/v1/sources',{headers:await domainHeaders(page),data:{
  name:'Synthetic quality browser '+randomUUID(),connectorId:'postgresql',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'
 }}),201);
 const {job}=await domainBody<{job:{id:string;sourceId:string}}>(await page.request.post('/api/v1/sources/'+source.id+'/scans',{headers:await domainHeaders(page),data:{}}),202);
 expect(job.sourceId).toBe(source.id);
 await expect.poll(async()=>(await domainBody<{job:{status:string}}>(await page.request.get('/api/v1/jobs/'+job.id))).job.status,{timeout:100_000,intervals:[1000,2000]}).toBe('succeeded');
 let table:Asset|undefined;
 await expect.poll(async()=>{
  let cursor:string|null=null;const seen=new Set<string>();
  for(let visited=0;visited<100;visited++){
   const result:AssetList=await domainBody(await page.request.get('/api/v1/assets?'+new URLSearchParams({q:'quality_fixture',type:'table',limit:'100',...(cursor?{cursor}:{})})));
   table=result.items.find(item=>item.sourceId===source.id&&item.name==='quality_fixture');
   if(table)return true;
   cursor=result.nextCursor;if(!cursor)return false;expect(seen.has(cursor)).toBe(false);seen.add(cursor);
  }throw new Error('Synthetic quality fixture exceeds the bounded catalog pagination profile');
 },{timeout:30_000,intervals:[500,1000,2000]}).toBe(true);
 expect(table).toBeDefined();const detail=await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+table!.id));
 expect(detail.asset.sourceId).toBe(source.id);expect(detail.asset.metadata.scanId).toBe(job.id);
 const columns=detail.columns.filter(item=>item.name==='email');expect(columns).toHaveLength(1);
 const column=(await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+columns[0].id))).asset;
 expect(column.type).toBe('column');expect(column.sourceId).toBe(source.id);expect(column.metadata.scanId).toBe(job.id);
 return {table:detail.asset,column};
}
async function publish(page:Page,body:QualityPublishInput,version:number){
 const dialog=page.getByRole('dialog',{name:version===1?'Create rule':'Publish new version',exact:true});
 const path='/api/v1/quality/rules'+(version===1?'':'/'+body.id+'/versions'),pending=responseFor(page,path);
 await dialog.getByRole('button',{name:version===1?'Publish rule':'Publish version',exact:true}).click();
 const response=await pending;expect(response.status()).toBe(201);
 const authored=response.request().postDataJSON() as QualityPublishInput;
 expect(authored).toEqual({...body,id:version===1?expect.stringMatching(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/):body.id});
 const rule:QualityRuleView=(await response.json()).rule;
 expect(rule).toMatchObject({id:authored.id,version,currentVersion:version,definition:body.definition,createdBy:stewardIdentity});
 expect(rule.definitionHash).toMatch(/^[a-f0-9]{64}$/);
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(/^[a-f0-9-]{36}$/);
 const replay=await domainBody<{rule:QualityRuleView}>(await page.request.post(path,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:authored}),201);
 expect(replay.rule).toEqual(rule);await expect(dialog).toHaveCount(0);
 return rule;
}
async function run(page:Page,rule:QualityRuleView,verdict:'PASS'|'FAIL'){
 if(rule.definition.kind!=='completeness')throw new Error('The completeness acceptance helper requires its exact rule family');
 const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});
 const pending=responseFor(page,'/api/v1/quality/rules/'+rule.id+'/runs');
 await panel.getByRole('button',{name:'Run check',exact:true}).click();
 const response=await pending;expect(response.status()).toBe(202);
 const body=response.request().postDataJSON() as QualityRunInput;
 expect(body).toEqual({id:expect.stringMatching(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/),ruleVersion:rule.version,ruleHash:rule.definitionHash});
 const requested:QualityRunView=(await response.json()).run;
 expect(requested).toMatchObject({id:body.id,ruleId:rule.id,ruleVersion:rule.version,ruleHash:rule.definitionHash,requesterId:stewardIdentity,...rule.definition.target});
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(/^[a-f0-9-]{36}$/);
 const replay=(await domainBody<{run:QualityRunView}>(await page.request.post('/api/v1/quality/rules/'+rule.id+'/runs',{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:body}),202)).run;
 expect(replay.id).toBe(body.id);expect(replay.ruleHash).toBe(rule.definitionHash);
 // Only the real dispatcher, Temporal workflow and source worker can complete.
 await expect.poll(async()=>{const value=await readRun(page,body.id);return {status:value.status,errorCode:value.errorCode,verdict:value.verdict};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',errorCode:null,verdict});
 const complete=await readRun(page,body.id);
 expect(complete.measurement).toMatchObject({formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:5,adapterVersion:'1',queryTemplate:'postgresql-completeness-v1'});
 expect(complete.measurement!.estimatedCost).toBeGreaterThanOrEqual(0);expect(complete.measurement!.estimatedBytes).toBeGreaterThanOrEqual(0);
 expect(Date.parse(complete.measurement!.observedFinishedAt)).toBeGreaterThanOrEqual(Date.parse(complete.measurement!.observedStartedAt));
 const evidence=page.getByRole('region',{name:'Run evidence',exact:true});
 await expect(evidence.getByText('Completed',{exact:true})).toBeVisible();
 await expect(evidence.getByText(verdict==='PASS'?'Pass':'Fail',{exact:true})).toBeVisible();
 await expect(evidence.getByTestId('quality-row-count')).toHaveText('20');await expect(evidence.getByTestId('quality-null-count')).toHaveText('5');
 await expect(evidence.getByTestId('quality-pinned-threshold')).toHaveText(rule.definition.maximumNullBasisPoints===0?'0%':'30%');
 await expect(evidence.getByText('25%',{exact:true})).toBeVisible();
 await historyMatches(page,complete);
 return complete;
}
test('DQ: real column completeness, immutable thresholds, aggregate outcomes and current read boundaries',async({page,browser},info)=>{
 test.setTimeout(480_000);await domainLogin(page);await language(page,'en');
 const me=await domainBody<Session>(await page.request.get('/api/v1/me'));expect(me.permissions).toEqual(expect.arrayContaining(['catalog:read','catalog:write','quality:read','quality:write','quality:execute']));
 const {table,column}=await scannedColumn(page),target={tableAssetId:table.id,columnAssetId:column.id};
 await page.goto('/catalog/'+table.id+'?tab=quality');
 await expect(page.getByRole('heading',{name:'This asset does not support source quality checks',exact:true})).toBeVisible();
 await page.getByRole('link',{name:'Open columns',exact:true}).click();
 await page.getByRole('table',{name:'Columns',exact:true}).getByRole('link',{name:'email',exact:true}).click();
 await expect(page).toHaveURL(new RegExp('/catalog/'+column.id+'$'));
 await page.getByRole('navigation',{name:'Details',exact:true}).getByRole('link',{name:'Quality',exact:true}).click();
 const initial=await domainBody<QualityAssetView>(await page.request.get('/api/v1/assets/'+column.id+'/quality'));
 expect(initial).toEqual({assetId:column.id,eligibility:{supported:true,reason:null,...target},items:[],nextCursor:null});
 await expect(page.getByRole('heading',{name:'No quality rules configured',exact:true})).toBeVisible();
 await expect(page.getByText('Pass',{exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:'Create rule',exact:true}).click();
 let dialog=page.getByRole('dialog',{name:'Create rule',exact:true});
 const name='Synthetic email completeness '+randomUUID(),purpose='Verify aggregate null coverage for the synthetic email column.';
 await dialog.getByRole('textbox',{name:'Rule name',exact:true}).fill(name);
 await dialog.getByRole('textbox',{name:'Business purpose',exact:true}).fill(purpose);
 await expect(dialog.getByRole('combobox',{name:'Owner',exact:true})).toBeEnabled();
 await dialog.getByRole('combobox',{name:'Owner',exact:true}).selectOption(stewardIdentity);
 await dialog.getByRole('combobox',{name:'Severity',exact:true}).selectOption('critical');
 await dialog.getByRole('textbox',{name:'Maximum null percentage',exact:true}).fill('0');
 const definition:QualityRuleView['definition']={formatVersion:1,kind:'completeness',target,name,purpose,ownerId:stewardIdentity,severity:'critical',maximumNullBasisPoints:0};
 const first=await publish(page,{id:'',expectedVersion:0,definition},1),failed=await run(page,first,'FAIL');
 await capture(page,info,'fail-en',1440,failed);await language(page,'ar');
 await expect(page.getByRole('region',{name:'أدلة التنفيذ',exact:true}).getByText('غير ناجح',{exact:true})).toBeVisible();
 await capture(page,info,'fail-ar',390,failed);await language(page,'en');await page.setViewportSize({width:1440,height:960});
 const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});
 await panel.getByRole('button',{name:'Publish new version',exact:true}).click();
 dialog=page.getByRole('dialog',{name:'Publish new version',exact:true});
 await expect(dialog.getByRole('textbox',{name:'Maximum null percentage',exact:true})).toHaveValue('0');
 await dialog.getByRole('textbox',{name:'Maximum null percentage',exact:true}).fill('30');
 const second=await publish(page,{id:first.id,expectedVersion:1,definition:{...definition,maximumNullBasisPoints:3000}},2);
 expect(second.definitionHash).not.toBe(first.definitionHash);const passed=await run(page,second,'PASS');
 expect(passed.id).not.toBe(failed.id);expect(await readRun(page,failed.id)).toEqual(failed);
 expect(await readRule(page,first.id,1)).toEqual({...first,currentVersion:2});expect((await readRule(page,first.id)).definition).toEqual(second.definition);
 await panel.getByRole('button',{name:'Previous version',exact:true}).click();
 await expect(panel.getByRole('button',{name:'Run check',exact:true})).toBeDisabled();
 await expect(panel.getByRole('button',{name:'Publish new version',exact:true})).toHaveCount(0);
 await panel.getByRole('button',{name:'Latest version',exact:true}).click();await expect(panel.getByRole('button',{name:'Run check',exact:true})).toBeEnabled();
 await historyMatches(page,failed);
 await capture(page,info,'pass-en',1440,passed);await language(page,'ar');
 await expect(page.getByRole('region',{name:'أدلة التنفيذ',exact:true}).getByText('ناجح',{exact:true})).toBeVisible();
 await capture(page,info,'pass-ar',390,passed);await language(page,'en');
 await panel.getByRole('button',{name:'View run '+failed.id,exact:true}).click();
 const oldEvidence=page.getByRole('region',{name:'Run evidence',exact:true});
 await expect(oldEvidence.getByText('Fail',{exact:true})).toBeVisible();await expect(oldEvidence.getByTestId('quality-pinned-threshold')).toHaveText('0%');
 await historyMatches(page,failed);await historyMatches(page,passed);
 const readerContext=await browser.newContext(),foreignContext=await browser.newContext();
 try{
  const reader=await readerContext.newPage();await domainLogin(reader,'consumer');await language(reader,'en');
  const readerMe=await domainBody<Session>(await reader.request.get('/api/v1/me'));expect(readerMe.permissions).toContain('quality:read');expect(readerMe.permissions).not.toEqual(expect.arrayContaining(['quality:write']));expect(readerMe.permissions).not.toEqual(expect.arrayContaining(['quality:execute']));
  await reader.goto('/catalog/'+column.id+'?tab=quality');await reader.getByRole('button',{name,exact:true}).click();
  for(const label of ['Create rule','Publish new version','Run check','Cancel run'])await expect(reader.getByRole('button',{name:label,exact:true})).toHaveCount(0);
  await reader.getByRole('button',{name:'View run '+passed.id,exact:true}).click();
  await expect(reader.getByRole('region',{name:'Run evidence',exact:true}).getByText('Pass',{exact:true})).toBeVisible();
  const denies=[
   ['/api/v1/quality/rules',{id:randomUUID(),expectedVersion:0,definition}],
   ['/api/v1/quality/rules/'+first.id+'/runs',{id:randomUUID(),ruleVersion:second.version,ruleHash:second.definitionHash}],
   ['/api/v1/quality/runs/'+passed.id+'/cancel',{expectedVersion:passed.version,reason:'Synthetic unauthorized cancellation'}],
  ] as const;
  for(const [path,body] of denies){const denial=await reader.request.post(path,{headers:await domainHeaders(reader),data:body});expect(denial.status()).toBe(403);expect((await denial.json()).code).toBe('FORBIDDEN');}
  const foreign=await foreignContext.newPage();await domainLogin(foreign,'summit');
  for(const path of ['/api/v1/assets/'+column.id+'/quality','/api/v1/quality/rules/'+first.id,'/api/v1/quality/runs/'+passed.id]){
   const denial=await foreign.request.get(path);expect(denial.status()).toBe(404);expect((await denial.json()).code).toBe('QUALITY_UNAVAILABLE');
  }
  expect(await readRun(page,failed.id)).toEqual(failed);expect(await readRun(page,passed.id)).toEqual(passed);
 }finally{await readerContext.close();await foreignContext.close();}
});
