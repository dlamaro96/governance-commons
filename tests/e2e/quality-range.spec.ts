// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, source scan and Temporal/source-worker execution. No response
 * interception, internal completion requests or test-side authority mutation. */
import {test,expect,type Page,type TestInfo} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID,createHash} from 'node:crypto';
import {waitForReferenceBrowserBudget} from './support/reference-workflow.ts';
import {domainBody,domainHeaders,domainLogin,stewardIdentity} from '../fixtures/business-domains-browser.ts';
import type {Asset,AssetDetail,AssetList,Session} from '../../apps/web/src/types.ts';
import type {QualityPublishInput,QualityRuleView,QualityRunInput,QualityRunView,RangeRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';

// Independent canonical preimage: UTF-16 sorted property names, exact ASCII bounds.
const rangeHash=createHash('sha256').update('{"comparison":"int64-inclusive","formatVersion":1,"kind":"range","maximum":"10","minimum":"0","nullPolicy":"exclude"}').digest('hex');
const binding={minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude',rangeHash} as const;
const responseFor=(page:Page,path:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()==='POST');
async function language(page:Page,locale:'en'|'ar'){
 await page.locator('#language').selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');
}
async function readRun(page:Page,id:string){return (await domainBody<{run:QualityRunView}>(await page.request.get('/api/v1/quality/runs/'+id))).run;}
async function scannedColumns(page:Page){
 const {source}=await domainBody<{source:{id:string}}>(await page.request.post('/api/v1/sources',{headers:await domainHeaders(page),data:{name:'Synthetic range '+randomUUID(),connectorId:'postgresql',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'}}),201);
 const {job}=await domainBody<{job:{id:string;sourceId:string}}>(await page.request.post('/api/v1/sources/'+source.id+'/scans',{headers:await domainHeaders(page),data:{}}),202);expect(job.sourceId).toBe(source.id);
 await expect.poll(async()=>(await domainBody<{job:{status:string}}>(await page.request.get('/api/v1/jobs/'+job.id))).job.status,{timeout:100_000,intervals:[1000,2000]}).toBe('succeeded');
 let table:Asset|undefined;
 await expect.poll(async()=>{
  let cursor:string|null=null;const seen=new Set<string>();
  for(let visited=0;visited<100;visited++){
   const result:AssetList=await domainBody(await page.request.get('/api/v1/assets?'+new URLSearchParams({q:'range_quality_fixture',type:'table',limit:'100',...(cursor?{cursor}:{})})));
   table=result.items.find(item=>item.sourceId===source.id&&item.name==='range_quality_fixture');if(table)return true;
   cursor=result.nextCursor;if(!cursor)return false;expect(seen.has(cursor)).toBe(false);seen.add(cursor);
  }throw new Error('Synthetic range fixture exceeds bounded catalog pagination');
 },{timeout:30_000,intervals:[500,1000,2000]}).toBe(true);
 expect(table,'The root-installed real source fixture must be scanned').toBeDefined();
 const detail=await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+table!.id));expect(detail.asset.metadata.scanId).toBe(job.id);
 const columns=new Map<string,Asset>();
 for(const name of ['amount','all_null']){
  const matches=detail.columns.filter(item=>item.name===name);expect(matches).toHaveLength(1);
  const column=(await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+matches[0].id))).asset;
  expect(column).toMatchObject({name,type:'column',sourceId:source.id});expect(column.metadata.scanId).toBe(job.id);expect(column.metadata.dataType).toBe('bigint');columns.set(name,column);
 }
 return {table:detail.asset,amount:columns.get('amount')!,allNull:columns.get('all_null')!};
}
async function editor(page:Page,definition:RangeRuleDefinition){
 await page.getByRole('button',{name:'Create rule',exact:true}).click();const dialog=page.getByRole('dialog',{name:'Create rule',exact:true});
 await dialog.getByRole('combobox',{name:'Check type',exact:true}).selectOption('range');
 await dialog.getByRole('textbox',{name:'Rule name',exact:true}).fill(definition.name);await dialog.getByRole('textbox',{name:'Business purpose',exact:true}).fill(definition.purpose);
 await dialog.getByRole('combobox',{name:'Owner',exact:true}).selectOption(stewardIdentity);await dialog.getByRole('textbox',{name:'Maximum out-of-range percentage',exact:true}).fill(String(definition.maximumOutOfRangeBasisPoints/100));
 await expect(dialog.getByRole('searchbox',{name:'Search reference sets',exact:true})).toHaveCount(0);
 await expect(dialog.getByText('Exact inclusive integer range. PostgreSQL smallint, integer and bigint columns only. SQL NULL is excluded; zero is a value.',{exact:true})).toBeVisible();
 const minimum=dialog.getByRole('textbox',{name:'Inclusive minimum',exact:true}),maximum=dialog.getByRole('textbox',{name:'Inclusive maximum',exact:true});
 await expect(minimum).toHaveAttribute('type','text');await expect(maximum).toHaveAttribute('type','text');
 await minimum.fill('9007199254740993');await maximum.fill('9007199254740992');await expect(dialog.getByRole('button',{name:'Publish rule',exact:true})).toBeDisabled();
 await maximum.fill('9223372036854775807');await expect(minimum).toHaveValue('9007199254740993');await expect(maximum).toHaveValue('9223372036854775807');await expect(dialog.getByRole('button',{name:'Publish rule',exact:true})).toBeEnabled();
 await minimum.fill('-0');await expect(dialog.getByRole('button',{name:'Publish rule',exact:true})).toBeDisabled();
 await minimum.fill(definition.minimum);await maximum.fill(definition.maximum);
}
async function publish(page:Page,definition:RangeRuleDefinition,previous?:QualityRuleView){
 const path='/api/v1/quality/rules'+(previous?'/'+previous.id+'/versions':''),dialog=page.getByRole('dialog',{name:previous?'Publish new version':'Create rule',exact:true});
 const pending=responseFor(page,path);await dialog.getByRole('button',{name:previous?'Publish version':'Publish rule',exact:true}).click();const response=await pending;expect(response.status()).toBe(201);
 const input=response.request().postDataJSON() as QualityPublishInput;expect(input).toEqual({id:previous?.id??expect.stringMatching(/^[a-f0-9-]{36}$/),expectedVersion:previous?.version??0,definition});
 const {rule}=await response.json() as {rule:QualityRuleView};expect(rule).toMatchObject({id:input.id,version:(previous?.version??0)+1,currentVersion:(previous?.version??0)+1,definition,createdBy:stewardIdentity});
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(/^[a-f0-9-]{36}$/);
 const replay=await domainBody<{rule:QualityRuleView}>(await page.request.post(path,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:input}),201);expect(replay.rule).toEqual(rule);
 await expect(dialog).toHaveCount(0);return rule;
}
async function execute(page:Page,rule:QualityRuleView,verdict:'PASS'|'FAIL'|'NO_DATA',allNull=false){
 const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});await expect(panel.getByRole('textbox',{name:'Reference date (UTC, optional)',exact:true})).toHaveCount(0);
 const path='/api/v1/quality/rules/'+rule.id+'/runs',pending=responseFor(page,path);await panel.getByRole('button',{name:'Run check',exact:true}).click();const response=await pending;expect(response.status()).toBe(202);
 const input=response.request().postDataJSON() as QualityRunInput;expect(input).toEqual({id:expect.stringMatching(/^[a-f0-9-]{36}$/),ruleVersion:rule.version,ruleHash:rule.definitionHash});
 const requested=(await response.json() as {run:QualityRunView}).run;expect(requested.kind).toBe('range');expect(requested).toHaveProperty('range',binding);expect(Object.hasOwn(requested,'reference')).toBe(false);
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(/^[a-f0-9-]{36}$/);
 const replay=(await domainBody<{run:QualityRunView}>(await page.request.post(path,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:input}),202)).run;expect(replay.id).toBe(input.id);expect(replay.kind).toBe('range');expect(replay).toHaveProperty('range',binding);
 await expect.poll(async()=>{const run=await readRun(page,input.id);return {status:run.status,verdict:run.verdict,error:run.errorCode};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',verdict,error:null});
 const run=await readRun(page,input.id);expect(run).toMatchObject({id:input.id,kind:'range',ruleId:rule.id,ruleVersion:rule.version,ruleHash:rule.definitionHash,...rule.definition.target});expect(Object.hasOwn(run,'reference')).toBe(false);expect(run).toHaveProperty('range',binding);
 expect(run.measurement).toMatchObject({formatVersion:1,kind:'range',strategy:'exact-bounded-role-scope',rowCount:6,nullCount:allNull?6:1,belowCount:allNull?0:1,aboveCount:allNull?0:1,rangeHash,adapterVersion:'1',queryTemplate:'postgresql-range-v1'});
 expect(Object.keys(run.measurement!).sort()).toEqual(['formatVersion','kind','strategy','rowCount','nullCount','belowCount','aboveCount','rangeHash','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'].sort());
 expect(Date.parse(run.measurement!.observedStartedAt)).toBeGreaterThanOrEqual(Date.parse(run.createdAt));expect(Date.parse(run.measurement!.observedFinishedAt)).toBeGreaterThanOrEqual(Date.parse(run.measurement!.observedStartedAt));
 const evidence=page.getByRole('region',{name:'Run evidence',exact:true});await expect(evidence.getByText('Completed',{exact:true})).toBeVisible();await expect(evidence.locator('.quality-outcomes').getByText(verdict==='NO_DATA'?'No data':verdict==='PASS'?'Pass':'Fail',{exact:true})).toBeVisible();
 for(const [name,value] of [['row-count',6],['null-count',allNull?6:1],['non-null-count',allNull?0:5],['below-count',allNull?0:1],['above-count',allNull?0:1],['out-of-range-count',allNull?0:2]] as const)await expect(evidence.getByTestId('quality-'+name)).toHaveText(String(value));
 await expect(evidence.getByTestId('quality-out-of-range-percentage')).toHaveText(allNull?'No data':'40%');await expect(evidence.getByTestId('quality-reference-hash')).toHaveCount(0);await expect(evidence.getByTestId('quality-pinned-minimum')).toHaveText('0');await expect(evidence.getByTestId('quality-pinned-maximum')).toHaveText('10');
 return run;
}
async function captures(page:Page,info:TestInfo,name:string,run:QualityRunView){
 for(const [locale,width] of [['en',1440],['ar',390]] as const){
  await language(page,locale);await page.setViewportSize({width,height:960});const ar=locale==='ar',evidence=page.getByRole('region',{name:ar?'أدلة التنفيذ':'Run evidence',exact:true});
  await expect(evidence.getByText(run.id,{exact:true})).toHaveCount(1);await expect(evidence.locator('.quality-outcomes').getByText(ar?'مكتمل':'Completed',{exact:true})).toBeVisible();await expect(evidence.locator('.quality-outcomes').getByText(run.verdict==='PASS'?(ar?'ناجح':'Pass'):(ar?'غير ناجح':'Fail'),{exact:true})).toBeVisible();
  const history=page.getByRole('table',{name:ar?'سجل التنفيذ':'Run history',exact:true}).getByRole('row').filter({has:page.getByRole('button',{name:(ar?'عرض التنفيذ':'View run')+' '+run.id,exact:true})});await expect(history).toHaveCount(1);await expect(history.getByText(ar?'مكتمل':'Completed',{exact:true})).toBeVisible();
  await evidence.evaluate(element=>element.scrollIntoView({block:'start',behavior:'instant'}));await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
  await page.screenshot({path:info.outputPath('quality-range-'+name+'-outcome-'+locale+'-'+width+'.png'),fullPage:false});
  await evidence.getByTestId('quality-out-of-range-count').evaluate(element=>element.parentElement!.scrollIntoView({block:'start',behavior:'instant'}));await expect(evidence.getByTestId('quality-out-of-range-percentage')).toBeInViewport({ratio:1});
  await page.screenshot({path:info.outputPath('quality-range-'+name+'-counts-'+locale+'-'+width+'.png'),fullPage:false});
 }
 await language(page,'en');await page.setViewportSize({width:1440,height:960});
}
test('DQ-RANGE: exact inclusive integer bounds, immutable thresholds, no-data semantics and current read boundaries',async({page,browser},info)=>{
 test.setTimeout(720_000);await waitForReferenceBrowserBudget(browser);await domainLogin(page);await language(page,'en');const me=await domainBody<Session>(await page.request.get('/api/v1/me'));expect(me.permissions).toEqual(expect.arrayContaining(['catalog:read','quality:read','quality:write','quality:execute']));
 const {table,amount,allNull}=await scannedColumns(page),target={tableAssetId:table.id,columnAssetId:amount.id},name='Synthetic integer range '+randomUUID();
 const definition:RangeRuleDefinition={formatVersion:1,kind:'range',target,name,purpose:'Measure values outside inclusive integer bounds, excluding SQL NULL.',ownerId:stewardIdentity,severity:'warning',maximumOutOfRangeBasisPoints:3999,minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'};
 await page.goto('/catalog/'+amount.id+'?tab=quality');await editor(page,definition);const first=await publish(page,definition),failed=await execute(page,first,'FAIL');await captures(page,info,'boundary-fail',failed);
 const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});await panel.getByRole('button',{name:'Publish new version',exact:true}).click();const edit=page.getByRole('dialog',{name:'Publish new version',exact:true});
 await expect(edit.getByRole('combobox',{name:'Check type',exact:true})).toHaveValue('range');await expect(edit.getByRole('textbox',{name:'Inclusive minimum',exact:true})).toHaveValue('0');await expect(edit.getByRole('textbox',{name:'Inclusive maximum',exact:true})).toHaveValue('10');await expect(edit.getByRole('textbox',{name:'Maximum out-of-range percentage',exact:true})).toHaveValue('39.99');await edit.getByRole('textbox',{name:'Maximum out-of-range percentage',exact:true}).fill('40');
 const second=await publish(page,{...definition,maximumOutOfRangeBasisPoints:4000},first),passed=await execute(page,second,'PASS');await captures(page,info,'boundary-pass',passed);
 expect(await readRun(page,failed.id)).toEqual(failed);expect((await domainBody<{rule:QualityRuleView}>(await page.request.get('/api/v1/quality/rules/'+first.id+'?version=1'))).rule).toEqual({...first,currentVersion:2});
 await panel.getByRole('button',{name:'Previous version',exact:true}).click();await expect(panel.getByRole('button',{name:'Run check',exact:true})).toBeDisabled();await expect(panel.getByRole('button',{name:'Publish new version',exact:true})).toHaveCount(0);await panel.getByRole('button',{name:'Latest version',exact:true}).click();
 await panel.getByRole('button',{name:'View run '+failed.id,exact:true}).click();const old=page.getByRole('region',{name:'Run evidence',exact:true});await expect(old.getByTestId('quality-pinned-threshold')).toHaveText('39.99%');await expect(old.getByTestId('quality-pinned-minimum')).toHaveText('0');await expect(old.getByTestId('quality-pinned-maximum')).toHaveText('10');await expect(old.locator('.quality-outcomes').getByText('Fail',{exact:true})).toBeVisible();
 const noDataDefinition={...definition,target:{tableAssetId:table.id,columnAssetId:allNull.id},name:'Synthetic all-null range '+randomUUID(),maximumOutOfRangeBasisPoints:0};await page.goto('/catalog/'+allNull.id+'?tab=quality');await editor(page,noDataDefinition);const nullRule=await publish(page,noDataDefinition),empty=await execute(page,nullRule,'NO_DATA',true);
 await expect(page.getByRole('region',{name:'Run evidence',exact:true}).getByText('No non-null rows were observed. Nulls are excluded; this is not a pass.',{exact:true})).toBeVisible();expect(empty.verdict).not.toBe('PASS');
 const readerContext=await browser.newContext(),foreignContext=await browser.newContext();
 try{
  const reader=await readerContext.newPage();await domainLogin(reader,'consumer');await language(reader,'en');await reader.goto('/catalog/'+amount.id+'?tab=quality');await reader.getByRole('button',{name,exact:true}).click();await reader.getByRole('button',{name:'View run '+passed.id,exact:true}).click();await expect(reader.getByTestId('quality-out-of-range-count')).toHaveText('2');
  for(const label of ['Create rule','Publish new version','Run check','Cancel run'])await expect(reader.getByRole('button',{name:label,exact:true})).toHaveCount(0);
  for(const [path,data] of [['/api/v1/quality/rules',{id:randomUUID(),expectedVersion:0,definition}],['/api/v1/quality/rules/'+second.id+'/runs',{id:randomUUID(),ruleVersion:second.version,ruleHash:second.definitionHash}],['/api/v1/quality/runs/'+passed.id+'/cancel',{expectedVersion:passed.version,reason:'Synthetic denied cancellation'}]] as const){const response=await reader.request.post(path,{headers:await domainHeaders(reader),data});expect(response.status()).toBe(403);expect((await response.json()).code).toBe('FORBIDDEN');}
  const foreign=await foreignContext.newPage();await domainLogin(foreign,'summit');for(const path of ['/api/v1/assets/'+amount.id+'/quality','/api/v1/quality/rules/'+first.id,'/api/v1/quality/runs/'+passed.id]){const response=await foreign.request.get(path);expect(response.status()).toBe(404);expect((await response.json()).code).toBe('QUALITY_UNAVAILABLE');}
  expect(await readRun(page,failed.id)).toEqual(failed);expect(await readRun(page,passed.id)).toEqual(passed);expect(await readRun(page,empty.id)).toEqual(empty);
 }finally{await readerContext.close();await foreignContext.close();}
});
