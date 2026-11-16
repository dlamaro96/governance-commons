// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, reviewed reference publications, PostgreSQL source scan and Temporal
 * aggregate execution. Requires the admitted reference_quality_fixture source
 * table:12 'A',4 'B',4 SQL NULL. No mocks, source writes or completion calls. */
import {test,expect,type Page,type TestInfo} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID} from 'node:crypto';
import {domainBody,domainHeaders,domainLogin,stewardIdentity} from '../fixtures/business-domains-browser.ts';
import type {Asset,AssetDetail,AssetList,Session} from '../../apps/web/src/types.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import type {ApprovalDefinitionView,ApprovalRequestView} from '../../packages/domain/src/approval-service.ts';
import type {Proposal,ReferenceReleaseView} from '../../packages/domain/src/reference-data-contracts.ts';
import type {QualityPublishInput,QualityRuleView,QualityRunInput,QualityRunView,ReferenceAllowedValuesRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
const reviewerId='10000000-0000-4000-8000-000000000002';
const responseFor=(page:Page,path:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()==='POST');
async function language(page:Page,locale:'en'|'ar'){await page.locator('#language').selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');}
async function readRun(page:Page,id:string){return (await domainBody<{run:QualityRunView}>(await page.request.get('/api/v1/quality/runs/'+id))).run;}
async function referencePublication(page:Page,reviewer:Page,workflow:ApprovalDefinitionView,setId:string,version:number,name:string,codes:string[]){
 const labels={en:{label:name,description:'Independent synthetic reference codes for an aggregate quality check.'},ar:{label:'رموز مرجعية اصطناعية',description:'قيم مرجعية مستقلة لفحص جودة تجميعي.'}};
 const body:Proposal={id:randomUUID(),setId,expectedVersion:version-1,audience:{visibility:'tenant',allowedIdentityIds:[]},release:{formatVersion:1,kind:'reference-code-list',labels,ownerId:stewardIdentity,status:'active',activation:{kind:'on-publication'},validUntil:null,values:codes.map(code=>({code,labels:{en:{label:'Synthetic '+code,description:'Exact synthetic code '+code},ar:{label:'قيمة '+code,description:'رمز اصطناعي دقيق '+code}},ownerId:stewardIdentity,status:'active',validFrom:null,validUntil:null}))},workflow:{id:workflow.definition.id,version:workflow.definition.version,definitionHash:workflow.definitionHash},assignments:{reviewer:reviewerId},expiresAt:new Date(Date.now()+3600_000).toISOString()};
 const receipt=await domainBody<{instance:{id:string}}>(await page.request.post('/api/v1/reference-data/proposals',{headers:await domainHeaders(page),data:body}),201);expect(receipt.instance.id).toBe(body.id);
 let row=(await domainBody<{request:ApprovalRequestView}>(await page.request.get('/api/v1/approval-requests/'+body.id))).request;
 expect(row.binding).toBe('reference.publish');expect(row.status).toBe('pending');expect(row.result).toBeNull();
 await reviewer.goto('/approvals/'+row.id);await expect(reviewer.getByRole('heading',{name:'Proposed reference publication',exact:true})).toBeVisible();await reviewer.getByRole('textbox',{name:'Decision reason',exact:true}).fill('Reviewed the complete synthetic codes, effective release and current audience for source quality.');
 const decision=responseFor(reviewer,'/api/v1/approval-requests/'+row.id+'/decisions');await reviewer.getByRole('button',{name:'Approve',exact:true}).click();expect((await decision).status()).toBe(200);
 await expect.poll(async()=>{row=(await domainBody<{request:ApprovalRequestView}>(await page.request.get('/api/v1/approval-requests/'+body.id))).request;return {status:row.status,error:row.errorCode};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',error:null});
 expect(row.decisions).toHaveLength(1);expect(row.decisions[0]).toMatchObject({actorId:reviewerId,decision:'approve'});
 const release=await domainBody<ReferenceReleaseView>(await page.request.get('/api/v1/reference-data/sets/'+setId+'/releases/'+version));
 expect(release.release.values.map(value=>value.code)).toEqual(codes);expect(row.result).toEqual({binding:'reference.publish',setId,version,publicationHash:release.publicationHash,publishedAt:release.release.publishedAt,effectiveFrom:release.release.effectiveFrom});return release;
}
async function scannedColumn(page:Page){
 const {source}=await domainBody<{source:{id:string}}>(await page.request.post('/api/v1/sources',{headers:await domainHeaders(page),data:{name:'Synthetic reference quality '+randomUUID(),connectorId:'postgresql',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'}}),201);
 const {job}=await domainBody<{job:{id:string;sourceId:string}}>(await page.request.post('/api/v1/sources/'+source.id+'/scans',{headers:await domainHeaders(page),data:{}}),202);expect(job.sourceId).toBe(source.id);
 await expect.poll(async()=>(await domainBody<{job:{status:string}}>(await page.request.get('/api/v1/jobs/'+job.id))).job.status,{timeout:100_000,intervals:[1000,2000]}).toBe('succeeded');
 let table:Asset|undefined,cursor:string|null=null;const seen=new Set<string>();
 for(let count=0;count<100;count++){
  const result:AssetList=await domainBody(await page.request.get('/api/v1/assets?'+new URLSearchParams({q:'reference_quality_fixture',type:'table',limit:'100',...(cursor?{cursor}:{})})));
  table=result.items.find(item=>item.sourceId===source.id&&item.name==='reference_quality_fixture');if(table)break;
  cursor=result.nextCursor;if(!cursor)break;expect(seen.has(cursor)).toBe(false);seen.add(cursor);
 }
 expect(table,'The admitted real PostgreSQL reference-quality fixture must be scanned').toBeDefined();
 const detail=await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+table!.id));expect(detail.asset.metadata.scanId).toBe(job.id);
 const columns=detail.columns.filter(column=>column.name==='code');expect(columns).toHaveLength(1);
 const column=(await domainBody<AssetDetail>(await page.request.get('/api/v1/assets/'+columns[0].id))).asset;expect(column.metadata.scanId).toBe(job.id);expect(column.sourceId).toBe(source.id);
 return {table:detail.asset,column};
}
async function publishRule(page:Page,definition:ReferenceAllowedValuesRuleDefinition,previous?:QualityRuleView){
 const dialog=page.getByRole('dialog',{name:previous?'Publish new version':'Create rule',exact:true}),path='/api/v1/quality/rules'+(previous?'/'+previous.id+'/versions':'');
 const pending=responseFor(page,path);await dialog.getByRole('button',{name:previous?'Publish version':'Publish rule',exact:true}).click();const response=await pending;expect(response.status()).toBe(201);
 const input=response.request().postDataJSON() as QualityPublishInput;expect(input).toEqual({id:previous?.id??expect.stringMatching(/^[a-f0-9-]{36}$/),expectedVersion:previous?.version??0,definition});
 const {rule}=await response.json() as {rule:QualityRuleView};expect(rule).toMatchObject({id:input.id,version:(previous?.version??0)+1,definition});
 const key=response.request().headers()['idempotency-key'];const replay=await domainBody<{rule:QualityRuleView}>(await page.request.post(path,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:input}),201);expect(replay.rule).toEqual(rule);await expect(dialog).toHaveCount(0);return rule;
}
async function startRun(page:Page,rule:QualityRuleView,release:ReferenceReleaseView,verdict:'PASS'|'FAIL',invalid:number,asOf?:string){
 const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});await panel.getByRole('textbox',{name:'Reference date (UTC, optional)',exact:true}).fill(asOf??'');
 const path='/api/v1/quality/rules/'+rule.id+'/runs',pending=responseFor(page,path);await panel.getByRole('button',{name:'Run check',exact:true}).click();const response=await pending;expect(response.status()).toBe(202);
 const input=response.request().postDataJSON() as QualityRunInput;expect(input).toEqual({id:expect.stringMatching(/^[a-f0-9-]{36}$/),ruleVersion:rule.version,ruleHash:rule.definitionHash,...(asOf?{referenceAsOf:asOf}:{})});
 const requested=(await response.json() as {run:QualityRunView}).run;if(requested.kind!=='reference-allowed-values')throw new Error('Reference run discriminator missing');
 expect(requested.reference).toEqual({setId:release.release.setId,version:release.release.version,publicationHash:release.publicationHash,asOf:asOf??expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),codeStatus:'active',bindingHash:expect.stringMatching(/^[a-f0-9]{64}$/)});
 const key=response.request().headers()['idempotency-key'];const replay=(await domainBody<{run:QualityRunView}>(await page.request.post(path,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:input}),202)).run;expect(replay.id).toBe(input.id);expect(replay.reference).toEqual(requested.reference);
 await expect.poll(async()=>{const run=await readRun(page,input.id);return {status:run.status,verdict:run.verdict,error:run.errorCode};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',verdict,error:null});
 const complete=await readRun(page,input.id);expect(complete.reference).toEqual(requested.reference);expect(complete.measurement).toMatchObject({kind:'reference-allowed-values',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,invalidCount:invalid,referenceBindingHash:requested.reference.bindingHash,queryTemplate:'postgresql-reference-allowed-values-v1'});
 expect(Date.parse(complete.measurement!.observedStartedAt)).toBeGreaterThanOrEqual(Date.parse(complete.createdAt));expect(Date.parse(complete.measurement!.observedFinishedAt)).toBeGreaterThanOrEqual(Date.parse(complete.measurement!.observedStartedAt));
 const evidence=page.getByRole('region',{name:'Run evidence',exact:true});await expect(evidence.getByText('Completed',{exact:true})).toBeVisible();await expect(evidence.getByText(verdict==='PASS'?'Pass':'Fail',{exact:true})).toBeVisible();await expect(evidence.getByTestId('quality-row-count')).toHaveText('20');await expect(evidence.getByTestId('quality-null-count')).toHaveText('4');await expect(evidence.getByTestId('quality-non-null-count')).toHaveText('16');await expect(evidence.getByTestId('quality-invalid-count')).toHaveText(String(invalid));await expect(evidence.getByTestId('quality-reference-hash')).toHaveText(release.publicationHash);
 return complete;
}
async function capture(page:Page,info:TestInfo,name:string,run:QualityRunView){
 for(const [locale,width] of [['en',1440],['ar',390]] as const){
  await language(page,locale);await page.setViewportSize({width,height:960});const arabic=locale==='ar',evidence=page.getByRole('region',{name:arabic?'أدلة التنفيذ':'Run evidence',exact:true});
  await expect(evidence.getByText(run.id,{exact:true})).toHaveCount(1);await expect(evidence.getByText(arabic?'مكتمل':'Completed',{exact:true})).toBeVisible();await expect(evidence.getByText(run.verdict==='PASS'?(arabic?'ناجح':'Pass'):(arabic?'غير ناجح':'Fail'),{exact:true})).toBeVisible();
  const history=page.getByRole('table',{name:arabic?'سجل التنفيذ':'Run history',exact:true}).getByRole('row').filter({has:page.getByRole('button',{name:(arabic?'عرض التنفيذ':'View run')+' '+run.id,exact:true})});await expect(history).toHaveCount(1);await expect(history.getByText(arabic?'مكتمل':'Completed',{exact:true})).toBeVisible();await expect(history.getByText(run.verdict==='PASS'?(arabic?'ناجح':'Pass'):(arabic?'غير ناجح':'Fail'),{exact:true})).toBeVisible();
  await evidence.evaluate(element=>element.scrollIntoView({block:'start'}));await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);await page.screenshot({path:info.outputPath('reference-quality-'+name+'-binding-'+locale+'-'+width+'.png'),fullPage:false});
  await evidence.locator('.quality-measurements').evaluate(element=>element.scrollIntoView({block:'start'}));await expect(evidence.getByTestId('quality-non-null-count')).toBeVisible();await expect(evidence.getByTestId('quality-invalid-count')).toBeVisible();await page.screenshot({path:info.outputPath('reference-quality-'+name+'-measurement-'+locale+'-'+width+'.png'),fullPage:false});
 }
 await language(page,'en');await page.setViewportSize({width:1440,height:960});
}
test('REF-DQ: approved allowed values, exact non-null thresholds, historical reference pins and current source observations',async({page,browser},info)=>{
 test.setTimeout(720_000);await domainLogin(page);await language(page,'en');
 const session=await domainBody<Session>(await page.request.get('/api/v1/me'));expect(session.permissions).toEqual(expect.arrayContaining(['reference:read','reference:write','quality:read','quality:write','quality:execute']));
 const ownerContext=await browser.newContext(),consumerContext=await browser.newContext(),foreignContext=await browser.newContext();
 try{
  const reviewer=await ownerContext.newPage();await domainLogin(reviewer,'owner');await language(reviewer,'en');
  const suffix=randomUUID().replaceAll('-',''),setId=randomUUID(),setName='Synthetic allowed codes '+suffix;
  const definition:ApprovalDefinition={formatVersion:1,id:'reference_quality_'+suffix,version:1,name:'Synthetic quality reference review '+suffix,separationOfDuties:true,stages:[{id:'review',name:'Reference codes',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]};
  const workflow=(await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.post('/api/v1/workflow-definitions',{headers:await domainHeaders(page),data:{definition}}),201)).workflow;
  const first=await referencePublication(page,reviewer,workflow,setId,1,setName,['A']),{table,column}=await scannedColumn(page);
  await page.goto('/catalog/'+column.id+'?tab=quality');await page.getByRole('button',{name:'Create rule',exact:true}).click();const dialog=page.getByRole('dialog',{name:'Create rule',exact:true});
  await dialog.getByRole('combobox',{name:'Check type',exact:true}).selectOption('reference-allowed-values');await dialog.getByRole('textbox',{name:'Rule name',exact:true}).fill('Synthetic allowed values '+suffix);await dialog.getByRole('textbox',{name:'Business purpose',exact:true}).fill('Compare current source codes against an approved immutable reference release.');await dialog.getByRole('combobox',{name:'Owner',exact:true}).selectOption(stewardIdentity);
  await dialog.getByRole('searchbox',{name:'Search reference sets',exact:true}).fill(setName);await dialog.getByRole('button',{name:'Search',exact:true}).click();await dialog.getByRole('button',{name:'Select reference set '+setName,exact:true}).click();await expect(dialog.getByText('Selected reference set: '+setName,{exact:true})).toBeVisible();await expect(dialog.getByText('The selected active codes, including codes from a restricted set, are sent privately to the authorized source connector for this check. Public run evidence contains the release and binding hashes, not the codes.',{exact:true})).toBeVisible();await dialog.getByRole('textbox',{name:'Maximum invalid percentage',exact:true}).fill('24.99');
  const ruleDefinition:ReferenceAllowedValuesRuleDefinition={formatVersion:1,kind:'reference-allowed-values',name:'Synthetic allowed values '+suffix,purpose:'Compare current source codes against an approved immutable reference release.',target:{tableAssetId:table.id,columnAssetId:column.id},ownerId:stewardIdentity,severity:'warning',maximumInvalidBasisPoints:2499,reference:{setId,selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'};
  const rule1=await publishRule(page,ruleDefinition),failed=await startRun(page,rule1,first,'FAIL',4);await capture(page,info,'exact-boundary-fail',failed);
  const panel=page.getByRole('region',{name:'Immutable rule version',exact:true});await panel.getByRole('button',{name:'Publish new version',exact:true}).click();const edit=page.getByRole('dialog',{name:'Publish new version',exact:true});await expect(edit.getByRole('combobox',{name:'Check type',exact:true})).toHaveValue('reference-allowed-values');await expect(edit.getByRole('textbox',{name:'Maximum invalid percentage',exact:true})).toHaveValue('24.99');await edit.getByRole('textbox',{name:'Maximum invalid percentage',exact:true}).fill('25');const rule2=await publishRule(page,{...ruleDefinition,maximumInvalidBasisPoints:2500},rule1);
  const second=await referencePublication(page,reviewer,workflow,setId,2,setName,['A','B']);expect(Date.parse(second.release.publishedAt)).toBeGreaterThan(Date.parse(first.release.publishedAt));
  const historical=await startRun(page,rule2,first,'PASS',4,first.release.publishedAt);await capture(page,info,'historical-reference-pass',historical);expect(await readRun(page,failed.id)).toEqual(failed);
  const exact=page.getByRole('region',{name:'Run evidence',exact:true}).getByRole('link',{name:'Open exact approved release',exact:true});await expect(exact).toHaveAttribute('href','/reference-data/'+setId+'?version=1');await exact.click();await expect(page).toHaveURL(new RegExp('/reference-data/'+setId+'\\?version=1$'));await expect(page.getByRole('cell',{name:'A',exact:true})).toBeVisible();await expect(page.getByRole('cell',{name:'B',exact:true})).toHaveCount(0);await expect(page.getByText(first.publicationHash,{exact:true})).toBeVisible();
  await page.goto('/reference-data/'+setId+'?version=0');await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('alert')).toBeVisible();
  await page.goto('/catalog/'+column.id+'?tab=quality');await page.getByRole('button',{name:ruleDefinition.name,exact:true}).click();const current=await startRun(page,rule2,second,'PASS',0);await capture(page,info,'current-reference-pass',current);expect(await readRun(page,historical.id)).toEqual(historical);expect(await readRun(page,failed.id)).toEqual(failed);
  const consumer=await consumerContext.newPage();await domainLogin(consumer,'consumer');await language(consumer,'en');await consumer.goto('/catalog/'+column.id+'?tab=quality');await consumer.getByRole('button',{name:ruleDefinition.name,exact:true}).click();await consumer.getByRole('button',{name:'View run '+historical.id,exact:true}).click();await expect(consumer.getByTestId('quality-reference-hash')).toHaveText(first.publicationHash);for(const label of ['Create rule','Run check','Publish new version'])await expect(consumer.getByRole('button',{name:label,exact:true})).toHaveCount(0);
  const denied=await consumer.request.post('/api/v1/quality/rules/'+rule2.id+'/runs',{headers:await domainHeaders(consumer),data:{id:randomUUID(),ruleVersion:rule2.version,ruleHash:rule2.definitionHash}});expect(denied.status()).toBe(403);
  const foreign=await foreignContext.newPage();await domainLogin(foreign,'summit');for(const path of ['/api/v1/quality/rules/'+rule1.id,'/api/v1/quality/runs/'+historical.id,'/api/v1/reference-data/sets/'+setId+'/releases/1'])expect((await foreign.request.get(path)).status()).toBe(404);
 }finally{await ownerContext.close();await consumerContext.close();await foreignContext.close();}
});
