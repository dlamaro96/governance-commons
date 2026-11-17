// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, current PostgreSQL metadata, independent review and Temporal
 * application. No intercepted responses, internal completion or SQL fixtures.
 * An unchanged scan must preserve selected-field evidence freshness; actual
 * source rename invalidation belongs to native qualification. */
import {test,expect,type Locator,type Page,type Response,type TestInfo} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID} from 'node:crypto';
import {waitForBrowserRateBudget} from '../fixtures/browser-rate-budget.ts';
import {classificationCopy} from '../../apps/web/src/classification/messages.ts';
import {domainBody,domainHeaders,domainLogin,rescanDomainBrowserAsset,scanDomainBrowserAsset,stewardIdentity} from '../fixtures/business-domains-browser.ts';
import type {Session} from '../../apps/web/src/types.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import type {ApprovalDefinitionView,ApprovalRequestView} from '../../packages/domain/src/approval-service.ts';
import type {ClassificationAssignmentView,ClassificationEvaluationView,ClassificationPage,ClassificationPin,ClassificationProposal,ClassificationRuleView,ClassificationSuggestionView,ClassificationTaxonomyView,MetadataClassificationRule} from '../../packages/domain/src/classification-contracts.ts';

const reviewerId='10000000-0000-4000-8000-000000000002';
const uuid=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
type Review=Extract<ApprovalRequestView,{binding:'classification.review'}>;
const pin=(value:ClassificationPin)=>({id:value.id,version:value.version,definitionHash:value.definitionHash});
const responseFor=(page:Page,path:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()==='POST');
async function request(page:Page,id:string):Promise<Review>{
 const row=(await domainBody<{request:ApprovalRequestView}>(await page.request.get('/api/v1/approval-requests/'+id))).request;
 if(row.binding!=='classification.review')throw new Error('Expected the exact classification approval binding');return row;
}
async function assignments(page:Page,assetId:string){return domainBody<ClassificationPage<ClassificationAssignmentView>>(await page.request.get('/api/v1/assets/'+assetId+'/classifications?limit=100'));}
async function suggestions(page:Page,assetId:string){return domainBody<ClassificationPage<ClassificationSuggestionView>>(await page.request.get('/api/v1/assets/'+assetId+'/classification-suggestions?limit=100'));}
async function language(page:Page,locale:'en'|'ar'){
 await page.locator('#language').selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');
}
async function capture(page:Page,info:TestInfo,name:string,width:number){
 await page.setViewportSize({width,height:960});await page.evaluate(()=>window.scrollTo(0,0));
 // Capture the asserted outcome even when existing synthetic rule pickers make
 // the page long. This is ordinary scrolling, with no altered page content.
 const locale=await page.locator('html').getAttribute('lang')==='ar'?'ar':'en';
 const section=/^(applied|withdrawn)-/.test(name)?classificationCopy[locale].approved:/^suggestion-/.test(name)?classificationCopy[locale].suggestions:null;
 if(section)await page.getByRole('heading',{name:section,exact:true}).evaluate(element=>element.scrollIntoView({block:'start',behavior:'instant'}));
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 await page.screenshot({path:info.outputPath('classification-'+name+'-'+width+'.png'),fullPage:false});
}
async function captureLocales(page:Page,info:TestInfo,name:string){
 await language(page,'en');await capture(page,info,name+'-en',1440);await language(page,'ar');await capture(page,info,name+'-ar',390);await language(page,'en');await page.setViewportSize({width:1440,height:960});
}
async function choose(root:Page|Locator,title:string,name:string){
 const group=root.getByRole('group',{name:title,exact:true});await expect(group).toBeVisible();
 // Existing environments may contain earlier synthetic definitions. Traverse
 // the actual signed UI pages; never assume the new UUID is on page one.
 for(let visited=0;visited<100;visited++){
  await expect(group.getByText('Loading…',{exact:true})).toHaveCount(0);
  const target=group.getByRole('button',{name,exact:true});if(await target.count()){await target.click();return;}
  const next=group.getByRole('button',{name:'Next page',exact:true});await expect(next).toBeEnabled();await next.click();
 }
 throw new Error('Classification picker exceeds the bounded browser pagination profile');
}
async function replay(page:Page,response:Response,expected:unknown){
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(uuid);
 const result=await domainBody<unknown>(await page.request.post(new URL(response.url()).pathname,{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:response.request().postDataJSON()}),201);
 expect(result).toEqual(expected);
}
async function publishTaxonomy(page:Page,name:string){
 await page.getByRole('link',{name:'Classification',exact:true}).click();await expect(page).toHaveURL(/\/classifications$/);
 await page.getByRole('button',{name:'Create taxonomy',exact:true}).click();
 await page.getByRole('textbox',{name:'Name',exact:true}).fill(name);
 await page.getByRole('textbox',{name:'Description',exact:true}).fill('Independent synthetic metadata sensitivity labels.');
 await page.getByRole('textbox',{name:'Stable label key',exact:true}).fill('synthetic_sensitive');
 await page.getByRole('textbox',{name:'Label name',exact:true}).fill('Synthetic sensitive metadata');
 await page.getByRole('textbox',{name:'Label description',exact:true}).fill('A reviewed synthetic sensitivity label, without source-row sampling.');
 const pending=responseFor(page,'/api/v1/classification/taxonomies');await page.getByRole('button',{name:'Publish definition',exact:true}).click();
 const response=await pending;expect(response.status()).toBe(201);const value:{taxonomy:ClassificationTaxonomyView}=await response.json(),taxonomy=value.taxonomy;
 expect(taxonomy.id).toMatch(uuid);expect(taxonomy).toMatchObject({version:1,currentVersion:1,createdBy:stewardIdentity,definition:{formatVersion:1,name,description:'Independent synthetic metadata sensitivity labels.',labels:[{key:'synthetic_sensitive',name:'Synthetic sensitive metadata',description:'A reviewed synthetic sensitivity label, without source-row sampling.',status:'active'}]}});
 expect(taxonomy.definitionHash).toMatch(/^[a-f0-9]{64}$/);expect(response.request().postDataJSON()).toEqual({id:taxonomy.id,expectedVersion:0,definition:taxonomy.definition});await replay(page,response,value);
 await expect(page.getByRole('heading',{name,exact:true})).toBeVisible();return taxonomy;
}
async function publishRule(page:Page,taxonomy:ClassificationTaxonomyView,name:string){
 await page.getByRole('button',{name:'Metadata rules',exact:true}).click();await page.getByRole('button',{name:'Create metadata rule',exact:true}).click();
 await page.getByRole('textbox',{name:'Name',exact:true}).fill(name);await page.getByRole('textbox',{name:'Business purpose',exact:true}).fill('Review synthetic orders metadata through independent approval.');
 await expect(page.getByRole('combobox',{name:'Rule owner',exact:true})).toBeEnabled();await page.getByRole('combobox',{name:'Rule owner',exact:true}).selectOption(stewardIdentity);
 await page.getByRole('checkbox',{name:'Column',exact:true}).uncheck();await page.getByRole('checkbox',{name:'Table',exact:true}).check();
 await choose(page,'Taxonomy',taxonomy.definition.name+' · Version 1');await page.getByRole('combobox',{name:'Label',exact:true}).selectOption('synthetic_sensitive');
 await page.getByRole('combobox',{name:'Metadata field',exact:true}).selectOption('name');await page.getByRole('combobox',{name:'Operator',exact:true}).selectOption('equals');await page.getByRole('combobox',{name:'Comparison',exact:true}).selectOption('exact');await page.getByRole('textbox',{name:'Literal value',exact:true}).fill('orders');
 const definition:MetadataClassificationRule={formatVersion:1,kind:'metadata-literal',name,purpose:'Review synthetic orders metadata through independent approval.',ownerId:stewardIdentity,status:'active',assetTypes:['table'],label:{taxonomy:pin(taxonomy),labelKey:'synthetic_sensitive'},all:[{field:'name',operator:'equals',comparison:'exact',literal:'orders'}]};
 const pending=responseFor(page,'/api/v1/classification/rules');await page.getByRole('button',{name:'Publish definition',exact:true}).click();const response=await pending;expect(response.status()).toBe(201);
 const value:{rule:ClassificationRuleView}=await response.json(),rule=value.rule;expect(rule.id).toMatch(uuid);expect(rule).toMatchObject({version:1,currentVersion:1,definition,createdBy:stewardIdentity});expect(rule.definitionHash).toMatch(/^[a-f0-9]{64}$/);
 expect(response.request().postDataJSON()).toEqual({id:rule.id,expectedVersion:0,definition});await replay(page,response,value);await expect(page.getByRole('heading',{name,exact:true})).toBeVisible();return rule;
}
async function submitReview(page:Page,workflow:ApprovalDefinitionView,change:ClassificationProposal['change']){
 const dialog=page.getByRole('dialog',{name:change.kind==='apply'?'Review proposed classification':'Review proposed withdrawal',exact:true});await expect(dialog).toBeVisible();
 await choose(dialog,'Approval workflow',workflow.definition.name+' · Version 1');
 const reviewer=dialog.getByRole('combobox',{name:'Reviewer: reviewer',exact:true});await expect(reviewer).toBeEnabled();await expect(reviewer.locator('option[value="'+stewardIdentity+'"]')).toHaveCount(0);await reviewer.selectOption(reviewerId);
 await expect(dialog.getByText(workflow.definitionHash,{exact:true})).toBeVisible();
 if(change.kind==='withdraw')await dialog.getByRole('textbox',{name:'Withdrawal reason',exact:true}).fill(change.reason);
 await dialog.getByRole('checkbox',{name:'I reviewed this exact label, evidence, assignment version and reviewer plan.',exact:true}).check();
 const pending=responseFor(page,'/api/v1/classification/proposals');await dialog.getByRole('button',{name:'Submit for independent review',exact:true}).click();const response=await pending;expect(response.status()).toBe(201);
 const body=response.request().postDataJSON() as ClassificationProposal;expect(body.id).toMatch(uuid);expect(body).toEqual({id:body.id,change,workflow:{id:workflow.definition.id,version:1,definitionHash:workflow.definitionHash},assignments:{reviewer:reviewerId},expiresAt:expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)});
 expect(Date.parse(body.expiresAt)).toBeGreaterThan(Date.now());const receipt={instance:{id:body.id}};expect(await response.json()).toEqual(receipt);await replay(page,response,receipt);await expect(dialog).toHaveCount(0);
 const row=await request(page,body.id);expect(row).toMatchObject({id:body.id,binding:'classification.review',requesterId:stewardIdentity,status:'pending',result:null,errorCode:null,decisions:[],preconditionsCurrent:true});
 expect(row.tasks).toHaveLength(1);expect(row.tasks[0]).toMatchObject({assignment:'reviewer',assignedIdentityId:reviewerId,stageIndex:0,status:'open'});expect(row.workflow.definition).toEqual(workflow.definition);
 await page.getByRole('link',{name:'Open approval request',exact:true}).click();await expect(page).toHaveURL(new RegExp('/approvals/'+body.id+'$'));await expect(page.getByRole('button',{name:'Approve',exact:true})).toHaveCount(0);
 return {row,body};
}
async function approve(reviewer:Page,requester:Page,row:Review,status:'active'|'withdrawn',version:number){
 await reviewer.goto('/approvals/'+row.id);await expect(reviewer.getByRole('heading',{name:'Proposed classification change',exact:true})).toBeVisible();
 await expect(reviewer.getByText(row.payload.assignmentId,{exact:true})).toBeVisible();const reason='Reviewed synthetic classification '+row.payload.change+' with pinned metadata evidence.';
 await reviewer.getByRole('textbox',{name:'Decision reason',exact:true}).fill(reason);const pending=responseFor(reviewer,'/api/v1/approval-requests/'+row.id+'/decisions');await reviewer.getByRole('button',{name:'Approve',exact:true}).click();
 const response=await pending;expect(response.status()).toBe(200);expect(response.request().postDataJSON()).toEqual({proposalDigest:row.proposalDigest,taskId:row.tasks[0].id,taskVersion:row.tasks[0].version,decision:'approve',reason});
 // Only the real dispatcher/Temporal approval worker may apply the label.
 await expect.poll(async()=>{const next=await request(requester,row.id);return {status:next.status,errorCode:next.errorCode};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',errorCode:null});
 const completed=await request(requester,row.id);expect(completed.payload).toEqual(row.payload);expect(completed.result).toEqual({binding:'classification.review',assetId:row.payload.assetId,assignmentId:row.payload.assignmentId,assignmentVersion:version,status,evidenceHash:row.payload.evidenceHash});
 expect(completed.decisions).toHaveLength(1);expect(completed.decisions[0]).toMatchObject({actorId:reviewerId,decision:'approve',reason,taskId:row.tasks[0].id,taskVersion:row.tasks[0].version});return completed;
}

test('CLS: real metadata suggestion, independent application, immutable pins, reviewed withdrawal and access boundaries',async({page,browser},info)=>{
 test.setTimeout(600_000);await waitForBrowserRateBudget(page.request,295);await page.setViewportSize({width:1440,height:960});await domainLogin(page);await language(page,'en');
 const me=await domainBody<Session>(await page.request.get('/api/v1/me'));expect(me.permissions).toEqual(expect.arrayContaining(['catalog:read','catalog:write','classification:read','classification:write','models:read','models:write','sources:read','sources:write']));
 const token=randomUUID().replaceAll('-',''),asset=await scanDomainBrowserAsset(page,'Synthetic classification browser '+token);
 const definition:ApprovalDefinition={formatVersion:1,id:'classification_browser_'+token,version:1,name:'Synthetic label review '+token,separationOfDuties:true,stages:[{id:'review',name:'Sensitivity review',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]};
 const workflow=(await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.post('/api/v1/workflow-definitions',{headers:await domainHeaders(page),data:{definition}}),201)).workflow;
 const taxonomy=await publishTaxonomy(page,'Synthetic sensitivity '+token),rule=await publishRule(page,taxonomy,'Synthetic order label '+token);await captureLocales(page,info,'definitions');
 const reviewerContext=await browser.newContext(),consumerContext=await browser.newContext(),foreignContext=await browser.newContext();
 try{
  const reviewer=await reviewerContext.newPage();await domainLogin(reviewer,'owner');await language(reviewer,'en');const reviewerMe=await domainBody<Session>(await reviewer.request.get('/api/v1/me'));expect(reviewerMe.user.id).toBe(reviewerId);expect(reviewerMe.permissions).toEqual(expect.arrayContaining(['catalog:read','classification:read','classification:approve']));
  await page.goto('/catalog/'+asset.id);await page.getByRole('navigation',{name:'Details',exact:true}).getByRole('link',{name:'Classification',exact:true}).click();await choose(page,'Select an active metadata rule',rule.definition.name+' · Version 1');
  const pending=responseFor(page,'/api/v1/assets/'+asset.id+'/classification-evaluations');await page.getByRole('button',{name:'Evaluate metadata',exact:true}).click();const response=await pending;expect(response.status()).toBe(201);
  const result:{evaluation:ClassificationEvaluationView}=await response.json(),evaluation=result.evaluation;
  expect(response.request().postDataJSON()).toEqual({id:evaluation.id,expectedAssetVersion:asset.version,rule:pin(rule)});expect(evaluation.id).toMatch(uuid);expect(evaluation.suggestionId).toBe(evaluation.id);
  expect(evaluation).toMatchObject({outcome:'matched',createdBy:stewardIdentity,evidence:{formatVersion:1,kind:'metadata-literal',assetId:asset.id,observedAssetVersion:asset.version,rule:pin(rule),label:rule.definition.label,matches:[{conditionIndex:0,field:'name',value:'orders',valueHash:expect.stringMatching(/^[a-f0-9]{64}$/)}],confidence:{kind:'not-estimated',reason:'metadata-only'},samplePolicy:{kind:'metadata-only',sourceRowsRead:0,sourceSamplesStored:0}}});expect(evaluation.evidenceHash).toMatch(/^[a-f0-9]{64}$/);await replay(page,response,result);
  expect(await assignments(page,asset.id)).toEqual({items:[],nextCursor:null});const proposed=await suggestions(page,asset.id);expect(proposed.items).toHaveLength(1);expect(proposed.items[0]).toMatchObject({id:evaluation.id,evidence:evaluation.evidence,evidenceHash:evaluation.evidenceHash,currentAssignmentVersion:0,evidenceCurrent:true});
  await expect(page.getByRole('heading',{name:'No reviewed classification records on this page',exact:true})).toBeVisible();await expect(page.getByText('Reviewed and applied',{exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Propose this label',exact:true})).toBeEnabled();await captureLocales(page,info,'suggestion');
  await page.getByRole('button',{name:'Propose this label',exact:true}).click();const submitted=await submitReview(page,workflow,{kind:'apply',suggestionId:evaluation.id,expectedAssignmentVersion:0});
  expect(submitted.row.payload).toMatchObject({formatVersion:1,kind:'classification-review',change:'apply',assetId:asset.id,expectedAssignmentVersion:0,suggestionId:evaluation.id,label:rule.definition.label,evidence:evaluation.evidence,evidenceHash:evaluation.evidenceHash});expect(await assignments(page,asset.id)).toEqual({items:[],nextCursor:null});
  await reviewer.goto('/approvals/'+submitted.row.id);await expect(reviewer.getByRole('button',{name:'Approve',exact:true})).toBeVisible();await expect(reviewer.getByText('Not estimated: metadata-only match',{exact:true})).toBeVisible();await captureLocales(reviewer,info,'review');
  const applied=await approve(reviewer,page,submitted.row,'active',1),appliedPage=await assignments(page,asset.id);expect(appliedPage.nextCursor).toBeNull();expect(appliedPage.items).toHaveLength(1);const assignment=appliedPage.items[0];
  expect(assignment).toMatchObject({id:submitted.row.payload.assignmentId,assetId:asset.id,version:1,status:'active',suggestionId:evaluation.id,approvalInstanceId:submitted.row.id,label:rule.definition.label,evidence:evaluation.evidence,evidenceCurrent:true});
  await page.goto('/approvals/'+submitted.row.id);await expect(page.getByText('Label applied',{exact:false})).toBeVisible();await page.getByRole('link',{name:'Open resource',exact:true}).click();await expect(page).toHaveURL(new RegExp('/catalog/'+asset.id+'\\?tab=classification$'));await expect(page.getByText('Reviewed and applied',{exact:true})).toBeVisible();await captureLocales(page,info,'applied');
  // A new rule version does not rewrite approved evidence or its old pin.
  await page.goto('/classifications');await page.getByRole('button',{name:'Metadata rules',exact:true}).click();await choose(page,'Metadata rules',rule.definition.name+' · Version 1');await page.getByRole('button',{name:'Publish new version',exact:true}).click();
  const revisedPurpose=rule.definition.purpose+' Version two preserves the selected metadata field.';await page.getByRole('textbox',{name:'Business purpose',exact:true}).fill(revisedPurpose);const revisedPending=responseFor(page,'/api/v1/classification/rules/'+rule.id+'/versions');await page.getByRole('button',{name:'Publish definition',exact:true}).click();const revisedResponse=await revisedPending;expect(revisedResponse.status()).toBe(201);const revised:ClassificationRuleView=(await revisedResponse.json()).rule;
  expect(revised).toMatchObject({id:rule.id,version:2,currentVersion:2,definition:{...rule.definition,purpose:revisedPurpose}});expect(revised.definitionHash).not.toBe(rule.definitionHash);expect(revisedResponse.request().postDataJSON()).toEqual({id:rule.id,expectedVersion:1,definition:revised.definition});
  await page.getByRole('button',{name:'Previous version',exact:true}).click();await expect(page.getByText(rule.definition.purpose,{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Publish new version',exact:true})).toHaveCount(0);
  const historic=(await domainBody<{rule:ClassificationRuleView}>(await page.request.get('/api/v1/classification/rules/'+rule.id+'?version=1'))).rule;expect(historic).toEqual({...rule,currentVersion:2});
  const oldPin=await page.request.post('/api/v1/assets/'+asset.id+'/classification-evaluations',{headers:await domainHeaders(page),data:{id:randomUUID(),expectedAssetVersion:asset.version,rule:pin(rule)}});expect(oldPin.status()).toBe(409);expect((await oldPin.json()).code).toBe('CLASSIFICATION_PIN_STALE');
  const staleProposal={...submitted.body,id:randomUUID(),change:{kind:'apply',suggestionId:evaluation.id,expectedAssignmentVersion:1}};
  const refused=await page.request.post('/api/v1/classification/proposals',{headers:await domainHeaders(page),data:staleProposal});expect(refused.status()).toBe(409);expect((await refused.json()).code).toBe('CLASSIFICATION_EVIDENCE_STALE');expect((await assignments(page,asset.id)).items).toEqual([assignment]);
  const refreshed=await rescanDomainBrowserAsset(page,asset);expect(refreshed.version).toBeGreaterThan(asset.version);expect(refreshed.metadata.scanId).not.toBe(asset.metadata.scanId);
  const unchanged=(await assignments(page,asset.id)).items;expect(unchanged).toEqual([assignment]);expect(unchanged[0].evidenceCurrent).toBe(true);expect(unchanged[0].evidence.observedAssetVersion).toBe(asset.version);expect((await suggestions(page,asset.id)).items[0]).toMatchObject({id:evaluation.id,evidenceCurrent:true,currentAssignmentVersion:1,evidence:evaluation.evidence});
  // Withdrawal reviews the approved slot, even after its original rule was
  // superseded. It must not require fabricating fresh source-row evidence.
  await page.goto('/catalog/'+asset.id+'?tab=classification');await expect(page.getByText('Reviewed and applied',{exact:true})).toBeVisible();await page.getByRole('button',{name:'Propose withdrawal',exact:true}).click();
  const withdrawalReason='Remove this independently reviewed synthetic classification.';const withdrawal=await submitReview(page,workflow,{kind:'withdraw',assignmentId:assignment.id,expectedAssignmentVersion:1,reason:withdrawalReason});
  expect(withdrawal.row.payload).toMatchObject({change:'withdraw',assignmentId:assignment.id,expectedAssignmentVersion:1,suggestionId:evaluation.id,evidence:evaluation.evidence,evidenceHash:evaluation.evidenceHash,reason:withdrawalReason});expect((await assignments(page,asset.id)).items).toEqual([assignment]);
  const withdrawn=await approve(reviewer,page,withdrawal.row,'withdrawn',2),current=await assignments(page,asset.id);expect(current.items).toHaveLength(1);expect(current.nextCursor).toBeNull();expect(current.items[0]).toMatchObject({...assignment,version:2,status:'withdrawn',approvalInstanceId:withdrawal.row.id,reason:withdrawalReason,updatedAt:expect.any(String)});
  expect(withdrawn.result?.assignmentId).toBe(applied.result?.assignmentId);const earlier=await request(page,submitted.row.id);expect({payload:earlier.payload,result:earlier.result,decisions:earlier.decisions,status:earlier.status}).toEqual({payload:applied.payload,result:applied.result,decisions:applied.decisions,status:applied.status});
  await page.goto('/approvals/'+withdrawal.row.id);await expect(page.getByText('Label withdrawn',{exact:false})).toBeVisible();await page.getByRole('link',{name:'Open resource',exact:true}).click();await expect(page.getByText('Withdrawn',{exact:true})).toBeVisible();await expect(page.getByText('Reviewed and applied',{exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Propose withdrawal',exact:true})).toHaveCount(0);await captureLocales(page,info,'withdrawn');
  const consumer=await consumerContext.newPage();await domainLogin(consumer,'consumer');await language(consumer,'en');const consumerMe=await domainBody<Session>(await consumer.request.get('/api/v1/me'));for(const permission of ['classification:read','classification:write','classification:approve'])expect(consumerMe.permissions).not.toContain(permission);
  for(const path of ['/api/v1/classification/taxonomies','/api/v1/classification/rules/'+rule.id,'/api/v1/assets/'+asset.id+'/classifications','/api/v1/assets/'+asset.id+'/classification-suggestions']){const denial=await consumer.request.get(path);expect(denial.status()).toBe(403);expect((await denial.json()).code).toBe('FORBIDDEN');}
  const consumerWrite=await consumer.request.post('/api/v1/assets/'+asset.id+'/classification-evaluations',{headers:await domainHeaders(consumer),data:{id:randomUUID(),expectedAssetVersion:refreshed.version,rule:pin(revised)}});expect(consumerWrite.status()).toBe(403);expect((await consumerWrite.json()).code).toBe('FORBIDDEN');
  await consumer.goto('/catalog/'+asset.id+'?tab=classification');await expect(consumer.getByRole('heading',{name:'You do not have access to this view',exact:true})).toBeVisible();await expect(consumer.getByRole('link',{name:'Classification',exact:true})).toHaveCount(0);await expect(consumer.getByRole('button',{name:'Evaluate metadata',exact:true})).toHaveCount(0);await captureLocales(consumer,info,'denied');
  const foreign=await foreignContext.newPage();await domainLogin(foreign,'summit');const foreignMe=await domainBody<Session>(await foreign.request.get('/api/v1/me'));expect(foreignMe.permissions).toEqual(expect.arrayContaining(['catalog:read','classification:read']));
  for(const path of ['/api/v1/classification/taxonomies/'+taxonomy.id,'/api/v1/classification/rules/'+rule.id,'/api/v1/assets/'+asset.id+'/classifications','/api/v1/assets/'+asset.id+'/classification-suggestions']){const denial=await foreign.request.get(path);expect(denial.status()).toBe(404);expect((await denial.json()).code).toBe('CLASSIFICATION_UNAVAILABLE');}
  const privateReview=await foreign.request.get('/api/v1/approval-requests/'+withdrawal.row.id);expect(privateReview.status()).toBe(404);expect((await privateReview.json()).code).toBe('APPROVAL_UNAVAILABLE');expect(await assignments(page,asset.id)).toEqual(current);
 }finally{await reviewerContext.close();await consumerContext.close();await foreignContext.close();}
});
