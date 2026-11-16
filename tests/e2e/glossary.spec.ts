// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, canonical approval commands, Temporal publication and search.
 * This journey covers metadata-only terms; it does not qualify glossary links. */
import {test,expect,type Browser,type Page,type TestInfo} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID} from 'node:crypto';
import {domainBody,domainHeaders,domainLogin,stewardIdentity} from '../fixtures/business-domains-browser.ts';
import {glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import type {GlossaryPublicationInput,GlossaryTranslation} from '../../packages/domain/src/glossary-contracts.ts';
import type {GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import type {ApprovalDefinitionView,ApprovalRequestView} from '../../packages/domain/src/approval-service.ts';
import type {getAssetType} from '../../packages/domain/src/asset-type-service.ts';
import type {AssetList,Session} from '../../apps/web/src/types.ts';

const reviewerId='10000000-0000-4000-8000-000000000002';
type PublishedAssetType=Awaited<ReturnType<typeof getAssetType>>['type'];
type Term={resourceId:string;resourceVersion:number;publication:GlossaryPublicationInput};
type Receipt={id:string;assetId:string;assetVersion:number;proposalDigest:string;
 workflowPin:{id:string;version:number;definitionHash:string};graphReceiptId:string|null;executedBy:string;executedAt:string};
const responseFor=(page:Page,path:string,method:string)=>page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()===method);
const readRequest=async(page:Page,id:string)=>(await domainBody<{request:ApprovalRequestView}>(await page.request.get(`/api/v1/approval-requests/${id}`))).request;
const readTerm=async(page:Page,id:string)=>domainBody<Term>(await page.request.get(`/api/v1/glossary/terms/${id}`));

test.beforeAll(async({browser}:{browser:Browser})=>{
 test.setTimeout(75_000);const context=await browser.newContext();
 try{const response=await context.request.get('/api/v1/me'),remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
  if(Number.isFinite(remaining)&&remaining<220&&Number.isFinite(reset)&&reset>=0&&reset<=60)await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
 }finally{await context.close();}
});

async function language(page:Page,locale:'en'|'ar'){
 await page.locator('#language').selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(page.locator('html')).toHaveAttribute('dir',locale==='ar'?'rtl':'ltr');
}
async function accessibleCapture(page:Page,info:TestInfo,name:string,width:number){
 await page.setViewportSize({width,height:960});await page.evaluate(()=>window.scrollTo(0,0));
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 // New captures stay in this attempt's owned output, never overwrite history.
 await page.screenshot({path:info.outputPath(`glossary-${name}-${width}.png`),fullPage:false});
}
async function starter(page:Page):Promise<PublishedAssetType>{
 const current=await page.request.get('/api/v1/asset-types/business_term');
 let type:PublishedAssetType;
 if(current.status()===404){
  expect((await current.json()).code).toBe('ASSET_TYPE_NOT_FOUND');
  type=(await domainBody<{type:PublishedAssetType}>(await page.request.post('/api/v1/asset-types',{headers:await domainHeaders(page),data:{definition:glossaryStarterType()}}),201)).type;
 }else type=(await domainBody<{type:PublishedAssetType}>(current)).type;
 expect(type.id).toBe('business_term');expect(type.version).toBe(type.currentVersion);expect(type.resolved.requiredOwner).toBe(true);
 // A changed deployment fixture must fail explicitly rather than silently
 // dropping required governed attributes or publishing a replacement model.
 expect(type.resolved.model.attributes).toEqual(glossaryStarterType().attributes);
 expect(type.resolved.lifecycle.initial).toBe('active');
 return type;
}
async function chooseWorkflow(page:Page,workflow:ApprovalDefinitionView){
 const picker=page.getByRole('region',{name:'Approval workflow',exact:true});
 await picker.getByLabel('Search: Approval workflow',{exact:true}).fill(workflow.definition.name);
 const searched=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/workflow-definitions'&&url.searchParams.get('q')===workflow.definition.name&&response.request().method()==='GET';});
 await picker.getByRole('button',{name:'Search',exact:true}).click();expect((await searched).status()).toBe(200);
 await expect(picker.getByRole('combobox',{name:'Approval workflow',exact:true})).toBeEnabled();
 await picker.getByRole('combobox',{name:'Approval workflow',exact:true}).selectOption(workflow.definition.id);
 await page.getByLabel('Reviewer: reviewer',{exact:true}).selectOption(reviewerId);
 await expect(page.getByText(workflow.definitionHash,{exact:true})).toBeVisible();
}
async function submit(page:Page,expected:GlossaryPublicationInput,workflow:ApprovalDefinitionView,base:Term|null){
 const pending=responseFor(page,'/api/v1/glossary/proposals','POST');
 await page.getByRole('button',{name:'Submit for approval',exact:true}).click();
 const response=await pending;expect(response.status()).toBe(201);
 const body=response.request().postDataJSON() as GlossaryProposalInput;
 expect(body.requestId).toMatch(/^[a-f0-9-]{36}$/);expect(body.resourceId).toMatch(/^[a-f0-9-]{36}$/);
 if(base)expect(body.resourceId).toBe(base.resourceId);
 expect(body.resourceVersion).toBe(base?.resourceVersion??null);expect(body.publication).toEqual(expected);
 expect(body.assignments).toEqual({reviewer:reviewerId});
 expect(body.workflowPin).toEqual({id:workflow.definition.id,version:workflow.definition.version,definitionHash:workflow.definitionHash});
 const request:ApprovalRequestView=(await response.json()).request;
 expect(request.id).toBe(body.requestId);expect(request.resourceId).toBe(body.resourceId);expect(request.resourceVersion).toBe(body.resourceVersion);
 expect(request.status).toBe('pending');expect(request.result).toBeNull();expect(request.errorCode).toBeNull();expect(request.payload).toEqual(expected);
 expect(request.requesterId).toBe(stewardIdentity);expect(request.workflow.definition).toEqual(workflow.definition);expect(request.decisions).toEqual([]);
 expect(request.tasks).toHaveLength(1);expect(request.tasks[0]).toMatchObject({assignment:'reviewer',assignedIdentityId:reviewerId,stageIndex:0,status:'open'});
 await expect(page).toHaveURL(new RegExp(`/approvals/${request.id}$`));
 await expect(page.getByRole('heading',{level:1,name:'Request',exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Approve',exact:true})).toHaveCount(0);
 const key=response.request().headers()['idempotency-key'];expect(key).toMatch(/^[a-f0-9-]{36}$/);
 const replay=(await domainBody<{request:ApprovalRequestView}>(await page.request.post('/api/v1/glossary/proposals',{headers:{...await domainHeaders(page),'Idempotency-Key':key},data:body}),201)).request;
 expect(replay.id).toBe(request.id);expect(replay.payload).toEqual(expected);expect(replay.tasks.map(task=>task.id)).toEqual(request.tasks.map(task=>task.id));expect(replay.decisions).toEqual([]);
 return {request,body};
}
async function approveAndPublish(reviewer:Page,requester:Page,submitted:ApprovalRequestView,version:number){
 const task=submitted.tasks[0],reason=`Reviewed synthetic term version ${version}.\nMeaning and restricted audience confirmed.`;
 await reviewer.goto(`/approvals/${submitted.id}`);
 await expect(reviewer.getByRole('heading',{level:1,name:'Request',exact:true})).toBeVisible();
 await expect(reviewer.getByRole('heading',{name:submitted.workflow.definition.name,exact:true})).toBeVisible();
 await reviewer.getByLabel('Decision reason',{exact:true}).fill(reason);
 const decided=responseFor(reviewer,`/api/v1/approval-requests/${submitted.id}/decisions`,'POST');
 await reviewer.getByRole('button',{name:'Approve',exact:true}).click();const response=await decided;expect(response.status()).toBe(200);
 expect(response.request().postDataJSON()).toEqual({proposalDigest:submitted.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason});
 const recorded:ApprovalRequestView=(await response.json()).request;
 expect(recorded.decisions).toHaveLength(1);expect(recorded.decisions[0]).toMatchObject({taskId:task.id,taskVersion:task.version,actorId:reviewerId,decision:'approve',reason});
 // Only the real worker may advance and publish. No direct tick, site token,
 // mocked response or test-side SQL can satisfy this eventual assertion.
 await expect.poll(async()=>{const row=await readRequest(requester,submitted.id);return {status:row.status,errorCode:row.errorCode};},{timeout:120_000,intervals:[1000,2000,4000]}).toEqual({status:'succeeded',errorCode:null});
 const completed=await readRequest(requester,submitted.id),receipt=completed.result as Receipt;
 expect(receipt.graphReceiptId===null||typeof receipt.graphReceiptId==='string'&&/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(receipt.graphReceiptId)).toBe(true);
 expect(receipt).toEqual({id:submitted.id,assetId:submitted.resourceId,assetVersion:version,proposalDigest:submitted.proposalDigest,
  workflowPin:{id:submitted.workflowId,version:submitted.workflowVersion,definitionHash:submitted.workflowHash},graphReceiptId:receipt.graphReceiptId,executedBy:stewardIdentity,executedAt:expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)});
 expect(completed.payload).toEqual(submitted.payload);expect(completed.decisions).toEqual(recorded.decisions);
 const term=await readTerm(requester,submitted.resourceId);expect(term).toEqual({resourceId:submitted.resourceId,resourceVersion:version,publication:submitted.payload});
 const detail=await domainBody<{asset:{id:string;name:string;description:string;type:string;version:number;ownerId:string;sourceId:null;observedAt:null}}>(await requester.request.get(`/api/v1/assets/${term.resourceId}`));
 const primary=(term.publication.attributes.translations as unknown as GlossaryTranslation[]).find(row=>row.locale===term.publication.primaryLocale)!;
 expect(detail.asset).toMatchObject({id:term.resourceId,name:primary.name,description:primary.definition,type:'business_term',version,ownerId:reviewerId,sourceId:null,observedAt:null});
 return {completed,term};
}
async function discover(page:Page,term:Term,token:string,name:string){
 const query=`/api/v1/assets?${new URLSearchParams({type:'business_term',limit:'25',q:token})}`;
 await expect.poll(async()=>{const result=await domainBody<AssetList>(await page.request.get(query));return {ids:result.items.map(item=>item.id),names:result.items.map(item=>item.name),versions:result.items.map(item=>item.version),total:result.total,facets:result.facets,nextCursor:result.nextCursor};},{timeout:45_000,intervals:[500,1000,2000]}).toEqual({ids:[term.resourceId],names:[name],versions:[term.resourceVersion],total:1,facets:[{type:'business_term',count:1}],nextCursor:null});
 await page.goto('/glossary');await expect(page.getByRole('heading',{level:1,name:'Business glossary',exact:true})).toBeVisible();
 await page.getByLabel('Search business terms',{exact:true}).fill(token);
 const searched=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/assets'&&url.searchParams.get('q')===token&&url.searchParams.get('type')==='business_term'&&response.request().method()==='GET';});
 await page.locator('form.glossary-toolbar').getByRole('button',{name:'Search',exact:true}).click();expect((await searched).status()).toBe(200);
 await expect(page.getByRole('link',{name,exact:true})).toHaveAttribute('href',`/glossary/${term.resourceId}`);
 await page.getByRole('link',{name,exact:true}).click();await expect(page.getByRole('heading',{level:1,name,exact:true})).toBeVisible();
}

test('GLS: real proposal, independent review, publication, amendment and restricted discovery',async({page,browser},info)=>{
 test.setTimeout(420_000);await page.setViewportSize({width:1440,height:960});await domainLogin(page);
 const type=await starter(page),token=randomUUID().replaceAll('-',''),amendedToken=randomUUID().replaceAll('-','');
 const definition:ApprovalDefinition={formatVersion:1,id:`glossary_browser_${token}`,version:1,name:`Synthetic term review ${token}`,separationOfDuties:true,
  stages:[{id:'review',name:'Meaning review',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]};
 const workflow=(await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.post('/api/v1/workflow-definitions',{headers:await domainHeaders(page),data:{definition}}),201)).workflow;
 expect(workflow.definition).toEqual(definition);
 const reviewerContext=await browser.newContext({viewport:{width:1440,height:960}}),consumerContext=await browser.newContext({viewport:{width:390,height:960}});
 try{
  const reviewer=await reviewerContext.newPage();await domainLogin(reviewer,'owner');
  const me=await domainBody<Session>(await reviewer.request.get('/api/v1/me'));expect(me.user.id).toBe(reviewerId);expect(me.permissions).toEqual(expect.arrayContaining(['catalog:read','catalog:write']));
  await page.goto('/glossary');await page.getByRole('link',{name:'Propose a term',exact:true}).click();await expect(page).toHaveURL(/\/glossary\/new$/);
  await expect(page.getByRole('combobox',{name:'Term type',exact:true})).toHaveValue('business_term');
  await page.getByLabel('Owner',{exact:true}).selectOption(reviewerId);await page.getByLabel('Visibility',{exact:true}).selectOption('restricted');
  const audience=page.getByRole('group',{name:'Allowed members',exact:true});await audience.getByRole('checkbox',{name:'Harbor Steward',exact:true}).check();await audience.getByRole('checkbox',{name:'Harbor Owner',exact:true}).check();
  const english:GlossaryTranslation={locale:'en',name:`Synthetic glossary ${token}`,definition:'Demand accepted for fulfilment.\nThis is synthetic business meaning.',synonyms:['Accepted demand'],abbreviations:['AD'],examples:['A synthetic order is accepted after validation.']};
  const arabic:GlossaryTranslation={locale:'ar',name:'الطلب المقبول',definition:'طلب اصطناعي معتمد للتنفيذ.',synonyms:['طلب معتمد'],abbreviations:['ط م'],examples:[]};
  await page.getByLabel('Term name 1',{exact:true}).fill(english.name);await page.getByLabel('Definition 1',{exact:true}).fill(english.definition);
  await page.getByLabel('Synonyms 1',{exact:true}).fill(english.synonyms.join('\n'));await page.getByLabel('Abbreviations 1',{exact:true}).fill(english.abbreviations.join('\n'));
  await page.getByRole('button',{name:'Add example',exact:true}).click();await page.getByLabel('Example 1.1',{exact:true}).fill(english.examples[0]);
  await page.getByRole('button',{name:'Add translation',exact:true}).click();await page.getByLabel('Language tag 2',{exact:true}).fill('ar');
  await page.getByLabel('Term name 2',{exact:true}).fill(arabic.name);await page.getByLabel('Definition 2',{exact:true}).fill(arabic.definition);
  await page.getByLabel('Synonyms 2',{exact:true}).fill(arabic.synonyms.join('\n'));await page.getByLabel('Abbreviations 2',{exact:true}).fill(arabic.abbreviations.join('\n'));
  await chooseWorkflow(page,workflow);
  const publication:GlossaryPublicationInput={typePin:{typeId:type.typeId,modelId:type.id,version:type.version,definitionHash:type.definitionHash,resolutionHash:type.resolutionHash},primaryLocale:'en',ownerId:reviewerId,visibility:'restricted',allowedIdentityIds:[stewardIdentity,reviewerId].sort(),state:'active',attributes:{translations:[{...english},{...arabic}]},links:[]};
  await accessibleCapture(page,info,'proposal-en',1440);await language(page,'ar');await accessibleCapture(page,info,'proposal-ar',390);await language(page,'en');await page.setViewportSize({width:1440,height:960});
  const first=await submit(page,publication,workflow,null);
  const absent=await page.request.get(`/api/v1/assets/${first.request.resourceId}`);expect(absent.status()).toBe(404);expect((await absent.json()).code).toBe('ASSET_NOT_FOUND');
  const published=await approveAndPublish(reviewer,page,first.request,1);await discover(page,published.term,token,english.name);
  await expect(page.getByText(arabic.definition,{exact:true})).toBeVisible();await expect(page.getByText(english.examples[0],{exact:true})).toBeVisible();
  await accessibleCapture(page,info,'published-en',1440);await language(page,'ar');await accessibleCapture(page,info,'published-ar',390);await language(page,'en');await page.setViewportSize({width:1440,height:960});

  await page.getByRole('link',{name:'Propose changes',exact:true}).click();await expect(page).toHaveURL(new RegExp(`/glossary/${published.term.resourceId}/edit$`));
  await expect(page.getByLabel('Term name 1',{exact:true})).toHaveValue(english.name);await expect(page.getByLabel('Language tag 2',{exact:true})).toHaveValue('ar');
  await expect(page.getByLabel('Owner',{exact:true})).toHaveValue(reviewerId);await expect(page.getByLabel('Visibility',{exact:true})).toHaveValue('restricted');
  await expect(page.getByRole('checkbox',{name:'Harbor Steward',exact:true})).toBeChecked();await expect(page.getByRole('checkbox',{name:'Harbor Owner',exact:true})).toBeChecked();
  const amendedEnglish={...english,name:`Revised glossary ${amendedToken}`,definition:'Demand accepted after the current quality checks.\nThis amendment is synthetic.',synonyms:['Validated demand']};
  await page.getByLabel('Term name 1',{exact:true}).fill(amendedEnglish.name);await page.getByLabel('Definition 1',{exact:true}).fill(amendedEnglish.definition);await page.getByLabel('Synonyms 1',{exact:true}).fill(amendedEnglish.synonyms.join('\n'));
  await chooseWorkflow(page,workflow);const amended:GlossaryPublicationInput={...publication,attributes:{translations:[amendedEnglish,{...arabic}]}};
  const second=await submit(page,amended,workflow,published.term);expect(second.request.id).not.toBe(first.request.id);expect(second.request.proposalDigest).not.toBe(first.request.proposalDigest);
  expect(await readTerm(page,published.term.resourceId)).toEqual(published.term);
  const republished=await approveAndPublish(reviewer,page,second.request,2);await discover(page,republished.term,amendedToken,amendedEnglish.name);
  const original=await readRequest(page,first.request.id);expect(original.status).toBe('succeeded');expect(original.payload).toEqual(publication);expect(original.result).toEqual(published.completed.result);expect(original.decisions).toEqual(published.completed.decisions);

  const consumer=await consumerContext.newPage();await domainLogin(consumer,'consumer');const consumerMe=await domainBody<Session>(await consumer.request.get('/api/v1/me'));expect(consumerMe.permissions).toContain('catalog:read');expect(consumerMe.permissions).not.toContain('catalog:write');
  const hidden=await domainBody<AssetList>(await consumer.request.get(`/api/v1/assets?${new URLSearchParams({q:amendedToken,type:'business_term',limit:'25'})}`));expect(hidden).toEqual({items:[],total:0,facets:[],nextCursor:null});
  const denied=await consumer.request.get(`/api/v1/glossary/terms/${republished.term.resourceId}`);expect(denied.status()).toBe(404);expect(await denied.text()).not.toContain(amendedToken);
  const deniedRequest=await consumer.request.get(`/api/v1/approval-requests/${second.request.id}`);expect(deniedRequest.status()).toBe(403);expect((await deniedRequest.json()).code).toBe('FORBIDDEN');
  await consumer.goto(`/glossary?${new URLSearchParams({q:amendedToken})}`);await expect(consumer.getByRole('heading',{name:'No terms found',exact:true})).toBeVisible();await expect(consumer.getByRole('link',{name:amendedEnglish.name,exact:true})).toHaveCount(0);await expect(consumer.getByRole('link',{name:'Propose a term',exact:true})).toHaveCount(0);
  await consumer.goto('/glossary/new');await expect(consumer.getByRole('heading',{name:'You do not have access to this view',exact:true})).toBeVisible();await expect(consumer.getByRole('button',{name:'Submit for approval',exact:true})).toHaveCount(0);
  const forbidden=await consumer.request.post('/api/v1/glossary/proposals',{headers:await domainHeaders(consumer),data:{...second.body,requestId:randomUUID()}});expect(forbidden.status()).toBe(403);expect((await forbidden.json()).code).toBe('FORBIDDEN');
  expect(await readTerm(page,republished.term.resourceId)).toEqual(republished.term);
 }finally{await reviewerContext.close();await consumerContext.close();}
});
