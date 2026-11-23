// SPDX-License-Identifier: Apache-2.0
/** Real OIDC, canonical approval commands, Temporal publication and search.
 * The original metadata journey and linked physical-context journey are separate. */
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
import type {Asset} from '../../apps/web/src/types.ts';
import type {AssetTypeDefinition} from '../../packages/domain/src/asset-type.ts';
import type {RelationTypeDefinition,RelationTypeView} from '../../packages/domain/src/relation-contracts.ts';
import type {AssetGlossaryContextPage} from '../../packages/domain/src/glossary-context-contracts.ts';

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
  expect(consumerMe.permissions).toContain('reference:read');expect(consumerMe.permissions).not.toContain('reference:write');expect(consumerMe.permissions).not.toContain('reference:approve');
  const hidden=await domainBody<AssetList>(await consumer.request.get(`/api/v1/assets?${new URLSearchParams({q:amendedToken,type:'business_term',limit:'25'})}`));expect(hidden).toEqual({items:[],total:0,facets:[],nextCursor:null});
  const denied=await consumer.request.get(`/api/v1/glossary/terms/${republished.term.resourceId}`);expect(denied.status()).toBe(404);expect(await denied.text()).not.toContain(amendedToken);
  // Reference readers can enter the generic approval reader; family and
  // participant visibility still hide every private glossary request. Known
  // hidden requests and a fresh absent UUID must expose the same safe problem.
  const unavailableProblems:Record<string,unknown>[]=[];
  for(const requestId of [second.request.id,first.request.id,randomUUID()]){
   const deniedRequest=await consumer.request.get(`/api/v1/approval-requests/${requestId}`);expect(deniedRequest.status()).toBe(404);expect(deniedRequest.headers()['content-type']).toContain('application/problem+json');
   const problem=await deniedRequest.json();expect(problem).toEqual({type:'about:blank',title:'Request rejected',status:404,code:'APPROVAL_UNAVAILABLE',detail:'The approval request or its referenced resources are unavailable.',correlationId:expect.any(String)});expect(problem.correlationId.length).toBeGreaterThan(0);
   const text=JSON.stringify(problem);for(const hiddenValue of [first.request.id,second.request.id,republished.term.resourceId,first.request.proposalDigest,second.request.proposalDigest,amendedToken,amendedEnglish.name])expect(text).not.toContain(hiddenValue);
   const {correlationId,...safeProblem}=problem;unavailableProblems.push(safeProblem);
  }
  expect(unavailableProblems[1]).toEqual(unavailableProblems[0]);expect(unavailableProblems[2]).toEqual(unavailableProblems[0]);
  await consumer.goto(`/glossary?${new URLSearchParams({q:amendedToken})}`);await expect(consumer.getByRole('heading',{name:'No terms found',exact:true})).toBeVisible();await expect(consumer.getByRole('link',{name:amendedEnglish.name,exact:true})).toHaveCount(0);await expect(consumer.getByRole('link',{name:'Propose a term',exact:true})).toHaveCount(0);
  await consumer.goto('/glossary/new');await expect(consumer.getByRole('heading',{name:'You do not have access to this view',exact:true})).toBeVisible();await expect(consumer.getByRole('button',{name:'Submit for approval',exact:true})).toHaveCount(0);
  const forbidden=await consumer.request.post('/api/v1/glossary/proposals',{headers:await domainHeaders(consumer),data:{...second.body,requestId:randomUUID()}});expect(forbidden.status()).toBe(403);expect((await forbidden.json()).code).toBe('FORBIDDEN');
  expect(await readTerm(page,republished.term.resourceId)).toEqual(republished.term);
 }finally{await reviewerContext.close();await consumerContext.close();}
});

async function contextBudget(page:Page){
 const response=await page.request.get('/api/v1/me');expect([200,429]).toContain(response.status());
 const remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
 expect(Number.isFinite(remaining)&&remaining>=0&&Number.isFinite(reset)&&reset>=0&&reset<=60).toBe(true);
 if(remaining<180)await new Promise(resolve=>setTimeout(resolve,(reset+1)*1000));
}
async function openLinkedTermEditor(page:Page,info:TestInfo,term:Term){
 // CI deliberately excludes credential-bearing traces. Preserve only bounded
 // status/shape diagnostics if this real navigation cannot render its links.
 const path=`/api/v1/glossary/terms/${term.resourceId}`;
 const responses:{route:'session'|'term';status:number;code:string|null;links:number|null}[]=[];
 const pending:Promise<void>[]=[];let requestFailures=0,pageErrors=0,collecting=true;
 const response=(value:import('@playwright/test').Response)=>{
  const pathname=new URL(value.url()).pathname;
  if(pending.length>=8||value.request().method()!=='GET'||!['/api/v1/me',path].includes(pathname))return;
  pending.push((async()=>{
   const body=await value.json().catch(()=>null);
   if(!collecting)return;responses.push({route:pathname===path?'term':'session',status:value.status(),
    code:typeof body?.code==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(body.code)?body.code:null,
    links:pathname===path&&Array.isArray(body?.publication?.links)?body.publication.links.length:null});
  })());
 };
 const requestFailed=(value:import('@playwright/test').Request)=>{if(['/api/v1/me',path].includes(new URL(value.url()).pathname))requestFailures++;};
 const pageError=()=>{pageErrors++;};
 const stop=()=>{page.off('response',response);page.off('requestfailed',requestFailed);page.off('pageerror',pageError);};
 page.on('response',response);page.on('requestfailed',requestFailed);page.on('pageerror',pageError);
 try{
  await page.goto(`/glossary/${term.resourceId}/edit`);
  await expect(page.getByRole('button',{name:'Remove link',exact:true})).toHaveCount(term.publication.links.length);
 }catch(error){
  stop();let timer:ReturnType<typeof setTimeout>|undefined;
  try{await Promise.race([Promise.allSettled(pending),new Promise<void>(resolve=>{timer=setTimeout(resolve,2000);})]);}
  finally{if(timer!==undefined)clearTimeout(timer);collecting=false;}
  const diagnostic={kind:'glossary-edit-navigation',responses,requestFailures,pageErrors,
   language:await page.locator('html').getAttribute('lang').catch(()=>null),
   forms:await page.locator('.glossary-form').count(),alerts:await page.getByRole('alert').count(),
   definitions:await page.getByLabel('Definition 1',{exact:true}).count()};
  const body=JSON.stringify(diagnostic);
  await info.attach('glossary-edit-navigation',{body,contentType:'application/json'});
  console.error(body);throw error;
 }finally{stop();collecting=false;}
}
// Each linked journey owns an exact nominal subtype. Repeated runs must not
// enroll every historical business_term relationship in one growing cohort.
async function linkedTermType(page:Page,token:string):Promise<PublishedAssetType>{
 const parent=await starter(page);
 const definition:AssetTypeDefinition={formatVersion:1,id:`gls_term_${token}`,version:1,
  parents:[{id:parent.id,version:parent.version}],attributes:{},overrideAttributes:[],requiredOwner:true,lifecycle:null};
 const type=(await domainBody<{type:PublishedAssetType}>(await page.request.post('/api/v1/asset-types',{headers:await domainHeaders(page),data:{definition}}),201)).type;
 expect(type.resolved.dependencies).toContainEqual({id:parent.id,version:parent.version});
 expect(type.resolved.model.attributes).toEqual(parent.resolved.model.attributes);
 expect(type.resolved.requiredOwner).toBe(true);expect(type.resolved.lifecycle).toEqual(parent.resolved.lifecycle);
 return type;
}
async function chooseLinkedTermType(page:Page,type:PublishedAssetType){
 const picker=page.getByRole('region',{name:'Term type',exact:true});
 await picker.getByLabel('Search: Term type',{exact:true}).fill(type.id);
 const searched=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/asset-types'&&url.searchParams.get('q')===type.id&&response.request().method()==='GET';});
 await picker.getByRole('button',{name:'Search',exact:true}).click();expect((await searched).status()).toBe(200);
 await expect(picker.getByRole('combobox',{name:'Term type',exact:true}).locator(`option[value="${type.id}"]`)).toHaveCount(1);
 const loaded=responseFor(page,`/api/v1/asset-types/${type.id}`,'GET');
 await picker.getByRole('combobox',{name:'Term type',exact:true}).selectOption(type.id);expect((await loaded).status()).toBe(200);
 await expect(picker.getByRole('combobox',{name:'Term type',exact:true})).toHaveValue(type.id);
 await expect(page.locator('.glossary-pins').filter({hasText:type.typeId})).toBeVisible();
}
async function physicalGlossaryTarget(page:Page,token:string){
 const definition:AssetTypeDefinition={formatVersion:1,id:`gls_target_${token}`,version:1,parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
  lifecycle:{initial:'active',states:['active','retired'],transitions:[{from:'active',to:'retired'}]}};
 const type=(await domainBody<{type:PublishedAssetType}>(await page.request.post('/api/v1/asset-types',{headers:await domainHeaders(page),data:{definition}}),201)).type;
 const source=(await domainBody<{source:{id:string}}>(await page.request.post('/api/v1/sources',{headers:await domainHeaders(page),
  data:{name:`Synthetic glossary context ${token}`,host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'}}),201)).source;
 const job=(await domainBody<{job:{id:string}}>(await page.request.post(`/api/v1/sources/${source.id}/scans`,{headers:await domainHeaders(page),data:{}}),202)).job;
 await expect.poll(async()=>(await domainBody<{job:{status:string}}>(await page.request.get(`/api/v1/jobs/${job.id}`))).job.status,{timeout:100_000,intervals:[1000,2000,4000]}).toBe('succeeded');
 let targetId:string|null=null;
 await expect.poll(async()=>{
  let cursor:string|null=null;
  for(let i=0;i<30;i++){
   const result:AssetList=await domainBody<AssetList>(await page.request.get(`/api/v1/assets?${new URLSearchParams({q:'orders',type:'table',limit:'100',...cursor?{cursor}:{}})}`));
   targetId=result.items.find(item=>item.sourceId===source.id&&item.name==='orders')?.id??null;
   cursor=result.nextCursor;if(targetId||!cursor)break;
  }return targetId!==null;
 },{timeout:35_000,intervals:[1000,2000]}).toBe(true);
 const id=targetId!,before=(await domainBody<{asset:Asset}>(await page.request.get(`/api/v1/assets/${id}`))).asset;
 await domainBody(await page.request.put(`/api/v1/assets/${id}/attributes`,{headers:{...await domainHeaders(page),'If-Match':String(before.version)},data:{modelId:type.id,modelVersion:type.version,attributes:{}}}));
 const typed=(await domainBody<{asset:Asset}>(await page.request.get(`/api/v1/assets/${id}`))).asset;
 const asset=(await domainBody<{asset:Asset}>(await page.request.patch(`/api/v1/assets/${id}`,{headers:{...await domainHeaders(page),'If-Match':String(typed.version)},data:{description:`Synthetic glossary physical target ${token}`}}))).asset;
 await expect.poll(async()=>(await domainBody<AssetList>(await page.request.get(`/api/v1/assets?${new URLSearchParams({q:token,limit:'25'})}`))).items.map(item=>item.id),{timeout:35_000,intervals:[1000,2000]}).toContain(id);
 expect(asset.sourceId).toBe(source.id);expect(asset.type).toBe('table');expect(asset.status).toBe('active');
 return {asset,type,token};
}
async function definesPolicy(page:Page,token:string,termType:PublishedAssetType,targetType:PublishedAssetType,required:boolean){
 const definition:RelationTypeDefinition={formatVersion:1,id:`gls_defines_${token}${required?'_attr':''}`,version:1,label:`Synthetic defines ${token}${required?' required':''}`,inverseLabel:'Defined by',direction:'directed',
  sourceTypes:[{typeId:termType.typeId,includeDescendants:false}],targetTypes:[{typeId:targetType.typeId,includeDescendants:false}],
  sourceStates:null,targetStates:null,cardinality:{outgoing:{min:0,max:null},incoming:{min:0,max:null}},allowSelf:false,cycles:'allow',
  attributes:required?{explanation:{type:'text',required:true,maxLength:200}}:{},requiredOwner:false,
  lifecycle:{initial:'active',states:['active','retired'],transitions:[{from:'active',to:'retired'}]}};
 return (await domainBody<{type:RelationTypeView}>(await page.request.post('/api/v1/relation-types',{headers:await domainHeaders(page),data:{definition}}),201)).type;
}
async function pickContextLink(page:Page,target:Awaited<ReturnType<typeof physicalGlossaryTarget>>,bad:RelationTypeView,good:RelationTypeView){
 const linkForm=page.getByRole('group',{name:'Add link',exact:true});
 const targetPicker=page.getByRole('region',{name:'Target resource',exact:true});
 await targetPicker.getByLabel('Search: Target resource',{exact:true}).fill(target.token);
 const result=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/assets'&&url.searchParams.get('q')===target.token&&response.request().method()==='GET';});
 await targetPicker.getByRole('button',{name:'Search',exact:true}).click();expect((await result).status()).toBe(200);
 await targetPicker.getByRole('combobox',{name:'Target resource',exact:true}).selectOption(target.asset.id);
 await expect(linkForm.locator('p').and(linkForm.getByText(`${target.asset.name} · Target version ${target.asset.version}`,{exact:true}))).toBeVisible();
 const relationPicker=page.getByRole('region',{name:'Relation definition',exact:true});
 async function select(policy:RelationTypeView){
  await relationPicker.getByLabel('Search: Relation definition',{exact:true}).fill(policy.id);
  const searched=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/v1/relation-types'&&url.searchParams.get('q')===policy.id&&response.request().method()==='GET';});
  await relationPicker.getByRole('button',{name:'Search',exact:true}).click();expect((await searched).status()).toBe(200);
  const loaded=responseFor(page,`/api/v1/relation-types/${policy.id}`,'GET');
  await relationPicker.getByRole('combobox',{name:'Relation definition',exact:true}).selectOption(policy.id);expect((await loaded).status()).toBe(200);
  await expect(linkForm.locator('p').and(linkForm.getByText(`${policy.label} · Version ${policy.version}`,{exact:true}))).toBeVisible();
 }
 await select(bad);await expect(page.getByRole('button',{name:'Add link',exact:true})).toBeDisabled();
 await expect(page.getByText('This relation requires attributes that the glossary link form cannot supply. Choose a relation with no required attributes.',{exact:true})).toBeVisible();
 await select(good);await expect(page.getByRole('button',{name:'Add link',exact:true})).toBeEnabled();
 await page.getByRole('button',{name:'Add link',exact:true}).click();await expect(page.getByRole('button',{name:'Remove link',exact:true})).toHaveCount(1);
}
async function readContext(page:Page,id:string,locale:'en'|'ar'='en'){
 return domainBody<AssetGlossaryContextPage>(await page.request.get(`/api/v1/assets/${id}/glossary-context?${new URLSearchParams({locale,limit:'10'})}`));
}
async function contextCapture(page:Page,info:TestInfo,locale:'en'|'ar',width:number){
 await page.setViewportSize({width,height:960});await language(page,locale);
 const panel=page.getByRole('region',{name:locale==='ar'?'المعنى التجاري':'Business meaning',exact:true});
 await expect(panel.locator('li')).toHaveCount(1);await panel.scrollIntoViewIfNeeded();
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 await page.screenshot({path:info.outputPath(`glossary-linked-context-${locale}-${width}.png`),fullPage:false});
}

// Separate from the original metadata-only journey: actual scanned and typed
// physical target, canonical defines edge, real approvals and worker publication.
test('GLS: approved definitions reach the linked asset and respect amendments, removal and visibility',async({page,browser},info)=>{
 test.setTimeout(720_000);await page.setViewportSize({width:1440,height:960});await domainLogin(page);await contextBudget(page);
 const token=randomUUID().replaceAll('-',''),termType=await linkedTermType(page,token),target=await physicalGlossaryTarget(page,token);
 const bad=await definesPolicy(page,token,termType,target.type,true),relation=await definesPolicy(page,token,termType,target.type,false);
 const contextViewer=await page.context().newPage();
 const definition:ApprovalDefinition={formatVersion:1,id:`gls_context_${token}`,version:1,name:`Synthetic linked term review ${token}`,separationOfDuties:true,
  stages:[{id:'review',name:'Linked meaning review',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]};
 const workflow=(await domainBody<{workflow:ApprovalDefinitionView}>(await page.request.post('/api/v1/workflow-definitions',{headers:await domainHeaders(page),data:{definition}}),201)).workflow;
 const reviewerContext=await browser.newContext({viewport:{width:1440,height:960}}),consumerContext=await browser.newContext({viewport:{width:390,height:960}});
 try{
  const reviewer=await reviewerContext.newPage();await domainLogin(reviewer,'owner');
  const consumer=await consumerContext.newPage();await domainLogin(consumer,'consumer');
  expect((await domainBody<{asset:Asset}>(await consumer.request.get(`/api/v1/assets/${target.asset.id}`))).asset.id).toBe(target.asset.id);
  expect(await readContext(page,target.asset.id)).toEqual({assetId:target.asset.id,items:[],nextCursor:null});
  await contextBudget(page);await page.goto('/glossary/new');await expect(page.getByRole('combobox',{name:'Term type',exact:true})).toHaveValue('business_term');
  await chooseLinkedTermType(page,termType);
  await page.getByLabel('Owner',{exact:true}).selectOption(reviewerId);await page.getByLabel('Visibility',{exact:true}).selectOption('restricted');
  const audience=page.getByRole('group',{name:'Allowed members',exact:true});await audience.getByRole('checkbox',{name:'Harbor Steward',exact:true}).check();await audience.getByRole('checkbox',{name:'Harbor Owner',exact:true}).check();
  const english:GlossaryTranslation={locale:'en',name:`Accepted order ${token}`,definition:'An order approved for synthetic fulfilment.',synonyms:[],abbreviations:[],examples:[]};
  const arabic:GlossaryTranslation={locale:'ar',name:'طلب معتمد للتنفيذ',definition:'طلب اصطناعي اجتاز مراجعة التنفيذ.',synonyms:[],abbreviations:[],examples:[]};
  await page.getByLabel('Term name 1',{exact:true}).fill(english.name);await page.getByLabel('Definition 1',{exact:true}).fill(english.definition);
  await page.getByRole('button',{name:'Add translation',exact:true}).click();await page.getByLabel('Language tag 2',{exact:true}).fill('ar');await page.getByLabel('Term name 2',{exact:true}).fill(arabic.name);await page.getByLabel('Definition 2',{exact:true}).fill(arabic.definition);
  await pickContextLink(page,target,bad,relation);await chooseWorkflow(page,workflow);
  const publication:GlossaryPublicationInput={typePin:{typeId:termType.typeId,modelId:termType.id,version:termType.version,definitionHash:termType.definitionHash,resolutionHash:termType.resolutionHash},
   primaryLocale:'en',ownerId:reviewerId,visibility:'restricted',allowedIdentityIds:[stewardIdentity,reviewerId].sort(),state:'active',attributes:{translations:[{...english},{...arabic}]},
   links:[{kind:'defines',typePin:{relationTypeId:relation.relationTypeId,version:relation.version,definitionHash:relation.definitionHash},targetAssetId:target.asset.id,targetAssetVersion:target.asset.version}]};
  const first=await submit(page,publication,workflow,null);
  expect(await readContext(page,target.asset.id)).toEqual({assetId:target.asset.id,items:[],nextCursor:null});
  const published=await approveAndPublish(reviewer,page,first.request,1);
  expect((published.completed.result as Receipt).graphReceiptId).toMatch(/^[a-f0-9-]{36}$/);
  const context=await readContext(page,target.asset.id);
  expect(context.assetId).toBe(target.asset.id);expect(context.nextCursor).toBeNull();expect(context.items).toHaveLength(1);
  const link=context.items[0];expect(link.relationId).toMatch(/^[a-f0-9-]{36}$/);
  expect(link).toEqual({termId:published.term.resourceId,termVersion:1,relationId:link.relationId,locale:'en',name:english.name,definition:english.definition,state:'active'});
  expect(await readContext(page,target.asset.id,'ar')).toEqual({assetId:target.asset.id,items:[{...link,locale:'ar',name:arabic.name,definition:arabic.definition}],nextCursor:null});
  // A reader of the physical target receives no summary or count for the
  // independently restricted term. No full publication is needed by this view.
  expect(await readContext(consumer,target.asset.id)).toEqual({assetId:target.asset.id,items:[],nextCursor:null});
  const denied=await consumer.request.get(`/api/v1/glossary/terms/${published.term.resourceId}`);expect(denied.status()).toBe(404);expect(await denied.text()).not.toContain(token);
  await consumer.goto(`/catalog/${target.asset.id}`);const hiddenPanel=consumer.getByRole('region',{name:'Business meaning',exact:true});
  await expect(hiddenPanel.getByRole('heading',{name:'No glossary definitions available',exact:true})).toBeVisible();await expect(hiddenPanel.getByRole('link')).toHaveCount(0);await expect(hiddenPanel).not.toContainText(english.name);
  await page.goto(`/catalog/${target.asset.id}`);let panel=page.getByRole('region',{name:'Business meaning',exact:true});
  await expect(panel.getByRole('link',{name:english.name,exact:true})).toHaveAttribute('href',`/catalog/${published.term.resourceId}`);await expect(panel.getByText(english.definition,{exact:true})).toBeVisible();
  await expect(panel.getByRole('button',{name:'First page',exact:true})).toBeDisabled();await expect(panel.getByRole('button',{name:'Next page',exact:true})).toBeDisabled();
  await contextCapture(page,info,'en',1440);await contextCapture(page,info,'ar',390);
  panel=page.getByRole('region',{name:'المعنى التجاري',exact:true});await expect(panel.getByRole('link',{name:arabic.name,exact:true})).toBeVisible();await expect(panel.getByText(arabic.definition,{exact:true})).toBeVisible();await expect(panel).not.toContainText(english.definition);
  await language(page,'en');await page.setViewportSize({width:1440,height:960});
  await page.goto(`/glossary/${published.term.resourceId}`);await expect(page.locator('.glossary-publication-summary').getByText('Harbor Owner',{exact:true})).toBeVisible();
  const technical=page.locator('details').filter({has:page.locator('summary').filter({hasText:'Technical details'})});await expect(technical).not.toHaveAttribute('open');
  await expect(page.getByText(english.definition,{exact:true})).toBeVisible();await expect(technical.getByText(termType.typeId,{exact:false})).toBeHidden();

  await contextViewer.goto(`/catalog/${target.asset.id}`);let livePanel=contextViewer.getByRole('region',{name:'Business meaning',exact:true});
  await expect(livePanel.getByText(english.definition,{exact:true})).toBeVisible();
  await contextBudget(page);await openLinkedTermEditor(page,info,published.term);
  const amendedEnglish={...english,definition:'An order approved after the current synthetic quality checks.'},amendedArabic={...arabic,definition:'طلب اجتاز فحوص الجودة الاصطناعية الحالية.'};
  await expect(page.getByRole('button',{name:'Remove link',exact:true})).toHaveCount(1);await page.getByLabel('Definition 1',{exact:true}).fill(amendedEnglish.definition);await page.getByLabel('Definition 2',{exact:true}).fill(amendedArabic.definition);await chooseWorkflow(page,workflow);
  const amended={...publication,attributes:{translations:[amendedEnglish,amendedArabic]}},second=await submit(page,amended,workflow,published.term);
  expect(await readContext(page,target.asset.id)).toEqual(context);
  const republished=await approveAndPublish(reviewer,page,second.request,2);
  await expect(livePanel.getByText(english.definition,{exact:true})).toBeVisible();
  await livePanel.getByRole('button',{name:'Refresh definitions',exact:true}).click();
  await expect(livePanel.getByText(amendedEnglish.definition,{exact:true})).toBeVisible();await expect(livePanel).not.toContainText(english.definition);
  const amendedContext=await readContext(page,target.asset.id),amendedRelationId=amendedContext.items[0]?.relationId;
  expect(amendedRelationId).toMatch(/^[a-f0-9-]{36}$/);expect(amendedRelationId).not.toBe(link.relationId);
  expect(amendedContext).toEqual({assetId:target.asset.id,items:[{...link,relationId:amendedRelationId,termVersion:2,definition:amendedEnglish.definition}],nextCursor:null});
  await language(contextViewer,'ar');await expect(contextViewer.getByRole('region',{name:'المعنى التجاري',exact:true}).getByText(amendedArabic.definition,{exact:true})).toBeVisible();await language(contextViewer,'en');
  livePanel=contextViewer.getByRole('region',{name:'Business meaning',exact:true});await expect(livePanel.getByText(amendedEnglish.definition,{exact:true})).toBeVisible();
  await contextBudget(page);await openLinkedTermEditor(page,info,republished.term);
  await page.getByRole('button',{name:'Remove link',exact:true}).click();await expect(page.getByText('No links proposed.',{exact:true})).toBeVisible();await chooseWorkflow(page,workflow);
  const third=await submit(page,{...amended,links:[]},workflow,republished.term);
  expect(await readContext(page,target.asset.id)).toEqual(amendedContext);
  await approveAndPublish(reviewer,page,third.request,3);
  expect(await readContext(page,target.asset.id)).toEqual({assetId:target.asset.id,items:[],nextCursor:null});expect(await readContext(consumer,target.asset.id)).toEqual({assetId:target.asset.id,items:[],nextCursor:null});
  await expect(livePanel.getByText(amendedEnglish.definition,{exact:true})).toBeVisible();await livePanel.getByRole('button',{name:'Refresh definitions',exact:true}).click();
  await expect(livePanel.getByRole('heading',{name:'No glossary definitions available',exact:true})).toBeVisible();await expect(livePanel.getByRole('link')).toHaveCount(0);
  expect((await domainBody<{asset:Asset}>(await page.request.get(`/api/v1/assets/${target.asset.id}`))).asset).toEqual(target.asset);
  const retained=await readRequest(page,first.request.id);expect(retained.result).toEqual(published.completed.result);expect(retained.payload).toEqual(publication);
 }finally{await contextViewer.close();await reviewerContext.close();await consumerContext.close();}
});
