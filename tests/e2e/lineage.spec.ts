// SPDX-License-Identifier: Apache-2.0
/** Real source scan, catalog-derived lineage, browser exploration and current
 * tenant read boundaries. No route mocks, raw SQL or test-created lineage. */
import {test,expect,type Browser,type Page,type TestInfo,type Response} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {randomUUID} from 'node:crypto';
import {domainBody,domainLogin,scanDomainBrowserAsset} from '../fixtures/business-domains-browser.ts';
import type {LineageView} from '../../packages/domain/src/lineage-contracts.ts';

test.beforeAll(async({browser}:{browser:Browser})=>{
 test.setTimeout(75_000);const context=await browser.newContext();
 try{const response=await context.request.get('/api/v1/me'),remaining=Number(response.headers()['x-ratelimit-remaining']),reset=Number(response.headers()['x-ratelimit-reset']);
  if(Number.isFinite(remaining)&&remaining<120&&Number.isFinite(reset)&&reset>=0&&reset<=60)await new Promise(resolve=>setTimeout(resolve,Math.min(60,reset+1)*1000));
 }finally{await context.close();}
});
async function language(page:Page,value:'en'|'ar'){
 await page.locator('#language').selectOption(value);await expect(page.locator('html')).toHaveAttribute('lang',value);await expect(page.locator('html')).toHaveAttribute('dir',value==='ar'?'rtl':'ltr');
}
async function capture(page:Page,info:TestInfo,name:string,width:number){
 await page.setViewportSize({width,height:960});
 await expect.poll(()=>page.evaluate(()=>document.getAnimations().filter(animation=>animation.playState==='running'&&animation.playbackRate!==0&&Number.isFinite(animation.effect?.getComputedTiming().endTime)).length)).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
 // Four captures belong only to this Playwright attempt's output directory.
 await page.screenshot({path:info.outputPath(`lineage-${name}-${width}.png`),fullPage:false});
}
async function lineage(page:Page,id:string,direction='upstream'){
 return domainBody<LineageView>(await page.request.get(`/api/v1/assets/${id}/lineage?direction=${direction}&depth=1&limit=25`));
}
async function observedBody(response:Response):Promise<LineageView>{expect(response.status(),await response.text()).toBe(200);return response.json();}
function changed(page:Page,id:string,predicate:(params:URLSearchParams)=>boolean){
 return page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname===`/api/v1/assets/${id}/lineage`&&predicate(url.searchParams)&&response.request().method()==='GET';});
}

test('LIN-001/004/006: real PostgreSQL view dependencies, evidence, paged exploration and tenant isolation',async({page,browser},info)=>{
 test.setTimeout(300_000);await page.setViewportSize({width:1440,height:960});await domainLogin(page);
 const orders=await scanDomainBrowserAsset(page,'Lineage browser '+randomUUID());
 // Discover the dependent view from the real stored lineage, not an unrelated
 // indexed object or a hardcoded ID. The source fixture is independently fixed.
 const downstream=await lineage(page,orders.id,'downstream');expect(downstream.coverage).toBe('COLLECTED');expect(downstream.edges).toHaveLength(1);
 const view=downstream.nodes.find(node=>node.id===downstream.edges[0].downstreamAssetId)!;
 expect(view.name).toBe('customer_order_summary');expect(view.type).toBe('view');expect(downstream.edges[0].upstreamAssetId).toBe(orders.id);
 const observed=await lineage(page,view.id);expect(observed.coverage).toBe('COLLECTED');expect(observed.nextCursor).toBeNull();expect(observed.edges).toHaveLength(2);expect(observed.nodes).toHaveLength(3);
 expect(observed.nodes.map(node=>node.name).sort()).toEqual(['customer_order_summary','customers','orders']);
 expect(observed.limitations).toEqual(['COLUMN_MAPPINGS_NOT_COLLECTED','SQL_BODIES_NOT_ANALYZED']);
 for(const edge of observed.edges){
  const upstream=observed.nodes.find(node=>node.id===edge.upstreamAssetId)!;
  expect(edge.downstreamAssetId).toBe(view.id);expect(edge.downstreamVersion).toBe(view.version);expect(edge.upstreamVersion).toBe(upstream.version);
  expect(edge.evidenceType).toBe('postgresql-catalog-view-dependency');expect(edge.scope).toBe('table');expect(edge.confidence).toBeNull();expect(edge.sourceCodeReference).toBeNull();expect(edge.sourceCodeAvailability).toBe('not-collected');
  expect(edge.referencedAttributeNumbers).toEqual(upstream.name==='customers'?[1,2,3]:[1,2,5]);
  expect(edge.id).toMatch(/^[a-f0-9]{64}$/);expect(edge.evidenceHash).toMatch(/^[a-f0-9]{64}$/);
  expect(edge.observation.id).toBe(orders.metadata.scanId);expect(edge.observation.sourceId).toBe(orders.sourceId);expect(edge.observation.generation).toMatch(/^[1-9][0-9]*$/);
  expect(edge.observation.adapterVersion).toBe('1');expect(edge.observation.queryTemplate).toBe('postgresql-view-dependencies-v1');expect(edge.observation.sourceVersion.length).toBeGreaterThan(0);
  expect(edge.evidencePointer).toBe(`lineage:${edge.observation.id}:${edge.id}`);
  for(const stamp of [edge.observation.observedAt,edge.observation.recordedAt])expect(new Date(stamp).toISOString()).toBe(stamp);
 }
 await page.goto(`/catalog/${view.id}?tab=lineage`);await expect(page.getByRole('heading',{level:1,name:view.name,exact:true})).toBeVisible();
 const panel=page.getByRole('region',{name:'Lineage',exact:true});
 const upstreamResponse=changed(page,view.id,q=>q.get('direction')==='upstream'&&q.get('limit')==='25');
 await panel.getByRole('combobox',{name:'Direction',exact:true}).selectOption('upstream');expect(await observedBody(await upstreamResponse)).toEqual(observed);
 await expect(panel.getByRole('region',{name:'Dependency graph',exact:true})).toBeVisible();await expect(panel.locator('.react-flow__node')).toHaveCount(3);await expect(panel.locator('.react-flow__edge')).toHaveCount(2);
 await expect(panel.getByText('Column mappings have not been collected.',{exact:true})).toBeVisible();await expect(panel.getByText('SQL bodies have not been analyzed.',{exact:true})).toBeVisible();
 await panel.scrollIntoViewIfNeeded();await capture(page,info,'graph-en',1440);
 await panel.getByRole('button',{name:'Dependency table',exact:true}).click();await expect(panel.getByRole('table',{name:'Dependency table',exact:true}).locator('tbody tr')).toHaveCount(2);
 const inspect=panel.getByRole('button',{name:'Inspect evidence: customers → customer_order_summary',exact:true});
 await inspect.focus();await page.keyboard.press('Enter');const drawer=page.getByRole('dialog',{name:'Dependency evidence',exact:true});
 await expect(drawer).toBeVisible();await expect(drawer.getByText('PostgreSQL catalog rewrite-rule dependency',{exact:true})).toBeVisible();await expect(drawer.getByText('No confidence score is asserted.',{exact:true})).toBeVisible();
 await drawer.getByText('Technical evidence',{exact:true}).click();const customerEdge=observed.edges.find(edge=>observed.nodes.find(n=>n.id===edge.upstreamAssetId)?.name==='customers')!;
 await expect(drawer.getByText(customerEdge.evidencePointer,{exact:true})).toBeVisible();await expect(drawer.getByText(customerEdge.evidenceHash,{exact:true})).toBeVisible();
 await capture(page,info,'evidence-en',1440);await page.keyboard.press('Escape');await expect(drawer).toBeHidden();await expect(inspect).toBeFocused();
 // Exercise actual signed cursor pagination and filter reset; neither page
 // may silently append stale edges to the newly authorized response.
 const firstResponse=changed(page,view.id,q=>q.get('limit')==='1'&&!q.has('cursor'));await panel.getByRole('combobox',{name:'Dependencies per page',exact:true}).selectOption('1');
 const first=await observedBody(await firstResponse);expect(first.edges).toHaveLength(1);expect(first.nextCursor).not.toBeNull();
 await expect(panel.locator('tbody tr')).toHaveCount(1);
 const secondResponse=changed(page,view.id,q=>q.get('cursor')===first.nextCursor);await panel.getByRole('button',{name:'Next page',exact:true}).click();
 const second=await observedBody(await secondResponse);expect(second.edges).toHaveLength(1);expect(second.edges[0].id).not.toBe(first.edges[0].id);expect(second.nextCursor).toBeNull();
 expect([first.edges[0].id,second.edges[0].id].sort()).toEqual(observed.edges.map(edge=>edge.id).sort());await expect(panel.locator('tbody tr')).toHaveCount(1);await expect(panel.getByRole('button',{name:'Next page',exact:true})).toBeDisabled();
 const resetResponse=changed(page,view.id,q=>q.get('direction')==='downstream'&&!q.has('cursor'));await panel.getByRole('combobox',{name:'Direction',exact:true}).selectOption('downstream');
 expect((await observedBody(await resetResponse)).edges).toEqual([]);await expect(panel.getByRole('heading',{name:'No dependencies on this page',exact:true})).toBeVisible();await expect(panel.getByRole('button',{name:'First page',exact:true})).toBeDisabled();
 const consumer=await browser.newContext({viewport:{width:390,height:960}}),foreign=await browser.newContext({viewport:{width:390,height:960}});
 try{
  const reader=await consumer.newPage();await domainLogin(reader,'consumer');const me=await domainBody<{permissions:string[]}>(await reader.request.get('/api/v1/me'));expect(me.permissions).toContain('catalog:read');expect(me.permissions).not.toContain('catalog:write');
  expect(await lineage(reader,view.id)).toEqual(observed);await reader.goto(`/catalog/${view.id}?tab=lineage`);await language(reader,'ar');
  const translated=reader.getByRole('region',{name:'تتبّع البيانات',exact:true});await translated.getByRole('combobox',{name:'الاتجاه',exact:true}).selectOption('upstream');await translated.getByRole('button',{name:'جدول التبعيات',exact:true}).click();
  await expect(translated.getByRole('table',{name:'جدول التبعيات',exact:true}).locator('tbody tr')).toHaveCount(2);await expect(translated.getByText('لم تُجمع تعيينات الأعمدة.',{exact:true})).toBeVisible();
  await translated.scrollIntoViewIfNeeded();await capture(reader,info,'table-ar',390);
  const outsider=await foreign.newPage();await domainLogin(outsider,'summit');const denied=await outsider.request.get(`/api/v1/assets/${view.id}/lineage?direction=upstream&depth=1&limit=25`);
  expect(denied.status()).toBe(404);expect((await denied.json()).code).toBe('LINEAGE_ASSET_NOT_FOUND');
  await outsider.goto(`/catalog/${view.id}?tab=lineage`);await language(outsider,'ar');await expect(outsider.getByRole('heading',{name:'هذا العنصر غير متاح',exact:true})).toBeVisible();
  await expect(outsider.getByText(view.name,{exact:true})).toHaveCount(0);await expect(outsider.locator('.lineage-canvas')).toHaveCount(0);await capture(outsider,info,'denial-ar',390);
 }finally{await consumer.close();await foreign.close();}
});
