// SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {mkdirSync,readFileSync} from 'node:fs';
import type {Asset,AssetList} from '../../apps/web/src/types.ts';

const credentials=JSON.parse(readFileSync('.local/bootstrap.json','utf8'));
const compareId=(a:Asset,b:Asset)=>a.id<b.id?-1:a.id>b.id?1:0;
const comparator=(sort:string)=>(a:Asset,b:Asset)=>(sort==='updated'?Date.parse(b.updatedAt)-Date.parse(a.updatedAt):
  (sort==='name-desc'?-1:1)*Buffer.compare(Buffer.from(a.name),Buffer.from(b.name)))||compareId(a,b);

async function rendered(page:Page,sort:string,cursor:string,action:()=>Promise<unknown>):Promise<AssetList>{
  const response=page.waitForResponse(r=>{
    const u=new URL(r.url());return r.request().method()==='GET'&&u.pathname==='/api/v1/assets'
      &&u.searchParams.get('sort')===sort&&(u.searchParams.get('cursor')||'')===cursor&&u.searchParams.get('limit')==='50';
  });
  await action();const r=await response;expect(r.status()).toBe(200);const result=await r.json() as AssetList;
  await expect.poll(()=>page.locator('.catalog-results tbody .asset-link').evaluateAll(links=>links.map(a=>a.getAttribute('href'))))
    .toEqual(result.items.map(a=>'/catalog/'+a.id));
  await expect(page).toHaveURL(u=>u.pathname==='/catalog'&&(u.searchParams.get('sort')||'name')===sort&&(u.searchParams.get('cursor')||'')===cursor);
  return result;
}

test('UX-04: catalog sorting spans real source results and resets cursor after changing order',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/auth/login');await page.locator('input[name="username"]').fill('steward');
  await page.locator('input[name="password"]').fill(credentials.personas.steward);
  await page.getByRole('button',{name:'Sign In',exact:true}).click();await expect(page).toHaveURL('http://localhost:4310/');
  const me=await (await page.request.get('/api/v1/me')).json();
  const baseline=await (await page.request.get('/api/v1/assets?limit=1')).json() as AssetList;
  // Two genuine PostgreSQL scans guarantee more than one50-row page even on a
  // fresh core. They use supported APIs and retain synthetic scan/audit history.
  for(let i=0;i<2;i++){
    const headers={'X-CSRF-Token':me.csrfToken,Origin:new URL(page.url()).origin,'Idempotency-Key':crypto.randomUUID()};
    const created=await page.request.post('/api/v1/sources',{headers,data:{name:`Harbor sort qualification ${Date.now()} ${i}`,host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'}});
    expect(created.status()).toBe(201);const {source}=await created.json();
    const submitted=await page.request.post(`/api/v1/sources/${source.id}/scans`,{headers:{...headers,'Idempotency-Key':crypto.randomUUID()},data:{}});
    expect(submitted.status()).toBe(202);const {job}=await submitted.json();
    await expect.poll(async()=>{const r=await page.request.get(`/api/v1/jobs/${job.id}`);expect(r.ok()).toBeTruthy();return(await r.json()).job.status;},
      {timeout:100_000,intervals:[1000,2000,3000]}).toBe('succeeded');
  }
  await expect.poll(async()=>{const r=await page.request.get('/api/v1/assets?limit=1');expect(r.ok()).toBeTruthy();return(await r.json()).total;},
    {timeout:30_000,intervals:[1000,2000]}).toBeGreaterThan(baseline.total+50);
  let first=await rendered(page,'name','',()=>page.goto('/catalog'));
  expect(first.items).toHaveLength(50);expect(first.nextCursor).not.toBeNull();
  const pagination=page.locator('.pagination');
  const previous=()=>pagination.getByRole('button',{name:'Previous page',exact:true});
  const next=()=>pagination.getByRole('button',{name:'Next page',exact:true});
  const pageLabel=()=>pagination.locator(':scope > span');
  const firstPage=async(result:AssetList)=>{
    if(result.nextCursor){await expect(pageLabel()).toHaveText('Page 1');await expect(previous()).toBeDisabled();}
    else await expect(pagination).toHaveCount(0);
  };
  let updatedCursor='';
  for(const sort of ['name','name-desc','updated']){
    if(sort!=='name')first=await rendered(page,sort,'',()=>page.getByRole('combobox',{name:'Sort by',exact:true}).selectOption(sort));
    expect(first.items).toEqual([...first.items].sort(comparator(sort)));expect(first.nextCursor).not.toBeNull();
    await expect(pageLabel()).toHaveText('Page 1');await expect(previous()).toBeDisabled();
    const second=await rendered(page,sort,first.nextCursor!,()=>next().click());
    const combined=[...first.items,...second.items];expect(new Set(combined.map(a=>a.id)).size).toBe(combined.length);
    expect(combined).toEqual([...combined].sort(comparator(sort)));
    await expect(previous()).toBeEnabled();await expect(pageLabel()).toHaveText('Page 2');
    if(sort==='updated')updatedCursor=first.nextCursor!;
  }
  // The last sort switch started from page2, so each new order must reset both
  // the signed cursor and the UI's previous-page history.
  first=await rendered(page,'name-desc','',()=>page.getByRole('combobox',{name:'Sort by',exact:true}).selectOption('name-desc'));
  await expect(previous()).toBeDisabled();await expect(pageLabel()).toHaveText('Page 1');
  // Browser Back and Forward restore each entry's own cursor trail even after
  // a sort/filter reset. The Previous control must then request its real prior
  // page instead of guessing from a component-local array.
  await rendered(page,'updated',updatedCursor,()=>page.goBack());
  await expect(pageLabel()).toHaveText('Page 2');await expect(previous()).toBeEnabled();
  await rendered(page,'name-desc','',()=>page.goForward());
  await expect(pageLabel()).toHaveText('Page 1');await expect(previous()).toBeDisabled();
  await rendered(page,'updated',updatedCursor,()=>page.goBack());
  await rendered(page,'updated','',()=>previous().click());
  await expect(pageLabel()).toHaveText('Page 1');await expect(previous()).toBeDisabled();
  first=await rendered(page,'name-desc','',()=>page.getByRole('combobox',{name:'Sort by',exact:true}).selectOption('name-desc'));
  const descendingCursor=first.nextCursor!;
  const second=await rendered(page,'name-desc',descendingCursor,()=>next().click());
  const secondUrl=page.url();
  const filtered=await rendered(page,'name-desc','',()=>page.locator('.catalog-facets input[value="table"]').check());
  expect(filtered.items.length).toBeGreaterThan(0);expect(filtered.items.every(asset=>asset.type==='table')).toBeTruthy();
  expect(new URL(page.url()).searchParams.get('type')).toBe('table');
  await firstPage(filtered);
  await rendered(page,'name-desc',descendingCursor,()=>page.goBack());
  await expect(pageLabel()).toHaveText('Page 2');await expect(previous()).toBeEnabled();
  expect(new URL(page.url()).searchParams.has('type')).toBeFalsy();
  const filteredForward=await rendered(page,'name-desc','',()=>page.goForward());
  expect(new URL(page.url()).searchParams.get('type')).toBe('table');
  await firstPage(filteredForward);
  await rendered(page,'name-desc',descendingCursor,()=>page.goBack());
  // Reload retains this browser entry; opening an asset and browser Back
  // remounts the catalog with the same bound predecessor state.
  await rendered(page,'name-desc',descendingCursor,()=>page.reload());
  await expect(pageLabel()).toHaveText('Page 2');await expect(previous()).toBeEnabled();
  await page.locator('.catalog-results tbody .asset-link').first().click();
  await expect(page).toHaveURL(u=>u.pathname==='/catalog/'+second.items[0]!.id);
  await expect(page.locator('#main-heading')).toHaveText(second.items[0]!.name);
  await rendered(page,'name-desc',descendingCursor,()=>page.goBack());
  await expect(pageLabel()).toHaveText('Page 2');await expect(previous()).toBeEnabled();
  await rendered(page,'name-desc','',()=>previous().click());
  await expect(pageLabel()).toHaveText('Page 1');await expect(previous()).toBeDisabled();

  // A shared cursor URL contains no trustworthy page number or predecessor.
  // Show an honest unknown position and offer a single bounded first-page reset.
  const direct=await page.context().newPage();
  try {
    await rendered(direct,'name-desc',descendingCursor,()=>direct.goto(secondUrl));
    const directPagination=direct.locator('.pagination');
    const unknownPosition=async()=>{
      await expect(directPagination.locator(':scope > span')).toHaveText('Current page');
      await expect(directPagination.getByRole('button',{name:'Previous page',exact:true})).toBeDisabled();
      await expect(directPagination.getByRole('button',{name:'First page',exact:true})).toBeEnabled();
    };
    await unknownPosition();
    // Malformed/oversized/mismatched state is cosmetic, never a new API cursor
    // or an invented page-one label. A real API response still supplies the rows.
    for(const invalid of [
      {binding:JSON.stringify(['','table','name-desc']),previous:['']},
      {cursor:'different-cursor',previous:['']},
      {previous:Array.from({length:21},()=>descendingCursor)},
      {page:1,previous:['']},
    ]){
      await direct.evaluate(({cursor,invalid})=>window.history.replaceState({catalogPagination:{version:1,binding:JSON.stringify(['','','name-desc']),cursor,page:2,...invalid}},''),{cursor:descendingCursor,invalid});
      await rendered(direct,'name-desc',descendingCursor,()=>direct.reload());
      await unknownPosition();
    }
    await rendered(direct,'name-desc','',()=>directPagination.getByRole('button',{name:'First page',exact:true}).click());
    await expect(directPagination.locator(':scope > span')).toHaveText('Page 1');
    await expect(directPagination.getByRole('button',{name:'Previous page',exact:true})).toBeDisabled();
    await expect(directPagination.getByRole('button',{name:'First page',exact:true})).toHaveCount(0);
  } finally { await direct.close(); }
  await expect(page.getByText('Sorted across all matching results.',{exact:true})).toBeVisible();
  mkdirSync('.local/evidence/catalog-sorting-captures',{recursive:true});
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:960});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBeTruthy();
    await page.screenshot({path:`.local/evidence/catalog-sorting-captures/catalog-name-desc-${width}.png`,fullPage:false});
  }
  await page.locator('#language').selectOption('ar');await expect(page.locator('html')).toHaveAttribute('dir','rtl');
  await expect(page.getByText('النتائج مرتبة عبر جميع الصفحات.',{exact:true})).toBeVisible();
  await page.screenshot({path:'.local/evidence/catalog-sorting-captures/catalog-name-desc-ar-390.png',fullPage:false});
});
