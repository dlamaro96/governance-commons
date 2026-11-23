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
  for(const sort of ['name','name-desc','updated']){
    if(sort!=='name')first=await rendered(page,sort,'',()=>page.getByRole('combobox',{name:'Sort by',exact:true}).selectOption(sort));
    expect(first.items).toEqual([...first.items].sort(comparator(sort)));expect(first.nextCursor).not.toBeNull();
    const second=await rendered(page,sort,first.nextCursor!,()=>page.locator('.pagination').getByRole('button').last().click());
    const combined=[...first.items,...second.items];expect(new Set(combined.map(a=>a.id)).size).toBe(combined.length);
    expect(combined).toEqual([...combined].sort(comparator(sort)));
    await expect(page.locator('.pagination').getByRole('button').first()).toBeEnabled();
  }
  // The last sort switch started from page2, so each new order must reset both
  // the signed cursor and the UI's previous-page history.
  first=await rendered(page,'name-desc','',()=>page.getByRole('combobox',{name:'Sort by',exact:true}).selectOption('name-desc'));
  await expect(page.locator('.pagination').getByRole('button').first()).toBeDisabled();
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
