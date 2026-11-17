// SPDX-License-Identifier: Apache-2.0
import {expect,type Page} from '@playwright/test';
import type {ApprovalDefinitionView} from '../../../packages/domain/src/approval-service.ts';

/** Drive the real paginated picker. A missing loading indicator alone can still
 * describe the previous page before useResource's cursor effect has run. */
export async function chooseReferenceWorkflow(page:Page,workflow:ApprovalDefinitionView,reviewerId:string){
 const group=page.getByRole('group',{name:'Review workflow',exact:true});
 const loading=group.getByText('Loading…',{exact:true});
 const next=group.getByRole('button',{name:'Next page',exact:true});
 await expect(group).toBeVisible();await expect(loading).toHaveCount(0);
 let expectedCursor:string|undefined;const visited=new Set<string>();
 for(let count=0;count<100;count++){
  const item=group.getByRole('button',{name:workflow.definition.name+' · Version '+workflow.definition.version,exact:true});
  if(await item.count()){
   const detail=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/workflow-definitions/'+workflow.definition.id&&response.request().method()==='GET');
   const [response]=await Promise.all([detail,item.click()]);expect(response.status()).toBe(200);
   const body=await response.json() as {workflow:ApprovalDefinitionView};
   expect(body.workflow.definition).toEqual(workflow.definition);expect(body.workflow.definitionHash).toBe(workflow.definitionHash);
   await expect(item).toHaveAttribute('aria-pressed','true');
   await page.getByRole('combobox',{name:'Reviewer: reviewer',exact:true}).selectOption(reviewerId);return;
  }
  if(count===99)throw new Error('Workflow fixture exceeds bounded discovery');
  await expect(next).toBeEnabled();
  const listed=page.waitForResponse(response=>{
   const url=new URL(response.url()),cursor=url.searchParams.get('cursor');
   return response.request().method()==='GET'&&url.pathname==='/api/v1/workflow-definitions'&&url.searchParams.get('limit')==='25'&&
    cursor!==null&&cursor!==''&&(expectedCursor===undefined||cursor===expectedCursor);
  });
  const [response]=await Promise.all([listed,next.click()]);expect(response.status()).toBe(200);
  const cursor=new URL(response.url()).searchParams.get('cursor')!;expect(visited.has(cursor)).toBe(false);visited.add(cursor);
  const body=await response.json() as {items:ApprovalDefinitionView[];nextCursor:string|null};
  expect(Array.isArray(body.items)).toBe(true);expect(body.items.length).toBeLessThanOrEqual(25);
  expect(body.nextCursor===null||typeof body.nextCursor==='string'&&body.nextCursor.length>0).toBe(true);
  const names=body.items.filter(value=>value.definition.separationOfDuties).map(value=>value.definition.name+' · Version '+value.definition.version);
  // Match the whole rendered page, including an empty filtered page, before
  // deciding whether to select or advance. The final-page button must settle too.
  await expect(group.locator('ul.reference-records > li > button')).toHaveText(names);
  await expect(loading).toHaveCount(0);
  if(body.nextCursor===null)await expect(next).toBeDisabled();else await expect(next).toBeEnabled();
  expectedCursor=body.nextCursor??undefined;
 }
 throw new Error('Workflow fixture exceeds bounded discovery');
}
