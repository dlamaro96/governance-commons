// SPDX-License-Identifier: Apache-2.0
import {expect,type APIRequestContext} from '@playwright/test';

/** Admit setup before starting OIDC. Never replay a callback, mutation or failed
 * product request; wait only for the real limiter's advertised reset. */
export async function waitForBrowserRateBudget(request:APIRequestContext,minimum=40){
 if(!Number.isSafeInteger(minimum)||minimum<1||minimum>295)throw new Error('Invalid browser rate admission budget');
 const deadline=performance.now()+130_000;
 for(let attempt=0;attempt<4;attempt++){
  const remainingTime=deadline-performance.now();
  if(remainingTime<=0)throw new Error('Browser rate admission timed out');
  const response=await request.get('/health/live',{timeout:Math.min(5000,remainingTime)});
  let reset:number;
  try{
   expect([200,429]).toContain(response.status());
   const headers=response.headers();
   for(const key of ['x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset'])expect(headers[key]).toMatch(/^\d+$/);
   expect(Number(headers['x-ratelimit-limit'])).toBe(300);
   const remaining=Number(headers['x-ratelimit-remaining']);reset=Number(headers['x-ratelimit-reset']);
   expect(remaining).toBeGreaterThanOrEqual(0);expect(remaining).toBeLessThanOrEqual(300);
   expect(reset).toBeGreaterThanOrEqual(0);expect(reset).toBeLessThanOrEqual(60);
   if(response.status()===200&&remaining>=minimum)return;
   expect(remaining).toBeLessThan(minimum);
  }finally{await response.dispose();}
  let delay=(reset+1)*1000;
  if(performance.now()+delay>=deadline)throw new Error('Browser rate admission timed out');
  while(delay>0){const step=Math.min(delay,30_000);await new Promise(resolve=>setTimeout(resolve,step));delay-=step;}
 }
 throw new Error('Browser rate admission unavailable');
}
