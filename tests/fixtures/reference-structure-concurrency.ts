// SPDX-License-Identifier: Apache-2.0
/** Real SQL024 lock races. Setup reuses the native fixture; operations do NOT
 * use its tenant-ledger prelock or its single-connection application pool. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import type {TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {canonical,structureFixture} from './reference-structure.ts';

type Outcome<T>={ok:true;value:T}|{ok:false;error:unknown};
export async function concurrencyFixture(t:TestContext){
 const f=await structureFixture(t),path=process.env.AUTHN_FOUNDATION_CONFIG;
 assert.ok(path,'Owned gate configuration required');
 const config=JSON.parse(readFileSync(path,'utf8')) as {owner:string;legacy:string};
 const blocker=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const probe=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const db=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:2,connectionTimeoutMillis:5000})})});
 await Promise.all([blocker.connect(),probe.connect()]);
 t.after(async()=>{await Promise.all([blocker.query('ROLLBACK'),probe.query('ROLLBACK')]);await Promise.all([blocker.end(),probe.end(),db.destroy()]);});
 for(const client of [blocker,probe])await client.query("SET statement_timeout='5s';SET lock_timeout='1s'");
 const blockerPid=Number((await blocker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
 const tables=Object.keys(await f.state());
 const snapshot=async(client:pg.Client)=>{const value:Record<string,any[]>={};for(const table of tables)value[table]=(await client.query('SELECT * FROM public."'+table+'" WHERE tenant_id=$1',[f.tenant])).rows.sort((a,b)=>canonical(a).localeCompare(canonical(b)));return value;};
 const begin=async(who=f.actor)=>{await blocker.query('BEGIN');await blocker.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,who]);};
 const operation=<T>(who:string,work:(tx:Tx)=>Promise<T>)=>{
  let pidResolve!:(pid:number)=>void;const pid=new Promise<number>(resolve=>{pidResolve=resolve;});
  let settled=false;
  const outcome:Promise<Outcome<T>>=db.transaction().execute(async tx=>{
   await sql`select set_config('gc.tenant_id',${f.tenant},true),set_config('gc.actor_id',${who},true)`.execute(tx);
   pidResolve(Number((await sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx)).rows[0].pid));
   return work(tx);
  }).then(value=>{settled=true;return {ok:true as const,value};},error=>{settled=true;return {ok:false as const,error};});
  return {pid,outcome,settled:()=>settled};
 };
 const observed=async<T>(run:ReturnType<typeof operation<T>>,milliseconds=1200)=>{
  const pid=await Promise.race([run.pid,run.outcome.then(value=>{throw new Error('Operation ended before PID: '+JSON.stringify(value));})]);
  const end=Date.now()+milliseconds;
  while(Date.now()<end){
   // pg_stat_activity wait details for gc_app are hidden from the native
   // migration owner. pg_locks exposes actual ungranted lock kinds without
   // granting that owner superuser or pg_read_all_stats. Both observations
   // must identify a real wait before the blocker can be released.
   const row=(await f.owner.query('SELECT pg_blocking_pids($1) AS blockers,ARRAY(SELECT locktype FROM pg_locks WHERE pid=$1 AND NOT granted ORDER BY locktype) AS waits',[pid])).rows[0];
   if(row?.blockers.includes(blockerPid)&&Array.isArray(row.waits)&&row.waits.length>0)return {pid,blockerPid,waits:row.waits as string[]};
   if(run.settled()){const result=await run.outcome;assert.fail('Operation did not reach the held lock: '+JSON.stringify(result));}
   // Polling is bounded and conditioned on actual PostgreSQL lock state.
   await new Promise(resolve=>setTimeout(resolve,5));
  }
  assert.fail('Did not observe the application blocked by the owned PostgreSQL transaction');
 };
 const refused=async<T>(who:string,change:()=>Promise<unknown>,work:(tx:Tx)=>Promise<T>,predicate:(error:unknown)=>boolean)=>{
  await begin();let run:ReturnType<typeof operation<T>>|undefined;
  try{
   await change();const expected=await snapshot(blocker);run=operation(who,work);const lock=await observed(run);
   await blocker.query('COMMIT');const result=await run.outcome;assert.equal(result.ok,false,'A revoked/stale operation must refuse after the lock is released');
   if(result.ok)throw Error('Unexpected success');assert.ok(predicate(result.error),'Unexpected refusal: '+String(result.error));
   assert.deepEqual(await f.state(),expected,'Refusal may not change canonical data, approvals, immutable history, journals or receipts');return lock;
  }finally{await blocker.query('ROLLBACK');if(run)await run.outcome;}
 };
 const membership=(who:string,grants:string[])=>blocker.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,who,JSON.stringify(grants)]);
 const probeLock=async(table:'identities'|'memberships'|'reference_sets',id:string,expectedLocked:boolean)=>{
  await probe.query('BEGIN');try{
   await probe.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);
   const where=table==='identities'?'id=$1':table==='memberships'?'identity_id=$1 AND tenant_id=$2':'id=$1 AND tenant_id=$2';
   let error:unknown;try{await probe.query('SELECT * FROM '+table+' WHERE '+where+' FOR UPDATE NOWAIT',table==='identities'?[id]:[id,f.tenant]);}catch(e){error=e;}
   if(expectedLocked)assert.equal((error as {code?:string}|undefined)?.code,'55P03',table+' '+id+' must already be locked');else if(error)throw error;
  }finally{await probe.query('ROLLBACK');}
 };
 return {...f,blocker,probe,begin,snapshot,operation,observed,refused,membership,probeLock};
}
