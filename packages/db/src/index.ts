// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import { Kysely, PostgresDialect, sql } from 'kysely';
export const pool = new pg.Pool({connectionString:process.env.DATABASE_URL,max:12,connectionTimeoutMillis:5000,idleTimeoutMillis:30000});
export const db = new Kysely<Record<string, any>>({dialect:new PostgresDialect({pool})});
export type Tx = import('kysely').Transaction<Record<string, any>>;
export async function scope<T>(tenantId:string, actorId:string, fn:(tx:Tx)=>Promise<T>):Promise<T> {
 return db.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id', ${tenantId}, true), set_config('gc.actor_id',${actorId},true)`.execute(tx);
  return fn(tx);
 });
}
export {sql};
