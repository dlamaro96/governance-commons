// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql} from 'kysely';
import type {Tx} from '../../db/src/index.ts';
import {Problem, type Principal} from '../../authz/src/index.ts';
import {signedCursor} from '../../domain/src/cursor.ts';

export type SourceListQuery = {limit?:number;q?:string;cursor?:string};
const invalid = () => new Problem(400,'SOURCE_PAGE_INVALID','This source page is invalid. Start a new search.');
const uuid = (value:unknown):value is string => typeof value==='string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value!=='00000000-0000-0000-0000-000000000000';
const text = (value:unknown,minimum:number):value is string => typeof value==='string' && [...value].length>=minimum && [...value].length<=120 && !value.includes('\0') && Buffer.from(value,'utf8').toString('utf8')===value;
function keys(value:unknown,expected:readonly string[]):value is Record<string,unknown> {
 if(value===null||typeof value!=='object'||Array.isArray(value))return false;
 const actual=Reflect.ownKeys(value);
 return actual.length===expected.length&&actual.every(key=>typeof key==='string'&&expected.includes(key)&&Object.getOwnPropertyDescriptor(value,key)?.enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,key)!,'value'));
}

/** Authorization belongs to the authenticated route. Every page still constrains
 * the tenant explicitly, alongside forced RLS; a cursor grants no permission. */
export async function listSources(tx:Tx,principal:Pick<Principal,'tenantId'|'id'>,query:SourceListQuery):Promise<{items:any[];nextCursor:string|null}> {
 if(!query||typeof query!=='object'||Array.isArray(query)||!keys(query,Object.keys(query))||Object.keys(query).some(key=>!['limit','q','cursor'].includes(key)))throw invalid();
 const limit=query.limit===undefined?100:query.limit,q=query.q===undefined?'':query.q;
 if(!Number.isInteger(limit)||limit<1||limit>100||!text(q,0)||/[\x00-\x1f\x7f]/.test(q)||!uuid(principal.tenantId)||!uuid(principal.id))throw invalid();
 if(query.cursor!==undefined&&(typeof query.cursor!=='string'||query.cursor.length<1||query.cursor.length>1024))throw invalid();
 const codec=signedCursor(process.env.SESSION_KEY,'source-inventory-v1');
 // A versioned tuple and UTF-8 base64url name avoid JSON control-character
 // expansion. Even120 four-byte codepoints fit the signed1024-character cap.
 const binding=createHash('sha256').update(JSON.stringify({tenantId:principal.tenantId,actorId:principal.id,q,limit,sort:'name:asc,id:asc'})).digest('base64url');
 let last:{name:string;id:string}|null=null;
 if(query.cursor!==undefined){
  try {
   const value=codec.decode(query.cursor);
   if(!Array.isArray(value)||value.length!==4||value[0]!==1||value[1]!==binding||typeof value[2]!=='string'||!/^[A-Za-z0-9_-]+$/.test(value[2])||!uuid(value[3]))throw invalid();
   const bytes=Buffer.from(value[2],'base64url'),name=bytes.toString('utf8');
   if(bytes.toString('base64url')!==value[2]||!Buffer.from(name,'utf8').equals(bytes)||!text(name,1))throw invalid();
   last={name,id:value[3]};
  }catch{throw invalid();}
 }
 let selection=tx.selectFrom('sources').selectAll().where('sources.tenant_id','=',principal.tenantId);
 if(q)selection=selection.where(sql<boolean>`sources.name ILIKE ${'%'+q.replace(/[\\%_]/g,'\\$&')+'%'} ESCAPE ${'\\'}`);
 if(last){const after=last;selection=selection.where(eb=>eb.or([eb('sources.name','>',after.name),eb.and([eb('sources.name','=',after.name),eb('sources.id','>',after.id)])]));}
 const rows=await selection.orderBy('sources.name','asc').orderBy('sources.id','asc').limit(limit+1).execute();
 const items=rows.slice(0,limit),tail=items.at(-1);
 return {items,nextCursor:rows.length>limit&&tail?codec.encode([1,binding,Buffer.from(tail.name,'utf8').toString('base64url'),tail.id]):null};
}
