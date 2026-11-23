// SPDX-License-Identifier: Apache-2.0
// Test-only observation. No SQL, deadline, parameter, result or release changes.
import {performance} from 'node:perf_hooks';
import type {PostgresPool,PostgresPoolClient} from 'kysely';
export const POPULATION_MARKER='GLOSSARY_POPULATION_PHASES_V1=';
export type PopulationPhase='fixture'|'population'|'target'|'policies'|'proposal'|'publication'|'assertions'|'replay';
type QueryPhase='connect'|'begin'|'commit'|'rollback'|'settings'|'prepare'|'stage'|'finish'|'graph-source'|'graph-prepare'|'graph-complete'|'unclassified';
const states=new Set(['08003','08006','22023','23503','23505','23514','25P02','40001','40P01','42501','42702','42703','42883','42P01','53000','53100','53200','53300','54000','55000','55P03','57014','57P01','P0001','P0002']);
const codes=new Set(['ERR_ASSERTION','RELATION_RETRY','RELATION_PROFILE_LIMIT','RELATION_INVALID','RELATION_CARDINALITY','RELATION_CYCLE','GLOSSARY_STORAGE_INVALID','GLOSSARY_UNAVAILABLE','GLOSSARY_INPUT_INVALID','GLOSSARY_CONFLICT','GLOSSARY_FORBIDDEN','GLOSSARY_LIMIT','GLOSSARY_PUBLICATION_INVALID']);
const ms=(n:number)=>Number.isFinite(n)?Math.max(0,Math.min(3600000,Math.round(n))):3600000;
function own(value:unknown,key:string):unknown{try{if(value&&typeof value==='object'){const d=Object.getOwnPropertyDescriptor(value,key);if(d&&'value'in d)return d.value;}}catch{}return undefined;}
function sqlstate(error:unknown):string|null{const value=own(error,'code');return typeof value==='string'&&states.has(value)?value:null;}
function queryPhase(text:string):QueryPhase{
 const s=text.trim().toLowerCase();
 if(s==='begin'||s.startsWith('start transaction'))return 'begin';if(s==='commit')return 'commit';if(s==='rollback')return 'rollback';
 if(s.startsWith('set ')||s.includes('set_config('))return 'settings';
 for(const [name,phase] of [['gc_glossary_prepare','prepare'],['gc_glossary_stage','stage'],['gc_glossary_finish','finish'],['gc_glossary_graph_source_evidence','graph-source'],['gc_relation_graph_prepare','graph-prepare'],['gc_relation_graph_complete','graph-complete']] as const)if(s.includes(name+'('))return phase;
 return 'unclassified';
}
interface Observation{phase:PopulationPhase;query:QueryPhase;startedMs:number;elapsedMs:number;outcome:'fulfilled'|'rejected';sqlstate:string|null}
export function observePopulationPool(pool:PostgresPool,clock:()=>number=performance.now.bind(performance)){
 const started=clock(),rows:Observation[]=[];let phase:PopulationPhase='fixture',count=0;
 const observed=async<T>(query:QueryPhase,work:()=>Promise<T>):Promise<T>=>{
  const begin=clock(),current=phase;let outcome:'fulfilled'|'rejected'='rejected',state:string|null=null;
  try{const result=await work();outcome='fulfilled';return result;}catch(error){state=sqlstate(error);throw error;}
  finally{count++;if(rows.length===64)rows.shift();rows.push({phase:current,query,startedMs:ms(begin-started),elapsedMs:ms(clock()-begin),outcome,sqlstate:state});}
 };
 // Preserve Kysely's native cancellation constructor and pooled-client identity.
 const clients=new WeakMap<PostgresPoolClient,PostgresPoolClient>();
 const wrapped:PostgresPool={Client:pool.Client,options:pool.options,end:()=>pool.end(),async connect(){
  const client=await observed('connect',()=>pool.connect());
  const previous=clients.get(client);if(previous)return previous;
  const query=((...args:unknown[])=>typeof args[0]==='string'?observed(queryPhase(args[0]),()=>Reflect.apply(client.query,client,args)):Reflect.apply(client.query,client,args)) as PostgresPoolClient['query'];
  const current={processID:client.processID,query,release:(destroy?:boolean)=>client.release(destroy)};
  clients.set(client,current);return current;
 }};
 const snapshot=(error?:unknown)=>{const code=own(error,'code');return {phase,elapsedMs:ms(clock()-started),queryCount:count,omittedQueries:Math.max(0,count-64),code:typeof code==='string'&&codes.has(code)?code:'UNCLASSIFIED',sqlstate:sqlstate(error),queries:rows.map(row=>({...row}))};};
 return {pool:wrapped,phase:(value:PopulationPhase)=>{phase=value;},snapshot,
  failure:(error:unknown)=>new Error('Population qualification failed; diagnostic\n'+POPULATION_MARKER+JSON.stringify(snapshot(error)))};
}
