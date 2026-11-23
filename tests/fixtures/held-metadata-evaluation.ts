// SPDX-License-Identifier: Apache-2.0
/** Native qualification constructor. Canonical registry installation,
 * source observations and independent approvals are real; no immutable history
 * is rewritten. The diagnostic profile is fixed before hashing and installation. */
import assert from 'node:assert/strict';
import type {TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {hashAuthorityRegistry} from '../../packages/authority/src/decision-identity.ts';
import type {ProducerRegistration} from '../../packages/authority/src/decision-types.ts';
import type {UUID,UTC,Version} from '../../packages/authority/src/types.ts';
import {makeDecisionFixture,parsed,type Mutable} from '../unit/fixtures/authority-decision.ts';
import {foundationInstall} from './authority-foundation.ts';
import * as authn from './authority-authn-foundation.ts';
import {scope,observe,bind,permissions,type Fixture} from './reviewed-classification-facts.ts';
export type {Fixture} from './reviewed-classification-facts.ts';
export * from './reviewed-classification-facts.ts';
const {query,scalar,tx,uuid,dbNow,config}=authn;

export async function fixture(t:TestContext,options:{bind?:boolean;source?:boolean;producerLifetimeMs?:number;emptyRegistry?:boolean;authnExpiryMs?:number;unsupportedProfile?:boolean}={}):Promise<Fixture>{
 const base=await authn.fixture(t,{expiryMs:options.authnExpiryMs}),s=await authn.session(base),registry=makeDecisionFixture().registry,now=await dbNow(base.owner),primaryId=uuid() as UUID;
 // Qualification fixtures are serial. A fresh real version keeps an empty
 // producer document distinct from the predecessor's globally unique digest.
 const registryVersion=Number((await scalar(base.owner,'SELECT coalesce(max(version),0)::bigint+1 version FROM gc_authority.registries')).version);
 assert.ok(Number.isSafeInteger(registryVersion)&&registryVersion>0&&registryVersion<=2147483647);registry.version=registryVersion as Version;
 const registration=(id:UUID=uuid() as UUID,version=1,extra:Partial<Mutable<ProducerRegistration>>={}):Mutable<ProducerRegistration>=>({ref:{id,version:version as Version},kind:'classifications',tenantId:base.tenant as UUID,state:'active',validity:{notBefore:null,expiresAt:null},...extra});
 const producers={primary:registration(primaryId,1,options.producerLifetimeMs===undefined?{}:{validity:{notBefore:null,expiresAt:new Date(Date.parse(now)+options.producerLifetimeMs).toISOString() as UTC}}),nextVersion:registration(primaryId,2),alternative:registration(),foreign:registration(undefined,1,{tenantId:base.otherTenant as UUID}),wrongKind:registration(undefined,1,{kind:'approved-tags'}),retired:registration(undefined,1,{state:'retired'}),future:registration(undefined,1,{validity:{notBefore:new Date(Date.parse(now)+3600000).toISOString() as UTC,expiresAt:null}}),expired:registration(undefined,1,{validity:{notBefore:null,expiresAt:new Date(Date.parse(now)-1000).toISOString() as UTC}})};
 // Construct the exact diagnostic profile before its immutable installation.
 // The unsupported case canonically installs the prior empty ceiling profile.
 if(!options.unsupportedProfile)for(const adapter of registry.adapters)adapter.ceilings=[{slot:'canonical-visibility',kind:'visibility'}];
 registry.producers=options.emptyRegistry?[]:Object.values(producers);const {digest:_digest,...body}=registry;registry.digest=parsed(hashAuthorityRegistry(body));
 const registryId=uuid();await foundationInstall(base.owner,'registry-install',[registryId,registry.version,JSON.stringify(registry),registry.digest]);
 for(const tenant of [base.tenant,base.otherTenant])await foundationInstall(base.owner,'tenant-initialize',[tenant,'1',1,registryId,registry.version,registry.digest]);
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:2,connectionTimeoutMillis:5000})})});t.after(()=>database.destroy());
 const assetId=uuid(),f:Fixture={...base,hash:s.hash,csrf:s.csrf,protectedSession:s.row,registry,registryId,now:now as UTC,pending:[],people:new Set([base.identity as UUID]),request:{action:'asset:metadata.read',resource:{tenantId:base.tenant as UUID,kind:'asset',id:assetId as UUID},revision:1 as Version,field:null},model:{grants:[],policies:[],definitions:[],memberships:[],parents:new Map(),uses:[]},database,sourceId:uuid(),assetId,reviewers:[uuid(),uuid(),uuid()],producers};
 for(const reviewer of f.reviewers)await query(f.owner,'INSERT INTO public.identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[reviewer,f.issuer,'Synthetic independent reviewer']);
 for(const tenant of [f.tenant,f.otherTenant])await tx(f.owner,async()=>{
  await scope(f.owner,f,tenant);await query(f.owner,'UPDATE public.memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,f.identity,JSON.stringify(permissions)]);
  for(const reviewer of f.reviewers)await query(f.owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic',$3::jsonb)",[tenant,reviewer,JSON.stringify(permissions)]);
 });
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.tenant,f.identity]);
 if(options.source!==false){
  await tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,'INSERT INTO public.sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',[f.tenant,f.sourceId,'Synthetic reviewed classification source','classification-source.invalid','synthetic','owned','synthetic-unused','postgresql']);});
  await observe(f);const selected=await scalar(f.owner,"SELECT id FROM public.assets WHERE tenant_id=$1 AND source_id=$2 AND type='column'",[f.tenant,f.sourceId]);f.assetId=selected.id;f.request={...f.request,resource:{...f.request.resource,id:selected.id as UUID}};
 }
 if(options.bind!==false)await bind(f);
 return f;
}

