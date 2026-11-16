// SPDX-License-Identifier: Apache-2.0
import Fastify from 'fastify';
import cookie from '@fastify/cookie';import helmet from '@fastify/helmet';import rateLimit from '@fastify/rate-limit';import swagger from '@fastify/swagger';import fastifyStatic from '@fastify/static';
import {Type} from '@sinclair/typebox';import {randomUUID} from 'node:crypto';import {existsSync} from 'node:fs';import {resolve} from 'node:path';
import {db,scope,sql,lockTenantLedger} from '../../../packages/db/src/index.ts';
import {Problem,requirePermission,type Principal} from '../../../packages/authz/src/index.ts';
import {Id,SourceInput,SourceListInput,AssetEdit,ScanCompletion} from '../../../packages/contracts/src/index.ts';
import {sourceStorage,sourceConfiguration,mayReconcileAbsence,validateSourceInput} from '../../../packages/connectors/src/sources.ts';
import {listSources,type SourceListQuery} from '../../../packages/connectors/src/source-list.ts';
import {connectorInventory} from '../../../packages/connectors/src/capabilities.ts';
import {authenticate,installAuth,siteTenant,random,publicUrl} from './security.ts';
import {assetView,sourceView,jobView,auditView,visibleAssets,visibleAudit,record,once} from './repository.ts';
import {startProjector} from './search.ts';
import {searchAssets,type AssetSearchQuery} from './asset-search.ts';
import {readAuditIntegrity} from './audit-reader.ts';
import {installModels} from './models.ts';
import {installAssetTypes} from './asset-types.ts';
import {installAssetTypeMigrations} from './asset-type-migrations.ts';
import {installModelMigrations} from './model-migrations.ts';
import {installRelations} from './relations.ts';
import {installRelationMigrations} from './relation-migrations.ts';
import {installBusinessDomains} from './business-domains.ts';
import {installLineage} from './lineage.ts';
import {installSourceScans} from './source-scans.ts';
import {installApprovals} from './approvals.ts';
import {installQuality} from './quality.ts';
import {installClassification} from './classification.ts';
import {validatePinnedType} from '../../../packages/domain/src/asset-type-policy.ts';
import {modelPersistence} from '../../../packages/domain/src/model-service.ts';
export const app=Fastify({logger:{level:'info',redact:['req.headers.authorization','req.headers.cookie','req.url','res.headers.set-cookie']},bodyLimit:8*1024*1024,requestTimeout:20000,trustProxy:false,genReqId:()=>randomUUID()});
await app.register(cookie);
await app.register(helmet,{contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:process.env.NODE_ENV==='production'?[]:null}},hsts:process.env.NODE_ENV==='production'});
await app.register(rateLimit,{max:300,timeWindow:'1 minute'});
await app.register(swagger,{openapi:{openapi:'3.1.0',info:{title:'Governance Commons',version:'0.1.0-dev.1'},servers:[{url:publicUrl}]}});
app.addHook('onSend',async(req,reply,payload)=>{reply.header('X-Correlation-Id',req.id);reply.header('Cache-Control','no-store');return payload;});
app.setErrorHandler((error,req,reply)=>{
 const e=error as any;const status=e instanceof Problem?e.status:e.validation?400:(e.statusCode>=400&&e.statusCode<500?e.statusCode:500);
 if(e instanceof Problem && e.status===503 && e.code==='RELATION_RETRY')reply.header('Retry-After','5');
 if(status===500)req.log.error({code:e.code??'INTERNAL',correlationId:req.id},'Request failed (details redacted)');
 reply.code(status).type('application/problem+json').send({type:'about:blank',title:status>=500?'Service unavailable':'Request rejected',status,code:e instanceof Problem?e.code:e.validation?'VALIDATION_FAILED':'INTERNAL_ERROR',detail:e instanceof Problem?e.message:e.validation?'Check the submitted fields.':'The request could not be completed. Use the correlation ID for support.',correlationId:req.id,...(e instanceof Problem&&e.issues?{issues:e.issues}:{})});
});
app.get('/health/live',async()=>({status:'ok'}));
app.get('/health/ready',async()=>{await sql`select 1`.execute(db);return {status:'ok',version:'0.1.0-dev.1'};});
await installAuth(app);
await installModels(app);
await installAssetTypes(app);
await installAssetTypeMigrations(app);
await installModelMigrations(app);
await installRelations(app);
await installRelationMigrations(app);
await installBusinessDomains(app);
await installApprovals(app);
await installLineage(app);
await installSourceScans(app);
await installQuality(app);
await installClassification(app);
const params={params:Type.Object({id:Id})};
app.get('/api/v1/me',async req=>{const a=await authenticate(req);return {user:{id:a.principal.id,name:a.principal.name},tenant:a.tenants.find(x=>x.id===a.principal.tenantId),tenants:a.tenants,permissions:a.principal.permissions,csrfToken:a.csrf};});
app.post('/api/v1/session/tenant',{schema:{body:Type.Object({tenantId:Id},{additionalProperties:false})}},async req=>{const a=await authenticate(req),tenant=(req.body as any).tenantId;if(!a.tenants.some(x=>x.id===tenant))throw new Problem(403,'TENANT_DENIED','Organization access is not permitted.');await db.updateTable('sessions').set({tenant_id:tenant,csrf:random()}).where('id_hash','=',a.sessionHash).execute();return {changed:true};});
app.get('/api/v1/openapi',async req=>{await authenticate(req);return app.swagger();});
app.get('/api/v1/members',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'catalog:write');return scope(p.tenantId,p.id,async tx=>({items:await tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id').select(['identities.id','identities.name','memberships.role']).where('memberships.active','=',true).where('identities.active','=',true).where('memberships.tenant_id','=',p.tenantId).execute()}));});
app.get('/api/v1/assets',{schema:{querystring:Type.Object({q:Type.Optional(Type.String({maxLength:200})),type:Type.Optional(Type.String({maxLength:64})),limit:Type.Optional(Type.Integer({minimum:1,maximum:100})),cursor:Type.Optional(Type.String({maxLength:2048}))},{additionalProperties:false})}},async req=>{
 return searchAssets(await authenticate(req),req.query as AssetSearchQuery);
});
app.get('/api/v1/assets/:id',{schema:params},async req=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');const {id}=req.params as any;
 return scope(p.tenantId,p.id,async tx=>{const a=await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirst();if(!a)throw new Problem(404,'ASSET_NOT_FOUND','Asset is unavailable.');const columns=a.source_id?await visibleAssets(tx,p).where('assets.source_id','=',a.source_id).where('assets.parent_external_id','=',a.external_id).where('assets.status','=','active').orderBy('assets.name').limit(500).execute():[];const audit=p.permissions.includes('audit:read')?await tx.selectFrom('audit').selectAll().where('resource_id','=',id).where('action','like','asset.%').orderBy('sequence','desc').limit(100).execute():[];return {asset:assetView(a),columns:columns.map(assetView),audit:audit.map(auditView)};});
});
app.patch('/api/v1/assets/:id',{schema:{...params,body:AssetEdit}},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'catalog:write');const {id}=req.params as any;const body=req.body as any,version=Number(String(req.headers['if-match']??'').replaceAll('"',''));if(!Number.isInteger(version)||version<1)throw new Problem(428,'VERSION_REQUIRED','Send the current asset version using If-Match.');
 return scope(p.tenantId,p.id,async tx=>{
  await lockTenantLedger(tx,p.tenantId);
  await modelPersistence.authorize(tx,p,['catalog:read','catalog:write']);
  const a=await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirst();if(!a)throw new Problem(404,'ASSET_NOT_FOUND','Asset is unavailable.');
  await validatePinnedType(tx,p,a,'ownerId'in body?body.ownerId:a.owner_id);
  if(body.ownerId){const owner=await tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id').select('memberships.identity_id').where('memberships.tenant_id','=',p.tenantId).where('memberships.identity_id','=',body.ownerId).where('memberships.active','=',true).where('identities.active','=',true).executeTakeFirst();if(!owner)throw new Problem(422,'OWNER_INVALID','Choose an active owner in this organization.');}
  const updated=await tx.updateTable('assets').set({...('description'in body?{description:body.description}:{}),...('ownerId'in body?{owner_id:body.ownerId}:{}),version:version+1,updated_at:new Date()}).where('id','=',id).where('version','=',version).returningAll().executeTakeFirst();if(!updated)throw new Problem(409,'VERSION_CONFLICT','This asset changed. Reload before saving your edits.');
  await tx.insertInto('asset_revisions').values({tenant_id:p.tenantId,asset_id:id,version:updated.version,snapshot:JSON.stringify(assetView(updated))}).execute();
  await record(tx,p,'asset.updated',id,updated.version,{before:{description:a.description,ownerId:a.owner_id},after:{description:updated.description,ownerId:updated.owner_id}},req.id);
  reply.header('ETag',String(updated.version));return {asset:assetView(await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirstOrThrow())};
 });
});
app.get('/api/v1/sources',{schema:{querystring:SourceListInput}},async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>{const page=await listSources(tx,p,req.query as SourceListQuery);return {items:page.items.map(sourceView),nextCursor:page.nextCursor};});});
app.get('/api/v1/sources/:id',{schema:params},async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>{const row=await tx.selectFrom('sources').selectAll().where('id','=',(req.params as {id:string}).id).executeTakeFirst();if(!row)throw new Problem(404,'SOURCE_NOT_FOUND','Source is unavailable.');return {source:sourceView(row)};});});
app.post('/api/v1/sources',{schema:{body:SourceInput},validatorCompiler:()=>validateSourceInput},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'sources:write');const b=req.body as any;
 return scope(p.tenantId,p.id,tx=>once(tx,p,'source.create',req.headers['idempotency-key'],b,async()=>{const row=await tx.insertInto('sources').values({tenant_id:p.tenantId,id:randomUUID(),...sourceStorage(b)}).returningAll().executeTakeFirstOrThrow();await record(tx,p,'source.created',row.id,1,{name:b.name,...sourceConfiguration(row as Parameters<typeof sourceConfiguration>[0])},req.id);reply.code(201);return {source:sourceView(row)};}));
});
app.post('/api/v1/sources/:id/scans',{schema:{...params,body:Type.Object({},{additionalProperties:false})}},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'sources:write');const {id}=req.params as any;
 return scope(p.tenantId,p.id,tx=>once(tx,p,'source.scan',req.headers['idempotency-key'],{sourceId:id},async()=>{const source=await tx.selectFrom('sources').selectAll().where('id','=',id).executeTakeFirst();if(!source)throw new Problem(404,'SOURCE_NOT_FOUND','Source is unavailable.');const job=await tx.insertInto('jobs').values({tenant_id:p.tenantId,id:randomUUID(),source_id:id,actor_id:p.id}).returningAll().executeTakeFirstOrThrow();await record(tx,p,'scan.requested',job.id,1,{sourceId:id},req.id);reply.code(202);return {job:jobView(job)};}));
});
app.get('/api/v1/jobs',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>({items:(await tx.selectFrom('jobs').selectAll().orderBy('created_at','desc').limit(100).execute()).map(jobView)}));});
app.get('/api/v1/jobs/:id',{schema:params},async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>{const j=await tx.selectFrom('jobs').selectAll().where('id','=',(req.params as any).id).executeTakeFirst();if(!j)throw new Problem(404,'JOB_NOT_FOUND','Job is unavailable.');return {job:jobView(j)};});});
app.get('/api/v1/audit',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'audit:read');return scope(p.tenantId,p.id,async tx=>({items:(await visibleAudit(tx,p).orderBy('sequence','desc').limit(200).execute()).map(auditView)}));});
app.get('/api/v1/audit/integrity',async req=>{const {principal,sessionHash}=await authenticate(req);return readAuditIntegrity(principal,sessionHash);});
app.get('/api/v1/overview',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');return scope(p.tenantId,p.id,async tx=>{const a=await visibleAssets(tx,p).where('assets.status','=','active').execute();const sources=p.permissions.includes('sources:read')?await tx.selectFrom('sources').select('id').execute():[];const jobs=p.permissions.includes('sources:read')?await tx.selectFrom('jobs').select('id').execute():[];const recent=p.permissions.includes('audit:read')?await visibleAudit(tx,p).orderBy('sequence','desc').limit(8).execute():[];return {assetCount:a.length,sourceCount:sources.length,ownedCount:a.filter(x=>x.owner_id).length,jobCount:jobs.length,recentAudit:recent.map(auditView)};});});
app.get('/api/v1/capabilities',async req=>{await authenticate(req);return {release:'development',items:connectorInventory(),aiEnabled:false};});
const web=resolve('apps/web/dist');
if(existsSync(web)){await app.register(fastifyStatic,{root:web,prefix:'/'});app.setNotFoundHandler(async(req,reply)=>{if(req.url.startsWith('/api/')||req.url.startsWith('/internal/')||req.url.startsWith('/auth/'))return reply.code(404).send({code:'NOT_FOUND'});return reply.sendFile('index.html');});}
if(!process.env.SESSION_KEY||process.env.SESSION_KEY.length<32)throw Error('SESSION_KEY must be at least 32 characters. Generate local configuration with ./dev bootstrap.');
const projector=await startProjector();
await app.listen({port:Number(process.env.PORT??4310),host:'0.0.0.0'});
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{clearInterval(projector);void app.close().then(()=>db.destroy()).then(()=>process.exit(0));});
