// SPDX-License-Identifier: Apache-2.0
import Fastify from 'fastify';
import cookie from '@fastify/cookie';import helmet from '@fastify/helmet';import rateLimit from '@fastify/rate-limit';import swagger from '@fastify/swagger';import fastifyStatic from '@fastify/static';
import {Type} from '@sinclair/typebox';import {randomUUID,createHmac} from 'node:crypto';import {existsSync} from 'node:fs';import {resolve} from 'node:path';
import {db,scope,sql} from '../../../packages/db/src/index.ts';
import {Problem,requirePermission,type Principal} from '../../../packages/authz/src/index.ts';
import {Id,SourceInput,AssetEdit,ScanCompletion} from '../../../packages/contracts/src/index.ts';
import {authenticate,installAuth,siteTenant,random,publicUrl,equal} from './security.ts';
import {assetView,sourceView,jobView,auditView,visibleAssets,record,once} from './repository.ts';
import {searchRequest,index,startProjector} from './search.ts';
export const app=Fastify({logger:{level:'info',redact:['req.headers.authorization','req.headers.cookie','req.url','res.headers.set-cookie']},bodyLimit:4*1024*1024,requestTimeout:20000,trustProxy:false,genReqId:()=>randomUUID()});
await app.register(cookie);
await app.register(helmet,{contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:process.env.NODE_ENV==='production'?[]:null}},hsts:process.env.NODE_ENV==='production'});
await app.register(rateLimit,{max:300,timeWindow:'1 minute'});
await app.register(swagger,{openapi:{openapi:'3.1.0',info:{title:'Governance Commons',version:'0.1.0-dev.1'},servers:[{url:publicUrl}]}});
app.addHook('onSend',async(req,reply,payload)=>{reply.header('X-Correlation-Id',req.id);reply.header('Cache-Control','no-store');return payload;});
app.setErrorHandler((error,req,reply)=>{
 const e=error as any;const status=e instanceof Problem?e.status:e.validation?400:500;
 if(status===500)req.log.error({code:e.code??'INTERNAL',correlationId:req.id},'Request failed (details redacted)');
 reply.code(status).type('application/problem+json').send({type:'about:blank',title:status>=500?'Service unavailable':'Request rejected',status,code:e instanceof Problem?e.code:e.validation?'VALIDATION_FAILED':'INTERNAL_ERROR',detail:e instanceof Problem?e.message:e.validation?'Check the submitted fields.':'The request could not be completed. Use the correlation ID for support.',correlationId:req.id});
});
app.get('/health/live',async()=>({status:'ok'}));
app.get('/health/ready',async()=>{await sql`select 1`.execute(db);return {status:'ok',version:'0.1.0-dev.1'};});
await installAuth(app);
const params={params:Type.Object({id:Id})};
app.get('/api/v1/me',async req=>{const a=await authenticate(req);return {user:{id:a.principal.id,name:a.principal.name},tenant:a.tenants.find(x=>x.id===a.principal.tenantId),tenants:a.tenants,permissions:a.principal.permissions,csrfToken:a.csrf};});
app.post('/api/v1/session/tenant',{schema:{body:Type.Object({tenantId:Id},{additionalProperties:false})}},async req=>{const a=await authenticate(req),tenant=(req.body as any).tenantId;if(!a.tenants.some(x=>x.id===tenant))throw new Problem(403,'TENANT_DENIED','Organization access is not permitted.');await db.updateTable('sessions').set({tenant_id:tenant,csrf:random()}).where('id_hash','=',a.sessionHash).execute();return {changed:true};});
app.get('/api/v1/openapi',async req=>{await authenticate(req);return app.swagger();});
app.get('/api/v1/members',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'catalog:write');return scope(p.tenantId,p.id,async tx=>({items:await tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id').select(['identities.id','identities.name','memberships.role']).where('memberships.active','=',true).execute()}));});
function cursorDecode(input:string|undefined,binding:string){if(!input)return 0;try{const [payload,signature]=input.split('.');const expected=createHmac('sha256',process.env.SESSION_KEY??'').update(payload).digest('base64url');if(!equal(signature,expected))throw Error();const data=JSON.parse(Buffer.from(payload,'base64url').toString());if(data.binding!==binding||!Number.isInteger(data.offset)||data.offset<0||data.offset>9000)throw Error();return data.offset;}catch{throw new Problem(400,'CURSOR_INVALID','This page cursor is invalid or belongs to another search.');}}
function cursorEncode(offset:number,binding:string){const payload=Buffer.from(JSON.stringify({offset,binding})).toString('base64url');return payload+'.'+createHmac('sha256',process.env.SESSION_KEY??'').update(payload).digest('base64url');}
app.get('/api/v1/assets',{schema:{querystring:Type.Object({q:Type.Optional(Type.String({maxLength:200})),type:Type.Optional(Type.String({maxLength:64})),limit:Type.Optional(Type.Integer({minimum:1,maximum:100})),cursor:Type.Optional(Type.String({maxLength:2048}))},{additionalProperties:false})}},async req=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');const q=req.query as {q?:string;type?:string;limit?:number;cursor?:string};const binding=JSON.stringify([p.tenantId,p.id,q.q??'',q.type??'',q.limit??50]),offset=cursorDecode(q.cursor,binding);
 return scope(p.tenantId,p.id,async tx=>{
  const permitted=await visibleAssets(tx,p).where('assets.status','=','active').limit(10001).execute();
  if(permitted.length>10000)throw new Problem(422,'SEARCH_PROFILE_LIMIT','This development search profile supports at most 10,000 authorized assets.');
  if(!permitted.length)return {items:[],total:0,nextCursor:null,facets:[]};
  const filter:any[]=[{term:{tenantId:p.tenantId}},{terms:{id:permitted.map(a=>a.id)}},{term:{status:'active'}}];if(q.type)filter.push({term:{type:q.type}});
  const results=await searchRequest('/'+index+'/_search',{track_total_hits:true,from:offset,size:q.limit??50,query:{bool:{filter,must:q.q?[{multi_match:{query:q.q,fields:['name^3','qualifiedName^2','description'],fuzziness:'AUTO'}}]:[{match_all:{}}]}},sort:[{'name.exact':'asc'},{id:'asc'}],aggs:{types:{terms:{field:'type',size:30}}}});
  const map=new Map(permitted.map(a=>[a.id,a]));const items=results.hits.hits.map((h:any)=>map.get(h._id)).filter(Boolean).map(assetView),total=results.hits.total.value;
  return {items,total,nextCursor:offset+items.length<total?cursorEncode(offset+items.length,binding):null,facets:results.aggregations.types.buckets.map((b:any)=>({type:b.key,count:b.doc_count}))};
 });
});
app.get('/api/v1/assets/:id',{schema:params},async req=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');const {id}=req.params as any;
 return scope(p.tenantId,p.id,async tx=>{const a=await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirst();if(!a)throw new Problem(404,'ASSET_NOT_FOUND','Asset is unavailable.');const columns=a.source_id?await visibleAssets(tx,p).where('assets.source_id','=',a.source_id).where('assets.parent_external_id','=',a.external_id).where('assets.status','=','active').orderBy('assets.name').limit(500).execute():[];const audit=p.permissions.includes('audit:read')?await tx.selectFrom('audit').selectAll().where('resource_id','=',id).orderBy('sequence','desc').limit(100).execute():[];return {asset:assetView(a),columns:columns.map(assetView),audit:audit.map(auditView)};});
});
app.patch('/api/v1/assets/:id',{schema:{...params,body:AssetEdit}},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'catalog:write');const {id}=req.params as any;const body=req.body as any,version=Number(String(req.headers['if-match']??'').replaceAll('"',''));if(!Number.isInteger(version)||version<1)throw new Problem(428,'VERSION_REQUIRED','Send the current asset version using If-Match.');
 return scope(p.tenantId,p.id,async tx=>{
  const a=await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirst();if(!a)throw new Problem(404,'ASSET_NOT_FOUND','Asset is unavailable.');
  if(body.ownerId){const owner=await tx.selectFrom('memberships').select('identity_id').where('identity_id','=',body.ownerId).where('active','=',true).executeTakeFirst();if(!owner)throw new Problem(422,'OWNER_INVALID','Choose an active owner in this organization.');}
  const updated=await tx.updateTable('assets').set({...('description'in body?{description:body.description}:{}),...('ownerId'in body?{owner_id:body.ownerId}:{}),version:version+1,updated_at:new Date()}).where('id','=',id).where('version','=',version).returningAll().executeTakeFirst();if(!updated)throw new Problem(409,'VERSION_CONFLICT','This asset changed. Reload before saving your edits.');
  await tx.insertInto('asset_revisions').values({tenant_id:p.tenantId,asset_id:id,version:updated.version,snapshot:JSON.stringify(assetView(updated))}).execute();
  await record(tx,p,'asset.updated',id,updated.version,{before:{description:a.description,ownerId:a.owner_id},after:{description:updated.description,ownerId:updated.owner_id}},req.id);
  reply.header('ETag',String(updated.version));return {asset:assetView(await visibleAssets(tx,p).where('assets.id','=',id).executeTakeFirstOrThrow())};
 });
});
app.get('/api/v1/sources',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>({items:(await tx.selectFrom('sources').selectAll().orderBy('name').limit(100).execute()).map(sourceView)}));});
app.post('/api/v1/sources',{schema:{body:SourceInput}},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'sources:write');const b=req.body as any;
 return scope(p.tenantId,p.id,tx=>once(tx,p,'source.create',req.headers['idempotency-key'],b,async()=>{const row=await tx.insertInto('sources').values({tenant_id:p.tenantId,id:randomUUID(),name:b.name,host:b.host,port:b.port,database_name:b.database,schema_name:b.schema,secret_ref:b.secretRef}).returningAll().executeTakeFirstOrThrow();await record(tx,p,'source.created',row.id,1,{name:b.name,secretRef:b.secretRef},req.id);reply.code(201);return {source:sourceView(row)};}));
});
app.post('/api/v1/sources/:id/scans',{schema:{...params,body:Type.Object({},{additionalProperties:false})}},async(req,reply)=>{
 const {principal:p}=await authenticate(req);requirePermission(p,'sources:write');const {id}=req.params as any;
 return scope(p.tenantId,p.id,tx=>once(tx,p,'source.scan',req.headers['idempotency-key'],{sourceId:id},async()=>{const source=await tx.selectFrom('sources').selectAll().where('id','=',id).executeTakeFirst();if(!source)throw new Problem(404,'SOURCE_NOT_FOUND','Source is unavailable.');const job=await tx.insertInto('jobs').values({tenant_id:p.tenantId,id:randomUUID(),source_id:id,actor_id:p.id}).returningAll().executeTakeFirstOrThrow();await record(tx,p,'scan.requested',job.id,1,{sourceId:id},req.id);reply.code(202);return {job:jobView(job)};}));
});
app.get('/api/v1/jobs',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>({items:(await tx.selectFrom('jobs').selectAll().orderBy('created_at','desc').limit(100).execute()).map(jobView)}));});
app.get('/api/v1/jobs/:id',{schema:params},async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'sources:read');return scope(p.tenantId,p.id,async tx=>{const j=await tx.selectFrom('jobs').selectAll().where('id','=',(req.params as any).id).executeTakeFirst();if(!j)throw new Problem(404,'JOB_NOT_FOUND','Job is unavailable.');return {job:jobView(j)};});});
app.get('/api/v1/audit',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'audit:read');return scope(p.tenantId,p.id,async tx=>({items:(await tx.selectFrom('audit').selectAll().orderBy('sequence','desc').limit(200).execute()).map(auditView)}));});
app.get('/api/v1/overview',async req=>{const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');return scope(p.tenantId,p.id,async tx=>{const a=await visibleAssets(tx,p).where('assets.status','=','active').execute();const sources=p.permissions.includes('sources:read')?await tx.selectFrom('sources').select('id').execute():[];const jobs=p.permissions.includes('sources:read')?await tx.selectFrom('jobs').select('id').execute():[];const recent=p.permissions.includes('audit:read')?await tx.selectFrom('audit').selectAll().orderBy('sequence','desc').limit(8).execute():[];return {assetCount:a.length,sourceCount:sources.length,ownedCount:a.filter(x=>x.owner_id).length,jobCount:jobs.length,recentAudit:recent.map(auditView)};});});
app.get('/api/v1/capabilities',async req=>{await authenticate(req);return {release:'development',items:[{id:'postgresql',name:'PostgreSQL metadata',implementation:'IN_PROGRESS',verification:'NOT_RUN',limitations:['Metadata scans only in this development increment.','Lineage, DQ and grants remain open requirements.']}],aiEnabled:false};});
const sitePrincipal=(tenant:string):Principal=>({id:'site:local',name:'Local execution site',tenantId:tenant,permissions:[]});
app.get('/internal/jobs/pending',async req=>{const tenant=siteTenant(req);return scope(tenant,'site:local',async tx=>({items:(await tx.selectFrom('jobs').select(['id','tenant_id','source_id']).where('status','in',['queued','running']).orderBy('created_at').limit(50).execute()).map(j=>({id:j.id,tenantId:j.tenant_id,sourceId:j.source_id}))}));});
app.post('/internal/jobs/:id/claim',{schema:params},async req=>{const tenant=siteTenant(req),id=(req.params as any).id;return scope(tenant,'site:local',async tx=>{let job=await tx.selectFrom('jobs').selectAll().where('id','=',id).forUpdate().executeTakeFirst();if(!job)throw new Problem(404,'JOB_NOT_FOUND','Job is unavailable.');if(!['queued','running'].includes(job.status))return {job:jobView(job)};job=await tx.updateTable('jobs').set({status:'running'}).where('id','=',id).returningAll().executeTakeFirstOrThrow();const source=await tx.selectFrom('sources').selectAll().where('id','=',job.source_id).executeTakeFirstOrThrow();return {job:jobView(job),source:sourceView(source)};});});
app.post('/internal/jobs/:id/complete',{schema:{...params,body:ScanCompletion}},async req=>{
 const tenant=siteTenant(req),id=(req.params as any).id,b=req.body as any,p=sitePrincipal(tenant);
 return scope(tenant,p.id,async tx=>{
  const job=await tx.selectFrom('jobs').selectAll().where('id','=',id).forUpdate().executeTakeFirst();if(!job)throw new Problem(404,'JOB_NOT_FOUND','Job is unavailable.');if(job.status==='succeeded')return {job:jobView(job)};if(job.status!=='running')throw new Problem(409,'JOB_STATE_CONFLICT','Job is not running.');
  const source=await tx.selectFrom('sources').selectAll().where('id','=',job.source_id).forUpdate().executeTakeFirstOrThrow();const keys=new Set<string>();
  for(const r of b.records){if(keys.has(r.externalId))throw new Problem(422,'DUPLICATE_SOURCE_ID','Scan contains duplicated source identities.');keys.add(r.externalId);const old=await tx.selectFrom('assets').selectAll().where('source_id','=',source.id).where('external_id','=',r.externalId).executeTakeFirst();
   const metadata={...r.metadata,sourceVersion:b.sourceVersion,scanId:id,provenance:'source-observed',aliases:old&&old.qualified_name!==r.qualifiedName?[...new Set([...(old.metadata.aliases??[]),old.qualified_name])]:old?.metadata.aliases??[]};
   const values={name:r.name,qualified_name:r.qualifiedName,type:r.type,parent_external_id:r.parentExternalId??null,metadata:JSON.stringify(metadata),observed_at:new Date(b.observedAt),updated_at:new Date(),status:'active',version:(old?.version??0)+1};
   const row=old?await tx.updateTable('assets').set(values).where('id','=',old.id).returningAll().executeTakeFirstOrThrow():await tx.insertInto('assets').values({...values,tenant_id:tenant,id:randomUUID(),source_id:source.id,external_id:r.externalId}).returningAll().executeTakeFirstOrThrow();
   await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:row.id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();await record(tx,p,'asset.observed',row.id,row.version,{name:row.name,type:row.type,scanId:id,sourceId:source.id},req.id);
  }
  // Empty or changed-permission scans cannot establish source deletion.
  if(keys.size>0&&source.permission_fingerprint===b.permissionFingerprint){const missing=await tx.selectFrom('assets').selectAll().where('source_id','=',source.id).where('status','=','active').where('external_id','not in',[...keys]).execute();for(const a of missing){await tx.updateTable('assets').set({status:'unavailable',version:a.version+1,updated_at:new Date()}).where('id','=',a.id).execute();await record(tx,p,'asset.unavailable',a.id,a.version+1,{scanId:id,reason:'Absent from complete matching-permission scan; deletion not yet confirmed.'},req.id);}}
  await tx.updateTable('sources').set({status:'healthy',last_successful_scan:new Date(),permission_fingerprint:b.permissionFingerprint}).where('id','=',source.id).execute();const done=await tx.updateTable('jobs').set({status:'succeeded',finished_at:new Date(),asset_count:keys.size,error_code:null}).where('id','=',id).returningAll().executeTakeFirstOrThrow();await record(tx,p,'scan.completed',id,1,{assetCount:keys.size,sourceVersion:b.sourceVersion},req.id);return {job:jobView(done)};
 });
});
app.post('/internal/jobs/:id/fail',{schema:{...params,body:Type.Object({code:Type.String({pattern:'^[A-Z_]{1,80}$'})},{additionalProperties:false})}},async req=>{const tenant=siteTenant(req),id=(req.params as any).id;return scope(tenant,'site:local',async tx=>{const old=await tx.selectFrom('jobs').selectAll().where('id','=',id).forUpdate().executeTakeFirst();if(!old)throw new Problem(404,'JOB_NOT_FOUND','Job is unavailable.');if(old.status==='succeeded')return {job:jobView(old)};const j=await tx.updateTable('jobs').set({status:'failed',finished_at:new Date(),error_code:(req.body as any).code}).where('id','=',id).returningAll().executeTakeFirstOrThrow();await record(tx,sitePrincipal(tenant),'scan.failed',id,1,{code:j.error_code},req.id);return {job:jobView(j)};});});
const web=resolve('apps/web/dist');
if(existsSync(web)){await app.register(fastifyStatic,{root:web,prefix:'/'});app.setNotFoundHandler(async(req,reply)=>{if(req.url.startsWith('/api/')||req.url.startsWith('/internal/')||req.url.startsWith('/auth/'))return reply.code(404).send({code:'NOT_FOUND'});return reply.sendFile('index.html');});}
if(!process.env.SESSION_KEY||process.env.SESSION_KEY.length<32)throw Error('SESSION_KEY must be at least 32 characters. Generate local configuration with ./dev bootstrap.');
const projector=await startProjector();
await app.listen({port:Number(process.env.PORT??4310),host:'0.0.0.0'});
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{clearInterval(projector);void app.close().then(()=>db.destroy()).then(()=>process.exit(0));});
