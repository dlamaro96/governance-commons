// SPDX-License-Identifier: Apache-2.0
/** Explicit owner-only qualification preparation. Persisted manifests and
 * exceptional sessions are replayed exactly, never renewed or reactivated. */
import {constants} from 'node:fs';
import {open,mkdir,lstat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {Client} from 'pg';
import {AUTHENTICATION_SCALARS as S} from '../packages/authority/src/authentication.ts';
import {parseInstallationManifest,installationHash,installationQuery,parseInstallationReceipt,type InstallationManifest,type InstallationOperation} from '../packages/authority/src/authentication-installation.ts';
import {validateDemoManifests,type DemoInstallationConfig} from './authentication-install-demo.ts';
import {PROTECTED_SEARCH_FIXTURE as search,PROTECTED_AUDIT_FIXTURE as audit} from '../tests/fixtures/protected-core-tenants.ts';
import {readProtectedPrivateJson,validateProtectedCoreEndpoints,issueProtectedCoreSession,inspectProtectedCoreSession,type ProtectedCoreEndpointConfig,type PersistedProtectedSession} from '../tests/fixtures/protected-core-authentication.ts';

const name='Synthetic protected qualification';
const tenants=[search.tenant,search.foreign,audit.tenant].sort();
const people=[search.steward,search.consumer,search.summit,search.membershipLoss,search.expired,audit.steward,audit.consumer].sort();
const members=[
 {tenant:search.tenant,identity:search.steward,role:'steward',permissions:['catalog:read']},
 {tenant:search.tenant,identity:search.consumer,role:'consumer',permissions:['catalog:read']},
 {tenant:search.foreign,identity:search.summit,role:'steward',permissions:['catalog:read']},
 {tenant:search.tenant,identity:search.membershipLoss,role:'consumer',permissions:['catalog:read']},
 {tenant:search.tenant,identity:search.expired,role:'consumer',permissions:['catalog:read']},
 {tenant:audit.tenant,identity:audit.steward,role:'auditor',permissions:['audit:read','catalog:read','models:read']},
 {tenant:audit.tenant,identity:audit.consumer,role:'consumer',permissions:['catalog:read']},
];
function requireValue(value:unknown):asserts value{if(!value)throw Error('PROTECTED_CORE_FIXTURE_NOT_CONFIRMED');}
const stable=(value:unknown):string=>Array.isArray(value)?'['+value.map(stable).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable((value as Record<string,unknown>)[k])).join(',')+'}':JSON.stringify(value);
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
async function writeNew(path:string,value:unknown){const f=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await f.writeFile(JSON.stringify(value,null,2)+'\n');await f.sync();}finally{await f.close();}}
async function existing(path:string):Promise<any|undefined>{try{return await readProtectedPrivateJson(path);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return undefined;throw error;}}
async function transaction<T>(owner:Client,work:()=>Promise<T>,isolation:'SERIALIZABLE'|'READ COMMITTED'='SERIALIZABLE'):Promise<T>{await owner.query(`BEGIN ISOLATION LEVEL ${isolation} READ WRITE`);try{const result=await work();await owner.query('COMMIT');return result;}catch(error){await owner.query('ROLLBACK').catch(()=>undefined);throw error;}}
async function prepareRows(owner:Client,issuer:string){
 await transaction(owner,async()=>{
  await owner.query('SELECT gc_authority.owner_check()');
  for(const tenant of tenants)await owner.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[tenant]);
  for(const id of [...tenants,...people].sort())await owner.query("SELECT pg_advisory_xact_lock(hashtextextended('gc-protected-fixture:'||$1::text,0))",[id]);
  const found=await owner.query('SELECT id,name FROM public.tenants WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE',[tenants]);
  const identities=await owner.query('SELECT id,issuer,subject,name,active FROM public.identities WHERE id=ANY($1::uuid[]) OR (issuer=$2 AND subject=ANY($1::text[])) ORDER BY id FOR UPDATE',[people,issuer]);
  const heads=await owner.query('SELECT identity_id FROM gc_authority.identity_heads WHERE identity_id=ANY($1::uuid[]) ORDER BY identity_id FOR UPDATE',[people]);
  const fresh=!found.rows.length&&!identities.rows.length&&!heads.rows.length;
  if(fresh){
   await owner.query('INSERT INTO public.tenants(id,name) SELECT id,$2 FROM unnest($1::uuid[]) id',[tenants,name]);
   for(const id of people)await owner.query('INSERT INTO public.identities(id,issuer,subject,name,active) VALUES($1::uuid,$2::text,$1::text,$3::text,true)',[id,issuer,id===audit.steward?audit.name:name]);
   for(const m of members){await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[m.tenant]);await owner.query('INSERT INTO public.memberships(tenant_id,identity_id,role,permissions,active) VALUES($1,$2,$3,$4::jsonb,true)',[m.tenant,m.identity,m.role,JSON.stringify(m.permissions)]);}
  }else{
   requireValue(found.rows.length===tenants.length&&found.rows.every(r=>tenants.includes(r.id)&&r.name===name));
   requireValue(identities.rows.length===people.length&&identities.rows.every(r=>people.includes(r.id)&&r.issuer===issuer&&r.subject===r.id&&r.name===(r.id===audit.steward?audit.name:name)&&r.active===true));
   requireValue(heads.rows.length===people.length);
  }
  const canonical=await owner.query('SELECT identity_id,revision,present,active,canonical_issuer,canonical_subject FROM gc_authority.identity_heads WHERE identity_id=ANY($1::uuid[]) ORDER BY identity_id',[people]);
  requireValue(canonical.rows.length===people.length&&canonical.rows.every(r=>r.revision==='1'&&r.present&&r.active&&r.canonical_issuer===issuer&&r.canonical_subject===r.identity_id));
  for(const tenant of tenants){
   await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id','',true)",[tenant]);
   const expected=members.filter(m=>m.tenant===tenant);
   const rows=await owner.query('SELECT identity_id,role,permissions,active FROM public.memberships WHERE tenant_id=$1 ORDER BY identity_id FOR UPDATE',[tenant]);
   requireValue(rows.rows.length===expected.length&&rows.rows.every(r=>{const m=expected.find(x=>x.identity===r.identity_id);return m&&r.role===m.role&&stable(r.permissions)===stable(m.permissions)&&(r.active===true||(!fresh&&r.identity_id===search.membershipLoss&&r.active===false));}));
   const heads=await owner.query('SELECT identity_id,revision,present,active FROM gc_authority.tenant_member_heads WHERE tenant_id=$1 ORDER BY identity_id',[tenant]);
   requireValue(heads.rows.length===expected.length&&heads.rows.every(head=>{
    const row=rows.rows.find(r=>r.identity_id===head.identity_id);
    return row&&head.present===true&&head.active===row.active&&head.revision===(head.identity_id===search.membershipLoss&&!row.active?2:1);
   }));
  }
  // Empty tenant scope plus exact actor exposes the complete actor membership
  // set, including an unexpected foreign grant that would change selection.
  for(const member of members){
   await owner.query("SELECT set_config('gc.tenant_id','',true),set_config('gc.actor_id',$1,true)",[member.identity]);
   const all=await owner.query('SELECT tenant_id,identity_id FROM public.memberships WHERE identity_id=$1 ORDER BY tenant_id',[member.identity]);
   requireValue(all.rows.length===1&&all.rows[0].tenant_id===member.tenant&&all.rows[0].identity_id===member.identity);
  }
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[audit.tenant,audit.steward]);
  if(fresh){
   const at=new Date().toISOString();
   await owner.query("INSERT INTO public.assets(tenant_id,id,external_id,name,qualified_name,type,observed_at,updated_at,visibility,allowed_identities) VALUES($1::uuid,$2::uuid,$2::text,'Synthetic inaccessible audit fixture','synthetic.protected.audit','dataset',$3,$3,'restricted',$4::jsonb)",[audit.tenant,audit.assetId,at,JSON.stringify([audit.consumer])]);
   const snapshot={id:audit.assetId,name:'Synthetic inaccessible audit fixture',qualifiedName:'synthetic.protected.audit',type:'dataset',description:'',ownerId:null,ownerName:null,sourceId:null,sourceName:null,version:1,observedAt:at,updatedAt:at,status:'active',metadata:{},modelId:null,modelVersion:null,attributes:{},typeState:null};
   await owner.query('INSERT INTO public.asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,1,$3::jsonb)',[audit.tenant,audit.assetId,JSON.stringify(snapshot)]);
   let previousHash='0'.repeat(64),batch:unknown[]=[];
   for(let i=0;i<audit.eventCount;i++){
    const id=randomUUID(),last=i===audit.eventCount-1,changes={synthetic:true};
    const envelope={id,tenantId:audit.tenant,actorId:audit.steward,actorName:audit.name,action:last?'asset.observed':'source.synthetic',resourceId:last?audit.assetId:`${audit.correlationId}:${i}`,version:1,changes,correlationId:audit.correlationId,occurredAt:at,previousHash};
    const digest=hash(stable(envelope));batch.push({tenant_id:audit.tenant,id,actor_id:audit.steward,actor_name:audit.name,action:envelope.action,resource_id:envelope.resourceId,changes:{...changes,resourceVersion:1},correlation_id:audit.correlationId,occurred_at:at,previous_hash:previousHash,hash:digest,envelope});previousHash=digest;
    if(batch.length===500||last){await owner.query(`INSERT INTO public.audit(tenant_id,id,actor_id,actor_name,action,resource_id,changes,correlation_id,occurred_at,previous_hash,hash,envelope)
     SELECT tenant_id,id,actor_id,actor_name,action,resource_id,changes,correlation_id,occurred_at,previous_hash,hash,envelope FROM jsonb_to_recordset($1::jsonb) AS x(tenant_id uuid,id uuid,actor_id text,actor_name text,action text,resource_id text,changes jsonb,correlation_id text,occurred_at timestamptz,previous_hash text,hash text,envelope jsonb)`,[JSON.stringify(batch)]);batch=[];}
   }
  }
  const ledger=await owner.query('SELECT id,actor_id,actor_name,action,resource_id,changes,correlation_id,occurred_at,previous_hash,hash,envelope FROM public.audit WHERE tenant_id=$1 ORDER BY sequence',[audit.tenant]);
  requireValue(ledger.rows.length===audit.eventCount);let previous='0'.repeat(64);
  for(const [i,row] of ledger.rows.entries()){
   const envelope={id:row.id,tenantId:audit.tenant,actorId:audit.steward,actorName:audit.name,action:i===audit.eventCount-1?'asset.observed':'source.synthetic',resourceId:i===audit.eventCount-1?audit.assetId:`${audit.correlationId}:${i}`,version:1,changes:{synthetic:true},correlationId:audit.correlationId,occurredAt:new Date(row.occurred_at).toISOString(),previousHash:previous};
   requireValue(row.actor_id===audit.steward&&row.actor_name===audit.name&&row.action===envelope.action&&row.resource_id===envelope.resourceId&&row.correlation_id===audit.correlationId&&stable(row.changes)===stable({synthetic:true,resourceVersion:1})&&stable(row.envelope)===stable(envelope)&&row.previous_hash===previous&&row.hash===hash(stable(envelope)));previous=row.hash;
  }
  const assets=await owner.query('SELECT id,version,visibility,allowed_identities FROM public.assets WHERE tenant_id=$1',[audit.tenant]);requireValue(assets.rows.length===1&&assets.rows[0].id===audit.assetId&&assets.rows[0].version===1&&assets.rows[0].visibility==='restricted'&&stable(assets.rows[0].allowed_identities)===stable([audit.consumer]));
  const revisions=await owner.query('SELECT asset_id,version FROM public.asset_revisions WHERE tenant_id=$1',[audit.tenant]);requireValue(revisions.rows.length===1&&revisions.rows[0].asset_id===audit.assetId&&revisions.rows[0].version===1);
 });
}
async function main(){
 requireValue(process.argv.length===6&&process.argv[2]==='--batch'&&process.argv[4]==='--core-plan');
 const folder=resolve(process.argv[3]!),corePath=resolve(process.argv[5]!);await mkdir(folder,{recursive:true,mode:0o700});const stat=await lstat(folder);requireValue(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid?.()&&(stat.mode&0o077)===0);
 const config:ProtectedCoreEndpointConfig={formatVersion:1,loginDatabaseUrl:process.env.AUTHN_LOGIN_DATABASE_URL??'',apiDatabaseUrl:process.env.AUTHN_API_DATABASE_URL??'',issuer:process.env.OIDC_ISSUER??'',clientId:'governance-protected-web',publicOrigin:process.env.PUBLIC_AUTHN_ORIGIN??'',environment:process.env.AUTHN_ENVIRONMENT as ProtectedCoreEndpointConfig['environment']};validateProtectedCoreEndpoints(config);requireValue(process.env.MIGRATION_DATABASE_URL);
 const core=await readProtectedPrivateJson(corePath) as any;
 const owner=new Client({connectionString:process.env.MIGRATION_DATABASE_URL,application_name:'gc-protected-core-qualification',connectionTimeoutMillis:5000,statement_timeout:15000,lock_timeout:2000,query_timeout:16000});
 try{
  await owner.connect();await owner.query('SELECT gc_authority.owner_check()');
  const r=(await owner.query("SELECT (SELECT oid FROM pg_database WHERE datname=current_database()) db,session_user::regrole::oid owner,(SELECT oid FROM pg_roles WHERE rolname='gc_authn_login') login,(SELECT oid FROM pg_roles WHERE rolname='gc_authn_api') api")).rows[0];
  const target={databaseOid:S.oid(r.db),ownerRoleOid:S.oid(r.owner),loginRoleOid:S.oid(r.login),apiRoleOid:S.oid(r.api)};
  const demoConfig:DemoInstallationConfig={issuer:config.issuer,publicOrigin:config.publicOrigin,environment:config.environment};
  requireValue(core.version===1&&stable(core.config)===stable(demoConfig)&&stable(core.target)===stable(target));
  const coreManifests=validateDemoManifests(core.manifests,demoConfig,target),issuer=coreManifests[4]!.operation;requireValue(issuer.type==='register-issuer');const coreHash=installationHash(coreManifests.at(-1)!);
  // Verify exact committed core installation before creating qualification rows.
  for(const m of coreManifests){const row=(await owner.query('SELECT manifest_hash FROM gc_authn.installation_receipts WHERE request_id=$1',[m.requestId])).rows;requireValue(row.length===1&&row[0].manifest_hash===installationHash(m));}
  await prepareRows(owner,config.issuer);
  const planPath=folder+'/fixture-plan.json';let plan=await existing(planPath);
  if(!plan){
   requireValue((await owner.query('SELECT manifest_hash FROM gc_authn.installation_receipts ORDER BY sequence DESC LIMIT 1')).rows[0]?.manifest_hash===coreHash);
   const now=(await owner.query('SELECT clock_timestamp() now')).rows[0].now as Date;
   const shortExpiry=new Date(now.getTime()+15000).toISOString();requireValue(Date.parse(issuer.expiresAt)>Date.parse(shortExpiry));
   const operations:InstallationOperation[]=[...people.map(id=>({type:'bind-identity' as const,bindingId:S.uuid(randomUUID()),issuerId:issuer.issuerId,identityId:S.uuid(id),expectedCanonicalIssuer:config.issuer,expectedCanonicalSubject:id,expiresAt:S.time(id===search.expired?shortExpiry:issuer.expiresAt)})),...tenants.map(id=>({type:'initialize-tenant' as const,tenantId:S.uuid(id),generation:1}))];
   let predecessor=coreHash;const manifests=operations.map(operation=>{const parsed=parseInstallationManifest({formatVersion:1,requestId:randomUUID(),releaseReference:'governance-commons/protected-core-qualification/v1',deploymentOperatorReference:'explicit-local-qualification-preparation',expectedDatabaseOid:target.databaseOid,expectedOwnerRoleOid:target.ownerRoleOid,predecessorManifestHash:predecessor,operation});requireValue(parsed.ok);predecessor=installationHash(parsed.value);return parsed.value;});
   plan={formatVersion:1,coreHash,manifests};await writeNew(planPath,plan);
  }
  requireValue(plan.formatVersion===1&&plan.coreHash===coreHash&&Array.isArray(plan.manifests)&&plan.manifests.length===people.length+tenants.length);
  let predecessor=coreHash;const manifests:InstallationManifest[]=[];
  for(const [index,raw] of plan.manifests.entries()){
   const parsed=parseInstallationManifest(raw);requireValue(parsed.ok);const m=parsed.value,op=m.operation;
   requireValue(m.predecessorManifestHash===predecessor&&m.expectedDatabaseOid===target.databaseOid&&m.expectedOwnerRoleOid===target.ownerRoleOid&&m.releaseReference==='governance-commons/protected-core-qualification/v1'&&m.deploymentOperatorReference==='explicit-local-qualification-preparation');
   if(index<people.length){const id=people[index];requireValue(op.type==='bind-identity'&&op.identityId===id&&op.expectedCanonicalSubject===id&&op.expectedCanonicalIssuer===config.issuer&&op.issuerId===issuer.issuerId&&(id===search.expired?Date.parse(op.expiresAt)<Date.parse(issuer.expiresAt):op.expiresAt===issuer.expiresAt));}
   else requireValue(op.type==='initialize-tenant'&&op.tenantId===tenants[index-people.length]&&op.generation===1);
   predecessor=installationHash(m);manifests.push(m);
  }
  for(const manifest of manifests)await transaction(owner,async()=>{const q=installationQuery(manifest),rows=await owner.query(q.text,[...q.values]);requireValue(rows.rows.length===1);const receipt=parseInstallationReceipt(rows.rows[0]);requireValue(receipt.ok&&receipt.value.manifestHash===installationHash(manifest));},'READ COMMITTED');
  const sessionsPath=folder+'/prepared-sessions.json';let sessions=await existing(sessionsPath) as {membershipLossSession:PersistedProtectedSession;expiredSession:PersistedProtectedSession}|undefined;
  if(!sessions){
   // An uncertain issue never authorizes a retry issuing new credentials.
   await writeNew(folder+'/session-issuance-started.json',{formatVersion:1,manifestHash:predecessor});
   const expiredSession=await issueProtectedCoreSession(config,search.expired),membershipLossSession=await issueProtectedCoreSession(config,search.membershipLoss);
   for(const value of [expiredSession,membershipLossSession]){const inspected=await inspectProtectedCoreSession(config,value);requireValue(inspected.identityId===value.identityId&&inspected.selectedTenantId===search.tenant&&inspected.sessionVersion===1&&inspected.expiresAt===value.expiresAt);}
   sessions={membershipLossSession,expiredSession};await writeNew(sessionsPath,sessions);
  }
  await transaction(owner,async()=>{
   await owner.query('SELECT gc_authority.owner_check()');await owner.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[search.tenant]);await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[search.tenant,search.membershipLoss]);
   for(const [key,id] of [['membershipLossSession',search.membershipLoss],['expiredSession',search.expired]] as const){const value=sessions![key];requireValue(value.identityId===id&&value.selectedTenantId===search.tenant&&value.sessionVersion===1&&hash(value.sessionToken)===value.sessionHash);const rows=(await owner.query('SELECT s.identity_id,s.selected_tenant_id,s.version,s.expires_at,s.csrf_hash,s.revoked_at,p.identity_id AS provenance_identity FROM gc_authn.sessions s JOIN gc_authn.session_provenance p ON p.session_id=s.id WHERE s.session_hash=$1',[value.sessionHash])).rows;requireValue(rows.length===1&&rows[0].identity_id===id&&rows[0].provenance_identity===id&&rows[0].selected_tenant_id===search.tenant&&rows[0].version===1&&new Date(rows[0].expires_at).toISOString()===value.expiresAt&&rows[0].csrf_hash===hash(value.csrfToken)&&rows[0].revoked_at===null);}
   const member=(await owner.query('SELECT active FROM public.memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[search.tenant,search.membershipLoss])).rows;requireValue(member.length===1);
   if(member[0].active)await owner.query('UPDATE public.memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2 AND active',[search.tenant,search.membershipLoss]);
  });
  const output={...config,...sessions},outputPath=folder+'/test-config.json',prior=await existing(outputPath);if(prior)requireValue(stable(prior)===stable(output));else await writeNew(outputPath,output);
  console.log(JSON.stringify({result:'PREPARED',tenants:tenants.length,identities:people.length,auditEvents:audit.eventCount,authenticationOperations:manifests.length,renewed:false,ownerCredentialExported:false}));
 }finally{await owner.end().catch(()=>undefined);}
}
main().catch(()=>{process.stderr.write('PROTECTED_CORE_FIXTURE_NOT_CONFIRMED: preserve the private preparation directory; inspect prerequisites and replay exact manifests. Uncertain session issuance requires a fresh isolated qualification database, never automatic reissue or renewal.\n');process.exitCode=1;});
