#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Populated SQL036-to037 protected application authentication qualification.

Own network-none PostgreSQL only. This qualifies native authentication admission,
not the main application's HTTP cutover, effect fencing or canonical authority.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'.local/evidence/application-authn-bridge.json'
MIGRATION='037_application_authentication_bridge.sql'
SEED='tests/qualification/application-authn-bridge-predecessor.test.ts'
NATIVE='tests/qualification/application-authn-bridge.test.ts'
PHASES=('application-authn-predecessor','application-authn-native')
EXPECTED_TESTS=25

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
content=module(ROOT/'scripts/runtime-test-content-security-revision.py','application_authn_transport')
read,authority,volume=content.read,content.authority,content.volume
require,sha=content.require,content.sha
original_sources=content.sources
NAMES=[*content.NAMES,'034_classification_label_identities.sql','035_reviewed_classification_producer.sql','036_authority_scope_alignment.sql',MIGRATION]

def sources():
 require(sorted(p.name for p in (ROOT/'packages/db/migrations').glob('*.sql'))==NAMES,'Exact SQL001–037 required')
 paths={r['path'] for r in original_sources()}|{SEED,NATIVE,'scripts/runtime-test-application-authn-bridge.py','scripts/test_application_authn_bridge.py'}|{'packages/db/migrations/'+name for name in NAMES}
 pending=[ROOT/p for p in paths if p.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for name in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',volume.source_file(current).read_text()):
   candidate=Path(os.path.abspath(current.parent/name))
   if candidate.suffix=='.js' and not candidate.exists():candidate=candidate.with_suffix('.ts')
   if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').exists() else candidate/'index.ts'
   candidate=volume.source_file(candidate);relative=str(candidate.relative_to(ROOT))
   if relative not in paths:
    paths.add(relative)
    if candidate.suffix in ('.ts','.tsx'):pending.append(candidate)
 require(len(paths)<=1024,'Qualification source inventory exceeds bound')
 return [{'path':p,'sha256':sha(volume.source_file(ROOT/p).read_bytes())} for p in sorted(paths)]

content.sources=sources
volume.sources=sources
volume.PHASES=PHASES
volume.effective_sources=lambda rows,phase:rows if phase in PHASES else (_ for _ in ()).throw(RuntimeError('Undeclared native phase'))
FUNCTIONS=read.FUNCTIONS.replace("'signature',p.oid::regprocedure::text","'metadata',to_jsonb(p)-'prosrc','oid',p.oid::text,'signature',p.oid::regprocedure::text")
TYPES="""SELECT jsonb_agg(jsonb_build_object('name',n.nspname||'.'||t.typname,'metadata',to_jsonb(t)-'typacl','acl',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY grantee,grantor,privilege_type,is_grantable),'[]') FROM aclexplode(coalesce(t.typacl,acldefault('T',t.typowner))) a)) ORDER BY n.nspname,t.typname) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN('public','gc_authn','gc_authority');"""
TABLES={'gc_authn.application_bridge_installations','gc_authn.application_bridge_receipts'}
NEW_FUNCTIONS={'gc_authn.application_role_safe(oid)',
 'gc_authn.application_bridge_encoding(text,uuid,text,text,oid,oid,text)',
 'gc_authn.application_bridge_existing(uuid,text)',
 'gc_authn.application_bridge_append(text,uuid,uuid,text,text,text,text)',
 'gc_authn.install_application_bridge_v1(uuid,text,text,oid,oid,text,uuid,oid,uuid,integer,integer,timestamp with time zone)',
 'gc_authn.revoke_application_bridge_v1(uuid,text,text,oid,oid,text,uuid,text)',
 'gc_authn.application_bridge_update()','gc_authn.application_bridge_complete()',
 'gc_app_protected_session_v1(text,text)'}

class Harness(content.Harness):
 def __init__(self):
  content.REPORT=REPORT
  super().__init__()
  self.report.update(command='python3 scripts/runtime-test-application-authn-bridge.py --run-local',profile='isolated-application-authn-bridge-sql037')
  self.save(final=True)

def metadata(h):
 return {key:json.loads(h.sql(statement)) for key,statement in [('functions',FUNCTIONS),('privileges',content.PRIVILEGES),('triggers',content.TRIGGERS),('types',TYPES)]}

def preserve(before,after,app_oid):
 old={r['signature']:r for r in before['functions']};new={r['signature']:r for r in after['functions']}
 require(all(new.get(k)==v for k,v in old.items()),'Prior function OID/body/interface/ACL changed')
 require(set(new)-set(old)==NEW_FUNCTIONS,'Unexpected bridge functions')
 old_tables={r['name']:r for r in before['privileges']['tables']};new_tables={r['name']:r for r in after['privileges']['tables']}
 require(set(new_tables)-set(old_tables)==TABLES and all(new_tables.get(k)==v for k,v in old_tables.items()),'Prior table ACL/RLS/owner changed')
 require({k:v for k,v in before['privileges'].items() if k!='tables'}=={k:v for k,v in after['privileges'].items() if k!='tables'},'Native roles or memberships changed')
 key=lambda r:(r['schema'],r['table'],r['name'])
 old={key(r):r for r in before['triggers']};new={key(r):r for r in after['triggers']}
 require(all(new.get(k)==v for k,v in old.items()) and len(new)-len(old)==7,'Prior triggers changed or bridge trigger count differs')
 require(all(k[0]+'.'+k[1] in TABLES for k in set(new)-set(old)),'Unexpected trigger target')
 old={r['name']:r for r in before['types']};new={r['name']:r for r in after['types']}
 require(set(new)-set(old)==TABLES|{'gc_authn._application_bridge_installations','gc_authn._application_bridge_receipts'},'Unexpected type additions')
 for name,row in old.items():
  observed=new[name]
  if name!='public.gc_authn_authenticated_session':require(observed==row,'Existing type changed');continue
  require(observed['metadata']==row['metadata'],'Public result type metadata changed')
  wanted={json.dumps(r,sort_keys=True) for r in row['acl']}
  wanted.add(json.dumps({'grantee':str(app_oid),'grantor':row['metadata']['typowner'],'privilege_type':'USAGE','is_grantable':False},sort_keys=True))
  require({json.dumps(r,sort_keys=True) for r in observed['acl']}==wanted,'Unexpected public type privilege change')

def execute(h):
 read.setup(h);read.additional_roles(h,48)
 target=h.folder/'application-authn-target';target.mkdir()
 for name in NAMES[:-1]:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
 h.phase='application-authn-install036'
 require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==NAMES[30:-1],'Exact SQL031–036 baseline required')
 read.config_offset(h,0);volume.native_suite(h,PHASES[0],SEED,1)
 h.phase='application-authn-before037'
 tables=volume.canonical_tables(h);snapshot=read.snapshot(h,tables);ledger=read.ledger(h,NAMES[:-1]);before=metadata(h)
 require(all(snapshot['gc_authn.'+n]['rows']>0 for n in ['sessions','session_provenance','session_events']),'Protected predecessor history must be populated')
 app_oid=int(h.sql("SELECT oid FROM pg_roles WHERE rolname='gc_app';"))
 shutil.copyfile(ROOT/'packages/db/migrations'/MIGRATION,target/MIGRATION)
 roles=module(ROOT/'scripts/authentication_roles.py','application_authn_deployment_roles')
 h.phase='application-authn-upgrade037'
 try:
  h.sql(roles.prepare_sql(authority.base.OWNER,authority.base.DATABASE))
  require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[MIGRATION],'Exactly SQL037 must apply')
 finally:h.sql(roles.finish_sql(authority.base.OWNER))
 current_tables=volume.canonical_tables(h);current=metadata(h);current_ledger=read.ledger(h,NAMES)
 (h.folder/'metadata-before.json').write_text(json.dumps(before,sort_keys=True))
 (h.folder/'metadata-after.json').write_text(json.dumps(current,sort_keys=True))
 require(set(current_tables)-set(tables)==TABLES and set(tables)<=set(current_tables),'Unexpected table additions')
 preserve(before,current,app_oid)
 require(read.snapshot(h,tables)==snapshot and current_ledger[:-1]==ledger,'Migration changed retained rows or ledger')
 require(h.sql("SELECT has_function_privilege('gc_app','public.gc_app_protected_session_v1(text,text)','EXECUTE') AND NOT has_schema_privilege('gc_app','gc_authn','USAGE');").strip()=='t','Exact inert native reader grant required')
 h.report['installation']={'before':snapshot,'priorLedger':ledger,'ledger':current_ledger,'preservation':True,'metadataBeforeSha256':sha(json.dumps(before,sort_keys=True).encode()),'metadataAfterSha256':sha(json.dumps(current,sort_keys=True).encode())}
 def replay(phase):
  h.phase=phase;saved=read.snapshot(h,current_tables)
  checks=h.report.setdefault('replayChecks',{}).setdefault(phase,{})
  for name,ok in [('migrationNoop','Applied' not in h.migrate(target).stdout),('ledgerPreserved',read.ledger(h,NAMES)==current_ledger),('tableInventoryPreserved',volume.canonical_tables(h)==current_tables),('rowsPreserved',read.snapshot(h,current_tables)==saved),('metadataPreserved',metadata(h)==current)]:
   checks[name]=bool(ok);require(ok,'Replay changed '+name)
 replay('application-authn-replay-before')
 read.config_offset(h,1);volume.native_suite(h,PHASES[1],NATIVE,EXPECTED_TESTS)
 replay('application-authn-replay-populated')
 require(sources()==h.frozen and [r['phase'] for r in h.report['nativeSuites']]==list(PHASES),'Source or phase drift')
 h.report.update(sources=h.frozen,migrations=current_ledger,sourceHashesMatched=True,nativeTotals={k:sum(r['tests'][k] for r in h.report['nativeSuites']) for k in ('tests','pass','fail','cancelled','skipped','todo')},limitations=['Native SQL issuance and protected application reader only; no OIDC browser or main-application cutover claim.','Authentication is held-snapshot admission, not commit-linearized content mutation or canonical authority activation.','Existing independent 50-outcome pipeline remains mandatory; this new gate does not replace any preceding outcome.'])

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');args=parser.parse_args();require(args.run_local,'Explicit --run-local required')
 h=Harness();failed=False
 try:execute(h)
 except BaseException as error:
  failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private evidence')
  controlled={"Prior function OID/body/interface/ACL changed","Unexpected bridge functions","Prior table ACL/RLS/owner changed","Native roles or memberships changed","Prior triggers changed or bridge trigger count differs","Unexpected trigger target","Unexpected type additions","Existing type changed","Public result type metadata changed","Unexpected public type privilege change","Unexpected table additions"}
  if type(error) is RuntimeError and str(error) in controlled:h.report['failedAssertion']=str(error)
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    observed=h.inventory();(h.folder/'resources-after.json').write_text(json.dumps(observed,sort_keys=True)+'\n');require(observed==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:failed=True;h.report['cleanupErrorType']=type(error).__name__
  finally:
   try:h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Generated credential cleanup refused');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
   except BaseException as error:failed=True;h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=False;h.report['credentialCleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
