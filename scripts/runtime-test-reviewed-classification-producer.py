#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Populated SQL034-to035 producer installation qualification; inactive authority."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'.local/evidence/reviewed-classification-producer.json'
MIGRATION='035_reviewed_classification_producer.sql'
NEW_TEST='tests/qualification/classification-producer-binding.test.ts'
PHASE='reviewed-classification-producer-native'
FACT_TEST='tests/qualification/reviewed-classification-facts.test.ts'
FACT_PHASE='reviewed-classification-facts-native'
EXPECTED_FACT_TESTS=25
EXPECTED_TESTS=23
EXECUTION_SECONDS=780
CLEANUP_SECONDS=90
WRAPPER_SECONDS=900

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
predecessor=module(ROOT/'scripts/runtime-test-classification-label-identities.py','reviewed_producer_predecessor')
read,authority,volume=predecessor.read,predecessor.authority,predecessor.volume
require,sha=predecessor.require,predecessor.sha
_original_sources=predecessor.sources
NAMES=[*predecessor.NAMES,MIGRATION]
PHASES=(*predecessor.PHASES,PHASE,FACT_PHASE)

def sources():
 require(sorted(p.name for p in (ROOT/'packages/db/migrations').glob('*.sql'))==NAMES,'Exactly immutable SQL001–035 required')
 paths={r['path'] for r in _original_sources()}|{NEW_TEST,FACT_TEST,'tests/fixtures/reviewed-classification-facts.ts',
  'scripts/runtime-test-reviewed-classification-producer.py','scripts/test_reviewed_classification_producer.py','packages/db/migrations/'+MIGRATION}
 pending=[ROOT/p for p in paths if p.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for name in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',volume.source_file(current).read_text()):
   candidate=Path(os.path.abspath(current.parent/name))
   if candidate.suffix=='.js' and not candidate.exists():candidate=candidate.with_suffix('.ts')
   if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').exists() else candidate/'index.ts'
   candidate=volume.source_file(candidate);rel=str(candidate.relative_to(ROOT))
   if rel not in paths:
    paths.add(rel)
    if candidate.suffix in ('.ts','.tsx'):pending.append(candidate)
 require(len(paths)<=1024,'Qualification source inventory exceeds bound')
 return [{'path':p,'sha256':sha(volume.source_file(ROOT/p).read_bytes())} for p in sorted(paths)]

# The unchanged034 executor still installs only its explicit34-file prefix and
# checks its own50 native outcomes. It observes the new whole-run source closure.
predecessor.sources=sources
volume.sources=sources
volume.PHASES=PHASES
volume.effective_sources=lambda rows,phase:rows if phase in PHASES else (_ for _ in ()).throw(RuntimeError('Undeclared native phase'))

class Harness(predecessor.Harness):
 def __init__(self):
  predecessor.REPORT=REPORT
  predecessor.sources=sources
  super().__init__()
  self.report.update(command='python3 scripts/runtime-test-reviewed-classification-producer.py --run-local',
   profile='isolated-reviewed-classification-facts-sql035')
  self.save(final=True)

TABLE_ADDITIONS={'gc_authority.classification_producer_installations','gc_authority.classification_producer_heads'}
FUNCTION_ADDITIONS={
 'gc_authority.classification_producer_request_encoding_v1(gc_authority.classification_producer_installations)',
 'gc_authority.classification_producer_manifest_encoding_v1(gc_authority.classification_producer_installations)',
 'gc_authority.classification_producer_receipt_v1(gc_authority.classification_producer_installations)',
 'gc_authority.validate_classification_producer_receipt_v1(gc_authority.classification_producer_installations)',
 'gc_authority.validate_classification_producer_write_v1(gc_authority.classification_producer_installations)',
 'gc_authority.classification_producer_guard_v1()','gc_authority.classification_producer_complete_v1()',
 'gc_authority.write_binding_complete_v2()',
 'gc_authority.change_reviewed_classification_producer_v1(text,uuid,text,text,oid,oid,uuid,bigint,bigint,bigint,integer,uuid,uuid,integer,text,uuid,integer)',
 'gc_authority.install_reviewed_classification_producer_v1(uuid,text,text,oid,oid,uuid,bigint,bigint,bigint,integer,uuid,uuid,integer,text,uuid,integer)',
 'gc_authority.revoke_reviewed_classification_producer_v1(uuid,text,text,oid,oid,uuid,bigint,bigint,bigint,integer,uuid,uuid,integer,text)',
 'gc_authority.load_reviewed_classification_producer_v1(text)'}
TRIGGER_TARGET=('gc_authority','write_bindings','authority_binding_complete')
TRIGGER_ADDITIONS={('gc_authority',table,name) for table,name in [
 ('classification_producer_installations','authority_no_truncate'),('classification_producer_heads','authority_no_truncate'),
 ('classification_producer_installations','classification_producer_receipt_immutable'),
 ('classification_producer_installations','classification_producer_installation_guard'),
 ('classification_producer_heads','classification_producer_head_guard'),
 ('classification_producer_installations','classification_producer_receipt_complete'),
 ('classification_producer_heads','classification_producer_head_complete')]}

def preserve_installation(before_tables,before_functions,before_privileges,before_triggers,
                          after_tables,after_functions,after_privileges,after_triggers):
 require(set(after_tables)-set(before_tables)==TABLE_ADDITIONS and set(before_tables)<=set(after_tables),'Exactly two private producer tables required')
 functions={r['signature']:r for r in after_functions}
 require(len(functions)==len(after_functions) and all(functions.get(r['signature'])==r for r in before_functions),'Prior functions/interface/ACL changed')
 require(set(functions)-{r['signature'] for r in before_functions}==FUNCTION_ADDITIONS,'Producer function additions differ')
 old={r['name']:r for r in before_privileges['tables']};new={r['name']:r for r in after_privileges['tables']}
 require(set(new)-set(old)==TABLE_ADDITIONS and all(new.get(k)==v for k,v in old.items()),'Prior table ACL/RLS/ownership changed')
 require({k:v for k,v in before_privileges.items() if k!='tables'}=={k:v for k,v in after_privileges.items() if k!='tables'},'Role flags/memberships changed')
 require(all(new[n]['rls'] is True and new[n]['forced'] is True for n in TABLE_ADDITIONS),'Producer tables must force RLS')
 key=lambda r:(r['schema'],r['table'],r['name'])
 old={key(r):r for r in before_triggers};new={key(r):r for r in after_triggers}
 require(len(new)==len(after_triggers) and set(new)-set(old)==TRIGGER_ADDITIONS and set(old)<=set(new),'Producer trigger additions differ')
 require(TRIGGER_TARGET in old,'Missing original binding completion guard')
 for k,v in old.items():
  expected=dict(v)
  if k==TRIGGER_TARGET:
   require(expected['function']=='gc_authority.deferred_complete()','Original binding completion function differs')
   expected['function']='gc_authority.write_binding_complete_v2()'
   original=expected['definition'];expected['definition']=original.replace('gc_authority.deferred_complete()','gc_authority.write_binding_complete_v2()')
   require(expected['definition']!=original,'Original binding completion target differs')
  require(new[k]==expected,'Prior trigger changed beyond exact binding completion target')

def install_prebaseline_fixture_wrapper(predecessor, authority, require, sha):
    original_seed = predecessor.seed_baselines

    def seed(h):
        fixtures = original_seed(h)
        h.phase = 'reviewed-classification-prebaseline-seed'
        candidates = json.loads(h.sql("""SET statement_timeout='25s'; SET lock_timeout='2s';
SELECT coalesce(jsonb_agg(to_jsonb(candidate)),'[]') FROM (
 SELECT a.tenant_id,a.id assignment_id,a.asset_id,a.taxonomy_id,a.label_key,a.version assignment_version,
 ar.suggestion_id,ar.approval_request_id,e.asset_version,e.rule_id,e.rule_version,
 rv.taxonomy_version,tv.definition,tv.definition_hash taxonomy_hash,r.requester_id,
 r.workflow_id,r.workflow_version,w.current_version workflow_head_version,
 (SELECT count(*) FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id) tasks,
 (SELECT count(*) FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id AND t.status='decided') decided_tasks,
 (SELECT count(*) FROM public.approval_decisions d WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id) decisions,
 (SELECT count(*) FROM public.approval_decisions d WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND d.decision='approve') approvals,
 (SELECT count(*) FROM public.classification_assignments other WHERE other.tenant_id=a.tenant_id AND other.asset_id=a.asset_id) assignments
 FROM public.classification_assignments a
 JOIN public.classification_assignment_revisions ar ON (ar.tenant_id,ar.assignment_id,ar.version)=(a.tenant_id,a.id,a.version)
 JOIN public.classification_evaluations e ON (e.tenant_id,e.id)=(ar.tenant_id,ar.suggestion_id)
 JOIN public.classification_rule_versions rv ON (rv.tenant_id,rv.rule_id,rv.version)=(e.tenant_id,e.rule_id,e.rule_version)
 JOIN public.classification_rules rh ON (rh.tenant_id,rh.id)=(rv.tenant_id,rv.rule_id)
 JOIN public.classification_taxonomies th ON (th.tenant_id,th.id)=(rv.tenant_id,rv.taxonomy_id)
 JOIN public.classification_taxonomy_versions tv ON (tv.tenant_id,tv.taxonomy_id,tv.version)=(th.tenant_id,th.id,th.current_version)
 JOIN public.approval_requests r ON (r.tenant_id,r.id)=(ar.tenant_id,ar.approval_request_id)
 JOIN public.workflow_definitions w ON (w.tenant_id,w.id)=(r.tenant_id,r.workflow_id)
 JOIN public.assets asset ON (asset.tenant_id,asset.id)=(a.tenant_id,a.asset_id)
 JOIN public.memberships m ON (m.tenant_id,m.identity_id)=(a.tenant_id,r.requester_id)
 JOIN public.identities i ON i.id=m.identity_id
 WHERE a.status='active' AND a.version=1 AND ar.status='active'
 AND r.binding='classification.review' AND r.status='succeeded'
 AND r.workflow_version=1 AND w.current_version=2
 AND rv.taxonomy_version=1 AND th.current_version=1 AND e.rule_version=1 AND rh.current_version=1
 AND rv.definition->>'status'='active' AND asset.status='active'
 AND asset.name='email_address' AND asset.version=e.asset_version
 AND m.active AND i.active AND m.permissions @> '["catalog:read","classification:read","classification:write","models:read","models:write"]'::jsonb
 AND NOT EXISTS(SELECT 1 FROM gc_authn.tenant_fences f WHERE f.tenant_id=a.tenant_id)
 AND NOT EXISTS(SELECT 1 FROM gc_authority.tenant_heads h WHERE h.tenant_id=a.tenant_id)
) candidate;"""))
        require(type(candidates) is list and len(candidates) == 1,
                'Exactly one unchanged pre032 workflow-pin assignment is required')
        row = candidates[0]
        require(all(row[key] == 2 for key in ('tasks', 'decided_tasks', 'decisions', 'approvals'))
                and row['assignments'] == 1, 'Original independent quorum proof differs')
        tenant = str(uuid.UUID(row['tenant_id']))
        taxonomy = str(uuid.UUID(row['taxonomy_id']))
        actor = str(uuid.UUID(row['requester_id']))
        quote = authority.literal
        scope = 'tenant_id=' + quote(tenant) + '::uuid'
        proof_tables = [
            'assets', 'asset_revisions', 'sources', 'jobs', 'memberships',
            'classification_assignments', 'classification_assignment_revisions', 'classification_evaluations',
            'classification_rules', 'classification_rule_versions', 'approval_requests', 'approval_tasks',
            'approval_decisions', 'approval_dispatch', 'workflow_definitions', 'workflow_definition_versions']
        parts = ["SELECT " + quote(name) + " name,coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') rows "
                 "FROM public." + name + " r WHERE " + scope for name in proof_tables]
        parts += ["SELECT 'historical_taxonomy' name,coalesce(jsonb_agg(to_jsonb(r) ORDER BY version),'[]') rows "
                  "FROM public.classification_taxonomy_versions r WHERE " + scope + " AND taxonomy_id=" + quote(taxonomy) + "::uuid AND version=1",
                  "SELECT 'original_identities' name,coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') rows "
                  "FROM public.identities r WHERE id IN(SELECT identity_id FROM public.memberships WHERE " + scope + ")"]
        proof_sql = "SET statement_timeout='25s'; SET lock_timeout='2s'; SELECT jsonb_object_agg(name,rows) FROM (" + ' UNION ALL '.join(parts) + ') proof;'
        before = json.loads(h.sql(proof_sql))
        require(all(before[name] for name in ('classification_assignments', 'classification_assignment_revisions',
                    'classification_evaluations', 'approval_requests', 'approval_tasks', 'approval_decisions',
                    'workflow_definition_versions', 'asset_revisions', 'historical_taxonomy')),
                'Preserved assignment lacks a real canonical proof family')

        def journal_state():
            return json.loads(h.sql("SET statement_timeout='25s'; SET lock_timeout='2s'; SELECT jsonb_build_object("
                "'audit',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM public.audit r WHERE " + scope + "),"
                "'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM public.outbox r WHERE " + scope + "),"
                "'idempotency',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY actor_id,operation,key),'[]') FROM public.idempotency r WHERE " + scope + "),"
                "'revision',(SELECT revision::text FROM gc_authority.content_security_heads WHERE " + scope + "));"))

        journals_before = journal_state()
        definition = dict(row['definition'])
        definition['name'] = 'Synthetic prebaseline taxonomy publication'
        request_id = str(uuid.uuid4())
        body = json.dumps({'id': taxonomy, 'expectedVersion': 1, 'definition': definition}, separators=(',', ':'))
        # A native owner connection, not SET ROLE or direct source/version DML.
        h.sql("BEGIN; SET LOCAL statement_timeout='25s'; SET LOCAL lock_timeout='2s'; DO $fixture$ BEGIN "
              "PERFORM set_config('gc.tenant_id'," + quote(tenant) + ",true);"
              "PERFORM set_config('gc.actor_id'," + quote(actor) + ",true);"
              "PERFORM public.gc_classification_command('classification.taxonomy.publish'," + quote(request_id) + "," + quote(body) +
              "::jsonb,'reviewed-classification-prebaseline'); END $fixture$; SET CONSTRAINTS ALL IMMEDIATE; COMMIT;",
              role=authority.base.OWNER)
        require(json.loads(h.sql(proof_sql)) == before, 'Canonical taxonomy publication changed original reviewed proof')
        journals_after = journal_state()
        added = {}
        for name in ('audit', 'outbox', 'idempotency'):
            prior = journals_before[name]
            current = journals_after[name]
            require(all(item in current for item in prior) and len(current) == len(prior) + 1,
                    'Canonical publisher did not preserve original journals with exactly one new row')
            added[name] = [item for item in current if item not in prior]
            require(len(added[name]) == 1, 'Canonical publication journal difference is not exact')
        require(added['audit'][0]['id'] == added['outbox'][0]['id']
                and added['audit'][0]['action'] == 'classification.taxonomy.publish'
                and added['outbox'][0]['event_type'] == 'classification.taxonomy.publish'
                and added['idempotency'][0]['operation'] == 'classification.taxonomy.publish'
                and added['idempotency'][0]['key'] == request_id
                and int(journals_after['revision']) == int(journals_before['revision']) + 1,
                'Canonical taxonomy journal/SQL033 revision delta differs')
        current = json.loads(h.sql("SET statement_timeout='25s'; SELECT jsonb_build_object('version',h.current_version,'hash',v.definition_hash,'definition',v.definition) "
            "FROM public.classification_taxonomies h JOIN public.classification_taxonomy_versions v "
            "ON (v.tenant_id,v.taxonomy_id,v.version)=(h.tenant_id,h.id,h.current_version) WHERE h.tenant_id=" + quote(tenant) +
            "::uuid AND h.id=" + quote(taxonomy) + "::uuid;"))
        require(current['version'] == 2 and current['definition'] == definition,
                'Prebaseline taxonomy2 publication must be exact')
        marker = {'formatVersion': 1, 'tenantId': tenant, 'assetId': row['asset_id'], 'assetVersion': row['asset_version'],
                  'assignmentId': row['assignment_id'], 'assignmentVersion': 1, 'suggestionId': row['suggestion_id'],
                  'approvalRequestId': row['approval_request_id'], 'taxonomyId': taxonomy, 'labelKey': row['label_key'],
                  'historicalTaxonomyVersion': 1, 'historicalTaxonomyHash': row['taxonomy_hash'],
                  'baselineVersion': 2, 'baselineHash': current['hash'], 'requesterId': actor,
                  'ruleId': row['rule_id'], 'ruleVersion': 1}
        config = json.loads(h.secret_path.read_text())
        require('reviewedClassificationPreBaselineFixture' not in config, 'Prebaseline marker already exists')
        config['reviewedClassificationPreBaselineFixture'] = marker
        h.secret_path.write_text(json.dumps(config)); h.secret_path.chmod(0o600)
        h.report['privateConfigSha256'] = sha(h.secret_path.read_bytes())
        h.report['prebaselineClassificationFixture'] = {
            'originalProofPreserved': True, 'originalProofSha256': sha(json.dumps(before, sort_keys=True).encode()),
            'markerSha256': sha(json.dumps(marker, sort_keys=True).encode()),
            'historicalTaxonomyVersion': 1, 'baselineVersion': 2,
            'newPairedJournalRows': 1, 'contentRevisionDelta': 1}
        return fixtures

    predecessor.seed_baselines = seed

install_prebaseline_fixture_wrapper(predecessor, authority, require, sha)

def execute(h):
 predecessor.execute(h)
 h.report['predecessor034']={key:h.report[key] for key in ('installation','populatedReplay','nativeTotals')}
 # Provision the additional synthetic principals before the035 ACL baseline.
 # Native tests may not silently change the baseline during replay qualification.
 h.phase='reviewed-producer-test-principals';read.additional_roles(h,128)
 target=h.folder/'reviewed-producer-target';target.mkdir()
 for name in NAMES:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
 h.phase='reviewed-producer-before035'
 tables=volume.canonical_tables(h);before=read.snapshot(h,tables);prior=read.ledger(h,predecessor.NAMES)
 functions=json.loads(h.sql(read.FUNCTIONS));privileges=json.loads(h.sql(predecessor.PRIVILEGES));triggers=json.loads(h.sql(predecessor.TRIGGERS))
 h.phase='reviewed-producer-install035'
 require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[MIGRATION],'Exactly035 must apply')
 ledger=read.ledger(h,NAMES);current_tables=volume.canonical_tables(h)
 current_functions=json.loads(h.sql(read.FUNCTIONS));current_privileges=json.loads(h.sql(predecessor.PRIVILEGES));current_triggers=json.loads(h.sql(predecessor.TRIGGERS))
 preserve_installation(tables,functions,privileges,triggers,current_tables,current_functions,current_privileges,current_triggers)
 require(ledger[:-1]==prior and read.snapshot(h,tables)==before,'SQL035 changed prior rows/epochs/ledger')
 require(all(v['rows']==0 for v in read.snapshot(h,sorted(TABLE_ADDITIONS)).values()),'Migration must not select or install a producer')
 h.report['installation']={'before':before,'priorLedger':prior,'ledger':ledger,'preservation':True,
  'addedTables':sorted(TABLE_ADDITIONS),'addedFunctions':sorted(FUNCTION_ADDITIONS),'addedTriggers':sorted(TRIGGER_ADDITIONS),
  'changedTriggerTarget':TRIGGER_TARGET,'functionsBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),
  'functionsAfterSha256':sha(json.dumps(current_functions,sort_keys=True).encode()),
  'privilegesBeforeSha256':sha(json.dumps(privileges,sort_keys=True).encode()),'privilegesAfterSha256':sha(json.dumps(current_privileges,sort_keys=True).encode()),
  'triggersBeforeSha256':sha(json.dumps(triggers,sort_keys=True).encode()),'triggersAfterSha256':sha(json.dumps(current_triggers,sort_keys=True).encode())}
 def replay(phase):
  h.phase=phase;snapshot=read.snapshot(h,current_tables)
  checks=h.report.setdefault('replayChecks',{}).setdefault(phase,{})
  def checked(name,passed):
   checks[name]=bool(passed);require(passed,'Replay changed '+name)
  checked('migrationNoop','Applied' not in h.migrate(target).stdout)
  checked('ledgerPreserved',read.ledger(h,NAMES)==ledger)
  checked('tableInventoryPreserved',volume.canonical_tables(h)==current_tables)
  checked('rowsPreserved',read.snapshot(h,current_tables)==snapshot)
  checked('functionsPreserved',json.loads(h.sql(read.FUNCTIONS))==current_functions)
  checked('privilegesPreserved',json.loads(h.sql(predecessor.PRIVILEGES))==current_privileges)
  checked('triggersPreserved',json.loads(h.sql(predecessor.TRIGGERS))==current_triggers)
  return snapshot
 replay('reviewed-producer-replay-before');h.report['installation']['replayBefore']=True
 require(len(re.findall(r'^test\(', (ROOT/NEW_TEST).read_text(),re.M))==EXPECTED_TESTS,'Declared producer native inventory differs')
 read.config_offset(h,48);volume.native_suite(h,PHASE,NEW_TEST,EXPECTED_TESTS)
 require(len(re.findall(r'^test\(', (ROOT/FACT_TEST).read_text(),re.M))==EXPECTED_FACT_TESTS,'Declared fact native inventory differs')
 read.config_offset(h,80);volume.native_suite(h,FACT_PHASE,FACT_TEST,EXPECTED_FACT_TESTS)
 populated=replay('reviewed-producer-populated-replay')
 require(sources()==h.frozen and [r['phase'] for r in h.report['nativeSuites']]==list(PHASES),'Source or phase drifted')
 h.report.update(sources=h.frozen,migrations=ledger,sourceHashesMatched=True,
  nativeTotals={key:sum(r['tests'][key] for r in h.report['nativeSuites']) for key in ('tests','pass','fail','cancelled','skipped','todo')},
  populatedReplay={'snapshot':populated,'preservation':True},
  limitations=['Explicit producer installation and same-snapshot reviewed classification reader only; no held effect executor, ingress cutover or content-authority activation qualified.',
   'The exact50 predecessor cases run before035; original schemas and preserved receipts remain distinct from new producer and reviewed-fact behavior.',
   'One780-second execution budget includes source admission and both schemas;90-second owned cleanup and900-second wrapper remain unchanged.',
   'Cached dependencies and exact current read-only source mounts; no build, live-vendor or release qualification.'])

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');args=parser.parse_args()
 require(args.run_local,'Explicit --run-local required');h=Harness();failed=False
 try:execute(h)
 except BaseException as error:
  failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private evidence')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    observed=h.inventory();(h.folder/'resources-after.json').write_text(json.dumps(observed,sort_keys=True)+'\n')
    require(observed==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:failed=True;h.report['cleanupErrorType']=type(error).__name__
  finally:
   try:
    h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Generated credential cleanup refused');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
   except BaseException as error:
    failed=True;h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=False;h.report['credentialCleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
