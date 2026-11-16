#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL015→016 native approved glossary publication upgrade; disposable PostgreSQL, no shared launch."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('glossary_upgrade_base',ROOT/'scripts/runtime-test-approvals-upgrade.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
REPORT=ROOT/'.local/evidence/glossary-upgrade.json'
MIGRATION='016_glossary_publication.sql'
NAMES=[*base.base.NAMES,base.MIGRATION]
TESTS=['tests/qualification/glossary-publication.test.ts','tests/qualification/glossary-publication-boundaries.test.ts']
require,sha=base.require,base.sha

def sources():
 paths={row['path'] for row in base.sources()}
 paths.update(['scripts/runtime-test-glossary-upgrade.py',*TESTS,'packages/domain/src/glossary-publication-service.ts','packages/domain/src/glossary-service.ts','packages/db/migrations/'+MIGRATION,'apps/api/src/repository.ts','packages/domain/src/approval-service.ts','packages/domain/src/approval.ts','packages/domain/src/approval-contracts.ts','packages/domain/src/glossary.ts','packages/domain/src/glossary-contracts.ts','packages/domain/src/model-service.ts','packages/domain/src/cursor.ts'])
 pending=[ROOT/name for name in paths if name.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''',current.read_text()):
   candidate=(current.parent/relative).resolve()
   if not candidate.suffix:
    candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate/'index.ts'
   require(candidate.is_relative_to(ROOT) and candidate.is_file(),'Unresolved local qualification source')
   name=str(candidate.relative_to(ROOT))
   if name not in paths:paths.add(name);pending.append(candidate)
 return [{'path':name,'sha256':sha((ROOT/name).read_bytes())} for name in sorted(paths)]

class Harness(base.Harness):
 def __init__(self):
  base.REPORT=REPORT
  super().__init__()
  self.report.update(command='./dev test --suite glossary-upgrade',profile='isolated-glossary-publication')

def execute(h):
 frozen=sources()
 # Execute the real predecessor storage gate; retain its original checks.
 base.execute(h)
 h.report['sources']=frozen
 h.phase='glossary-predecessor'
 tables=json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
 before=h.snapshot(tables)
 ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 target=h.folder/'glossary-target';target.mkdir()
 for name in [*NAMES,MIGRATION]:shutil.copyfile(base.base.base.MIGRATIONS/name,target/name)
 h.phase='glossary-upgrade'
 result=h.migrate(target)
 require(re.findall(r'^Applied (.+)$',result.stdout,re.MULTILINE)==[MIGRATION],'Expected exact SQL016 application')
 require(h.snapshot(tables)==before,'Glossary upgrade changed predecessor canonical/history rows')
 after=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 require(after[:15]==ledger and len(after)==16,'Glossary upgrade changed predecessor ledger')
 require('Applied' not in h.migrate(target).stdout and h.snapshot(tables)==before,'Glossary replay changed predecessor rows')
 h.report['checks'].append('Exact SQL015→016 application and inert replay preserve all predecessor canonical, protected, audit and receipt rows and original migration ledger')
 h.phase='glossary-native-tests'
 expected=sum(len(re.findall(r'^test\(', (ROOT/name).read_text(),re.MULTILINE)) for name in TESTS)
 tested=h.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',*TESTS],timeout=180,allow_failure=True)
 require(tested.returncode==0,'Native glossary publication suite failed; retained bounded TAP identifies failing case')
 h.report['tests']=base.base.base.tap_summary(tested.stdout,expected)
 require(sources()==frozen,'Glossary publication source changed during native qualification')
 h.report['migrations']=[{'name':name,'sha256':sha((base.base.base.MIGRATIONS/name).read_bytes())} for name in [*NAMES,MIGRATION]]
 h.report['limitations']=['Approved glossary publication storage and production domain-service paths; API/browser and Temporal restart qualification remain separate.','Canonical content authority remains inactive. No shared runtime or external infrastructure was modified.']

def main():
 h,failed=Harness(),False
 try:execute(h)
 except BaseException as error:
  failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private diagnostics')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:
   failed=True;h.report['cleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)

if __name__=='__main__':raise SystemExit(main())
