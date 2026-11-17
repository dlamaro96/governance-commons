#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL017→018 native glossary population upgrade; disposable PostgreSQL only."""
from datetime import datetime, timezone
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
import re
import shutil

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'policies'))
import glossary_population_diagnostics as diagnostics
spec=importlib.util.spec_from_file_location('glossary_population_upgrade_base',ROOT/'scripts/runtime-test-relation-scope-upgrade.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
REPORT=ROOT/'.local/evidence/glossary-population-upgrade.json'
MIGRATION='018_glossary_nominal_candidates.sql'
MIGRATIONS=ROOT/'packages/db/migrations'
NAMES=[*base.NAMES,base.MIGRATION]
TESTS=[*base.TESTS,'tests/qualification/glossary-population.test.ts']
require,sha=base.require,base.sha
# Stable aliases for subsequent gates, without exposing this predecessor depth.
tap_summary=base.base.base.base.base.tap_summary


def sources():
 return diagnostics.source_inventory(ROOT)


def canonical_snapshot(h,tables):
 """Hash the same sorted canonical row JSON in PostgreSQL, before returning it.

 The real predecessor leaves more than eleven thousand assets and revisions.
 Returning their complete arrays would breach the inherited 4MiB command cap;
 compact counts/digests preserve every row without increasing that cap.
 """
 result={}
 for table in tables:
  require(re.fullmatch(r'[a-z_]+\.[a-z_]+',table),'Invalid fixed snapshot table')
  result[table]=json.loads(h.sql(f"SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]')::text,'UTF8')),'hex')) FROM {table} r;"))
  row=result[table]
  require(set(row)=={'rows','sha256'} and type(row['rows']) is int and row['rows']>=0 and re.fullmatch(r'[a-f0-9]{64}',row['sha256']),'Invalid canonical snapshot')
 return result


class Harness(base.Harness):
 def __init__(self):
  base.REPORT=REPORT
  super().__init__()
  self.report.update(command='./dev test --suite glossary-population-upgrade',profile='isolated-glossary-population')
  self.last_command,self.command_failure=None,None
  if re.fullmatch(r'[a-f0-9]{40}',os.environ.get('GITHUB_SHA','')):self.report['commit']=os.environ['GITHUB_SHA']

 def command(self,args,**kwargs):
  phase,serial,started=self.phase,self.serial,time.monotonic()
  self.last_command=None;error=None
  try:return super().command(args,**kwargs)
  except BaseException as caught:error=caught;raise
  finally:
   elapsed=max(0,min(3600000,round((time.monotonic()-started)*1000)))
   log=self.folder/f'{self.serial:03d}-{phase}.log'
   if self.serial>serial and log.is_file():self.last_command={'phase':phase,'path':str(log.relative_to(ROOT)),'elapsedMs':elapsed}
   if error is not None and self.command_failure is None:
    category='interrupted' if isinstance(error,KeyboardInterrupt) else 'command_timeout' if str(error)=='Bounded qualification command timed out' else 'command_failed'
    self.command_failure=self.failure_record(phase,category,self.last_command,elapsed)

 def failure_record(self,phase,category,command=None,elapsed=0):
  if command is None or command['phase']!=phase:return {'phase':phase,'category':'interrupted' if category=='interrupted' else 'unknown','commandLog':None,'elapsedMs':elapsed}
  path=ROOT/command['path'];data=path.read_bytes();header=re.match(rb'phase=[a-z0-9_-]+\nexit=(-?[0-9]+)\n',data)
  if header is None or (category in ('command_failed','suite_failed') and int(header[1])==0):return {'phase':phase,'category':'unknown','commandLog':None,'elapsedMs':elapsed}
  marker=('\n'+diagnostics.MARKER+category+'\n').encode();path.write_bytes(data+marker);self.output_bytes+=len(marker)
  return {'phase':phase,'category':category,'commandLog':{'path':command['path'],'sha256':sha(data+marker)},'elapsedMs':command['elapsedMs']}

 def remember_failure(self,error):
  if 'failure_diagnostic' in self.report:return
  if self.command_failure is not None:failure=self.command_failure
  elif self.phase.endswith('-native-tests') and self.last_command is not None and self.last_command['phase']==self.phase:
   data=(ROOT/self.last_command['path']).read_bytes();code=re.match(rb'phase=[a-z0-9_-]+\nexit=(-?[0-9]+)\n',data)
   failure=self.failure_record(self.phase,'suite_failed',self.last_command) if code and int(code[1])!=0 else {'phase':self.phase,'category':'invariant_failed','commandLog':None,'elapsedMs':0}
  else:failure={'phase':self.phase,'category':'interrupted' if isinstance(error,KeyboardInterrupt) else 'invariant_failed','commandLog':None,'elapsedMs':0}
  self.report['failure_diagnostic']=failure



def execute(h):
 frozen=sources()
 h.report['diagnostic_sources']=frozen
 # Run the actual SQL001–017 predecessor and all 25 native scope cases. Historical
 # reports never stand in for execution, and original checks remain in the report.
 base.execute(h)
 h.report['predecessor_scope_tests']=dict(h.report['tests'])
 h.report['sources']=frozen
 h.phase='population-predecessor'
 tables=json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
 before=canonical_snapshot(h,tables)
 ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 require(len(NAMES)==17 and [row['name'] for row in ledger]==NAMES,'Expected exact SQL001–017 predecessor ledger')
 target=h.folder/'glossary-population-target';target.mkdir()
 for name in [*NAMES,MIGRATION]:shutil.copyfile(MIGRATIONS/name,target/name)
 h.phase='glossary-population-upgrade'
 result=h.migrate(target)
 require(re.findall(r'^Applied (.+)$',result.stdout,re.MULTILINE)==[MIGRATION],'Expected exact SQL018 application')
 require(canonical_snapshot(h,tables)==before,'Population upgrade changed predecessor canonical/history rows')
 after=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 require(after[:17]==ledger and len(after)==18 and after[-1]['name']==MIGRATION,'Population upgrade changed predecessor ledger')
 require('Applied' not in h.migrate(target).stdout,'Population migration replay reapplied a migration')
 require(canonical_snapshot(h,tables)==before,'Population replay changed predecessor canonical/history rows')
 require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))==after,'Population replay changed migration ledger')
 h.report['populationUpgradeBaseline']=[{'table':name,**row} for name,row in before.items()]
 h.report['checks'].append('Exact SQL017→018 application and inert replay preserve full canonical row digests/counts for every predecessor table and the original seventeen migration ledger entries')
 h.phase='population-native-tests'
 expected=sum(len(re.findall(r'^test\(', (ROOT/name).read_text(),re.MULTILINE)) for name in TESTS)
 require(expected==26,'Expected all twenty-five scope cases plus one population case')
 tested=h.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',*TESTS],timeout=300,allow_failure=True)
 require(tested.returncode==0,'Native glossary population suite failed; retained bounded TAP identifies failing case')
 h.report['tests']=tap_summary(tested.stdout,expected)
 require(sources()==frozen,'Population qualification source changed during execution')
 h.report['migrations']=[{'name':name,'sha256':sha((MIGRATIONS/name).read_bytes())} for name in [*NAMES,MIGRATION]]
 h.report['limitations']=['Actual isolated SQL017 predecessor and SQL018 production domain-service qualification; no captured pre-upgrade population failure is claimed.',
  'The population case retains the original thirty-second product transaction budget; API/browser and Temporal restart qualification remain separate.',
  'Canonical content authority remains inactive. No shared runtime or external infrastructure was modified.']


def main():
 h,failed=Harness(),False
 try:execute(h)
 except BaseException as error:
  failed=True;h.remember_failure(error);h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private diagnostics')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:
   failed=True;h.remember_failure(error);h.report.setdefault('failed_phase',h.phase);h.report['cleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)


if __name__=='__main__':raise SystemExit(main())
