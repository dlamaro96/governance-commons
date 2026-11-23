#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual freshness executor checks in the local synthetic source.

No build, bootstrap, HTTP, Temporal or canonical rule authority qualification.
Only this run's owned helper, marker/OID-owned tables and domain are created and removed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid

# Fixed repository layout; no fallback source or candidate mode.
ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('freshness_quality_worker_base', ROOT / 'scripts/runtime-test-quality-worker.py')
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
require, decode = base.require, base.decode
KINDS = ('fresh', 'stale', 'future', 'tolerated', 'infinity', 'outside', 'mixed', 'allinvalid',
         'precision0', 'precision3', 'precision6', 'offset', 'allnull', 'empty', 'naive', 'date',
         'text', 'epoch', 'array', 'domain', 'rls', 'parent', 'child', 'many', 'edge')
CHECKS = [
    'latest_timestamp_recency_and_stale_oracle', 'future_values_cannot_mask_staleness',
    'explicit_future_tolerance', 'infinity_and_unrepresentable_fail_closed_counts',
    'empty_allnull_and_allinvalid_distinct', 'native_precision_zero_three_six',
    'equivalent_offsets_have_identical_max', 'exact_microsecond_template_boundary_oracle',
    'canonical_binding_hash_vector', 'lowered_row_bound_and_100001_refusal',
    'actual_plan_cost_and_bytes_refusal', 'all_eight_target_pins_refused_when_stale',
    'naive_date_text_epoch_array_domain_unsupported', 'rls_and_inheritance_unsupported',
    'native_reader_role_and_read_only_default', 'native_reader_dml_denied',
    'closed_aggregates_without_row_examples', 'actual_lock_timeout_refusal',
]


CANDIDATE = ROOT
OVERLAYS = {name: CANDIDATE / name for name in (
    'python/governance_workers/quality.py', 'python/governance_workers/server.py')}


def source_hashes():
    result = base.source_hashes()
    for path in [Path(__file__).resolve(), *OVERLAYS.values(), Path(__file__).with_name('freshness_quality_worker_program.py')]:
        result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def effective_hashes(recorded):
    result = {p:h for p,h in recorded.items() if p.startswith('python/') and p!='python/Dockerfile'}
    for name,path in OVERLAYS.items(): result[name]=recorded[str(path.relative_to(ROOT))]
    return result


TYPE_INVENTORY_SQL = """SELECT encode(sha256(convert_to(coalesce(jsonb_agg(
 jsonb_build_array(t.oid::text,t.typname,t.typowner::text,t.typtype,t.typbasetype::text,t.typrelid::text,
 t.typarray::text,t.typelem::text,t.typacl::text,t.typnotnull,t.typdefault,obj_description(t.oid,'pg_type')) ORDER BY t.oid),'[]'::jsonb)::text,'UTF8')),'hex')
 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public';"""

WORKER_PATH = Path(__file__).with_name('freshness_quality_worker_program.py')
WORKER = WORKER_PATH.read_text()


def bounded_command(args, data, duration, cwd):
    """Bound both streams while running; no stderr/source/credential echo.

    Only the exact freshly started local process group is signalled. Docker exec
    commands also carry their own remote timeout; no remote orphan depends
    solely on local-client termination.
    """
    require(duration > 0 and (data is None or len(data.encode('utf-8')) <= 65536))
    with tempfile.TemporaryFile() as stdin:
        if data is not None:
            stdin.write(data.encode('utf-8')); stdin.seek(0)
        child = subprocess.Popen(args, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=cwd, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, 'out')
                selector.register(child.stderr, selectors.EVENT_READ, 'err')
                output, counts = bytearray(), {'out': 0, 'err': 0}
                expires = time.monotonic() + duration
                while selector.get_map():
                    require(time.monotonic() < expires)
                    for key, _ in selector.select(min(.1, expires-time.monotonic())):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj);continue
                        counts[key.data] += len(chunk)
                        require(counts[key.data] <= (65536 if key.data=='out' else 8192))
                        if key.data=='out': output.extend(chunk)
                require(child.wait(timeout=max(.001, expires-time.monotonic()))==0)
                return output.decode('utf-8','strict').strip()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)
            child.stdout.close();child.stderr.close()


class Harness(base.Harness):
    def __init__(self):
        super().__init__()
        self.deadline=time.monotonic()+420
        token=uuid.uuid4().hex
        self.marker='freshness-quality-worker:'+token
        self.names={kind:f'gc_fq_{token}_{kind}' for kind in KINDS}
        self.domain_name=f'gc_fq_{token}_dtype'
        self.domain_oid=None
        self.locker_name='gc_fq_lock_'+token
        self.lock_owner=None
        self.helper_name='gc_fq_helper_'+token
        self.helper=None

    def helper_identity(self):
        identifier=self.command(['docker','ps','--all','--quiet','--no-trunc','--filter','name=^/'+self.helper_name+'$'],cleanup=True)
        if not identifier: return None
        require(re.fullmatch(r'[a-f0-9]{64}',identifier))
        fields='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"owner":{{json (index .Config.Labels "io.governance-commons.qualification")}},"mounts":{{json .Mounts}},"autoRemove":{{json .HostConfig.AutoRemove}},"restart":{{json .HostConfig.RestartPolicy.Name}}}'
        value=decode(self.command(['docker','inspect','--format',fields,identifier],cleanup=True))
        require(set(value)=={'id','image','running','owner','mounts','autoRemove','restart'} and value['id']==identifier
                and value['owner']==self.marker and value['image']==self.worker['image']
                and value['autoRemove'] is True and value['restart']=='no')
        for name,path in OVERLAYS.items():
            matches=[m for m in value['mounts'] if m['Destination']=='/worker/'+name.removeprefix('python/')]
            require(len(matches)==1 and matches[0]['Type']=='bind' and matches[0]['RW'] is False
                    and matches[0]['Source']==str(path.resolve()))
        allowed={'/worker/'+name.removeprefix('python/') for name in OVERLAYS}
        require(all(m['Destination'] in allowed or not(m['Destination']=='/worker' or m['Destination'].startswith('/worker/')) for m in value['mounts']))
        return {k:value[k] for k in ('id','image','owner','running')}

    def start_helper(self):
        require(re.fullmatch(r'gc_fq_helper_[a-f0-9]{32}',self.helper_name))
        require(re.fullmatch(r'sha256:[a-f0-9]{64}',self.worker['image']))
        require(not self.command(['docker','ps','--all','--quiet','--filter','name=^/'+self.helper_name+'$']))
        # Compose 2.29 run has no --pull option. A closed override pins the
        # already admitted cached image, forbids pulls, and removes build config.
        # The first Compose file remains unchanged, preserving its secret mounts
        # and security/resource settings. No expanded configuration is emitted.
        content=('services:\n  python-worker:\n    image: "'+self.worker['image']+'"\n'
                 '    pull_policy: never\n    build: !reset null\n    restart: "no"\n')
        with tempfile.TemporaryDirectory(prefix='gc-rq-compose-') as folder:
            override=Path(folder)/'helper.yaml'
            override.write_text(content);override.chmod(0o600)
            compose=[*base.COMPOSE,'-f',str(override)]
            require(self.command(compose+['config','--quiet'],seconds=15)=='')
            require(override.read_text()==content)
            args=compose+['run','--detach','--no-deps','--rm','--name',self.helper_name,
                          '--label','io.governance-commons.qualification='+self.marker]
            for name,path in OVERLAYS.items():
                require(path.is_file() and not path.is_symlink())
                args += ['--volume',str(path.resolve())+':/worker/'+name.removeprefix('python/')+':ro']
            args += ['--entrypoint','/bin/sleep','python-worker','480']
            identifier=self.command(args,seconds=35)
            require(override.read_text()==content)
        require(re.fullmatch(r'[a-f0-9]{64}',identifier))
        self.helper=self.helper_identity()
        require(self.helper is not None and self.helper['id']==identifier and self.helper['running'] is True)

    def cleanup_helper(self):
        if not self.worker: return
        value=self.helper_identity()
        if value is not None:
            if self.helper is not None: require(value['id']==self.helper['id'])
            self.command(['docker','rm','--force',value['id']],seconds=20,cleanup=True)
        require(self.helper_identity() is None)

    def command(self,args,*,data=None,seconds=20,cleanup=False):
        duration=seconds if cleanup else min(seconds,self.deadline-time.monotonic())
        return bounded_command(args,data,duration,ROOT)

    def inventory(self,cleanup=False):
        value={'catalog':self.sql(base.INVENTORY_SQL,cleanup=cleanup),'types':self.sql(TYPE_INVENTORY_SQL,cleanup=cleanup)}
        require(all(re.fullmatch(r'[a-f0-9]{64}',v) for v in value.values()))
        return value

    def prepare(self):
        for kind,name in self.names.items(): require(re.fullmatch(r'gc_fq_[a-f0-9]{32}_'+kind,name))
        require(re.fullmatch(r'gc_fq_[a-f0-9]{32}_dtype',self.domain_name))
        statements=['BEGIN;',f'CREATE DOMAIN public."{self.domain_name}" AS timestamptz;',
                    f"COMMENT ON DOMAIN public.\"{self.domain_name}\" IS '{self.marker}';"]
        for kind,name in self.names.items():
            typ={'precision0':'timestamptz(0)','precision3':'timestamptz(3)','precision6':'timestamptz(6)',
                 'naive':'timestamp','date':'date','text':'text','epoch':'bigint','array':'timestamptz[]',
                 'domain':f'public."{self.domain_name}"'}.get(kind,'timestamptz')
            create=(f'CREATE TABLE public."{name}" () INHERITS (public."{self.names["parent"]}");' if kind=='child'
                    else f'CREATE TABLE public."{name}" (payload {typ});')
            statements += [create,f"COMMENT ON TABLE public.\"{name}\" IS '{self.marker}';",
                           f'REVOKE ALL ON TABLE public."{name}" FROM PUBLIC,harbor_reader;',
                           f'GRANT SELECT ON TABLE public."{name}" TO harbor_reader;']
        values={
          'fresh':"(statement_timestamp()-interval '600 seconds'),(statement_timestamp()-interval '1 second'),(NULL)",
          'stale':"(statement_timestamp()-interval '600 seconds'),(statement_timestamp()-interval '300 seconds'),(NULL)",
          'future':"(statement_timestamp()-interval '600 seconds'),('9999-12-31 23:59:59.999999+00'),(NULL)",
          'tolerated':"(statement_timestamp()+interval '120 seconds'),(NULL)",
          'infinity':"('infinity'),('-infinity'),(NULL)",
          'outside':"('0001-01-01 00:00:00+00 BC'),('10000-01-01 00:00:00+00'),(NULL)",
          'mixed':"('infinity'),('10000-01-01 00:00:00+00'),(statement_timestamp()-interval '1 second'),(NULL)",
          'allinvalid':"('infinity'),('-infinity'),('0001-01-01 00:00:00+00 BC'),('10000-01-01 00:00:00+00'),(NULL)",
          'offset':"('2020-02-29 12:00:00.123456+04'),('2020-02-29 08:00:00.123456+00'),(NULL)",
          'edge':"('2026-01-01 00:00:00.000000+00')",
        }
        for kind in ('precision0','precision3','precision6'): values[kind]="('2020-02-29 12:00:00.123456+04'),(NULL)"
        for kind,rows in values.items(): statements.append(f'INSERT INTO public."{self.names[kind]}" VALUES {rows};')
        statements += [f'INSERT INTO public."{self.names["allnull"]}" SELECT NULL FROM generate_series(1,5);',
                       f"INSERT INTO public.\"{self.names['many']}\" SELECT '2020-01-01 00:00:00+00'::timestamptz FROM generate_series(1,100001);",
                       f'ALTER TABLE public."{self.names["rls"]}" ENABLE ROW LEVEL SECURITY;',
                       f'CREATE POLICY qualification_reader ON public."{self.names["rls"]}" FOR SELECT TO harbor_reader USING(true);']
        for name in self.names.values(): statements.append(f'ANALYZE public."{name}";')
        names=','.join("'"+n+"'" for n in self.names.values())
        statements += [f"SELECT jsonb_build_object('tables',(SELECT jsonb_object_agg(c.relname,jsonb_build_object('oid',c.oid::text,'owner',r.rolname,'marker',obj_description(c.oid,'pg_class'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN({names})),'domain',(SELECT jsonb_build_object('oid',t.oid::text,'owner',r.rolname,'marker',obj_description(t.oid,'pg_type')) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_roles r ON r.oid=t.typowner WHERE n.nspname='public' AND t.typname='{self.domain_name}' AND t.typtype='d'));",'COMMIT;']
        owned=decode(self.sql('\n'.join(statements)))
        require(set(owned)=={'tables','domain'} and set(owned['tables'])==set(self.names.values()))
        for value in [*owned['tables'].values(),owned['domain']]:
            require(set(value)=={'oid','owner','marker'} and re.fullmatch(r'[1-9][0-9]*',value['oid']) and value['owner']=='source_admin' and value['marker']==self.marker)
        self.owned=owned['tables'];self.domain_oid=owned['domain']['oid']

    def fixture_digest(self):
        # ONLY avoids double counting inherited rows; source values never leave PG.
        pieces=[]
        for kind,name in self.names.items():
            pieces.append(f"SELECT '{kind}' AS kind,encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text COLLATE \"C\"),'[]'::jsonb)::text,'UTF8')),'hex') AS digest FROM ONLY public.\"{name}\" t")
        value=decode(self.sql("SELECT jsonb_object_agg(kind,digest) FROM ("+' UNION ALL '.join(pieces)+') d;'))
        require(set(value)==set(KINDS) and all(re.fullmatch(r'[a-f0-9]{64}',v) for v in value.values()))
        return value

    def worker_call(self,mode,targets,hashes):
        allowed=effective_hashes(hashes)
        payload=json.dumps({'mode':mode,'tenantId':base.TENANT,'targets':targets,'hashes':allowed},separators=(',',':'))
        require(len(payload.encode())<=16384)
        inner,outer=(10,15) if mode in ('probe','locked') else (200,210)
        require(self.deadline-time.monotonic()>=outer)
        require(self.helper_identity()==self.helper)
        value=decode(self.command(['docker','exec','-i',self.helper['id'],'timeout','-s','TERM','-k','3s',str(inner)+'s','/worker/.venv/bin/python','-c',WORKER],data=payload,seconds=outer))
        require(type(value) is dict and value.get('ok') is True and value.get('hashes')==allowed)
        if mode=='probe': require(set(value)=={'ok','hashes'})
        elif mode=='locked':
            require(set(value)=={'ok','hashes','checks','elapsedMs'} and value['checks']==CHECKS[-1:] and type(value['elapsedMs']) is int and 1500<=value['elapsedMs']<=6500)
        else: require(set(value)=={'ok','hashes','checks','measurements','plans'} and value['checks']==CHECKS[:-1] and len(value['measurements'])==14 and len(value['plans'])==1)
        require(self.helper_identity()==self.helper)
        return value

    def start_lock(self):
        # The remote backend is bounded independently of this local client. The
        # caller waits for its exact owned lock, not for an assumed sleep delay.
        require(self.deadline-time.monotonic()>40)
        statement=f"SET application_name='{self.locker_name}'; SET statement_timeout='10s'; SET lock_timeout='2s'; SET idle_in_transaction_session_timeout='12s'; BEGIN; LOCK TABLE ONLY public.\"{self.names['fresh']}\" IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(8); ROLLBACK;"
        args=['docker','exec','-i',self.source['id'],'timeout','--signal=TERM','--kill-after=2s','14s','psql','-X','-q','-A','-t','-U','source_admin','-d','harbor','-v','ON_ERROR_STOP=1']
        # SQL output is deliberately discarded, including all server diagnostics.
        input_file=tempfile.TemporaryFile();input_file.write(statement.encode());input_file.seek(0)
        child=None
        try:
            child=subprocess.Popen(args,stdin=input_file,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=ROOT,start_new_session=True)
            self.lock_owner=(child,input_file)
            self.await_lock()
        except BaseException:
            if child is None: input_file.close()
            raise

    def await_lock(self):
        end=time.monotonic()+5
        while time.monotonic()<end:
            child,_=self.lock_owner
            require(child.poll() is None)
            found=decode(self.sql(f"SELECT coalesce(jsonb_agg(jsonb_build_object('pid',a.pid,'started',a.backend_start)), '[]'::jsonb) FROM pg_stat_activity a WHERE a.application_name='{self.locker_name}' AND a.usename='source_admin' AND a.datname='harbor' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.relation={self.owned[self.names['fresh']]['oid']}::oid AND l.mode='AccessExclusiveLock' AND l.granted);"))
            if len(found)==1:
                require(type(found[0]['pid']) is int and type(found[0]['started']) is str)
                return
            require(len(found)==0);time.sleep(.05)
        raise base.Refusal()

    def finish_lock(self):
        if self.lock_owner is None: return
        child,input_file=self.lock_owner
        try:
            # No remote cancel is necessary: psql commits no data and the remote
            # timeout caps the backend lifetime even if its local client dies.
            try: child.wait(timeout=18)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=3)
                raise base.Refusal() from None
            require(child.returncode==0)
        finally:
            input_file.close();self.lock_owner=None
        require(self.sql(f"SELECT count(*) FROM pg_stat_activity WHERE application_name='{self.locker_name}' AND usename='source_admin' AND datname='harbor';",cleanup=True)=='0')

    def cleanup(self):
        try: self.finish_lock()
        finally:
            try:
                if self.source: self.cleanup_objects()
            finally: self.cleanup_helper()

    def cleanup_objects(self):
        blocks=['BEGIN;']
        for kind in reversed(KINDS):
            name=self.names[kind]
            require(re.fullmatch(r'gc_fq_[a-f0-9]{32}_'+kind,name))
            expected=self.owned.get(name,{}).get('oid')
            pin=f' AND c.oid={expected}::oid' if expected else ''
            blocks.append(f"""DO $cleanup$ DECLARE found oid; BEGIN
 SELECT c.oid INTO found FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
 WHERE n.nspname='public' AND c.relname='{name}' AND c.relkind='r' AND r.rolname='source_admin'
 AND obj_description(c.oid,'pg_class')='{self.marker}'{pin};
 IF found IS NOT NULL THEN EXECUTE 'DROP TABLE public."{name}"';
 ELSIF to_regclass('public.{name}') IS NOT NULL THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 END $cleanup$;""")
        pin=f' AND t.oid={self.domain_oid}::oid' if self.domain_oid else ''
        blocks.append(f"""DO $cleanup$ DECLARE found oid; BEGIN
 SELECT t.oid INTO found FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_roles r ON r.oid=t.typowner
 WHERE n.nspname='public' AND t.typname='{self.domain_name}' AND t.typtype='d' AND r.rolname='source_admin'
 AND obj_description(t.oid,'pg_type')='{self.marker}'{pin};
 IF found IS NOT NULL THEN EXECUTE 'DROP DOMAIN public."{self.domain_name}"';
 ELSIF to_regtype('public.{self.domain_name}') IS NOT NULL THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 END $cleanup$;""")
        blocks.append('COMMIT;');self.sql('\n'.join(blocks),cleanup=True)
        names=','.join("'"+n+"'" for n in self.names.values())
        require(self.sql(f"SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN({names}))+(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typname='{self.domain_name}');",cleanup=True)=='0')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local',action='store_true')
    args=parser.parse_args()
    if not args.run_local: parser.error('--run-local required; no builds or bootstrap')
    h=Harness();before=source_hashes();original=None;data_before=None;result=None;locked=None;failure=None
    try:
        h.local();h.phase='owned_helper_binding';h.start_helper();h.worker_call('probe',{},before)
        h.phase='source_inventory';original=h.inventory()
        h.phase='owned_fixture_setup';h.prepare();targets=h.targets();data_before=h.fixture_digest()
        h.phase='real_executor';result=h.worker_call('run',targets,before)
        h.phase='real_lock_timeout';h.start_lock()
        try: locked=h.worker_call('locked',{'fresh':targets['fresh']},before)
        finally: h.finish_lock()
        h.phase='source_readback'
        require(h.fixture_digest()==data_before)
        require(h.inspect('python-worker')==h.worker and h.inspect('source-postgres')==h.source)
        h.worker_call('probe',{},before);require(source_hashes()==before)
    except BaseException: failure=h.phase
    finally:
        try:
            if data_before is not None: require(h.fixture_digest()==data_before)
        except BaseException: failure='owned_fixture_data_preservation'
        try:
            h.cleanup()
            if original is not None: require(h.inventory(cleanup=True)==original)
            require(source_hashes()==before)
        except BaseException: failure='cleanup_or_inventory_preservation'
    if failure:
        print(json.dumps({'suite':'freshness-quality-worker-local','result':'failed','phase':failure,'code':'FRESHNESS_QUALITY_WORKER_GATE_FAILED'},separators=(',',':')));return 1
    print(json.dumps({'suite':'freshness-quality-worker-local','result':'passed','checks':CHECKS,
      'measurements':result['measurements'],'observedPlanEstimates':result['plans'],'lockRefusalElapsedMs':locked['elapsedMs'],'sourceHashes':before,
      'effectiveWorkerHashes':effective_hashes(before),'worker':h.worker,'helper':h.helper,'source':h.source,'sourceInventorySha256':original,
      'cleanup':'owned_helper_tables_domain_and_lock_session_absent_and_catalog_inventory_preserved',
      'limits':['local synthetic demo source and built-in timestamptz type only; no external TLS qualification',
                'direct executor only; no HTTP, API, Temporal or canonical-rule authorization qualification',
                'source values are synthetic; reports expose only aggregate clocks/MAX/counts/ages, bound hashes and plan estimates',
                'actual lock timeout exercised; no induced complete 30-second wall-deadline or caller cancellation qualification',
                'planner bytes/cost are estimates; no physical IO bound claim',
                'source catalog/ACL/type and owned synthetic data preservation; not a whole-database row checksum; preexisting source tables are never written']},separators=(',',':')))
    return 0


if __name__=='__main__': raise SystemExit(main())
