#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real completeness executor gate against disposable tables in the local demo source.

Run only after the matching worker image is built. No build/bootstrap, source
credential export, shared application mutation, or worker HTTP/Temporal claim.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '--project-name', 'governance-commons', '--env-file',
           str(ROOT / '.local/runtime.env'), '-f', str(ROOT / 'deploy/compose/compose.yaml')]
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
CHECKS = ['exact_20_rows_5_nulls', 'empty_exact_measurement', 'row_budget_refusal',
          'all_eight_target_pins_refused_when_stale', 'rls_unsupported',
          'native_reader_role_and_read_only_default', 'native_reader_dml_denied',
          'closed_measurements_without_row_values']


class Refusal(Exception):
    """Only closed phase names are rendered by the entry point."""


def require(condition):
    if not condition:
        raise Refusal()


def decode(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal()))


def source_hashes():
    paths = sorted((ROOT / 'python/governance_workers').glob('*.py')) + [
        ROOT / 'python/pyproject.toml', ROOT / 'python/uv.lock', ROOT / 'python/Dockerfile',
        ROOT / 'deploy/compose/compose.yaml', Path(__file__).resolve()]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


# No catalog password column or business values are selected. The whole digest
# covers preexisting public relation identities/ACLs, columns, constraints, RLS,
# schema grants and the two fixture roles; stats/counters are deliberately absent.
INVENTORY_SQL = """SELECT encode(sha256(convert_to(jsonb_build_object(
 'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid::text,c.relname,c.relkind,c.relowner::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity,obj_description(c.oid,'pg_class')) ORDER BY c.oid),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid::text,a.attnum,a.attname,a.atttypid::text,a.atttypmod,a.attnotnull,a.attisdropped,a.attacl::text) ORDER BY a.attrelid,a.attnum),'[]'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND a.attnum>0),
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid::text,c.conrelid::text,c.conname,pg_get_constraintdef(c.oid)) ORDER BY c.oid),'[]'::jsonb) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public'),
 'policies',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.oid::text,p.polrelid::text,p.polname,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY p.oid),'[]'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'schema',(SELECT jsonb_build_array(n.oid::text,n.nspowner::text,n.nspacl::text) FROM pg_namespace n WHERE n.nspname='public'),
 'roles',(SELECT jsonb_agg(jsonb_build_array(oid::text,rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolcanlogin,rolconfig::text) ORDER BY oid) FROM pg_roles WHERE rolname IN('source_admin','harbor_reader'))
 )::text,'UTF8')),'hex');"""

WORKER = r'''
import copy, hashlib, json, math, os, re, sys, time
from datetime import datetime
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from governance_workers.quality import execute
from governance_workers.postgresql import ScanFailure, _connection_parameters
from governance_workers.secrets import resolve
from governance_workers.deadline import deadline

def require(value):
    if not value: raise ValueError('qualification refused')
def load():
    raw=sys.stdin.buffer.read(16385)
    require(len(raw)<=16384)
    value=json.loads(raw)
    require(type(value) is dict and set(value)=={'mode','tenantId','targets','hashes'})
    require(value['tenantId']=='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    return value

def hashes(expected):
    result={}
    require(type(expected) is dict and 1<=len(expected)<=64)
    for path,digest in expected.items():
        require(re.fullmatch(r'python/(?:governance_workers/[a-z_]+\.py|pyproject\.toml|uv\.lock)',path))
        require(re.fullmatch(r'[a-f0-9]{64}',digest))
        actual=hashlib.sha256(Path('/worker',path.removeprefix('python/')).read_bytes()).hexdigest()
        require(actual==digest)
        result[path]=actual
    return result

def measurement(value,rows,nulls):
    require(type(value) is dict and set(value)=={'formatVersion','kind','strategy','rowCount','nullCount','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'})
    require(type(value['formatVersion']) is int and value['formatVersion']==1 and value['kind']=='completeness')
    require(value['strategy']=='exact-bounded-role-scope' and value['queryTemplate']=='postgresql-completeness-v1' and value['adapterVersion']=='1')
    require(type(value['rowCount']) is int and value['rowCount']==rows and type(value['nullCount']) is int and value['nullCount']==nulls)
    require(type(value['elapsedMs']) is int and 0<=value['elapsedMs']<=30000)
    require(type(value['sourceVersion']) is str and re.fullmatch(r'[0-9]{5,16}',value['sourceVersion']))
    for key in ('observedStartedAt','observedFinishedAt'):
        require(type(value[key]) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',value[key]))
    started=datetime.fromisoformat(value['observedStartedAt'].replace('Z','+00:00'))
    finished=datetime.fromisoformat(value['observedFinishedAt'].replace('Z','+00:00'))
    require(0<=(finished-started).total_seconds()<=31 and abs((finished-started).total_seconds()*1000-value['elapsedMs'])<=1000)
    require(type(value['estimatedCost']) in (int,float) and math.isfinite(value['estimatedCost']) and 0<=value['estimatedCost']<=1000000)
    require(type(value['estimatedBytes']) is int and 0<=value['estimatedBytes']<=67108864)
    return value

def main():
    config=load(); matched=hashes(config['hashes'])
    if config['mode']=='probe':
        require(config['targets']=={})
        print(json.dumps({'ok':True,'hashes':matched},separators=(',',':')));return
    require(config['mode']=='run' and type(config['targets']) is dict and set(config['targets'])=={'data','empty','rls'})
    for target in config['targets'].values():
        require(re.fullmatch(r'gc_quality_[a-f0-9]{32}_(?:data|empty|rls)',target['tableName']))
    source={'connectorId':'postgresql','host':'source-postgres','port':5432,'database':'harbor','schema':'public','secretRef':'demo-postgres'}
    secret=resolve(os.environ['SOURCE_SECRETS_FILE'],'demo-postgres',config['tenantId'],'postgresql')
    require(secret['username']=='harbor_reader')
    budget={'maximumRows':100000,'maximumSeconds':30,'statementTimeoutMs':15000,'maximumEstimatedCost':1000000,'maximumEstimatedBytes':67108864}
    def request(target): return {'formatVersion':1,'kind':'completeness','target':copy.deepcopy(target),'budget':dict(budget)}
    def run(value): return execute(source,secret,config['tenantId'],value)
    def refused(value,code):
        try: run(value)
        except ScanFailure as error: require(error.code==code)
        else: raise ValueError('expected refusal')
    a=measurement(run(request(config['targets']['data'])),20,5)
    b=measurement(run(request(config['targets']['empty'])),0,0)
    require(a['sourceVersion']==b['sourceVersion'])
    limited=request(config['targets']['data']);limited['budget']['maximumRows']=19
    refused(limited,'QUALITY_RESOURCE_LIMIT')
    target=config['targets']['data']
    stale={'databaseOid':str(1 if target['databaseOid']!='1' else 2),
           'schemaOid':str(1 if target['schemaOid']!='1' else 2),
           'relationOid':config['targets']['empty']['relationOid'], 'attributeNumber':2,
           'schemaName':'quality_wrong_schema','tableName':config['targets']['empty']['tableName'],
           'columnName':'wrong_column','dataType':'integer'}
    for field,value in stale.items():
        change=request(target);change['target'][field]=value
        refused(change,'QUALITY_TARGET_STALE')
    refused(request(config['targets']['rls']),'QUALITY_TARGET_UNSUPPORTED')
    # Separate actual native connection checks role/default/ACL, then attempts a
    # zero-row UPDATE in READ WRITE. A privilege failure proves reader capability,
    # not merely the read-only GUC (the transaction is always rolled back).
    with deadline(12):
        with _connection_parameters(source,secret,config['tenantId'],time.monotonic()+12) as params:
            with psycopg.connect(**params,row_factory=dict_row) as conn:
                row=conn.execute("SELECT current_user AS name,current_setting('default_transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(row=={'name':'harbor_reader','readonly':'on','rolsuper':False,'rolbypassrls':False,'rolcreaterole':False,'rolcreatedb':False})
                conn.rollback()
                conn.execute('SET TRANSACTION READ WRITE')
                try:
                    conn.execute(sql.SQL('UPDATE {} SET payload=NULL WHERE false').format(sql.Identifier('public',target['tableName'])))
                except psycopg.Error as error: require(error.sqlstate=='42501')
                else: raise ValueError('reader has write permission')
                finally: conn.rollback()
    require(hashes(config['hashes'])==matched)
    print(json.dumps({'ok':True,'checks':[
      'exact_20_rows_5_nulls','empty_exact_measurement','row_budget_refusal',
      'all_eight_target_pins_refused_when_stale','rls_unsupported',
      'native_reader_role_and_read_only_default','native_reader_dml_denied',
      'closed_measurements_without_row_values'],
      'measurements':[a,b],'hashes':matched},separators=(',',':')))
try: main()
except BaseException:
    print(json.dumps({'ok':False,'code':'QUALITY_WORKER_QUALIFICATION_FAILED'},separators=(',',':')))
    sys.exit(1)
'''


class Harness:
    def __init__(self):
        self.deadline = time.monotonic() + 300
        self.phase = 'local_admission'
        self.worker = None
        self.source = None
        self.owned = {}
        self.marker = 'quality-worker:' + uuid.uuid4().hex
        token = uuid.uuid4().hex
        self.names = {kind: f'gc_quality_{token}_{kind}' for kind in ('data', 'empty', 'rls')}

    def command(self, args, *, data=None, seconds=20, cleanup=False):
        duration = seconds if cleanup else min(seconds, self.deadline - time.monotonic())
        require(duration > 0)
        # stdout/stderr are never echoed on failure, including psycopg/psql paths.
        result = subprocess.run(args, input=data, text=True, capture_output=True,
                                cwd=ROOT, timeout=duration)
        require(result.returncode == 0 and len(result.stdout.encode()) <= 65536)
        return result.stdout.strip()

    def sql(self, statement, *, cleanup=False):
        require(cleanup or self.deadline - time.monotonic() >= 20)
        preface = "SET statement_timeout='12s'; SET lock_timeout='3s'; SET idle_in_transaction_session_timeout='15s';\n"
        return self.command(['docker', 'exec', '-i', self.source['id'], 'timeout', '--signal=TERM', '--kill-after=2s', '16s',
                             'psql', '-X', '-q', '-A', '-t', '-U', 'source_admin', '-d', 'harbor', '-v', 'ON_ERROR_STOP=1'],
                            data=preface + statement, seconds=20, cleanup=cleanup)

    def inspect(self, service):
        identifier = self.command(COMPOSE + ['ps', '--quiet', service])
        require(re.fullmatch(r'[a-f0-9]{64}', identifier))
        fields = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"mounts":{{json .Mounts}}}'
        value = decode(self.command(['docker', 'inspect', '--format', fields, identifier]))
        require(set(value) == {'id','image','running','project','service','mounts'} and value['id'] == identifier)
        require(value['project'] == 'governance-commons' and value['service'] == service and value['running'] is True)
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', value['image']))
        if service == 'python-worker':
            require(all(m['Destination'] != '/worker' and not m['Destination'].startswith('/worker/') for m in value['mounts']))
        return {key: value[key] for key in ('id','image','project','service')}

    def local(self):
        require(os.name == 'posix' and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')))
        context = decode(self.command(['docker','context','inspect']))
        require(len(context)==1 and context[0]['Endpoints']['docker']['Host'].startswith('unix://'))
        self.worker, self.source = self.inspect('python-worker'), self.inspect('source-postgres')

    def worker_call(self, mode, targets, hashes):
        allowed = {p: h for p,h in hashes.items() if p.startswith('python/') and p != 'python/Dockerfile'}
        payload = json.dumps({'mode':mode,'tenantId':TENANT,'targets':targets,'hashes':allowed}, separators=(',',':'))
        require(len(payload.encode()) <= 16384)
        inner_seconds, outer_seconds = (10, 15) if mode == 'probe' else (200, 210)
        require(self.deadline - time.monotonic() >= outer_seconds)
        result = decode(self.command(['docker','exec','-i', self.worker['id'], 'timeout','--signal=TERM','--kill-after=3s',str(inner_seconds)+'s',
                                    '/worker/.venv/bin/python','-c',WORKER], data=payload, seconds=outer_seconds))
        require(type(result) is dict and result.get('ok') is True and result.get('hashes') == allowed)
        if mode == 'probe': require(set(result) == {'ok','hashes'})
        else:
            require(set(result)=={'ok','checks','measurements','hashes'} and result['checks']==CHECKS and len(result['measurements'])==2)
        return result

    def prepare(self):
        for name in self.names.values(): require(re.fullmatch(r'gc_quality_[a-f0-9]{32}_(?:data|empty|rls)', name))
        statements = ['BEGIN;']
        for name in self.names.values():
            statements += [f'CREATE TABLE public."{name}" (payload text);',
                           f"COMMENT ON TABLE public.\"{name}\" IS '{self.marker}';",
                           f'REVOKE ALL ON TABLE public."{name}" FROM PUBLIC,harbor_reader;',
                           f'GRANT SELECT ON TABLE public."{name}" TO harbor_reader;']
        statements += [f"INSERT INTO public.\"{self.names['data']}\" SELECT CASE WHEN g<=5 THEN NULL ELSE 'synthetic-quality-value' END FROM generate_series(1,20) g;",
                       f'ALTER TABLE public."{self.names["rls"]}" ENABLE ROW LEVEL SECURITY;',
                       f'CREATE POLICY quality_fixture ON public."{self.names["rls"]}" FOR SELECT TO harbor_reader USING (true);']
        for name in self.names.values(): statements.append(f'ANALYZE public."{name}";')
        # Catalog identities are read in the same transaction as their creation.
        names = ','.join("'"+name+"'" for name in self.names.values())
        statements += [f"SELECT jsonb_object_agg(c.relname,jsonb_build_object('oid',c.oid::text,'owner',r.rolname,'marker',obj_description(c.oid,'pg_class'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN({names});", 'COMMIT;']
        # If transport fails after COMMIT, cleanup may rediscover only these exact
        # unguessable names plus this marker/owner; it never drops by prefix.
        owned = decode(self.sql('\n'.join(statements)))
        require(set(owned) == set(self.names.values()))
        for value in owned.values():
            require(set(value)=={'oid','owner','marker'} and re.fullmatch(r'[1-9][0-9]*',value['oid']) and value['owner']=='source_admin' and value['marker']==self.marker)
        self.owned = owned

    def targets(self):
        names = ','.join("'"+name+"'" for name in self.names.values())
        value = decode(self.sql(f"SELECT jsonb_object_agg(c.relname,jsonb_build_object('databaseOid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),'schemaOid',n.oid::text,'relationOid',c.oid::text,'attributeNumber',a.attnum,'schemaName',n.nspname,'tableName',c.relname,'columnName',a.attname,'dataType',format_type(a.atttypid,a.atttypmod))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=1 WHERE n.nspname='public' AND c.relname IN({names});"))
        require(set(value)==set(self.names.values()))
        for name,target in value.items(): require(target['relationOid']==self.owned[name]['oid'])
        return {kind:value[name] for kind,name in self.names.items()}

    def fixture_digest(self):
        data = self.names['data']
        return self.sql(f"SELECT encode(sha256(convert_to(coalesce(jsonb_agg(payload ORDER BY payload NULLS FIRST),'[]')::text,'UTF8')),'hex') FROM public.\"{data}\";")

    def cleanup(self):
        if not self.source:
            return
        blocks = ['BEGIN;']
        for name in self.names.values():
            require(re.fullmatch(r'gc_quality_[a-f0-9]{32}_(?:data|empty|rls)',name))
            expected = self.owned.get(name, {}).get('oid')
            pin = f" AND c.oid={expected}::oid" if expected else ''
            blocks.append(f"""DO $cleanup$ DECLARE found oid; BEGIN
 SELECT c.oid INTO found FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
 WHERE n.nspname='public' AND c.relname='{name}' AND c.relkind='r' AND r.rolname='source_admin'
 AND obj_description(c.oid,'pg_class')='{self.marker}'{pin};
 IF found IS NOT NULL THEN EXECUTE 'DROP TABLE public."{name}"';
 ELSIF to_regclass('public.{name}') IS NOT NULL THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 END $cleanup$;""")
        blocks.append('COMMIT;')
        self.sql('\n'.join(blocks), cleanup=True)
        names = ','.join("'"+name+"'" for name in self.names.values())
        require(self.sql(f"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN({names});", cleanup=True)=='0')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local', action='store_true', help='execute against the existing local synthetic source and matching worker image')
    args = parser.parse_args()
    if not args.run_local:
        parser.error('--run-local is required; this gate never builds or bootstraps')
    harness = Harness()
    before = source_hashes()
    original = None
    result = None
    failed = False
    try:
        harness.local()
        harness.phase = 'source_binding'
        harness.worker_call('probe', {}, before)
        harness.phase = 'source_inventory'
        original = harness.sql(INVENTORY_SQL)
        require(re.fullmatch(r'[a-f0-9]{64}', original))
        harness.phase = 'owned_fixture_setup'
        harness.prepare()
        data_before = harness.fixture_digest()
        harness.phase = 'real_executor'
        result = harness.worker_call('run', harness.targets(), before)
        harness.phase = 'source_readback'
        require(harness.fixture_digest() == data_before)
        require(harness.inspect('python-worker') == harness.worker and harness.inspect('source-postgres') == harness.source)
        require(source_hashes() == before)
    except BaseException:
        failed = True
    finally:
        failure_phase = harness.phase
        try:
            harness.cleanup()
            if original is not None:
                require(harness.sql(INVENTORY_SQL, cleanup=True) == original)
        except BaseException:
            failed = True
            failure_phase = 'cleanup_or_inventory_preservation'
    if failed:
        print(json.dumps({'suite':'quality-worker-local','result':'failed','phase':failure_phase,
                          'code':'QUALITY_WORKER_GATE_FAILED'},separators=(',',':')))
        return 1
    print(json.dumps({'suite':'quality-worker-local','result':'passed','checks':CHECKS,
                      'measurements':result['measurements'],'sourceHashes':before,
                      'worker':harness.worker,'source':harness.source,'sourceInventorySha256':original,
                      'cleanup':'owned_tables_absent_and_catalog_inventory_preserved',
                      'limits':['local synthetic demo source only; no external TLS qualification',
                                'direct executor only; no HTTP, API, Temporal or publication qualification',
                                'planner bytes/cost are estimates; no physical IO bound claim',
                                'source catalog/ACL and owned synthetic data preservation; not a whole-database row checksum']},separators=(',',':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
