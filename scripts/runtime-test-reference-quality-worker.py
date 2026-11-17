#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual reference-membership executor checks in the local synthetic source.

No build, bootstrap, HTTP, Temporal or canonical reference authority qualification.
Only this run's marker/OID-owned tables and domain are created and removed.
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

# Also works while staged privately beneath the checkout; no history/network use.
ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/runtime-test-quality-worker.py').is_file() and (p / 'package.json').is_file())
_spec = importlib.util.spec_from_file_location('reference_quality_worker_base', ROOT / 'scripts/runtime-test-quality-worker.py')
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
require, decode = base.require, base.decode
KINDS = ('text', 'varchar', 'allnull', 'empty', 'long', 'integer', 'bpchar', 'domain', 'rls', 'parent', 'child')
CHECKS = [
    'text_exact_bytes_default_collation', 'varchar_exact_bytes_default_collation',
    'case_and_leading_zero_distinctions', 'empty_vector_counts_all_nonnull_invalid',
    'all_null_excludes_denominator', 'empty_relation_counts_zero',
    'all_256_long_codes_match_exactly', 'row_budget_refusal',
    'all_eight_target_pins_refused_when_stale', 'integer_bpchar_domain_unsupported',
    'rls_unsupported', 'inheritance_parent_and_child_unsupported',
    'native_reader_role_and_read_only_default', 'native_reader_dml_denied',
    'closed_aggregate_measurements_without_source_values', 'actual_lock_timeout_refusal',
]


def source_hashes():
    result = base.source_hashes()
    path = Path(__file__).resolve()
    result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


TYPE_INVENTORY_SQL = """SELECT encode(sha256(convert_to(coalesce(jsonb_agg(
 jsonb_build_array(t.oid::text,t.typname,t.typowner::text,t.typtype,t.typbasetype::text,t.typrelid::text,
 t.typarray::text,t.typelem::text,t.typacl::text,t.typnotnull,t.typdefault,obj_description(t.oid,'pg_type')) ORDER BY t.oid),'[]'::jsonb)::text,'UTF8')),'hex')
 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public';"""

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
from governance_workers.postgres_targets import _Resources, _blocked_alarm

def require(value):
    if not value: raise ValueError('qualification refused')
def load():
    raw=sys.stdin.buffer.read(16385)
    require(len(raw)<=16384)
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result);result[k]=v
        return result
    value=json.loads(raw,object_pairs_hook=pairs)
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
        require(actual==digest);result[path]=actual
    return result

def binding(codes):
    value={'setId':'70000000-0000-4000-8000-000000000099','version':1,
      'publicationHash':'a'*64,'asOf':'2026-01-01T00:00:00.000Z','codeStatus':'active','codes':list(codes)}
    value['bindingHash']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return value

def measurement(value,rows,nulls,invalid,pin):
    require(type(value) is dict and set(value)=={'formatVersion','kind','strategy','rowCount','nullCount','invalidCount','referenceBindingHash','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'})
    require(type(value['formatVersion']) is int and value['formatVersion']==1 and value['kind']=='reference-allowed-values')
    require(value['strategy']=='exact-bounded-role-scope' and value['queryTemplate']=='postgresql-reference-allowed-values-v1' and value['adapterVersion']=='1')
    for key,want in (('rowCount',rows),('nullCount',nulls),('invalidCount',invalid)):
        require(type(value[key]) is int and value[key]==want)
    require(value['referenceBindingHash']==pin and re.fullmatch(r'[a-f0-9]{64}',pin))
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
    config=load();matched=hashes(config['hashes'])
    if config['mode']=='probe':
        require(config['targets']=={})
        print(json.dumps({'ok':True,'hashes':matched},separators=(',',':')));return
    require(config['mode'] in ('run','locked') and type(config['targets']) is dict)
    expected={'text'} if config['mode']=='locked' else {'text','varchar','allnull','empty','long','integer','bpchar','domain','rls','parent','child'}
    require(set(config['targets'])==expected)
    for kind,target in config['targets'].items():
        require(type(target) is dict and re.fullmatch(r'gc_rq_[a-f0-9]{32}_'+kind,target['tableName']))
    source={'connectorId':'postgresql','host':'source-postgres','port':5432,'database':'harbor','schema':'public','secretRef':'demo-postgres'}
    secret=resolve(os.environ['SOURCE_SECRETS_FILE'],'demo-postgres',config['tenantId'],'postgresql')
    require(secret['username']=='harbor_reader')
    budget={'maximumRows':100000,'maximumSeconds':30,'statementTimeoutMs':15000,'maximumEstimatedCost':1000000,'maximumEstimatedBytes':67108864}
    def request(target,codes=('01','1','A','a')):
        return {'formatVersion':1,'kind':'reference-allowed-values','target':copy.deepcopy(target),'budget':dict(budget),'reference':binding(codes)}
    def run(value): return execute(source,secret,config['tenantId'],value)
    def refused(value,code):
        try: run(value)
        except ScanFailure as error: require(error.code==code)
        else: raise ValueError('expected refusal')
    if config['mode']=='locked':
        started=time.monotonic();refused(request(config['targets']['text']),'QUALITY_RESOURCE_LIMIT')
        elapsed=math.floor((time.monotonic()-started)*1000)
        require(1500<=elapsed<=6500 and hashes(config['hashes'])==matched)
        print(json.dumps({'ok':True,'hashes':matched,'checks':['actual_lock_timeout_refusal'],'elapsedMs':elapsed},separators=(',',':')));return
    measurements=[]
    # These expected counts are literal, independent of the executor query.
    for kind,codes,counts in [
      ('text',('01','1','A','a'),(14,1,9)),('varchar',('01','1','A','a'),(14,1,9)),
      ('text',('A',),(14,1,12)),('text',('a',),(14,1,12)),
      ('text',('01',),(14,1,12)),('text',('1',),(14,1,12)),
      ('text',(),(14,1,13)),('allnull',(),(5,5,0)),('empty',(),(0,0,0)),
      ('long',tuple(str(i).zfill(3)+'x'*125 for i in range(256)),(258,1,1))]:
        value=request(config['targets'][kind],codes)
        measurements.append(measurement(run(value),*counts,value['reference']['bindingHash']))
    require(len({m['sourceVersion'] for m in measurements})==1)
    limited=request(config['targets']['text']);limited['budget']['maximumRows']=13
    refused(limited,'QUALITY_RESOURCE_LIMIT')
    target=config['targets']['text']
    stale={'databaseOid':str(1 if target['databaseOid']!='1' else 2),
           'schemaOid':str(1 if target['schemaOid']!='1' else 2),
           'relationOid':config['targets']['empty']['relationOid'],'attributeNumber':2,
           'schemaName':'quality_wrong_schema','tableName':config['targets']['empty']['tableName'],
           'columnName':'wrong_column','dataType':'integer'}
    for field,value in stale.items():
        change=request(target);change['target'][field]=value;refused(change,'QUALITY_TARGET_STALE')
    for kind in ('integer','bpchar','domain','rls','parent','child'):
        refused(request(config['targets'][kind]),'QUALITY_TARGET_UNSUPPORTED')
    with deadline(12):
        with _connection_parameters(source,secret,config['tenantId'],time.monotonic()+12) as params:
            with _Resources() as resources:
                with _blocked_alarm():
                    kwargs=dict(params);kwargs['connect_timeout']=5
                    conn=psycopg.connect(**kwargs,row_factory=dict_row);resources.own(conn.close)
                row=conn.execute("SELECT current_user AS name,current_setting('default_transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(row=={'name':'harbor_reader','readonly':'on','rolsuper':False,'rolbypassrls':False,'rolcreaterole':False,'rolcreatedb':False})
                conn.rollback();conn.execute('SET TRANSACTION READ WRITE')
                try: conn.execute(sql.SQL('UPDATE {} SET payload=NULL WHERE false').format(sql.Identifier('public',target['tableName'])))
                except psycopg.Error as error: require(error.sqlstate=='42501')
                else: raise ValueError('reader has write permission')
                finally: conn.rollback()
    require(hashes(config['hashes'])==matched)
    print(json.dumps({'ok':True,'checks':[
      'text_exact_bytes_default_collation','varchar_exact_bytes_default_collation',
      'case_and_leading_zero_distinctions','empty_vector_counts_all_nonnull_invalid',
      'all_null_excludes_denominator','empty_relation_counts_zero','all_256_long_codes_match_exactly',
      'row_budget_refusal','all_eight_target_pins_refused_when_stale','integer_bpchar_domain_unsupported',
      'rls_unsupported','inheritance_parent_and_child_unsupported',
      'native_reader_role_and_read_only_default','native_reader_dml_denied',
      'closed_aggregate_measurements_without_source_values'],
      'measurements':measurements,'hashes':matched},separators=(',',':')))
try: main()
except BaseException:
    print(json.dumps({'ok':False,'code':'REFERENCE_QUALITY_WORKER_QUALIFICATION_FAILED'},separators=(',',':')))
    sys.exit(1)
'''


def bounded_command(args, data, duration, cwd):
    """Bound both streams while running; no stderr/source/credential echo.

    Only the exact freshly started local process group is signalled. Docker exec
    commands also carry their own remote GNU timeout; no remote orphan depends
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
        self.deadline=time.monotonic()+360
        token=uuid.uuid4().hex
        self.marker='reference-quality-worker:'+token
        self.names={kind:f'gc_rq_{token}_{kind}' for kind in KINDS}
        self.domain_name=f'gc_rq_{token}_dtype'
        self.domain_oid=None
        self.locker_name='gc_rq_lock_'+token
        self.lock_owner=None

    def command(self,args,*,data=None,seconds=20,cleanup=False):
        duration=seconds if cleanup else min(seconds,self.deadline-time.monotonic())
        return bounded_command(args,data,duration,ROOT)

    def inventory(self,cleanup=False):
        value={'catalog':self.sql(base.INVENTORY_SQL,cleanup=cleanup),'types':self.sql(TYPE_INVENTORY_SQL,cleanup=cleanup)}
        require(all(re.fullmatch(r'[a-f0-9]{64}',v) for v in value.values()))
        return value

    def prepare(self):
        for kind,name in self.names.items(): require(re.fullmatch(r'gc_rq_[a-f0-9]{32}_'+kind,name))
        require(re.fullmatch(r'gc_rq_[a-f0-9]{32}_dtype',self.domain_name))
        statements=['BEGIN;',f'CREATE DOMAIN public."{self.domain_name}" AS text;',
                    f"COMMENT ON DOMAIN public.\"{self.domain_name}\" IS '{self.marker}';"]
        for kind,name in self.names.items():
            typ={'varchar':'varchar(256)','integer':'integer','bpchar':'char(8)','domain':f'public."{self.domain_name}"'}.get(kind,'text')
            create=(f'CREATE TABLE public."{name}" () INHERITS (public."{self.names["parent"]}");' if kind=='child'
                    else f'CREATE TABLE public."{name}" (payload {typ});')
            statements += [create,f"COMMENT ON TABLE public.\"{name}\" IS '{self.marker}';",
                           f'REVOKE ALL ON TABLE public."{name}" FROM PUBLIC,harbor_reader;',
                           f'GRANT SELECT ON TABLE public."{name}" TO harbor_reader;']
        # Hex UTF-8 literals keep independent values byte-exact under every
        # client encoding; no business rows or caller-supplied SQL are accepted.
        data=['01','1','A','a',' A','A ','A\t','A\n','','é','e\u0301','١','001',None]
        values=','.join('(NULL)' if v is None else f"(convert_from(decode('{v.encode('utf-8').hex()}','hex'),'UTF8'))" for v in data)
        for kind in ('text','varchar'):
            statements.append(f'INSERT INTO public."{self.names[kind]}" VALUES {values};')
        statements += [f'INSERT INTO public."{self.names["allnull"]}" SELECT NULL FROM generate_series(1,5);',
                       f"INSERT INTO public.\"{self.names['long']}\" SELECT lpad(g::text,3,'0')||repeat('x',125) FROM generate_series(0,256) g;",
                       f'INSERT INTO public."{self.names["long"]}" VALUES(NULL);',
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
        allowed={p:h for p,h in hashes.items() if p.startswith('python/') and p!='python/Dockerfile'}
        payload=json.dumps({'mode':mode,'tenantId':base.TENANT,'targets':targets,'hashes':allowed},separators=(',',':'))
        require(len(payload.encode())<=16384)
        inner,outer=(10,15) if mode in ('probe','locked') else (200,210)
        require(self.deadline-time.monotonic()>=outer)
        value=decode(self.command(['docker','exec','-i',self.worker['id'],'timeout','--signal=TERM','--kill-after=3s',str(inner)+'s','/worker/.venv/bin/python','-c',WORKER],data=payload,seconds=outer))
        require(type(value) is dict and value.get('ok') is True and value.get('hashes')==allowed)
        if mode=='probe': require(set(value)=={'ok','hashes'})
        elif mode=='locked':
            require(set(value)=={'ok','hashes','checks','elapsedMs'} and value['checks']==CHECKS[-1:] and type(value['elapsedMs']) is int and 1500<=value['elapsedMs']<=6500)
        else: require(set(value)=={'ok','hashes','checks','measurements'} and value['checks']==CHECKS[:-1] and len(value['measurements'])==10)
        return value

    def start_lock(self):
        # The remote backend is bounded independently of this local client. The
        # caller waits for its exact owned lock, not for an assumed sleep delay.
        require(self.deadline-time.monotonic()>40)
        statement=f"SET application_name='{self.locker_name}'; SET statement_timeout='10s'; SET lock_timeout='2s'; SET idle_in_transaction_session_timeout='12s'; BEGIN; LOCK TABLE ONLY public.\"{self.names['text']}\" IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(8); ROLLBACK;"
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
            found=decode(self.sql(f"SELECT coalesce(jsonb_agg(jsonb_build_object('pid',a.pid,'started',a.backend_start)), '[]'::jsonb) FROM pg_stat_activity a WHERE a.application_name='{self.locker_name}' AND a.usename='source_admin' AND a.datname='harbor' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.relation={self.owned[self.names['text']]['oid']}::oid AND l.mode='AccessExclusiveLock' AND l.granted);"))
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
            if self.source: self.cleanup_objects()

    def cleanup_objects(self):
        blocks=['BEGIN;']
        for kind in reversed(KINDS):
            name=self.names[kind]
            require(re.fullmatch(r'gc_rq_[a-f0-9]{32}_'+kind,name))
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
    h=Harness();before=source_hashes();original=None;result=None;locked=None;failure=None
    try:
        h.local();h.phase='source_binding';h.worker_call('probe',{},before)
        h.phase='source_inventory';original=h.inventory()
        h.phase='owned_fixture_setup';h.prepare();targets=h.targets();data_before=h.fixture_digest()
        h.phase='real_executor';result=h.worker_call('run',targets,before)
        h.phase='real_lock_timeout';h.start_lock()
        try: locked=h.worker_call('locked',{'text':targets['text']},before)
        finally: h.finish_lock()
        h.phase='source_readback'
        require(h.fixture_digest()==data_before)
        require(h.inspect('python-worker')==h.worker and h.inspect('source-postgres')==h.source)
        h.worker_call('probe',{},before);require(source_hashes()==before)
    except BaseException: failure=h.phase
    finally:
        try:
            h.cleanup()
            if original is not None: require(h.inventory(cleanup=True)==original)
        except BaseException: failure='cleanup_or_inventory_preservation'
    if failure:
        print(json.dumps({'suite':'reference-quality-worker-local','result':'failed','phase':failure,'code':'REFERENCE_QUALITY_WORKER_GATE_FAILED'},separators=(',',':')));return 1
    print(json.dumps({'suite':'reference-quality-worker-local','result':'passed','checks':CHECKS,
      'measurements':result['measurements'],'lockRefusalElapsedMs':locked['elapsedMs'],'sourceHashes':before,
      'worker':h.worker,'source':h.source,'sourceInventorySha256':original,
      'cleanup':'owned_tables_domain_and_lock_session_absent_and_catalog_inventory_preserved',
      'limits':['local synthetic demo source and default database collation only; no external TLS qualification',
                'direct executor only; no HTTP, API, Temporal or retained-reference authorization qualification',
                'allowed codes are synthetic inputs; reports expose only aggregates and binding hashes',
                'actual lock timeout exercised; no induced complete 30-second wall-deadline or caller cancellation qualification',
                'planner bytes/cost are estimates; no physical IO bound claim',
                'source catalog/ACL/type and owned synthetic data preservation; not a whole-database row checksum']},separators=(',',':')))
    return 0


if __name__=='__main__': raise SystemExit(main())
