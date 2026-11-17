#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native lineage gate; unittest discovery never launches it.

Run on the host with --run-core after building the matching worker image. Only
UUID-named local synthetic fixtures are mutated, through source_admin; the real
adapter and independent catalog oracle both use harbor_reader. No source rows,
SQL bodies, credentials, application ingestion, or browser behavior are exported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SELF = 'python/tests/test_postgres_lineage_conformance.py'
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
MAX_OUTPUT = 128 * 1024
CHECKS = ['native_reader_catalog_and_real_scan', 'harbor_exact_oid_rewrite_and_attnum_witnesses',
          'all_scanned_views_and_dependencies_have_admitted_endpoints',
          'constant_view_has_collected_empty_dependencies',
          'external_relation_and_routine_are_closed_gaps',
          'table_and_column_rename_preserve_oid_attnum_and_lineage',
          'owned_fixture_cleanup_preserves_catalog_acl_and_scan']


class Refusal(Exception):
    pass


def require(value):
    if not value:
        raise Refusal('LINEAGE_CONFORMANCE_REFUSED')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode()).hexdigest()


def source_hashes():
    paths = sorted((ROOT / 'python/governance_workers').glob('*.py')) + [
        ROOT / 'python/pyproject.toml', ROOT / 'python/uv.lock', ROOT / 'python/Dockerfile',
        ROOT / 'deploy/compose/compose.yaml', Path(__file__).resolve()]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def bounded(args, seconds, data=''):
    """Bound both captured streams and reap only this new, owned process group."""
    require(0 < seconds <= 120 and len(data.encode()) <= 32768)
    end = time.monotonic() + seconds
    with tempfile.TemporaryFile() as incoming:
        incoming.write(data.encode()); incoming.seek(0)
        with selectors.DefaultSelector() as selector:
            proc = subprocess.Popen(args, stdin=incoming, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
            total, output = 0, bytearray()
            try:
                for stream in (proc.stdout, proc.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    require(time.monotonic() < end)
                    for key, _ in selector.select(min(.1, max(0, end - time.monotonic()))):
                        chunk = os.read(key.fd, 16384)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        require(total <= MAX_OUTPUT)
                        if key.fileobj is proc.stdout:
                            output.extend(chunk)
                require(proc.wait(timeout=max(.001, end - time.monotonic())) == 0)
                return output.decode('utf-8').strip()
            finally:
                # A leader may already have exited while an owned descendant
                # holds the pipe. Kill the group before reaping the leader.
                if proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=3)
                proc.stdout.close(); proc.stderr.close()


# Full catalog rows are hashed inside PostgreSQL; no source SQL definitions,
# private names, or credentials leave the database. This is metadata preservation,
# not a checksum of existing business rows. Object OID allocation is not reset.
INVENTORY_SQL = """WITH namespaces AS MATERIALIZED (
 SELECT oid FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
), records AS (
 SELECT 'namespace' AS family,n.oid::text AS key,to_jsonb(n)::text AS value FROM pg_namespace n JOIN namespaces s ON s.oid=n.oid
 UNION ALL SELECT 'relation',c.oid::text,to_jsonb(c)::text FROM pg_class c JOIN namespaces s ON s.oid=c.relnamespace
 UNION ALL SELECT 'attribute',a.attrelid::text||':'||a.attnum::text,to_jsonb(a)::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN namespaces s ON s.oid=c.relnamespace
 UNION ALL SELECT 'rewrite',r.oid::text,to_jsonb(r)::text FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN namespaces s ON s.oid=c.relnamespace
 UNION ALL SELECT 'routine',p.oid::text,to_jsonb(p)::text FROM pg_proc p JOIN namespaces s ON s.oid=p.pronamespace
 UNION ALL SELECT 'type',t.oid::text,to_jsonb(t)::text FROM pg_type t JOIN namespaces s ON s.oid=t.typnamespace
 UNION ALL SELECT 'constraint',c.oid::text,to_jsonb(c)::text FROM pg_constraint c JOIN namespaces s ON s.oid=c.connamespace
 UNION ALL SELECT 'policy',p.oid::text,to_jsonb(p)::text FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN namespaces s ON s.oid=c.relnamespace
 UNION ALL SELECT 'default_acl',d.oid::text,to_jsonb(d)::text FROM pg_default_acl d
 UNION ALL SELECT 'role',r.oid::text,to_jsonb(r)::text FROM pg_roles r WHERE rolname IN('source_admin','harbor_reader')
), hashes AS MATERIALIZED (SELECT family,key,sha256(convert_to(value,'UTF8')) AS hash FROM records)
SELECT encode(sha256(coalesce(string_agg(hash,''::bytea ORDER BY family,key),''::bytea)),'hex') FROM hashes;"""


class Harness:
    def __init__(self):
        self.end = time.monotonic() + 600
        self.phase = 'local_admission'
        self.source = self.worker = None
        self.owned = {}
        self.created = False
        self.prefix = 'gc_lineage_' + uuid.uuid4().hex
        self.marker = 'lineage-conformance:' + uuid.uuid4().hex
        self.names = {key: self.prefix + '_' + key for key in ('table', 'renamed', 'view', 'empty', 'gap', 'outside')}
        self.compose = ['docker', 'compose', '--project-name', 'governance-commons', '--env-file',
                        str(ROOT / '.local/runtime.env'), '-f', str(ROOT / 'deploy/compose/compose.yaml')]
        self.cleanup_end = None

    def command(self, args, *, data='', seconds=20, cleanup=False):
        end = self.cleanup_end if cleanup else self.end
        require(end is not None)
        return bounded(args, min(seconds, end - time.monotonic()), data)

    def inspect(self, service):
        identifier = self.command(self.compose + ['ps', '--quiet', service])
        require(re.fullmatch(r'[a-f0-9]{64}', identifier))
        template = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"mounts":{{json .Mounts}}}'
        value = decode(self.command(['docker', 'inspect', '--format', template, identifier]))
        require(set(value) == {'id', 'image', 'running', 'project', 'service', 'mounts'})
        require(value['id'] == identifier and value['running'] is True and value['project'] == 'governance-commons' and value['service'] == service)
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', value['image']))
        if service == 'python-worker':
            require(all(m['Destination'] != '/worker' and not m['Destination'].startswith('/worker/') for m in value['mounts']))
        return {k: value[k] for k in ('id', 'image', 'project', 'service')}

    def local(self):
        require(os.name == 'posix' and shutil.disk_usage(ROOT).free >= 64 * 1024 * 1024)
        require(not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://'))
        context = decode(self.command(['docker', 'context', 'inspect']))
        require(len(context) == 1 and context[0]['Endpoints']['docker']['Host'].startswith('unix://'))
        self.source, self.worker = self.inspect('source-postgres'), self.inspect('python-worker')

    def sql(self, statement, *, cleanup=False):
        preface = "SET statement_timeout='12s'; SET lock_timeout='3s'; SET idle_in_transaction_session_timeout='15s';\n"
        return self.command(['docker', 'exec', '-i', self.source['id'], 'timeout', '--signal=TERM', '--kill-after=2s', '16s',
                             'psql', '-X', '-q', '-A', '-t', '-U', 'source_admin', '-d', 'harbor', '-v', 'ON_ERROR_STOP=1'],
                            data=preface + statement, seconds=22, cleanup=cleanup)

    def worker_call(self, mode, hashes):
        allowed = {p: h for p, h in hashes.items() if p.startswith('python/') and p != 'python/Dockerfile'}
        payload = json.dumps({'mode': mode, 'hashes': allowed, 'prefix': self.prefix}, separators=(',', ':'))
        result = decode(self.command(['docker', 'exec', '-i', self.worker['id'], 'timeout', '--signal=TERM', '--kill-after=3s', '105s',
                                      '/worker/.venv/bin/python', '-m', 'tests.test_postgres_lineage_conformance', '--worker'],
                                     data=payload, seconds=112))
        require(type(result) is dict and result.get('ok') is True and result.get('hashes') == allowed)
        require(set(result) == ({'ok', 'hashes'} if mode == 'probe' else {'ok', 'hashes', 'scan', 'fixture'}))
        return result

    def prepare(self):
        t, v, e, g, s = (self.names[k] for k in ('table', 'view', 'empty', 'gap', 'outside'))
        self.created = True  # Cleanup also handles an unknown post-COMMIT transport result.
        query = f'''BEGIN;
CREATE SCHEMA "{s}" AUTHORIZATION source_admin;
COMMENT ON SCHEMA "{s}" IS '{self.marker}';
CREATE TABLE "{s}".external_input (value integer);
CREATE FUNCTION "{s}".opaque(value integer) RETURNS integer LANGUAGE SQL IMMUTABLE RETURN value;
REVOKE ALL ON FUNCTION "{s}".opaque(integer) FROM PUBLIC;
CREATE TABLE public."{t}" (before_name integer, payload text);
CREATE VIEW public."{v}" AS SELECT before_name,payload FROM public."{t}";
CREATE VIEW public."{e}" AS SELECT 1 AS constant_value;
CREATE VIEW public."{g}" AS SELECT "{s}".opaque(value) AS opaque_value FROM "{s}".external_input;
'''
        for name, kind in ((t, 'TABLE'), (v, 'VIEW'), (e, 'VIEW'), (g, 'VIEW')):
            query += f'COMMENT ON {kind} public."{name}" IS \'{self.marker}\'; REVOKE ALL ON public."{name}" FROM PUBLIC,harbor_reader; GRANT SELECT ON public."{name}" TO harbor_reader;\n'
        query += f"COMMENT ON TABLE \"{s}\".external_input IS '{self.marker}'; COMMENT ON FUNCTION \"{s}\".opaque(integer) IS '{self.marker}';\n"
        query += self.ownership_query() + '\nCOMMIT;'
        self.owned = decode(self.sql(query))
        require(set(self.owned) == {'table', 'view', 'empty', 'gap', 'outside', 'external_input', 'opaque'})
        require(all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,9}', v) for v in self.owned.values()))

    def ownership_query(self):
        p, s = self.prefix, self.names['outside']
        return f"""SELECT jsonb_object_agg(key,oid) FROM (
 SELECT substring(c.relname FROM {len(p) + 2}) AS key,c.oid::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN('{p}_table','{p}_view','{p}_empty','{p}_gap')
 UNION ALL SELECT 'outside',n.oid::text FROM pg_namespace n WHERE n.nspname='{s}'
 UNION ALL SELECT 'external_input',c.oid::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{s}' AND c.relname='external_input'
 UNION ALL SELECT 'opaque',p.oid::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='{s}' AND p.proname='opaque'
) objects;"""

    def rename(self):
        t, r = self.names['table'], self.names['renamed']
        self.sql(f'''BEGIN;
DO $guard$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='{t}' AND c.oid={self.owned['table']}::oid AND c.relowner='source_admin'::regrole AND obj_description(c.oid,'pg_class')='{self.marker}') THEN RAISE EXCEPTION 'Fixture mismatch'; END IF; END $guard$;
ALTER TABLE public."{t}" RENAME TO "{r}";
ALTER TABLE public."{r}" RENAME COLUMN before_name TO after_name;
COMMIT;''')

    def cleanup(self):
        if not self.created:
            return
        self.cleanup_end = time.monotonic() + 60
        blocks = ['BEGIN;']
        # Exact dependencies are removed first, never CASCADE or a prefix sweep.
        for key, schema, name, kind in [('gap', 'public', self.names['gap'], 'VIEW'),
                ('empty', 'public', self.names['empty'], 'VIEW'), ('view', 'public', self.names['view'], 'VIEW'),
                ('table', 'public', self.names['table'], 'TABLE'), ('table', 'public', self.names['renamed'], 'TABLE'),
                ('external_input', self.names['outside'], 'external_input', 'TABLE')]:
            pin = f" AND c.oid={self.owned[key]}::oid" if key in self.owned else ''
            relkind = 'v' if kind == 'VIEW' else 'r'
            blocks.append(f'''DO $cleanup$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{schema}' AND c.relname='{name}') THEN
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{schema}' AND c.relname='{name}' AND c.relkind='{relkind}' AND c.relowner='source_admin'::regrole AND obj_description(c.oid,'pg_class')='{self.marker}'{pin}) THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 DROP {kind} "{schema}"."{name}"; END IF; END $cleanup$;''')
        s = self.names['outside']
        fp = f" AND p.oid={self.owned['opaque']}::oid" if 'opaque' in self.owned else ''
        sp = f" AND n.oid={self.owned['outside']}::oid" if 'outside' in self.owned else ''
        blocks.append(f'''DO $cleanup$ BEGIN
 IF to_regprocedure('"{s}".opaque(integer)') IS NOT NULL THEN
 IF NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='{s}' AND p.proname='opaque' AND p.proargtypes='23'::oidvector AND p.proowner='source_admin'::regrole AND obj_description(p.oid,'pg_proc')='{self.marker}'{fp}) THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 DROP FUNCTION "{s}".opaque(integer); END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='{s}') THEN
 IF NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='{s}' AND n.nspowner='source_admin'::regrole AND obj_description(n.oid,'pg_namespace')='{self.marker}'{sp}) THEN RAISE EXCEPTION 'Fixture ownership mismatch'; END IF;
 DROP SCHEMA "{s}"; END IF; END $cleanup$;''')
        blocks.append('COMMIT;')
        self.sql('\n'.join(blocks), cleanup=True)
        names = ','.join("'" + name + "'" for name in self.names.values())
        require(self.sql(f"SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN({names}))+(SELECT count(*) FROM pg_namespace WHERE nspname='{s}');", cleanup=True) == '0')
        self.created = False


def worker_hashes(expected):
    require(type(expected) is dict and SELF in expected and 1 <= len(expected) <= 64)
    actual = {}
    for path, sha in expected.items():
        require(re.fullmatch(r'python/(?:governance_workers/[a-z_]+\.py|pyproject\.toml|uv\.lock|tests/test_postgres_lineage_conformance\.py)', path))
        require(type(sha) is str and re.fullmatch(r'[a-f0-9]{64}', sha))
        actual[path] = hashlib.sha256(Path('/worker', path.removeprefix('python/')).read_bytes()).hexdigest()
    require(actual == expected)
    return actual


def worker():
    raw = sys.stdin.buffer.read(32769)
    require(len(raw) <= 32768)
    config = decode(raw)
    require(type(config) is dict and set(config) == {'mode', 'hashes', 'prefix'})
    require(config['mode'] in ('probe', 'baseline', 'created', 'renamed'))
    require(type(config['prefix']) is str and re.fullmatch(r'gc_lineage_[a-f0-9]{32}', config['prefix']))
    hashes = worker_hashes(config['hashes'])
    if config['mode'] == 'probe':
        return {'ok': True, 'hashes': hashes}
    import psycopg
    from psycopg.rows import dict_row
    from governance_workers.postgresql import scan, _connection_parameters
    from governance_workers.secrets import resolve
    from governance_workers.deadline import deadline
    from governance_workers.postgres_targets import _Resources, _blocked_alarm

    source = {'connectorId': 'postgresql', 'host': 'source-postgres', 'port': 5432,
              'database': 'harbor', 'schema': 'public', 'secretRef': 'demo-postgres'}
    secret = resolve(os.environ['SOURCE_SECRETS_FILE'], 'demo-postgres', TENANT, 'postgresql')
    require(secret['username'] == 'harbor_reader')
    result = scan(source, secret, TENANT)
    require(result['complete'] is True)
    lineage = result['lineage']
    require(set(lineage) == {'formatVersion', 'kind', 'adapterVersion', 'queryTemplate', 'views'})
    require(lineage['formatVersion'] == 1 and lineage['kind'] == 'postgresql-view-dependencies' and lineage['adapterVersion'] == '1' and lineage['queryTemplate'] == 'postgresql-view-dependencies-v1')
    records = {r['externalId']: r for r in result['records']}
    require(len(records) == len(result['records']))
    views = {v['viewExternalId']: v for v in lineage['views']}
    require(len(views) == len(lineage['views']) and list(views) == sorted(views))
    require(set(views) == {r['externalId'] for r in records.values() if r['type'] == 'view'})
    for view in views.values():
        require(set(view) == {'viewExternalId', 'rewriteOid', 'dependencies', 'gaps'})
        require(re.fullmatch(r'[1-9][0-9]{0,9}', view['rewriteOid']))
        require(view['gaps'] == sorted(set(view['gaps'])) and set(view['gaps']) <= {'OPAQUE_ROUTINE_DEPENDENCY', 'OUT_OF_SCOPE_RELATION', 'UNSUPPORTED_RELATION_KIND'})
        ids = [d['referencedExternalId'] for d in view['dependencies']]
        require(ids == sorted(set(ids)))
        for dep in view['dependencies']:
            require(set(dep) == {'referencedExternalId', 'referencedAttributeNumbers'})
            require(dep['referencedExternalId'] in records and records[dep['referencedExternalId']]['type'] in ('view', 'table'))
            numbers = dep['referencedAttributeNumbers']
            require(numbers and numbers == sorted(set(numbers)) and all(type(n) is int and 0 <= n <= 32767 for n in numbers))
    # Independent read-only catalog oracle. No view is evaluated and no source
    # SQL definition is fetched. This follows the scan, not its private snapshot.
    with deadline(12):
        with _connection_parameters(source, secret, TENANT, time.monotonic() + 12) as params:
            with _Resources() as resources:
                with _blocked_alarm():
                    conn = psycopg.connect(**params, row_factory=dict_row)
                    resources.own(conn.close)
                conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                role = conn.execute("SELECT current_user AS name,current_setting('transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(role == {'name': 'harbor_reader', 'readonly': 'on', 'rolsuper': False, 'rolbypassrls': False, 'rolcreaterole': False, 'rolcreatedb': False})
                db_oid = conn.execute('SELECT oid::text AS oid FROM pg_database WHERE datname=current_database()').fetchone()['oid']
                p = config['prefix']
                wanted = ['customer_order_summary', 'customers', 'orders']
                if config['mode'] != 'baseline':
                    wanted += [p + suffix for suffix in ('_renamed' if config['mode'] == 'renamed' else '_table', '_view', '_empty', '_gap')]
                rows = conn.execute("SELECT c.oid::text AS oid,c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(%s) ORDER BY c.oid", (wanted,)).fetchall()
                by_name = {r['relname']: r for r in rows}
                require(set(by_name) == set(wanted))
                oids = [r['oid'] for r in rows]
                attrs = conn.execute('SELECT attrelid::text AS oid,attnum,attname FROM pg_attribute WHERE attrelid=ANY(%s::oid[]) AND attnum>0 AND NOT attisdropped ORDER BY attrelid,attnum', (oids,)).fetchall()
                rules = conn.execute("SELECT ev_class::text AS oid,oid::text AS rewrite FROM pg_rewrite WHERE ev_class=ANY(%s::oid[]) AND rulename='_RETURN' AND ev_type='1' AND is_instead", (oids,)).fetchall()
                rule_by_oid = {r['oid']: r['rewrite'] for r in rules}
                require(len(rule_by_oid) == len(rules))
                def external(oid): return f'pg:{db_oid}:relation:{oid}'
                for row in rows:
                    item = records[external(row['oid'])]
                    require(item['name'] == row['relname'] and item['metadata']['oid'] == row['oid'] and item['metadata']['relationKind'] == row['relkind'])
                    if row['relkind'] == 'v':
                        require(views[external(row['oid'])]['rewriteOid'] == rule_by_oid[row['oid']])
                for row in attrs:
                    item = records[external(row['oid']) + ':column:' + str(row['attnum'])]
                    require(item['name'] == row['attname'] and item['metadata']['ordinalPosition'] == row['attnum'])
                expected = {'customers': [1, 2, 3], 'orders': [1, 2, 5]}
                # Verify the native witness set independently of extractor SQL.
                native = conn.execute("""SELECT c.relname,d.refobjsubid AS n FROM pg_depend d
                    JOIN pg_class c ON c.oid=d.refobjid JOIN pg_namespace ns ON ns.oid=c.relnamespace
                    WHERE d.classid='pg_rewrite'::regclass AND d.objid=%s::oid AND d.objsubid=0
                      AND d.refclassid='pg_class'::regclass AND d.deptype='n'
                    ORDER BY c.relname,d.refobjsubid""", (rule_by_oid[by_name['customer_order_summary']['oid']],)).fetchall()
                actual = {}
                for row in native: actual.setdefault(row['relname'], []).append(row['n'])
                require({k: sorted(set(v)) for k, v in actual.items()} == expected)
                harbor = views[external(by_name['customer_order_summary']['oid'])]
                require(harbor['gaps'] == [] and harbor['dependencies'] == sorted([
                    {'referencedExternalId': external(by_name[name]['oid']), 'referencedAttributeNumbers': ns}
                    for name, ns in expected.items()], key=lambda d: d['referencedExternalId']))
                fixture = None
                if config['mode'] != 'baseline':
                    table_name = p + ('_renamed' if config['mode'] == 'renamed' else '_table')
                    table_id = external(by_name[table_name]['oid'])
                    own = views[external(by_name[p + '_view']['oid'])]
                    require(own['dependencies'] == [{'referencedExternalId': table_id, 'referencedAttributeNumbers': [1, 2]}] and own['gaps'] == [])
                    require(records[table_id + ':column:1']['name'] == ('after_name' if config['mode'] == 'renamed' else 'before_name'))
                    empty = views[external(by_name[p + '_empty']['oid'])]
                    require(empty['dependencies'] == [] and empty['gaps'] == [])
                    gap = views[external(by_name[p + '_gap']['oid'])]
                    require(gap['dependencies'] == [] and gap['gaps'] == ['OPAQUE_ROUTINE_DEPENDENCY', 'OUT_OF_SCOPE_RELATION'])
                    outside = conn.execute("SELECT c.oid::text AS oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname='external_input'", (p + '_outside',)).fetchone()
                    require(outside and external(outside['oid']) not in records and external(outside['oid']) not in json.dumps(lineage))
                    require(p + '_outside' not in json.dumps(result))
                    fixture = {'tableOid': by_name[table_name]['oid'], 'columnAttnum': 1, 'viewOid': by_name[p + '_view']['oid'], 'rewriteOid': own['rewriteOid'], 'lineageSha256': digest([own, empty, gap])}
    # Raw credentials, source rows and source SQL bodies are never returned.
    require(worker_hashes(config['hashes']) == hashes)
    return {'ok': True, 'hashes': hashes, 'fixture': fixture,
            'scan': {'sourceVersion': result['sourceVersion'], 'permissionFingerprint': result['permissionFingerprint'],
                     'lineageSha256': digest(lineage), 'recordsSha256': digest(result['records'])}}


def run_core():
    harness = Harness()
    hashes = source_hashes()
    original = baseline = None
    failure = None
    cleanup_ok = False
    try:
        harness.local()
        harness.phase = 'worker_source_binding'
        harness.worker_call('probe', hashes)
        harness.phase = 'original_inventory'
        original = harness.sql(INVENTORY_SQL)
        require(re.fullmatch(r'[a-f0-9]{64}', original))
        harness.phase = 'harbor_native_oracle'
        baseline = harness.worker_call('baseline', hashes)
        harness.phase = 'owned_fixture_setup'
        harness.prepare()
        harness.phase = 'empty_gap_and_edge_scan'
        first = harness.worker_call('created', hashes)
        harness.phase = 'owned_rename'
        harness.rename()
        harness.phase = 'renamed_native_scan'
        renamed = harness.worker_call('renamed', hashes)
        require(first['fixture'] == renamed['fixture'] and first['fixture'] is not None)
        require(first['scan']['lineageSha256'] == renamed['scan']['lineageSha256'])
        require(first['scan']['permissionFingerprint'] == renamed['scan']['permissionFingerprint'] == baseline['scan']['permissionFingerprint'])
        require(harness.inspect('python-worker') == harness.worker and harness.inspect('source-postgres') == harness.source)
    except BaseException:
        failure = harness.phase
    finally:
        try:
            harness.cleanup()
            if original is not None:
                harness.cleanup_end = time.monotonic() + 25
                require(harness.sql(INVENTORY_SQL, cleanup=True) == original)
            cleanup_ok = True
        except BaseException:
            failure = 'owned_cleanup_or_catalog_preservation'
    if failure is None:
        try:
            harness.phase = 'post_cleanup_native_scan'
            final = harness.worker_call('baseline', hashes)
            require(final['scan'] == baseline['scan'] and final['fixture'] is None)
            require(source_hashes() == hashes)
        except BaseException:
            failure = harness.phase
    if failure is not None:
        return {'suite': 'postgres-lineage-native-conformance', 'result': 'failed',
                'phase': failure, 'code': 'LINEAGE_CONFORMANCE_FAILED', 'cleanupConfirmed': cleanup_ok}, 1
    return {'suite': 'postgres-lineage-native-conformance', 'result': 'passed', 'checks': CHECKS,
            'sourceHashes': hashes, 'worker': harness.worker, 'source': harness.source,
            'catalogInventorySha256': original, 'observation': baseline['scan'], 'cleanupConfirmed': True,
            'limits': ['synthetic local source; direct adapter and catalog only',
                       'empty dependency view, not an entirely empty schema',
                       'catalog/ACL and metadata preservation, not business-row checksums',
                       'no external TLS, ingestion, API, Temporal, UI, column mapping or SQL-body analysis claim']}, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--run-core', action='store_true')
    modes.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker:
            result, status = worker(), 0
        else:
            result, status = run_core()
    except BaseException:
        result, status = {'ok': False, 'code': 'LINEAGE_CONFORMANCE_FAILED'}, 1
    print(json.dumps(result, separators=(',', ':')))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
