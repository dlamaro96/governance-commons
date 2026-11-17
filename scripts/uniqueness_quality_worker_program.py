# SPDX-License-Identifier: Apache-2.0
# Executed inside an owned helper by the private qualification launcher only.
import copy, hashlib, json, math, os, re, sys, time
from datetime import datetime
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from governance_workers import quality
from governance_workers.quality import execute
from governance_workers.postgresql import ScanFailure, _connection_parameters
from governance_workers.secrets import resolve
from governance_workers.deadline import deadline
from governance_workers.postgres_targets import _Resources, _blocked_alarm


def require(value):
    if not value: raise ValueError('qualification refused')


def load():
    raw = sys.stdin.buffer.read(16385)
    require(len(raw) <= 16384)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid scalar')))
    require(type(value) is dict and set(value) == {'mode', 'tenantId', 'targets', 'hashes'})
    require(value['tenantId'] == 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    return value


def hashes(expected):
    result = {}
    require(type(expected) is dict and 1 <= len(expected) <= 64)
    for path, digest in expected.items():
        require(re.fullmatch(r'python/(?:governance_workers/[a-z_]+\.py|pyproject\.toml|uv\.lock)', path))
        require(re.fullmatch(r'[a-f0-9]{64}', digest))
        actual = hashlib.sha256(Path('/worker', path.removeprefix('python/')).read_bytes()).hexdigest()
        require(actual == digest)
        result[path] = actual
    return result


def measurement(value, expected):
    fields = {'formatVersion', 'kind', 'strategy', 'rowCount', 'nullCount', 'distinctCount',
              'duplicateGroupCount', 'duplicateRowCount', 'totalValueBytes', 'largestValueBytes',
              'observedStartedAt', 'observedFinishedAt', 'elapsedMs', 'sourceVersion',
              'adapterVersion', 'queryTemplate', 'estimatedCost', 'estimatedBytes'}
    require(type(value) is dict and set(value) == fields)
    require(type(value['formatVersion']) is int and value['formatVersion'] == 1 and value['kind'] == 'uniqueness')
    require(value['strategy'] == 'exact-bounded-role-scope' and value['queryTemplate'] == 'postgresql-uniqueness-v1' and value['adapterVersion'] == '1')
    for key, want in zip(('rowCount', 'nullCount', 'distinctCount', 'duplicateGroupCount', 'duplicateRowCount', 'totalValueBytes', 'largestValueBytes'), expected):
        require(type(value[key]) is int and value[key] == want)
    require(type(value['elapsedMs']) is int and 0 <= value['elapsedMs'] <= 30000)
    require(type(value['sourceVersion']) is str and re.fullmatch(r'[0-9]{5,16}', value['sourceVersion']))
    for key in ('observedStartedAt', 'observedFinishedAt'):
        require(type(value[key]) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value[key]))
    started = datetime.fromisoformat(value['observedStartedAt'])
    finished = datetime.fromisoformat(value['observedFinishedAt'])
    require(0 <= (finished-started).total_seconds() <= 31 and abs((finished-started).total_seconds()*1000-value['elapsedMs']) <= 1000)
    require(type(value['estimatedCost']) in (int, float) and math.isfinite(value['estimatedCost']) and 0 <= value['estimatedCost'] <= 1000000)
    require(type(value['estimatedBytes']) is int and 0 <= value['estimatedBytes'] <= 67108864)
    return value


def main():
    config = load()
    matched = hashes(config['hashes'])
    if config['mode'] == 'probe':
        require(config['targets'] == {})
        print(json.dumps({'ok': True, 'hashes': matched}, separators=(',', ':')))
        return
    require(config['mode'] in ('run', 'locked') and type(config['targets']) is dict)
    kinds = {'text', 'varchar', 'allnull', 'empty', 'long', 'too_long', 'integer', 'bpchar', 'domain', 'rls', 'parent', 'child', 'many', 'canonical', 'canonical_null'}
    require(set(config['targets']) == ({'text'} if config['mode'] == 'locked' else kinds))
    for kind, target in config['targets'].items():
        require(type(target) is dict)
        if kind in ('canonical', 'canonical_null'):
            require(target['tableName'] == 'uniqueness_quality_fixture')
            require(target['columnName'] == ('code' if kind == 'canonical' else 'all_null'))
        else:
            require(re.fullmatch(r'gc_uq_[a-f0-9]{32}_' + kind, target['tableName']))
    source = {'connectorId': 'postgresql', 'host': 'source-postgres', 'port': 5432, 'database': 'harbor', 'schema': 'public', 'secretRef': 'demo-postgres'}
    secret = resolve(os.environ['SOURCE_SECRETS_FILE'], 'demo-postgres', config['tenantId'], 'postgresql')
    require(secret['username'] == 'harbor_reader')
    budget = {'maximumRows': 100000, 'maximumSeconds': 30, 'statementTimeoutMs': 15000,
              'maximumEstimatedCost': 1000000, 'maximumEstimatedBytes': 67108864,
              'maximumValueBytes': 4096, 'maximumTotalValueBytes': 67108864}
    def request(target):
        return {'formatVersion': 1, 'kind': 'uniqueness', 'target': copy.deepcopy(target), 'budget': dict(budget)}
    def run(value):
        return execute(source, secret, config['tenantId'], value)
    def refused(value, code):
        try: run(value)
        except ScanFailure as error: require(error.code == code)
        else: raise ValueError('expected refusal')
    if config['mode'] == 'locked':
        started = time.monotonic()
        refused(request(config['targets']['text']), 'QUALITY_RESOURCE_LIMIT')
        elapsed = math.floor((time.monotonic()-started)*1000)
        require(1500 <= elapsed <= 6500 and hashes(config['hashes']) == matched)
        print(json.dumps({'ok': True, 'hashes': matched, 'checks': ['actual_lock_timeout_refusal'], 'elapsedMs': elapsed}, separators=(',', ':')))
        return
    expected = [
        ('canonical', (20, 4, 12, 2, 6, 16, 1)),
        ('canonical_null', (20, 20, 0, 0, 0, 0, 0)),
        ('text', (13, 1, 9, 3, 6, 17, 3)),
        ('varchar', (13, 1, 9, 3, 6, 17, 3)),
        ('allnull', (5, 5, 0, 0, 0, 0, 0)),
        ('empty', (0, 0, 0, 0, 0, 0, 0)),
        ('long', (2, 0, 1, 1, 2, 8192, 4096))]
    measurements = [measurement(run(request(config['targets'][kind])), counts) for kind, counts in expected]
    require(len({value['sourceVersion'] for value in measurements}) == 1)
    # Observe actual planner result tuples without replacing the function,
    # changing arguments, editing SQL or substituting any return value.
    plans = []
    code = quality._estimates.__code__
    def observe(frame, event, arg):
        if frame.f_code is code and event == 'return':
            require(len(plans) < 2 and type(arg) is tuple and len(arg) == 2)
            plans.append(arg)
    require(sys.getprofile() is None)
    try:
        sys.setprofile(observe)
        measured = measurement(run(request(config['targets']['canonical'])), expected[0][1])
    finally:
        sys.setprofile(None)
    require(len(plans) == 2 and measured['estimatedCost'] == sum(value[0] for value in plans)
            and measured['estimatedBytes'] == sum(value[1] for value in plans))
    for field, index in [('maximumEstimatedCost', 0), ('maximumEstimatedBytes', 1)]:
        values = [plan[index] for plan in plans]
        require(min(values) > 0)
        cap = max(values) + (min(values)/2 if index == 0 else min(values)//2)
        require(max(values) <= cap < sum(values))
        limited = request(config['targets']['canonical'])
        limited['budget'][field] = cap
        refused(limited, 'QUALITY_RESOURCE_LIMIT')
    for kind, lower in [('canonical', {'maximumRows': 19}), ('many', {}), ('too_long', {}),
                        ('long', {'maximumValueBytes': 4095}), ('long', {'maximumTotalValueBytes': 8191})]:
        limited = request(config['targets'][kind])
        limited['budget'].update(lower)
        refused(limited, 'QUALITY_RESOURCE_LIMIT')
    target = config['targets']['text']
    stale = {'databaseOid': str(1 if target['databaseOid'] != '1' else 2),
             'schemaOid': str(1 if target['schemaOid'] != '1' else 2),
             'relationOid': config['targets']['empty']['relationOid'], 'attributeNumber': 2,
             'schemaName': 'quality_wrong_schema', 'tableName': config['targets']['empty']['tableName'],
             'columnName': 'wrong_column', 'dataType': 'integer'}
    for field, value in stale.items():
        changed = request(target)
        changed['target'][field] = value
        refused(changed, 'QUALITY_TARGET_STALE')
    for kind in ('integer', 'bpchar', 'domain', 'rls', 'parent', 'child'):
        refused(request(config['targets'][kind]), 'QUALITY_TARGET_UNSUPPORTED')
    with deadline(12):
        with _connection_parameters(source, secret, config['tenantId'], time.monotonic()+12) as params:
            with _Resources() as resources:
                with _blocked_alarm():
                    kwargs = dict(params)
                    kwargs['connect_timeout'] = 5
                    conn = psycopg.connect(**kwargs, row_factory=dict_row)
                    resources.own(conn.close)
                row = conn.execute("SELECT current_user AS name,current_setting('default_transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(row == {'name': 'harbor_reader', 'readonly': 'on', 'rolsuper': False, 'rolbypassrls': False, 'rolcreaterole': False, 'rolcreatedb': False})
                conn.rollback()
                conn.execute('SET TRANSACTION READ WRITE')
                try: conn.execute(sql.SQL('UPDATE {} SET payload=NULL WHERE false').format(sql.Identifier('public', target['tableName'])))
                except psycopg.Error as error: require(error.sqlstate == '42501')
                else: raise ValueError('reader has write permission')
                finally: conn.rollback()
    require(hashes(config['hashes']) == matched)
    print(json.dumps({'ok': True, 'checks': [
        'canonical_20_rows_duplicate_members_oracle', 'canonical_all_null', 'text_and_varchar_exact_utf8_groups',
        'case_spaces_unicode_empty_string_distinct', 'owned_all_null_and_empty', 'all_group_members_not_excess_copies',
        'lowered_row_bound_and_100001_refusal', 'logical_value_and_total_bytes_refusal',
        'actual_cumulative_plan_cost_and_bytes_refusal', 'all_eight_target_pins_refused_when_stale',
        'integer_bpchar_domain_unsupported', 'rls_and_inheritance_unsupported', 'native_reader_role_and_read_only_default',
        'native_reader_dml_denied', 'closed_aggregates_without_source_values'],
        'measurements': measurements, 'plans': plans, 'hashes': matched}, separators=(',', ':')))


try:
    main()
except BaseException:
    print(json.dumps({'ok': False, 'code': 'UNIQUENESS_QUALITY_WORKER_QUALIFICATION_FAILED'}, separators=(',', ':')))
    sys.exit(1)
