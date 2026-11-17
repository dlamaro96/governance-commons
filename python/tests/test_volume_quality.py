# SPDX-License-Identifier: Apache-2.0
"""Volume closed admission, observed SQL, cleanup and real loopback controls.

Database replies are controlled doubles. Actual PostgreSQL COUNT, permissions,
planner and source no-write proof belong to the separate native worker gate.
"""
import copy
import hashlib
import json
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import quality, server
from test_postgres_targets import source, secret
import test_quality as baseline
import test_server as http_baseline

VECTORS = (
    (0, 5, '3b2199a5b4d34da6e2408b6fe7f6158434cad02517ee08b2c24ad06551a51219'),
    (0, 0, '84f12349cdd0d6377677ea35694d2c074ed49c6f70e73fa085bd0c6b005219bd'),
    (100000, 100000, 'aaed04bc354ccdaf5ef948e5bd1a213331eb37059b433ea2dbf66759ee2eb0eb'),
    (6, 6, '08d5c181809ded58cf68240b793f9e54f7a372b32b9fd0bf16cce1fcd993f421'),
)


def binding(minimum=0, maximum=5):
    preimage = {'formatVersion': 1, 'kind': 'volume', 'minimumRows': minimum,
                'maximumRows': maximum, 'comparison': 'row-count-inclusive', 'scope': 'entire-table'}
    digest = hashlib.sha256(json.dumps(preimage, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    return {key: preimage[key] for key in ('minimumRows', 'maximumRows', 'comparison', 'scope')} | {'volumeHash': digest}


def execution():
    result = baseline.execution()
    result.update(kind='volume', volume=binding())
    result['target'] = {key: result['target'][key] for key in ('databaseOid', 'schemaOid', 'relationOid', 'schemaName', 'tableName')}
    result['target'].update(kind='table', tableName='volume_quality_fixture')
    return result


def payload():
    result = http_baseline.quality_payload()
    result['execution'] = execution()
    result['execution']['target']['schemaName'] = result['source']['schema']
    return result


def measurement():
    result = http_baseline.quality_measurement()
    del result['nullCount']
    result.update(kind='volume', queryTemplate='postgresql-volume-v1', rowCount=6, volumeHash=VECTORS[0][2])
    return result


class Connection(baseline.Connection):
    def __init__(self, params):
        super().__init__(params)
        self.catalog = {key: self.catalog[key] for key in (
            'relation_oid', 'schema_oid', 'nspname', 'relname', 'relkind', 'relispartition',
            'relrowsecurity', 'inherited', 'schema_allowed', 'table_allowed', 'locked')}
        self.catalog.update(relname='volume_quality_fixture', relforcerowsecurity=False)
        self.counts = {'row_count': 6}

    def execute(self, statement, parameters=None):
        text = statement if type(statement) is str else statement.as_string()
        if text.startswith('SELECT pg_catalog.count(*) AS row_count'):
            self.queries.append((text, parameters))
            self.before_query(text)
            return baseline.Rows(self.counts)
        return super().execute(statement, parameters)


class AdmissionTests(baseline.Cases):
    def test_fixed_vectors_and_detached_table_contract_without_column_metadata(self):
        for minimum, maximum, digest in VECTORS:
            supplied = binding(minimum, maximum)
            self.assertEqual(supplied['volumeHash'], digest)
            detached = quality.validate_volume_binding(supplied)
            supplied['minimumRows'] = -1
            self.assertEqual(detached, binding(minimum, maximum))
        value = execution()
        src, target, budget = quality.validate_execution(source(), value)
        value['target']['tableName'] = 'changed'
        value['budget']['maximumRows'] = 1
        self.assertEqual(target['tableName'], 'volume_quality_fixture')
        self.assertEqual(budget, quality.BUDGETS)
        self.assertEqual(set(target), {'kind', 'databaseOid', 'schemaOid', 'relationOid', 'schemaName', 'tableName'})
        self.assertEqual(src, source())

    def test_noninteger_and_out_of_range_thresholds_refuse_before_destination(self):
        for key in ('minimumRows', 'maximumRows'):
            for bad in (True, False, -1, 100001, 1.0, '1', None, [], {}, float('nan'), float('inf')):
                value = execution()
                value['volume'][key] = bad
                with patch.object(quality, '_connection_parameters') as destination, patch.object(quality.psycopg, 'connect') as connect:
                    self.failure('QUALITY_INPUT_INVALID', lambda: quality.execute(source(), secret(), 'tenant-one', value))
                    destination.assert_not_called()
                    connect.assert_not_called()
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_volume_binding(binding(6, 5)))

    def test_closed_binding_tampered_hash_missing_fields_and_threshold_drift(self):
        variants = [dict(binding(), minimumRows=1), dict(binding(), volumeHash='0'*64),
                    dict(binding(), volumeHash=VECTORS[0][2].upper()), dict(binding(), volumeHash=True),
                    dict(binding(), comparison='approximately'), dict(binding(), scope='visible-columns'),
                    dict(binding(), formatVersion=1), dict(binding(), nullPolicy='exclude'), dict(binding(), sql='private')]
        for key in quality.VOLUME_KEYS:
            value = binding()
            del value[key]
            variants.append(value)
        for value in variants:
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_volume_binding(value))

    def test_cross_family_and_fake_column_targets_are_rejected(self):
        import test_reference_quality, test_uniqueness_quality, test_range_quality, test_freshness_quality
        for factory in [baseline.execution, test_reference_quality.execution, test_uniqueness_quality.execution,
                        test_range_quality.execution, test_freshness_quality.execution]:
            old = factory()
            quality.validate_execution(source(), old)
            old['volume'] = binding()
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), old))
        for key, item in [('attributeNumber', 1), ('dataType', 'bigint'), ('columnName', 'amount'), ('kind', 'column')]:
            value = execution()
            value['target'][key] = item
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for family in ('reference', 'range', 'freshness'):
            value = execution()
            value[family] = {}
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for key, maximum in quality.BUDGETS.items():
            value = execution()
            value['budget'][key] = maximum + 1
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))


class ExecutorTests(baseline.Cases):
    setUp = baseline.ExecutorTests.setUp
    assert_closed = baseline.ExecutorTests.assert_closed

    def connect(self, **params):
        conn = Connection(params)
        self.connections.append(conn)
        self.configure(conn)
        return conn

    def run_volume(self, value=None):
        return quality.execute(source(), secret(), 'tenant-one', value if value is not None else execution())

    def assert_no_aggregate(self, conn):
        self.assertFalse(any(text.startswith('SELECT pg_catalog.count(*) AS') for text, _ in conn.queries))

    def test_whole_table_count_has_no_columns_and_threshold_does_not_limit_query(self):
        result = self.run_volume()
        self.assertEqual(set(result), set(measurement()))
        self.assertEqual((result['rowCount'], result['volumeHash'], result['kind'], result['queryTemplate']),
                         (6, VECTORS[0][2], 'volume', 'postgresql-volume-v1'))
        self.assertEqual((result['estimatedCost'], result['estimatedBytes']), (10.5, 416))
        conn = self.assert_closed()
        self.assertEqual(conn.params['sslmode'], 'verify-full')
        self.assertEqual(conn.queries[0][0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        self.assertEqual(next(text for text, _ in conn.queries if text.startswith('LOCK ')),
                         'LOCK TABLE ONLY "catalog"."volume_quality_fixture" IN ACCESS SHARE MODE')
        aggregate, params = next((text, params) for text, params in conn.queries if text.startswith('SELECT pg_catalog.count(*) AS'))
        self.assertEqual(aggregate, 'SELECT pg_catalog.count(*) AS row_count FROM (SELECT 1 FROM ONLY "catalog"."volume_quality_fixture" LIMIT %s) AS bounded')
        self.assertEqual(params, (100001,))
        self.assertEqual(next(params for text, params in conn.queries if text.startswith('EXPLAIN ')), params)
        self.assertEqual(sum(text.startswith('EXPLAIN ') for text, _ in conn.queries), 1)
        self.assertFalse(any('pg_attribute' in text or 'pg_type' in text or 'attname' in text for text, _ in conn.queries))
        self.assertFalse({'nullCount', 'columnName', 'dataType', 'verdict', 'maximumRows', 'minimumRows'} & set(result))

    def test_zero_exact_cap_and_lowered_resource_cap_are_not_rule_thresholds(self):
        for rows in (0, 6, 100000):
            self.configure = lambda conn: setattr(conn, 'counts', {'row_count': rows})
            self.assertEqual(self.run_volume()['rowCount'], rows)
            self.assert_closed()
        self.configure = lambda conn: setattr(conn, 'counts', {'row_count': 100001})
        self.failure('QUALITY_RESOURCE_LIMIT', self.run_volume)
        self.assert_closed()
        self.configure = lambda conn: None
        value = execution()
        value['volume'] = binding(100000, 100000)
        value['budget']['maximumRows'] = 6
        self.assertEqual(self.run_volume(value)['rowCount'], 6)
        self.assert_closed()
        value['budget']['maximumRows'] = 5
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_volume(value))
        self.assertEqual(next(params for text, params in self.assert_closed().queries if text.startswith('SELECT pg_catalog.count(*) AS')), (6,))

    def test_count_is_closed_integral_and_never_returns_raw_or_partial_values(self):
        for counts in (None, {}, {'row_count': True}, {'row_count': -1}, {'row_count': 1.0}, {'row_count': '6'},
                       {'row_count': 100002}, {'row_count': 6, 'null_count': 6}, {'row_count': 6, 'values': ['private']}):
            self.configure = lambda conn: setattr(conn, 'counts', counts)
            self.failure('SOURCE_DATABASE_ERROR', self.run_volume)
            self.assert_closed()

    def test_only_ordinary_nonrls_noninherited_tables_are_supported(self):
        for key, value in [('relkind', 'v'), ('relkind', 'm'), ('relkind', 'p'), ('relkind', 'f'),
                           ('relispartition', True), ('relrowsecurity', True), ('relforcerowsecurity', True), ('inherited', True)]:
            self.configure = lambda conn: conn.catalog.update({key: value})
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_volume)
            self.assert_no_aggregate(self.assert_closed())

    def test_exact_relation_and_database_pins_full_table_permission_and_role_rechecked(self):
        for key, value in [('relation_oid', '66'), ('schema_oid', '19'), ('nspname', 'other'),
                           ('relname', 'replacement'), ('locked', False)]:
            self.configure = lambda conn: conn.catalog.update({key: value})
            self.failure('QUALITY_TARGET_STALE', self.run_volume)
            self.assert_no_aggregate(self.assert_closed())
        for key in ('schema_allowed', 'table_allowed'):
            self.configure = lambda conn: conn.catalog.update({key: False})
            self.failure('SOURCE_SCOPE_DENIED', self.run_volume)
            self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: conn.identity.update(database_oid='24')
        self.failure('QUALITY_TARGET_STALE', self.run_volume)
        self.assert_no_aggregate(self.assert_closed())
        for key in ('rolsuper', 'rolbypassrls'):
            self.configure = lambda conn: conn.identity.update({key: True})
            self.failure('SOURCE_PRIVILEGE_TOO_BROAD', self.run_volume)
            self.assert_no_aggregate(self.assert_closed())

    def test_planner_cost_bytes_and_lowered_limits_refuse_before_count(self):
        for observed in (baseline.plan(cost=1000001), baseline.plan(rows=100000, width=1000), None):
            self.configure = lambda conn: setattr(conn, 'plan', observed)
            self.failure('SOURCE_DATABASE_ERROR' if observed is None else 'QUALITY_RESOURCE_LIMIT', self.run_volume)
            self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: None
        for key, limit in [('maximumEstimatedCost', 10), ('maximumEstimatedBytes', 400)]:
            value = execution()
            value['budget'][key] = limit
            self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_volume(value))
            self.assert_no_aggregate(self.assert_closed())

    def test_quoted_identifiers_detached_target_and_binding(self):
        value = execution()
        value['target']['tableName'] = 'count";SELECT private--'
        def configure(conn):
            conn.catalog.update(relname=value['target']['tableName'])
            value['target']['tableName'] = 'later'
            value['volume'].update(minimumRows=1, volumeHash='f'*64)
        self.configure = configure
        result = self.run_volume(value)
        self.assertEqual(result['volumeHash'], VECTORS[0][2])
        aggregate, params = next((text, params) for text, params in self.assert_closed().queries if text.startswith('SELECT pg_catalog.count(*) AS'))
        self.assertIn('FROM ONLY "catalog"."count"";SELECT private--" LIMIT %s', aggregate)
        self.assertEqual(params, (100001,))

    def test_original_deadline_and_owned_cleanup_still_apply_to_count(self):
        value = execution()
        value['budget']['maximumSeconds'] = 3
        self.configure = lambda conn: setattr(conn, 'before_query', lambda text: time.sleep(5) if text.startswith('SELECT pg_catalog.count(*) AS') else None)
        started = time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_volume(value))
        self.assertLess(time.monotonic() - started, 3.5)
        self.assert_closed()

    def test_driver_error_mappings_do_not_expose_private_source_diagnostics(self):
        for error, code in [(psycopg.errors.QueryCanceled, 'QUALITY_RESOURCE_LIMIT'),
                            (psycopg.errors.LockNotAvailable, 'QUALITY_RESOURCE_LIMIT'),
                            (psycopg.errors.InsufficientPrivilege, 'SOURCE_SCOPE_DENIED'),
                            (psycopg.errors.UndefinedTable, 'QUALITY_TARGET_STALE'),
                            (psycopg.errors.WrongObjectType, 'QUALITY_TARGET_UNSUPPORTED'),
                            (psycopg.OperationalError, 'SOURCE_DATABASE_ERROR')]:
            def configure(conn):
                def fail(text):
                    if text.startswith('SELECT pg_catalog.count(*) AS'):
                        raise error('private table rows and credential')
                conn.before_query = fail
            self.configure = configure
            caught = self.failure(code, self.run_volume)
            self.assertIsNone(caught.__cause__)
            self.assertTrue(caught.__suppress_context__)
            self.assert_closed()


class HTTPTests(unittest.TestCase):
    setUp = http_baseline.WorkerHTTPTest.setUp
    write_fixture = http_baseline.WorkerHTTPTest.write_fixture
    request = http_baseline.WorkerHTTPTest.request

    def test_closed_table_execution_16k_frame_and_rotated_credentials(self):
        self.payload = payload()
        self.write_fixture('postgres')
        raw = json.dumps(self.payload).encode()
        raw += b' ' * (16384 - len(raw))
        with patch.object(server, 'execute_quality', return_value=measurement()) as execute, patch.object(server, 'scan') as scan:
            self.assertEqual(self.request(raw, path='/quality'), (200, {'measurement': measurement()}))
            self.assertEqual(execute.call_args.args[3], self.payload['execution'])
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-test-password')
            self.write_fixture('postgres-rotated')
            self.assertEqual(self.request(raw, path='/quality')[0], 200)
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-rotated-password')
            scan.assert_not_called()
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            self.assertEqual(self.request(raw + b' ', path='/quality'), (413, {'code': 'REQUEST_SIZE'}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_hash_duplicate_fake_column_and_crossfamily_fail_before_secrets(self):
        value = payload()
        altered = copy.deepcopy(value)
        altered['execution']['volume']['maximumRows'] = 6
        fake = copy.deepcopy(value)
        fake['execution']['target']['columnName'] = 'amount'
        crossed = copy.deepcopy(value)
        crossed['execution']['range'] = {}
        raw = json.dumps(value).encode()
        duplicate = raw.replace(b'"minimumRows": 0', b'"minimumRows":1,"minimumRows":0')
        cases = [(json.dumps(item).encode(), 'QUALITY_INPUT_INVALID') for item in (altered, fake, crossed)] + [(duplicate, 'INVALID_REQUEST')]
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            for body, code in cases:
                self.assertEqual(self.request(body, path='/quality'), (400, {'code': code}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_unknown_volume_exception_is_closed(self):
        self.payload = payload()
        self.write_fixture('postgres')
        with patch.object(server, 'execute_quality', side_effect=RuntimeError('private source values')):
            self.assertEqual(self.request(path='/quality'), (500, {'code': 'WORKER_FAILURE'}))


if __name__ == '__main__':
    unittest.main()
