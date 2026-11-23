# SPDX-License-Identifier: Apache-2.0
"""Range admission/SQL-observing controls and actual loopback HTTP framing.

Aggregate replies are controlled test doubles. PostgreSQL integer comparisons,
planner execution and actual source visibility remain native-gate prerequisites.
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
    ('0', '10', 'd9d1c5de1d8da97b52234be367e92343b365e59e7f3bde85748db969b857d161'),
    ('-9223372036854775808', '9223372036854775807', '0834cdeae46a46f1b6859649b262c0a5eeb23b019d513dbabfe889fa657829f1'),
    ('9007199254740993', '9007199254740993', 'd79dbdaffccf16bd9c113a103e3ec9e6c018392d7974daa5c5c8cbce1a43dab4'),
)


def binding(minimum='0', maximum='10'):
    preimage = {'formatVersion': 1, 'kind': 'range', 'minimum': minimum, 'maximum': maximum,
                'comparison': 'int64-inclusive', 'nullPolicy': 'exclude'}
    encoded = json.dumps(preimage, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {key: preimage[key] for key in ('minimum', 'maximum', 'comparison', 'nullPolicy')} | {
        'rangeHash': hashlib.sha256(encoded).hexdigest()}


def execution():
    result = baseline.execution()
    result.update(kind='range', range=binding())
    result['target'].update(tableName='range_quality_fixture', columnName='amount', dataType='bigint')
    return result


def payload():
    result = http_baseline.quality_payload()
    result['execution'] = execution()
    result['execution']['target']['schemaName'] = result['source']['schema']
    return result


def measurement():
    result = http_baseline.quality_measurement()
    result.update(kind='range', queryTemplate='postgresql-range-v1', rowCount=6, nullCount=1,
                  belowCount=1, aboveCount=1, rangeHash=VECTORS[0][2])
    return result


class Connection(baseline.Connection):
    def __init__(self, params):
        super().__init__(params)
        self.catalog.update(relname='range_quality_fixture', attname='amount', data_type='bigint', type_oid='20')
        self.counts = {'row_count': 6, 'null_count': 1, 'below_count': 1, 'above_count': 1}


class AdmissionTests(baseline.Cases):
    def test_shared_fixed_hash_vectors_and_detached_bounds(self):
        for minimum, maximum, expected in VECTORS:
            supplied = binding(minimum, maximum)
            self.assertEqual(supplied['rangeHash'], expected)
            value = quality.validate_range_binding(supplied)
            self.assertEqual(value, supplied)
            supplied['minimum'] = '-1'
            self.assertEqual(value['minimum'], minimum)
        for minimum, maximum in [('0', '0'), ('-1', '0'), ('-1', '-1')]:
            quality.validate_range_binding(binding(minimum, maximum))
        value = execution()
        detached = quality.validate_execution(source(), value)
        self.assertEqual(len(detached), 3)
        value['budget']['maximumRows'] = 1
        value['target']['columnName'] = 'changed'
        self.assertEqual(detached[1]['columnName'], 'amount')
        self.assertEqual(detached[2], quality.BUDGETS)

    def test_noncanonical_int64_inputs_and_reversed_bounds_rejected(self):
        invalid = ['', ' ', '+1', '-0', '00', '01', '-01', ' 1', '1 ', '1\n', '\t1',
                   '1.0', '1e3', '١', '１', '\ud800', '0\0', '9'*21,
                   '-9223372036854775809', '9223372036854775808', 0, 1.0, True, None, [], {}]
        for key in ('minimum', 'maximum'):
            for bad in invalid:
                with self.subTest(key=key, bad=repr(bad)):
                    value = binding('-9223372036854775808', '9223372036854775807')
                    value[key] = bad
                    self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_range_binding(value))
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_range_binding(binding('11', '10')))
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_range_binding(binding('0', '-1')))

    def test_closed_binding_and_tampered_hash_refuse_before_destination_or_connection(self):
        variants = [dict(binding(), minimum='1'), dict(binding(), rangeHash='0'*64),
                    dict(binding(), rangeHash=VECTORS[0][2].upper()), dict(binding(), rangeHash=True),
                    dict(binding(), comparison='numeric'), dict(binding(), nullPolicy='include'),
                    dict(binding(), formatVersion=1), dict(binding(), sql='SELECT private')]
        for key in quality.RANGE_KEYS:
            value = binding()
            del value[key]
            variants.append(value)
        for bad in variants:
            value = execution()
            value['range'] = bad
            with patch.object(quality, '_connection_parameters') as destination, patch.object(quality.psycopg, 'connect') as connect:
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.execute(source(), secret(), 'tenant-one', value))
                destination.assert_not_called()
                connect.assert_not_called()

    def test_closed_range_and_old_family_envelopes_preserve_exact_budgets(self):
        for path, key, extra in [((), 'reference', {}), ((), 'minimum', '0'), ((), 'referenceAsOf', '2026-01-01T00:00:00.000Z'),
                                 (('budget',), 'maximumValueBytes', 4096), (('budget',), 'maximumTotalValueBytes', 67108864),
                                 (('range',), 'codes', ['private'])]:
            value = execution()
            child = value
            for part in path:
                child = child[part]
            child[key] = extra
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        import test_reference_quality, test_uniqueness_quality
        for factory in [baseline.execution, test_reference_quality.execution, test_uniqueness_quality.execution]:
            value = factory()
            quality.validate_execution(source(), value)
            value['range'] = binding()
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for key, maximum in quality.BUDGETS.items():
            value = execution()
            value['budget'][key] = maximum + 1
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))


class ExecutorTests(baseline.Cases):
    setUp = baseline.ExecutorTests.setUp
    assert_closed = baseline.ExecutorTests.assert_closed
    assert_no_aggregate = baseline.ExecutorTests.assert_no_aggregate

    def connect(self, **params):
        conn = Connection(params)
        self.connections.append(conn)
        self.configure(conn)
        return conn

    def run_range(self, value=None):
        return quality.execute(source(), secret(), 'tenant-one', value if value is not None else execution())

    def test_closed_aggregate_and_pinned_readonly_parameterized_inclusive_query(self):
        result = self.run_range()
        self.assertEqual(set(result), set(measurement()))
        for key in ('kind', 'queryTemplate', 'rowCount', 'nullCount', 'belowCount', 'aboveCount', 'rangeHash'):
            self.assertEqual(result[key], measurement()[key])
        self.assertEqual((result['estimatedCost'], result['estimatedBytes']), (10.5, 416))
        self.assertNotIn('minimum', result)
        self.assertNotIn('maximum', result)
        conn = self.assert_closed()
        self.assertEqual(conn.params['sslmode'], 'verify-full')
        self.assertEqual(conn.queries[0][0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        self.assertEqual(next(text for text, _ in conn.queries if text.startswith('LOCK ')),
                         'LOCK TABLE ONLY "catalog"."range_quality_fixture" IN ACCESS SHARE MODE')
        aggregate, parameters = next((text, params) for text, params in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertIn('WHERE value OPERATOR(pg_catalog.<) %s::pg_catalog.int8', aggregate)
        self.assertIn('WHERE value OPERATOR(pg_catalog.>) %s::pg_catalog.int8', aggregate)
        self.assertNotIn('value::', aggregate)
        self.assertNotIn('<=', aggregate)
        self.assertNotIn('>=', aggregate)
        self.assertIn('SELECT "amount" AS value FROM ONLY "catalog"."range_quality_fixture" LIMIT %s', aggregate)
        self.assertEqual(parameters, ('0', '10', 100001))
        self.assertEqual(next(params for text, params in conn.queries if text.startswith('EXPLAIN ')), parameters)
        self.assertEqual(len([text for text, _ in conn.queries if text.startswith('EXPLAIN ')]), 1)

    def test_int64_extrema_and_above_js_safe_integer_preserved_as_text_parameters(self):
        for minimum, maximum, expected in VECTORS[1:]:
            value = execution()
            value['range'] = binding(minimum, maximum)
            result = self.run_range(value)
            self.assertEqual(result['rangeHash'], expected)
            conn = self.assert_closed()
            self.assertEqual(next(params for text, params in conn.queries if text.startswith('SELECT count(*) AS')),
                             (minimum, maximum, 100001))

    def test_only_builtin_integer_oids_reach_aggregate(self):
        for oid, name in [('20', 'bigint'), ('21', 'smallint'), ('23', 'integer')]:
            value = execution()
            value['target']['dataType'] = name
            self.configure = lambda conn: conn.catalog.update(type_oid=oid, data_type=name)
            self.assertEqual(self.run_range(value)['rowCount'], 6)
            self.assert_closed()
        for key, bad in [('type_oid', oid) for oid in ('25', '1043', '1700', '700', '701', '790', '80000')] + [
                ('typtype', 'd'), ('type_namespace', 'public'), ('relrowsecurity', True), ('inherited', True),
                ('relispartition', True), ('relkind', 'v'), ('relkind', 'm'), ('relkind', 'f')]:
            self.configure = lambda conn: conn.catalog.update({key: bad})
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_range)
            self.assert_no_aggregate(self.assert_closed())

    def test_source_identity_scope_and_target_pins_checked_before_measurement(self):
        for key, bad in [('relation_oid', '66'), ('schema_oid', '19'), ('attnum', 2), ('attname', 'renamed'),
                         ('data_type', 'numeric'), ('relname', 'replacement'), ('nspname', 'different'),
                         ('attisdropped', True), ('locked', False)]:
            self.configure = lambda conn: conn.catalog.update({key: bad})
            self.failure('QUALITY_TARGET_STALE', self.run_range)
            self.assert_no_aggregate(self.assert_closed())
        for key in ('schema_allowed', 'table_allowed'):
            self.configure = lambda conn: conn.catalog.update({key: False})
            self.failure('SOURCE_SCOPE_DENIED', self.run_range)
            self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: conn.identity.update(database_oid='24')
        self.failure('QUALITY_TARGET_STALE', self.run_range)
        self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: conn.identity.update(rolbypassrls=True)
        self.failure('SOURCE_PRIVILEGE_TOO_BROAD', self.run_range)
        self.assert_no_aggregate(self.assert_closed())

    def test_empty_all_null_and_zero_outliers_return_complete_counts(self):
        for rows, nulls, below, above in [(0, 0, 0, 0), (6, 6, 0, 0), (6, 1, 0, 0), (6, 1, 5, 0), (6, 1, 0, 5)]:
            self.configure = lambda conn: setattr(conn, 'counts', dict(row_count=rows, null_count=nulls, below_count=below, above_count=above))
            result = self.run_range()
            self.assertEqual((result['rowCount'], result['nullCount'], result['belowCount'], result['aboveCount']), (rows, nulls, below, above))
            self.assert_closed()
            self.assertNotIn('verdict', result)  # The canonical server decides thresholds/NO_DATA.

    def test_count_algebra_is_closed_and_never_returns_values_or_partial_results(self):
        for changed in [{'row_count': True}, {'null_count': 7}, {'below_count': True}, {'above_count': False},
                        {'below_count': -1}, {'above_count': -1}, {'below_count': 5}, {'below_count': 1.0},
                        {'above_count': None}, {'below_count': '1'}, {'private_values': [-1, 11]}, {'row_count': 100002}]:
            self.configure = lambda conn: conn.counts.update(changed)
            self.failure('SOURCE_DATABASE_ERROR', self.run_range)
            self.assert_closed()
        for key in ('row_count', 'null_count', 'below_count', 'above_count'):
            self.configure = lambda conn: conn.counts.pop(key)
            self.failure('SOURCE_DATABASE_ERROR', self.run_range)
            self.assert_closed()

    def test_exact_and_lowered_row_caps_and_planner_limits(self):
        value = execution()
        value['budget']['maximumRows'] = 6
        self.assertEqual(self.run_range(value)['rowCount'], 6)
        self.assert_closed()
        value['budget']['maximumRows'] = 5
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_range(value))
        self.assertEqual(next(params for text, params in self.assert_closed().queries if text.startswith('SELECT count(*) AS')), ('0', '10', 6))
        for plan in [baseline.plan(cost=1000001), baseline.plan(rows=100000, width=1000)]:
            self.configure = lambda conn: setattr(conn, 'plan', plan)
            self.failure('QUALITY_RESOURCE_LIMIT', self.run_range)
            self.assertFalse(any(text.startswith('SELECT count(*) AS') for text, _ in self.assert_closed().queries))
        self.configure = lambda conn: None
        value = execution()
        value['budget']['maximumEstimatedCost'] = 10
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_range(value))
        self.assertFalse(any(text.startswith('SELECT count(*) AS') for text, _ in self.assert_closed().queries))

    def test_identifiers_quoted_and_binding_detached_before_connection(self):
        value = execution()
        value['target'].update(tableName='range";SELECT private--', columnName='amount" OR TRUE--')
        def configure(conn):
            conn.catalog.update(relname=value['target']['tableName'], attname=value['target']['columnName'])
            value['range'].update(minimum='-2', rangeHash='f'*64)
        self.configure = configure
        result = self.run_range(value)
        self.assertEqual(result['rangeHash'], VECTORS[0][2])
        text, parameters = next((text, params) for text, params in self.assert_closed().queries if text.startswith('SELECT count(*) AS'))
        self.assertIn('SELECT "amount"" OR TRUE--" AS value FROM ONLY "catalog"."range"";SELECT private--" LIMIT %s', text)
        self.assertEqual(parameters, ('0', '10', 100001))

    def test_original_deadline_interrupts_query_and_closes_owned_connection(self):
        value = execution()
        value['budget']['maximumSeconds'] = 3
        self.configure = lambda conn: setattr(conn, 'before_query', lambda text: time.sleep(5) if text.startswith('SELECT count(*) AS') else None)
        started = time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_range(value))
        self.assertLess(time.monotonic()-started, 3.5)
        self.assert_closed()

    def test_driver_failure_mapping_keeps_private_diagnostics_closed(self):
        for error, code in [(psycopg.errors.QueryCanceled, 'QUALITY_RESOURCE_LIMIT'),
                            (psycopg.errors.LockNotAvailable, 'QUALITY_RESOURCE_LIMIT'),
                            (psycopg.errors.InsufficientPrivilege, 'SOURCE_SCOPE_DENIED'),
                            (psycopg.errors.UndefinedColumn, 'QUALITY_TARGET_STALE'),
                            (psycopg.OperationalError, 'SOURCE_DATABASE_ERROR')]:
            def configure(conn):
                def fail(text):
                    if text.startswith('SELECT count(*) AS'):
                        raise error('private amount and source credential')
                conn.before_query = fail
            self.configure = configure
            caught = self.failure(code, self.run_range)
            self.assertIsNone(caught.__cause__)
            self.assertTrue(caught.__suppress_context__)
            self.assert_closed()


class HTTPTests(unittest.TestCase):
    setUp = http_baseline.WorkerHTTPTest.setUp
    write_fixture = http_baseline.WorkerHTTPTest.write_fixture
    request = http_baseline.WorkerHTTPTest.request

    def test_range_16k_frame_and_rotated_credentials_through_actual_http(self):
        self.payload = payload()
        self.write_fixture('postgres')
        raw = json.dumps(self.payload).encode()
        raw += b' '*(16384-len(raw))
        with patch.object(server, 'execute_quality', return_value=measurement()) as execute, patch.object(server, 'scan') as scan:
            self.assertEqual(self.request(raw, path='/quality'), (200, {'measurement': measurement()}))
            self.assertEqual(execute.call_args.args[3], self.payload['execution'])
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-test-password')
            self.write_fixture('postgres-rotated')
            self.assertEqual(self.request(raw, path='/quality')[0], 200)
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-rotated-password')
            scan.assert_not_called()
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            self.assertEqual(self.request(raw+b' ', path='/quality'), (413, {'code': 'REQUEST_SIZE'}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_bad_bounds_hash_duplicate_and_cross_family_refuse_before_secrets(self):
        value = payload()
        altered = copy.deepcopy(value)
        altered['execution']['range']['minimum'] = '1'
        number = copy.deepcopy(value)
        number['execution']['range']['minimum'] = 0
        crossed = copy.deepcopy(value)
        crossed['execution']['reference'] = {}
        valid = json.dumps(value).encode()
        duplicate = valid.replace(b'"minimum": "0"', b'"minimum":"1","minimum":"0"')
        cases = [(json.dumps(item).encode(), 'QUALITY_INPUT_INVALID') for item in [altered, number, crossed]] + [(duplicate, 'INVALID_REQUEST')]
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            for raw, code in cases:
                self.assertEqual(self.request(raw, path='/quality'), (400, {'code': code}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_range_unknown_driver_exception_never_returns_source_values(self):
        self.payload = payload()
        self.write_fixture('postgres')
        with patch.object(server, 'execute_quality', side_effect=RuntimeError('private range amount')):
            self.assertEqual(self.request(path='/quality'), (500, {'code': 'WORKER_FAILURE'}))


if __name__ == '__main__':
    unittest.main()
