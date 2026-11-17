# SPDX-License-Identifier: Apache-2.0
"""Uniqueness protocol, bounded SQL construction and real loopback HTTP controls.

Database replies are controlled aggregates, not a source execution proof. Actual
PostgreSQL equality/TOAST/plan behavior requires the separately executed gate.
"""
import copy
import json
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import quality, server
from test_postgres_targets import source, secret
import test_quality as baseline
import test_server as http_baseline


def execution():
    result = baseline.execution()
    result.update(kind='uniqueness', budget=dict(quality.UNIQUENESS_BUDGETS))
    result['target']['dataType'] = 'text'
    return result


def payload():
    result = http_baseline.quality_payload()
    result['execution'] = execution()
    result['execution']['target']['schemaName'] = result['source']['schema']
    return result


def measurement():
    result = http_baseline.quality_measurement()
    result.update(kind='uniqueness', queryTemplate='postgresql-uniqueness-v1',
                  rowCount=20, nullCount=4, distinctCount=12, duplicateGroupCount=2,
                  duplicateRowCount=6, totalValueBytes=26, largestValueBytes=2)
    return result


class Connection(baseline.Connection):
    def __init__(self, params):
        super().__init__(params)
        self.catalog.update(data_type='text', type_oid='25', typcategory='S')
        self.encoding = {'encoding': 'UTF8'}
        self.preflight = {'row_count': 20, 'null_count': 4, 'total_value_bytes': 26, 'largest_value_bytes': 2}
        self.groups = {'distinct_count': 12, 'duplicate_group_count': 2, 'duplicate_row_count': 6}
        self.plans = [baseline.plan(), baseline.plan()]
        self.explained = 0

    def execute(self, statement, parameters=None):
        text = statement if type(statement) is str else statement.as_string()
        if (text.startswith('EXPLAIN ') or text.startswith("SELECT current_setting('server_encoding')")
                or text.startswith(('SELECT count(*) AS row_count', 'SELECT count(*) AS distinct_count'))):
            self.queries.append((text, parameters))
            self.before_query(text)
            if text.startswith('EXPLAIN '):
                value = self.plans[self.explained]
                self.explained += 1
                return baseline.Rows({'QUERY PLAN': value})
            if 'server_encoding' in text:
                return baseline.Rows(self.encoding)
            return baseline.Rows(self.preflight if ' AS row_count' in text else self.groups)
        return super().execute(statement, parameters)


class AdmissionTests(baseline.Cases):
    def test_closed_uniqueness_schema_and_detached_limits(self):
        value = execution()
        _, target, budgets = quality.validate_execution(source(), value)
        value['target']['tableName'] = 'changed'
        value['budget']['maximumValueBytes'] = 1
        self.assertEqual(target['tableName'], 'orders')
        self.assertEqual(budgets, quality.UNIQUENESS_BUDGETS)
        for key in ('maximumValueBytes', 'maximumTotalValueBytes'):
            for bad in (None, True, False, 0, -1, 1.0, float('inf'), float('nan'), '1', quality.UNIQUENESS_BUDGETS[key] + 1):
                with self.subTest(key=key, bad=bad):
                    value = execution()
                    value['budget'][key] = bad
                    self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for path, key, extra in (((), 'reference', {}), ((), 'comparison', 'utf8-exact'),
                                  (('budget',), 'sql', 'SELECT private'), (('target',), 'values', ['private'])):
            value = execution()
            child = value
            for part in path:
                child = child[part]
            child[key] = extra
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for key in ('maximumValueBytes', 'maximumTotalValueBytes'):
            value = execution()
            del value['budget'][key]
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        value = execution()
        value['budget'].update(maximumValueBytes=1, maximumTotalValueBytes=1)
        quality.validate_execution(source(), value)

    def test_legacy_family_budgets_stay_closed(self):
        value = baseline.execution()
        value['budget'].update(maximumValueBytes=4096, maximumTotalValueBytes=67108864)
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        import test_reference_quality
        value = test_reference_quality.execution()
        value['budget']['maximumValueBytes'] = 4096
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))

    def test_invalid_input_never_resolves_destination_or_connection(self):
        value = execution()
        value['budget']['maximumTotalValueBytes'] = 67108865
        with patch.object(quality, '_connection_parameters') as provider, patch.object(quality.psycopg, 'connect') as connect:
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.execute(source(), secret(), 'tenant-one', value))
            provider.assert_not_called()
            connect.assert_not_called()


class ExecutorTests(baseline.Cases):
    setUp = baseline.ExecutorTests.setUp
    assert_closed = baseline.ExecutorTests.assert_closed

    def connect(self, **params):
        conn = Connection(params)
        self.connections.append(conn)
        self.configure(conn)
        return conn

    def run_unique(self, value=None):
        return quality.execute(source(), secret(), 'tenant-one', value if value is not None else execution())

    def assert_no_group(self, conn):
        self.assertFalse(any('pg_catalog.convert_to' in text for text, _ in conn.queries))

    def test_counts_include_all_duplicate_group_members_and_only_closed_aggregates(self):
        result = self.run_unique()
        self.assertEqual(set(result), set(measurement()))
        for key in ('kind', 'queryTemplate', 'rowCount', 'nullCount', 'distinctCount', 'duplicateGroupCount',
                    'duplicateRowCount', 'totalValueBytes', 'largestValueBytes'):
            self.assertEqual(result[key], measurement()[key])
        self.assertEqual((result['estimatedCost'], result['estimatedBytes']), (21, 832))
        conn = self.assert_closed()
        statements = [text for text, _ in conn.queries]
        preflight = next(i for i, text in enumerate(statements) if text.startswith('SELECT count(*) AS row_count'))
        grouped = next(i for i, text in enumerate(statements) if text.startswith('SELECT count(*) AS distinct_count'))
        self.assertLess(preflight, grouped)
        self.assertIn('pg_catalog.octet_length(value)', statements[preflight])
        self.assertNotIn('convert_to', statements[preflight])
        self.assertIn("GROUP BY pg_catalog.convert_to(value,'UTF8')", statements[grouped])
        self.assertIn('sum(group_size) FILTER (WHERE group_size > 1)', statements[grouped])
        self.assertIn('WHERE value IS NOT NULL', statements[grouped])
        self.assertIn('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY', statements)
        self.assertTrue(all(params == (100001,) for text, params in conn.queries if text.startswith(('EXPLAIN ', 'SELECT count(*) AS'))))
        self.assertNotIn('reference', result)

    def test_empty_all_null_and_empty_string_groups_are_valid(self):
        cases = [(0, 0, 0, 0, 0), (9, 9, 0, 0, 0), (2, 0, 1, 1, 2)]
        for rows, nulls, distinct, groups, duplicates in cases:
            def configure(conn):
                conn.preflight.update(row_count=rows, null_count=nulls, total_value_bytes=0, largest_value_bytes=0)
                conn.groups.update(distinct_count=distinct, duplicate_group_count=groups, duplicate_row_count=duplicates)
            self.configure = configure
            result = self.run_unique()
            self.assertEqual((result['rowCount'], result['nullCount'], result['distinctCount'], result['duplicateRowCount']), (rows, nulls, distinct, duplicates))
            self.assert_closed()

    def test_type_oid_encoding_and_unsupported_table_refuse_before_preflight(self):
        for key, value in [('type_oid', '1042'), ('type_oid', '80000'), ('typtype', 'd'), ('relrowsecurity', True), ('inherited', True), ('relispartition', True)]:
            self.configure = lambda conn: conn.catalog.update({key: value})
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_unique)
            self.assertFalse(any(text.startswith('EXPLAIN ') for text, _ in self.assert_closed().queries))
        for value in ({'encoding': 'LATIN1'}, {'encoding': 'SQL_ASCII'}, {'encoding': None}, {}):
            self.configure = lambda conn: setattr(conn, 'encoding', value)
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_unique)
            self.assert_no_group(self.assert_closed())
        self.configure = lambda conn: conn.catalog.update(type_oid='1043')
        self.assertEqual(self.run_unique()['rowCount'], 20)
        self.assert_closed()

    def test_row_value_and_total_byte_limits_refuse_before_group_materialization(self):
        cases = [({'row_count': 100001}, None), ({'total_value_bytes': 4097, 'largest_value_bytes': 4097}, None),
                 ({'row_count': 20000, 'null_count': 0, 'total_value_bytes': 67108865, 'largest_value_bytes': 4096}, None),
                 ({}, {'maximumValueBytes': 1}), ({}, {'maximumTotalValueBytes': 25})]
        for changed, lower in cases:
            self.configure = lambda conn: conn.preflight.update(changed)
            value = execution()
            if lower:
                value['budget'].update(lower)
            self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_unique(value))
            self.assert_no_group(self.assert_closed())

    def test_exact_value_and_total_byte_limits_are_admitted(self):
        def configure(conn):
            conn.preflight.update(row_count=16384, null_count=0, total_value_bytes=67108864, largest_value_bytes=4096)
            conn.groups.update(distinct_count=1, duplicate_group_count=1, duplicate_row_count=16384)
        self.configure = configure
        result = self.run_unique()
        self.assertEqual((result['totalValueBytes'], result['largestValueBytes']), (67108864, 4096))
        self.assert_closed()

    def test_two_plans_share_cumulative_cost_and_byte_budgets(self):
        for plans in ([baseline.plan(cost=600000), baseline.plan(cost=500000)],
                      [baseline.plan(rows=100000, width=350), baseline.plan(rows=100000, width=350)]):
            self.configure = lambda conn: setattr(conn, 'plans', plans)
            self.failure('QUALITY_RESOURCE_LIMIT', self.run_unique)
            conn = self.assert_closed()
            self.assertEqual(conn.explained, 2)
            self.assertFalse(any(text.startswith('SELECT count(*) AS distinct_count') for text, _ in conn.queries))
        self.configure = lambda conn: setattr(conn, 'plans', [baseline.plan(cost=1000001), baseline.plan()])
        self.failure('QUALITY_RESOURCE_LIMIT', self.run_unique)
        self.assertFalse(any(text.startswith('SELECT count(*) AS') for text, _ in self.assert_closed().queries))

    def test_malformed_preflight_and_group_counts_never_escape(self):
        for changed in ({'row_count': True}, {'null_count': 21}, {'total_value_bytes': -1}, {'largest_value_bytes': 27},
                        {'total_value_bytes': 1000}, {'raw_keys': ['private']}, {'total_value_bytes': 1.0}):
            self.configure = lambda conn: conn.preflight.update(changed)
            self.failure('SOURCE_DATABASE_ERROR', self.run_unique)
            self.assert_no_group(self.assert_closed())
        for changed in ({'distinct_count': 11}, {'duplicate_row_count': 4}, {'duplicate_group_count': 0},
                        {'duplicate_row_count': True}, {'duplicate_row_count': 17}, {'distinct_count': -1},
                        {'raw_keys': ['private']}, {'distinct_count': 0, 'duplicate_group_count': 0, 'duplicate_row_count': 16}):
            self.configure = lambda conn: conn.groups.update(changed)
            self.failure('SOURCE_DATABASE_ERROR', self.run_unique)
            self.assert_closed()

    def test_identifier_quoting_preserves_fixed_templates(self):
        value = execution()
        value['target'].update(tableName='orders";SELECT private--', columnName='key" OR TRUE--')
        self.configure = lambda conn: conn.catalog.update(relname=value['target']['tableName'], attname=value['target']['columnName'])
        self.run_unique(value)
        conn = self.assert_closed()
        for text, _ in conn.queries:
            if text.startswith(('EXPLAIN ', 'SELECT count(*) AS')):
                self.assertIn('SELECT "key"" OR TRUE--" AS value FROM ONLY "catalog"."orders"";SELECT private--" LIMIT %s', text)
                self.assertNotIn('SELECT private-- AS', text)

    def test_original_deadline_spans_both_queries_and_owned_cleanup(self):
        value = execution()
        value['budget']['maximumSeconds'] = 3
        self.configure = lambda conn: setattr(conn, 'before_query', lambda text: time.sleep(1.7) if text.startswith('SELECT count(*) AS') else None)
        started = time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_unique(value))
        self.assertLess(time.monotonic() - started, 3.5)
        conn = self.assert_closed()
        self.assertTrue(any(text.startswith('SELECT count(*) AS distinct_count') for text, _ in conn.queries))

    def test_driver_failure_is_closed_and_private_diagnostics_do_not_escape(self):
        for error, code in [(psycopg.errors.QueryCanceled, 'QUALITY_RESOURCE_LIMIT'),
                            (psycopg.errors.InsufficientPrivilege, 'SOURCE_SCOPE_DENIED'),
                            (psycopg.OperationalError, 'SOURCE_DATABASE_ERROR')]:
            def configure(conn):
                def fail(text):
                    if text.startswith('SELECT count(*) AS distinct_count'):
                        raise error('private key and source credential')
                conn.before_query = fail
            self.configure = configure
            caught = self.failure(code, self.run_unique)
            self.assertIsNone(caught.__cause__)
            self.assertTrue(caught.__suppress_context__)
            self.assert_closed()


class HTTPTests(unittest.TestCase):
    setUp = http_baseline.WorkerHTTPTest.setUp
    write_fixture = http_baseline.WorkerHTTPTest.write_fixture
    request = http_baseline.WorkerHTTPTest.request

    def test_exact_16k_admission_and_fresh_credentials_through_real_http(self):
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

    def test_duplicate_fields_and_malformed_budgets_refuse_before_secrets(self):
        valid = json.dumps(payload()).encode()
        duplicate = valid.replace(b'"kind": "uniqueness"', b'"kind":"completeness","kind":"uniqueness"')
        invalid = payload()
        invalid['execution']['budget']['maximumValueBytes'] = 4097
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            self.assertEqual(self.request(duplicate, path='/quality'), (400, {'code': 'INVALID_REQUEST'}))
            self.assertEqual(self.request(json.dumps(invalid).encode(), path='/quality'), (400, {'code': 'QUALITY_INPUT_INVALID'}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_unknown_driver_exception_never_returns_raw_key(self):
        self.payload = payload()
        self.write_fixture('postgres')
        with patch.object(server, 'execute_quality', side_effect=RuntimeError('private duplicate key')):
            self.assertEqual(self.request(path='/quality'), (500, {'code': 'WORKER_FAILURE'}))


if __name__ == '__main__':
    unittest.main()
