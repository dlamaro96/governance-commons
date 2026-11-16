# SPDX-License-Identifier: Apache-2.0
"""Completeness protocol and security tests with real policy files and alarms.

The database is a SQL-observing test double; these are not live PostgreSQL/TLS
qualification. SQL execution and row visibility require the separate native gate.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import quality, postgres_targets as targets
from governance_workers.postgresql import ScanFailure
from test_postgres_targets import document, source, secret


def execution():
    return {'formatVersion': 1, 'kind': 'completeness', 'target': {
        'databaseOid': '23', 'schemaOid': '18', 'relationOid': '65', 'attributeNumber': 1,
        'schemaName': 'catalog', 'tableName': 'orders', 'columnName': 'order_id', 'dataType': 'integer'},
        'budget': dict(quality.BUDGETS)}


def catalog():
    return {'relation_oid': '65', 'schema_oid': '18', 'nspname': 'catalog', 'relname': 'orders',
            'relkind': 'r', 'relispartition': False, 'relrowsecurity': False, 'inherited': False,
            'schema_allowed': True, 'table_allowed': True, 'attnum': 1, 'attname': 'order_id',
            'attisdropped': False, 'data_type': 'integer', 'typtype': 'b', 'typcategory': 'N',
            'type_element': '0', 'type_namespace': 'pg_catalog', 'locked': True}


def plan(rows=100, width=4, cost=10.5):
    return [{'Plan': {'Node Type': 'Aggregate', 'Plan Rows': 1, 'Plan Width': 16,
                     'Total Cost': cost, 'Plans': [{'Node Type': 'Limit', 'Plan Rows': rows,
                                                 'Plan Width': width, 'Total Cost': cost / 2}]}}]


class Rows:
    def __init__(self, value=None):
        self.value = value

    def fetchone(self):
        return self.value


class Connection:
    def __init__(self, params):
        self.params = params
        self.identity = {'database_oid': '23', 'version': '170006', 'rolsuper': False, 'rolbypassrls': False}
        self.catalog = catalog()
        self.plan = plan()
        self.counts = {'row_count': 100, 'null_count': 25}
        self.queries = []
        self.closed = False
        self.close_had_ca = None
        self.before_query = lambda text: None

    def close(self):
        self.close_had_ca = Path(self.params['sslrootcert']).is_file()
        self.closed = True

    def execute(self, statement, parameters=None):
        text = statement if type(statement) is str else statement.as_string()
        self.queries.append((text, parameters))
        self.before_query(text)
        if text.startswith(('SET ', 'LOCK ')):
            return Rows()
        if 'FROM pg_catalog.pg_database' in text:
            return Rows(self.identity)
        if 'FROM pg_catalog.pg_class' in text:
            return Rows(self.catalog)
        if text.startswith('EXPLAIN '):
            return Rows({'QUERY PLAN': self.plan})
        if text.startswith('SELECT count(*) AS row_count'):
            return Rows(self.counts)
        raise AssertionError('Unexpected SQL template')


class Cases(unittest.TestCase):
    def failure(self, code, call):
        with self.assertRaises(ScanFailure) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        return caught.exception


class AdmissionTests(Cases):
    def test_detached_closed_request_and_numeric_limits(self):
        original = execution()
        src, target, budget = quality.validate_execution(source(), original)
        original['target']['tableName'] = 'changed'
        original['budget']['maximumRows'] = 1
        self.assertEqual(target['tableName'], 'orders')
        self.assertEqual(budget['maximumRows'], 100000)
        for path in ((), ('target',), ('budget',)):
            value = execution()
            subject = value
            for key in path:
                subject = subject[key]
            subject['additional'] = True
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for field, maximum in quality.BUDGETS.items():
            for bad in (True, False, 0, -1, maximum + 1, float('nan'), float('inf'), '1', None):
                with self.subTest(field=field, bad=bad):
                    value = execution()
                    value['budget'][field] = bad
                    self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for field in ('maximumRows', 'maximumSeconds', 'statementTimeoutMs', 'maximumEstimatedBytes'):
            value = execution()
            value['budget'][field] = 1.5
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))

    def test_target_identity_and_unicode_byte_admission(self):
        for key in ('databaseOid', 'schemaOid', 'relationOid'):
            for bad in ('0', '01', '+1', '1.0', '4294967296', 1, True, '١'):
                value = execution()
                value['target'][key] = bad
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for bad in (True, 0, 32768, 1.5):
            value = execution()
            value['target']['attributeNumber'] = bad
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        for key in ('tableName', 'columnName'):
            value = execution()
            value['target'][key] = 'é' * 31 + 'a'
            quality.validate_execution(source(), value)
            for bad in ('é' * 32, 'x' * 64, '', '\ud800', 'bad\0name'):
                value['target'][key] = bad
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        value = execution()
        value['target']['dataType'] = 'x' * 257
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))
        self.failure('QUALITY_TARGET_STALE', lambda: quality.validate_execution(dict(source(), schema='other'), execution()))
        self.failure('QUALITY_TARGET_UNSUPPORTED', lambda: quality.validate_execution(dict(source(), connectorId='unity-catalog'), execution()))

    def test_plan_parser_and_cumulative_estimates_refuse_before_measurement(self):
        self.assertEqual(quality._estimates(plan(), execution()['budget']), (10.5, 416))
        for value in (None, [], {}, [{'Plan': {}}], plan(cost=float('nan')), plan(rows=True), plan(width=-1)):
            self.failure('SOURCE_DATABASE_ERROR', lambda: quality._estimates(value, execution()['budget']))
        for value in (plan(cost=1000001), plan(rows=100000, width=1000),
                      [{'Plan': dict(plan()[0]['Plan'], Plans=[plan()[0]['Plan']] * 64)}]):
            self.failure('QUALITY_RESOURCE_LIMIT', lambda: quality._estimates(value, execution()['budget']))
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: quality._plan_json(b' ' * 65537))
        for raw in (b'\xff', b'{', b'NaN', b'[' * 2000 + b']' * 2000,
                    b'{"Plan":1,"Plan":2}', b'["\\ud800"]'):
            self.failure('SOURCE_DATABASE_ERROR', lambda: quality._plan_json(raw))
        self.assertEqual(quality._plan_json(json.dumps(plan()).encode()), plan())


class ExecutorTests(Cases):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.path = self.directory / 'targets.json'
        self.path.write_text(json.dumps(document()))
        self.path.chmod(0o600)
        environment = patch.dict(os.environ, {'POSTGRES_TARGETS_FILE': str(self.path)}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        dns = patch.object(targets, '_resolve', return_value=(ipaddress.ip_address('10.8.0.4'),))
        dns.start()
        self.addCleanup(dns.stop)
        loaders = patch.object(quality, 'set_json_loads')
        self.loaders = loaders.start()
        self.addCleanup(loaders.stop)
        self.connections = []
        self.configure = lambda conn: None
        connect = patch.object(quality.psycopg, 'connect', side_effect=self.connect)
        self.connect_mock = connect.start()
        self.addCleanup(connect.stop)

    def connect(self, **params):
        conn = Connection(params)
        self.connections.append(conn)
        self.configure(conn)
        return conn

    def run_measurement(self, value=None):
        return quality.execute(source(), secret(), 'tenant-one', value or execution())

    def assert_closed(self):
        conn = self.connections[-1]
        self.assertTrue(conn.closed)
        self.assertTrue(conn.close_had_ca)
        self.assertFalse(Path(conn.params['sslrootcert']).parent.exists())
        return conn

    def assert_no_aggregate(self, conn):
        self.assertFalse(any(text.startswith(('EXPLAIN ', 'SELECT count(*) AS')) for text, _ in conn.queries))

    def test_exact_measurement_only_and_original_readonly_connection(self):
        result = self.run_measurement()
        self.assertEqual(set(result), {'formatVersion', 'kind', 'strategy', 'rowCount', 'nullCount',
                         'observedStartedAt', 'observedFinishedAt', 'elapsedMs', 'sourceVersion',
                         'adapterVersion', 'queryTemplate', 'estimatedCost', 'estimatedBytes'})
        self.assertEqual((result['rowCount'], result['nullCount'], result['estimatedCost'], result['estimatedBytes']), (100, 25, 10.5, 416))
        self.assertEqual(result['strategy'], 'exact-bounded-role-scope')
        self.assertEqual(result['sourceVersion'], '170006')
        self.assertEqual(result['queryTemplate'], 'postgresql-completeness-v1')
        for name in ('observedStartedAt', 'observedFinishedAt'):
            self.assertRegex(result[name], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
        self.assertLessEqual(result['observedStartedAt'], result['observedFinishedAt'])
        self.assertGreaterEqual(result['elapsedMs'], 0)
        self.assertLess(result['elapsedMs'], 30000)
        self.assertNotIn(secret()['password'], json.dumps(result))
        self.assertNotIn('order_id', json.dumps(result))
        conn = self.assert_closed()
        self.assertEqual(conn.params['sslmode'], 'verify-full')
        self.assertEqual(conn.params['hostaddr'], '10.8.0.4')
        self.assertEqual(conn.queries[0][0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        self.assertIn("current_setting('server_version_num')", next(text for text, _ in conn.queries if 'FROM pg_catalog.pg_database' in text))
        self.assertEqual(next(text for text, _ in conn.queries if text.startswith('LOCK ')), 'LOCK TABLE ONLY "catalog"."orders" IN ACCESS SHARE MODE')
        aggregate, params = next((text, params) for text, params in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertIn('SELECT "order_id" IS NULL AS missing FROM ONLY "catalog"."orders" LIMIT %s', aggregate)
        self.assertEqual(params, (100001,))
        self.assertIn('i.inhrelid=c.oid OR i.inhparent=c.oid', next(text for text, _ in conn.queries if 'FROM pg_catalog.pg_class' in text))
        self.loaders.assert_called_once_with(quality._plan_json, context=conn)

    def test_zero_data_and_exact_row_cap_are_measurements_overflow_is_not_partial(self):
        value = execution()
        value['budget']['maximumRows'] = 4
        for rows, nulls in ((0, 0), (4, 3)):
            self.configure = lambda conn: setattr(conn, 'counts', {'row_count': rows, 'null_count': nulls})
            self.assertEqual(self.run_measurement(value)['rowCount'], rows)
            self.assert_closed()
        self.configure = lambda conn: setattr(conn, 'counts', {'row_count': 5, 'null_count': 3})
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_measurement(value))
        conn = self.assert_closed()
        self.assertEqual(next(params for text, params in conn.queries if text.startswith('SELECT count(*) AS')), (5,))

    def test_all_identity_pins_and_exact_locked_oid_are_rechecked(self):
        cases = [('relation_oid', '66'), ('schema_oid', '19'), ('nspname', 'another'), ('relname', 'replacement'),
                 ('attnum', 2), ('attname', 'another'), ('data_type', 'bigint'), ('attisdropped', True), ('locked', False)]
        for key, value in cases:
            with self.subTest(key=key):
                self.configure = lambda conn: conn.catalog.update({key: value})
                self.failure('QUALITY_TARGET_STALE', self.run_measurement)
                self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: conn.identity.update(database_oid='24')
        self.failure('QUALITY_TARGET_STALE', self.run_measurement)
        self.assert_no_aggregate(self.assert_closed())
        self.configure = lambda conn: setattr(conn, 'catalog', None)
        self.failure('QUALITY_TARGET_STALE', self.run_measurement)
        self.assert_no_aggregate(self.assert_closed())

    def test_unsupported_source_profiles_never_explain_or_read_business_values(self):
        for key, value in [('relkind', kind) for kind in ('v', 'm', 'f', 'p', 'S')] + [
            ('relispartition', True), ('relrowsecurity', True), ('inherited', True),
            ('type_namespace', 'extension'), ('typtype', 'd'), ('typtype', 'c'), ('typtype', 'p'),
            ('typcategory', 'A'), ('typcategory', 'C'), ('typcategory', 'P'), ('type_element', '23')]:
            with self.subTest(key=key, value=value):
                self.configure = lambda conn: conn.catalog.update({key: value})
                self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_measurement)
                self.assert_no_aggregate(self.assert_closed())

    def test_server_version_is_numeric_and_not_arbitrary_database_text(self):
        for version in ('17.6', '17000 private', '9' * 17, '', None, 170006):
            self.configure = lambda conn: conn.identity.update(version=version)
            self.failure('SOURCE_DATABASE_ERROR', self.run_measurement)
            self.assert_no_aggregate(self.assert_closed())

    def test_role_and_permission_denials_do_not_read_target_rows(self):
        for key in ('rolsuper', 'rolbypassrls'):
            self.configure = lambda conn: conn.identity.update({key: True})
            self.failure('SOURCE_PRIVILEGE_TOO_BROAD', self.run_measurement)
            self.assert_no_aggregate(self.assert_closed())
        for key in ('schema_allowed', 'table_allowed'):
            self.configure = lambda conn: conn.catalog.update({key: False})
            self.failure('SOURCE_SCOPE_DENIED', self.run_measurement)
            self.assert_no_aggregate(self.assert_closed())

    def test_identifiers_are_driver_quoted_and_never_source_authored_sql(self):
        value = execution()
        value['target']['tableName'] = 'orders"; SELECT private--'
        value['target']['columnName'] = 'secret"value'
        self.configure = lambda conn: conn.catalog.update(relname=value['target']['tableName'], attname=value['target']['columnName'])
        self.run_measurement(value)
        conn = self.assert_closed()
        aggregate = next(text for text, _ in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertIn('"secret""value" IS NULL', aggregate)
        self.assertIn('FROM ONLY "catalog"."orders""; SELECT private--" LIMIT %s', aggregate)
        self.assertNotIn('SELECT *', aggregate)

    def test_plan_cap_prevents_aggregate_and_bad_counts_never_return_measurement(self):
        for changed in (plan(cost=1000001), plan(rows=100000, width=1000)):
            self.configure = lambda conn: setattr(conn, 'plan', changed)
            self.failure('QUALITY_RESOURCE_LIMIT', self.run_measurement)
            self.assertFalse(any(text.startswith('SELECT count(*) AS') for text, _ in self.assert_closed().queries))
        for counts in ({'row_count': True, 'null_count': 0}, {'row_count': 2, 'null_count': 3},
                       {'row_count': -1, 'null_count': 0}, {'row_count': 100002, 'null_count': 0},
                       {'row_count': 2, 'null_count': 0, 'private': 'value'}):
            self.configure = lambda conn: setattr(conn, 'counts', counts)
            self.failure('SOURCE_DATABASE_ERROR', self.run_measurement)
            self.assert_closed()

    def test_policy_rotates_per_execution_and_cannot_fall_back(self):
        self.run_measurement()
        changed = document()
        changed['targets']['warehouse']['tenantIds'] = ['different-tenant']
        replacement = self.directory / 'replacement'
        replacement.write_text(json.dumps(changed))
        replacement.chmod(0o600)
        replacement.replace(self.path)
        self.failure('SOURCE_SCOPE_DENIED', self.run_measurement)
        self.assertEqual(self.connect_mock.call_count, 1)

    def test_scope_and_malformed_input_refuse_before_connection(self):
        self.failure('SOURCE_SCOPE_DENIED', lambda: quality.execute(source(), secret(), 'different-tenant', execution()))
        self.failure('SOURCE_TARGET_DENIED', lambda: quality.execute(source(), dict(secret(), database='wrong'), 'tenant-one', execution()))
        value = execution()
        value['budget']['maximumRows'] = True
        self.failure('QUALITY_INPUT_INVALID', lambda: self.run_measurement(value))
        self.connect_mock.assert_not_called()

    def test_driver_errors_are_closed_and_ca_is_removed(self):
        errors = [(psycopg.errors.UndefinedTable, 'QUALITY_TARGET_STALE'),
                  (psycopg.errors.UndefinedColumn, 'QUALITY_TARGET_STALE'),
                  (psycopg.errors.InsufficientPrivilege, 'SOURCE_SCOPE_DENIED'),
                  (psycopg.errors.QueryCanceled, 'QUALITY_RESOURCE_LIMIT'),
                  (psycopg.errors.LockNotAvailable, 'QUALITY_RESOURCE_LIMIT'),
                  (psycopg.OperationalError, 'SOURCE_DATABASE_ERROR')]
        for error_type, code in errors:
            def configure(conn):
                def throw(text):
                    if text.startswith('SELECT count(*) AS'):
                        raise error_type('synthetic private row, password and server detail')
                conn.before_query = throw
            self.configure = configure
            error = self.failure(code, self.run_measurement)
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)
            self.assert_closed()

    def test_original_wall_deadline_interrupts_blocked_policy_loading(self):
        # A real 1s signal interrupts a blocking policy read before connect.
        value = execution()
        value['budget']['maximumSeconds'] = 1
        before = time.monotonic()
        with patch.object(targets, 'load_policy', side_effect=lambda _: time.sleep(2)):
            self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_measurement(value))
        self.assertLess(time.monotonic() - before, 1.5)
        self.connect_mock.assert_not_called()

    def test_original_wall_deadline_interrupts_blocked_aggregate_and_closes(self):
        value = execution()
        value['budget']['maximumSeconds'] = 3
        def configure(conn):
            conn.before_query = lambda text: time.sleep(4) if text.startswith('SELECT count(*) AS') else None
        self.configure = configure
        before = time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_measurement(value))
        self.assertLess(time.monotonic() - before, 3.5)
        conn = self.assert_closed()
        timeouts = [int(re.search(r"'(\d+)ms'", text).group(1)) for text, _ in conn.queries if text.startswith('SET LOCAL statement_timeout')]
        self.assertTrue(all(0 < timeout <= 3000 for timeout in timeouts))
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))

    def test_pending_alarm_during_connect_closes_registered_connection_before_ca(self):
        def connect(**params):
            self.assertIn(signal.SIGALRM, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            conn = self.connect(**params)
            signal.raise_signal(signal.SIGALRM)
            return conn
        self.connect_mock.side_effect = connect
        self.failure('SOURCE_DEADLINE_EXCEEDED', self.run_measurement)
        self.assert_closed()


if __name__ == '__main__':
    unittest.main()
