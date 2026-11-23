# SPDX-License-Identifier: Apache-2.0
"""Private reference-quality controls, not PostgreSQL/TLS qualification.

Exercises the candidate with actual policy files, signal deadlines and loopback
HTTP. The SQL connection observes statements and returns controlled aggregates;
byte-comparison behavior on real source rows still requires the native gate.
"""
import copy
import hashlib
import json
import signal
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import quality, server
from governance_workers.postgresql import ScanFailure
import test_quality as baseline
import test_server as http_baseline
from test_postgres_targets import source, secret


def binding(codes=None, **changes):
    value = {'setId': '10000000-0000-4000-8000-000000000001', 'version': 1,
             'publicationHash': 'a' * 64, 'asOf': '2026-11-17T00:00:00.000Z',
             'codeStatus': 'active', 'codes': ['01', '1', 'A', 'a'] if codes is None else codes}
    value.update(changes)
    value['bindingHash'] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return value


def execution(codes=None):
    value = baseline.execution()
    value['kind'] = 'reference-allowed-values'
    value['target']['dataType'] = 'text'
    value['reference'] = binding(codes)
    return value


def full_codes():
    return [f'{index:03d}' + 'x' * 125 for index in range(256)]


def payload(codes=None):
    value = http_baseline.quality_payload()
    value['execution'] = execution(codes)
    value['execution']['target']['schemaName'] = value['source']['schema']
    return value


def measurement(ref):
    result = http_baseline.quality_measurement()
    result.update(kind='reference-allowed-values', rowCount=20, nullCount=4, invalidCount=4,
                  queryTemplate='postgresql-reference-allowed-values-v1', referenceBindingHash=ref['bindingHash'])
    return result


class BindingTests(unittest.TestCase):
    failure = baseline.Cases.failure

    def test_literal_preimage_hash_and_detached_code_vector(self):
        original = binding()
        self.assertEqual(original['bindingHash'], '6f8f895e160dbe71d7051cb143a262baf1262e571ae89af90c8e93bb778158c0')
        result = quality.validate_reference_binding(original)
        original['codes'].append('z')
        self.assertEqual(result['codes'], ['01', '1', 'A', 'a'])
        self.assertEqual(result['bindingHash'], '6f8f895e160dbe71d7051cb143a262baf1262e571ae89af90c8e93bb778158c0')
        self.assertEqual(quality.validate_reference_binding(binding([]))['codes'], [])

    def test_complete_maximum_code_vector_is_admitted_without_truncation(self):
        original = binding(full_codes(), version=2147483647)
        result = quality.validate_reference_binding(original)
        self.assertEqual(len(result['codes']), 256)
        self.assertTrue(all(len(code.encode('ascii')) == 128 for code in result['codes']))
        self.assertEqual(result, original)
        self.assertGreater(len(json.dumps(execution(full_codes())).encode()), 16384)

    def test_invalid_code_vectors_and_hashes_refuse(self):
        vectors = (['a', 'A'], ['1', '01'], ['A', 'A'], [''], ['A '], [' A'], ['A\n'], ['\0'],
                   ['é'], ['١'], ['_A'], ['A' * 129], ['A/B'], ['A"B'], ['A\\B'], [True],
                   [1], [None], {}, (), full_codes() + ['z'])
        for codes in vectors:
            with self.subTest(codes=repr(codes)[:70]):
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(binding(codes)))
        for changed in ('b' * 64, 'A' * 64, '0' * 63, '', None, 1):
            value = binding()
            value['bindingHash'] = changed
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(value))
        value = binding()
        value['codes'] = ['01', '1', 'A', 'b']
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(value))

    def test_closed_binding_scalar_bounds_and_real_utc_millisecond_instants(self):
        invalid = {'setId': ['', '10000000-0000-4000-8000-00000000000A', '00000000-0000-0000-0000-000000000000', None],
                   'version': [0, -1, True, 1.0, 2147483648, '1'],
                   'publicationHash': ['a' * 63, 'A' * 64, None],
                   'asOf': ['0000-01-01T00:00:00.000Z', '1900-02-29T00:00:00.000Z',
                            '2026-02-30T00:00:00.000Z', '2026-11-17T24:00:00.000Z',
                            '2026-11-17T00:00:60.000Z', '2026-11-17T00:00:00Z',
                            '2026-11-17T00:00:00.000+00:00', ' 2026-11-17T00:00:00.000Z', None],
                   'codeStatus': ['deprecated', '', None, True]}
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(binding(**{key: value})))
        for stamp in ('0001-01-01T00:00:00.000Z', '2000-02-29T23:59:59.999Z', '9999-12-31T23:59:59.999Z'):
            self.assertEqual(quality.validate_reference_binding(binding(asOf=stamp))['asOf'], stamp)
        for key in binding():
            value = binding()
            del value[key]
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(value))
        value = binding()
        value['extra'] = True
        self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_reference_binding(value))

    def test_execution_families_are_closed_and_completeness_return_compatible(self):
        for value in (baseline.execution(), execution(), execution([])):
            admitted = quality.validate_execution(source(), value)
            self.assertEqual(len(admitted), 3)
            self.assertEqual(admitted[1], value['target'])
        invalid = [dict(baseline.execution(), reference=binding()), dict(execution(), kind='other'),
                   {key: value for key, value in execution().items() if key != 'reference'},
                   dict(execution(), comparison='utf8-exact')]
        for value in invalid:
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), value))


class ReferenceExecutorTests(unittest.TestCase):
    failure = baseline.Cases.failure
    connect = baseline.ExecutorTests.connect
    assert_closed = baseline.ExecutorTests.assert_closed
    assert_no_aggregate = baseline.ExecutorTests.assert_no_aggregate

    def setUp(self):
        baseline.ExecutorTests.setUp(self)
        self.adjust = lambda conn: None

        def configure(conn):
            conn.catalog.update(data_type='text', type_oid='25', typcategory='S')
            conn.counts = {'row_count': 20, 'null_count': 4, 'invalid_count': 4}
            self.adjust(conn)
        self.configure = configure

    def run_reference(self, value=None):
        return quality.execute(source(), secret(), 'tenant-one', value if value is not None else execution())

    def test_fixed_byte_membership_query_returns_only_aggregate_and_binding_hash(self):
        value = execution()
        result = self.run_reference(value)
        expected = {'formatVersion', 'kind', 'strategy', 'rowCount', 'nullCount', 'invalidCount', 'referenceBindingHash',
                    'observedStartedAt', 'observedFinishedAt', 'elapsedMs', 'sourceVersion', 'adapterVersion',
                    'queryTemplate', 'estimatedCost', 'estimatedBytes'}
        self.assertEqual(set(result), expected)
        self.assertEqual((result['rowCount'], result['nullCount'], result['invalidCount']), (20, 4, 4))
        self.assertEqual(result['referenceBindingHash'], value['reference']['bindingHash'])
        self.assertEqual(result['queryTemplate'], 'postgresql-reference-allowed-values-v1')
        self.assertEqual(result['kind'], 'reference-allowed-values')
        self.assertNotIn('verdict', result)
        self.assertNotIn('codes', result)
        self.assertNotIn('setId', result)
        self.assertNotIn(secret()['password'], json.dumps(result))
        conn = self.assert_closed()
        self.assertEqual(conn.queries[0][0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        self.assertEqual(conn.params['sslmode'], 'verify-full')
        self.assertEqual(conn.params['hostaddr'], '10.8.0.4')
        aggregate, parameters = next((text, params) for text, params in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertIn("pg_catalog.convert_to(value, 'UTF8') OPERATOR(pg_catalog.=) ANY (%s::pg_catalog.bytea[])", aggregate)
        self.assertIn('value IS NOT NULL AND NOT', aggregate)
        self.assertIn('SELECT "order_id" AS value FROM ONLY "catalog"."orders" LIMIT %s', aggregate)
        self.assertEqual(parameters, ([b'01', b'1', b'A', b'a'], 100001))
        self.assertNotIn("'01'", aggregate)
        explain = next((text, params) for text, params in conn.queries if text.startswith('EXPLAIN '))
        self.assertEqual(explain, ('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ' + aggregate, parameters))
        self.loaders.assert_called_once_with(quality._plan_json, context=conn)

    def test_empty_vector_all_null_empty_data_and_exact_cap_remain_measurements(self):
        value = execution([])
        value['budget']['maximumRows'] = 20
        for rows, nulls, invalid in ((0, 0, 0), (20, 20, 0), (20, 4, 16)):
            self.adjust = lambda conn: setattr(conn, 'counts', {'row_count': rows, 'null_count': nulls, 'invalid_count': invalid})
            result = self.run_reference(value)
            self.assertEqual((result['rowCount'], result['nullCount'], result['invalidCount']), (rows, nulls, invalid))
            self.assertNotIn('verdict', result)
            conn = self.assert_closed()
            self.assertEqual(next(params for text, params in conn.queries if text.startswith('SELECT count(*) AS')), ([], 21))
        self.adjust = lambda conn: setattr(conn, 'counts', {'row_count': 21, 'null_count': 4, 'invalid_count': 17})
        self.failure('QUALITY_RESOURCE_LIMIT', lambda: self.run_reference(value))
        self.assert_closed()

    def test_all_256_codes_are_private_bound_binary_parameters(self):
        result = self.run_reference(execution(full_codes()))
        conn = self.assert_closed()
        aggregate, parameters = next((text, params) for text, params in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertEqual(parameters[0], [code.encode('ascii') for code in full_codes()])
        self.assertEqual(len(parameters[0]), 256)
        self.assertNotIn(full_codes()[0], aggregate)
        self.assertNotIn(full_codes()[0], json.dumps(result))

    def test_actual_builtin_type_oid_is_required_before_explain(self):
        for oid in ('23', '1042', '19', '1700', '40000', None, 25):
            self.adjust = lambda conn: conn.catalog.update(type_oid=oid)
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_reference)
            self.assert_no_aggregate(self.assert_closed())
        value = execution()
        value['target']['dataType'] = 'character varying(20)'
        self.adjust = lambda conn: conn.catalog.update(type_oid='1043', data_type='character varying(20)')
        self.assertEqual(self.run_reference(value)['rowCount'], 20)
        self.assert_closed()
        for key, changed in [('typtype', 'd'), ('type_namespace', 'private'), ('relrowsecurity', True),
                             ('relispartition', True), ('inherited', True), ('relkind', 'v')]:
            self.adjust = lambda conn: conn.catalog.update({key: changed})
            self.failure('QUALITY_TARGET_UNSUPPORTED', self.run_reference)
            self.assert_no_aggregate(self.assert_closed())

    def test_stale_pins_permissions_and_plans_refuse_before_aggregate(self):
        for key, changed in [('relation_oid', '66'), ('schema_oid', '19'), ('attnum', 2),
                             ('attname', 'different'), ('data_type', 'character varying'), ('locked', False)]:
            self.adjust = lambda conn: conn.catalog.update({key: changed})
            self.failure('QUALITY_TARGET_STALE', self.run_reference)
            self.assert_no_aggregate(self.assert_closed())
        for key in ('schema_allowed', 'table_allowed'):
            self.adjust = lambda conn: conn.catalog.update({key: False})
            self.failure('SOURCE_SCOPE_DENIED', self.run_reference)
            self.assert_no_aggregate(self.assert_closed())
        self.adjust = lambda conn: setattr(conn, 'plan', baseline.plan(cost=1000001))
        self.failure('QUALITY_RESOURCE_LIMIT', self.run_reference)
        self.assertFalse(any(text.startswith('SELECT count(*) AS') for text, _ in self.assert_closed().queries))

    def test_quoted_identifiers_cannot_change_fixed_expression(self):
        value = execution()
        value['target'].update(tableName='orders";SELECT private--', columnName='value" OR TRUE--')
        self.adjust = lambda conn: conn.catalog.update(relname=value['target']['tableName'], attname=value['target']['columnName'])
        self.run_reference(value)
        conn = self.assert_closed()
        aggregate, parameters = next((text, params) for text, params in conn.queries if text.startswith('SELECT count(*) AS'))
        self.assertIn('SELECT "value"" OR TRUE--" AS value FROM ONLY "catalog"."orders"";SELECT private--" LIMIT %s', aggregate)
        self.assertEqual(parameters[0], [b'01', b'1', b'A', b'a'])

    def test_invalid_counts_cannot_escape_as_partial_measurement(self):
        invalid = [{'row_count': 20, 'null_count': 4, 'invalid_count': bad} for bad in (-1, 17, True, '4', None)]
        invalid.extend(({'row_count': 20, 'null_count': 4},
                        {'row_count': 20, 'null_count': 4, 'invalid_count': 4, 'private': 'source value'},
                        {'row_count': True, 'null_count': 0, 'invalid_count': 0}))
        for counts in invalid:
            self.adjust = lambda conn: setattr(conn, 'counts', counts)
            self.failure('SOURCE_DATABASE_ERROR', self.run_reference)
            self.assert_closed()

    def test_reference_validation_precedes_destination_or_connection(self):
        value = execution()
        value['reference']['bindingHash'] = '0' * 64
        with patch.object(quality, '_connection_parameters') as provider:
            self.failure('QUALITY_INPUT_INVALID', lambda: self.run_reference(value))
            provider.assert_not_called()
        self.connect_mock.assert_not_called()

    def test_original_deadline_interrupts_aggregate_and_discards_values(self):
        value = execution()
        value['budget']['maximumSeconds'] = 3
        self.adjust = lambda conn: setattr(conn, 'before_query', lambda text: time.sleep(4) if text.startswith('SELECT count(*) AS') else None)
        started = time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED', lambda: self.run_reference(value))
        self.assertLess(time.monotonic() - started, 3.5)
        self.assert_closed()

    def test_driver_cancellation_and_private_diagnostics_are_sanitized(self):
        for error_type, code in ((psycopg.errors.QueryCanceled, 'QUALITY_RESOURCE_LIMIT'),
                                 (psycopg.errors.InsufficientPrivilege, 'SOURCE_SCOPE_DENIED'),
                                 (psycopg.OperationalError, 'SOURCE_DATABASE_ERROR')):
            def adjust(conn):
                def fail_query(text):
                    if text.startswith('SELECT count(*) AS'):
                        raise error_type('private code row and credential details')
                conn.before_query = fail_query
            self.adjust = adjust
            caught = self.failure(code, self.run_reference)
            self.assertIsNone(caught.__cause__)
            self.assertTrue(caught.__suppress_context__)
            self.assert_closed()


class ReferenceHTTPTests(unittest.TestCase):
    setUp = http_baseline.WorkerHTTPTest.setUp
    write_fixture = http_baseline.WorkerHTTPTest.write_fixture
    request = http_baseline.WorkerHTTPTest.request
    raw_request = http_baseline.WorkerHTTPTest.raw_request
    assert_alarm_restored = http_baseline.WorkerHTTPTest.assert_alarm_restored

    def test_full_legal_vector_traverses_actual_http_with_fresh_private_credential(self):
        self.payload = payload(full_codes())
        self.write_fixture('postgres')
        raw = json.dumps(self.payload).encode()
        self.assertGreater(len(raw), 16384)
        self.assertLess(len(raw), 65536)
        expected = measurement(self.payload['execution']['reference'])
        with patch.object(server, 'execute_quality', return_value=expected) as execute, patch.object(server, 'scan') as scan:
            self.assertEqual(self.request(raw, path='/quality'), (200, {'measurement': expected}))
            self.assertEqual(execute.call_args.args[3], self.payload['execution'])
            self.assertEqual(len(execute.call_args.args[3]['reference']['codes']), 256)
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-test-password')
            self.write_fixture('postgres-rotated')
            self.assertEqual(self.request(raw, path='/quality'), (200, {'measurement': expected}))
            self.assertEqual(execute.call_args.args[1]['password'], 'synthetic-quality-rotated-password')
            scan.assert_not_called()

    def test_exact_64k_reference_and_16k_completeness_physical_caps(self):
        self.write_fixture('postgres')
        for value, maximum in ((payload(full_codes()), 65536), (http_baseline.quality_payload(), 16384)):
            raw = json.dumps(value).encode()
            raw += b' ' * (maximum - len(raw))
            expected = measurement(value['execution']['reference']) if 'reference' in value['execution'] else http_baseline.quality_measurement()
            with patch.object(server, 'execute_quality', return_value=expected) as execute:
                self.assertEqual(self.request(raw, path='/quality'), (200, {'measurement': expected}))
                self.assertEqual(execute.call_count, 1)
            with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
                self.assertEqual(self.request(raw + b' ', path='/quality'), (413, {'code': 'REQUEST_SIZE'}))
                resolve.assert_not_called()
                execute.assert_not_called()
        with patch.object(server, 'resolve') as resolve:
            self.assertEqual(self.request(body=b'{', length=16385, path='/scan'), (413, {'code': 'REQUEST_SIZE'}))
            resolve.assert_not_called()

    def test_large_reference_duplicate_unknown_unsorted_and_hash_tamper_refuse_before_secret(self):
        value = payload(full_codes())
        raw = json.dumps(value).encode()
        invalid = [raw.replace(b'"codeStatus": "active"', b'"codeStatus":"active","codeStatus":"active"'),
                   raw.replace(b'"kind": "reference-allowed-values"', b'"kind":"completeness","kind":"reference-allowed-values"')]
        with patch.object(server, 'resolve') as resolve, patch.object(server, 'execute_quality') as execute:
            for body in invalid:
                self.assertEqual(self.request(body, path='/quality'), (400, {'code': 'INVALID_REQUEST'}))
            for codes in (list(reversed(full_codes())), full_codes()[:-1] + [full_codes()[0]], full_codes() + ['z']):
                self.assertEqual(self.request(json.dumps(payload(codes)).encode(), path='/quality'), (400, {'code': 'QUALITY_INPUT_INVALID'}))
            changed = copy.deepcopy(value)
            changed['execution']['reference']['bindingHash'] = '0' * 64
            self.assertEqual(self.request(json.dumps(changed).encode(), path='/quality'), (400, {'code': 'QUALITY_INPUT_INVALID'}))
            changed = copy.deepcopy(value)
            changed['execution']['extra'] = True
            self.assertEqual(self.request(json.dumps(changed).encode(), path='/quality'), (400, {'code': 'QUALITY_INPUT_INVALID'}))
            changed['execution']['kind'] = 'unknown'
            self.assertEqual(self.request(json.dumps(changed).encode(), path='/quality'), (413, {'code': 'REQUEST_SIZE'}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_enlarged_body_keeps_original_header_and_body_deadline(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        initial = ('POST /quality HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer ' + http_baseline.TOKEN +
                   '\r\nContent-Type: application/json\r\nContent-Length: 40000\r\nX-Slow: ').encode()
        with patch.object(server, 'REQUEST_SECONDS', 0.25), patch.object(server, 'resolve') as resolve:
            response, writes = self.raw_request(initial, delayed=((0.16, b'done\r\n\r\n{'),), trickle=True)
            head, body = response.split(b'\r\n\r\n', 1)
            self.assertEqual(int(head.split(b' ', 2)[1]), 408)
            self.assertEqual(json.loads(body), {'code': 'REQUEST_TIMEOUT'})
            self.assertGreaterEqual(writes, 2)
            self.assertLess(self.server_elapsed, 0.34)
            self.assertGreater(self.server_elapsed, 0.20)
            resolve.assert_not_called()
        self.assert_alarm_restored(handler, mask)
        with patch.object(server, 'REQUEST_SECONDS', 0.06), patch.object(server, 'resolve') as resolve:
            raw = json.dumps(http_baseline.quality_payload()).encode()
            self.assertEqual(self.request(raw, length=16385, path='/quality'), (408, {'code': 'REQUEST_TIMEOUT'}))
            resolve.assert_not_called()

    def test_large_reference_framing_and_errors_do_not_disclose_private_codes(self):
        raw = json.dumps(payload(full_codes())).encode()
        base = [('Authorization', 'Bearer ' + http_baseline.TOKEN), ('Content-Type', 'application/json')]
        with patch.object(server, 'resolve') as resolve:
            for extra in ([('Content-Length', str(len(raw)))], [('Content-Encoding', 'gzip')], [('Transfer-Encoding', 'chunked')]):
                self.assertEqual(self.request(raw, headers=base + extra, path='/quality'), (400, {'code': 'INVALID_REQUEST'}))
            self.assertEqual(self.request(raw, headers=base[1:], path='/quality'), (401, {'code': 'UNAUTHORIZED'}))
            resolve.assert_not_called()
        self.write_fixture('postgres')
        with patch.object(server, 'execute_quality', side_effect=RuntimeError(full_codes()[0])):
            self.assertEqual(self.request(raw, path='/quality'), (500, {'code': 'WORKER_FAILURE'}))


if __name__ == '__main__':
    unittest.main()
