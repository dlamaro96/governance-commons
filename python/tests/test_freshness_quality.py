# SPDX-License-Identifier: Apache-2.0
"""Freshness protocol controls; SQL replies are doubles, not native evidence."""
import copy
import hashlib
import json
import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import psycopg
from governance_workers import quality, server
from test_postgres_targets import source, secret
import test_quality as base
import test_server as http

VECTOR = 'b7cd429cfbc4669fdd7ddd36964234b7ec458affbe757af28de26030f063faf9'
STAMP = '2026-11-17T05:00:00.123456Z'
WALL = '2026-11-17T05:00:00.123Z'


def binding(age=3600, future=0):
    fields = dict(maximumAgeSeconds=age, maximumFutureSkewSeconds=future,
                  comparison='latest-timestamptz', clock='source-statement-start',
                  nullPolicy='exclude', invalidTimestampPolicy='fail')
    text = json.dumps(dict(fields, formatVersion=1, kind='freshness'), sort_keys=True, separators=(',', ':'))
    return dict(fields, freshnessHash=hashlib.sha256(text.encode()).hexdigest())


def execution():
    v = base.execution()
    v.update(kind='freshness', freshness=binding())
    v['target'].update(tableName='freshness_fixture', columnName='observed', dataType='timestamp with time zone')
    return v


def payload():
    v = http.quality_payload()
    v['execution'] = execution()
    v['execution']['target']['schemaName'] = v['source']['schema']
    return v


def counts(**changes):
    v = dict(row_count=6, null_count=1, non_finite_count=0, unrepresentable_count=0, future_count=0,
             source_observed_at=STAMP, latest_observed_at='2026-11-17T04:59:00.123455Z', age_microseconds='60000001')
    v.update(changes)
    return v


def measurement():
    v = http.quality_measurement()
    v.update(kind='freshness', queryTemplate='postgresql-freshness-v1', rowCount=6, nullCount=1,
             nonFiniteCount=0, unrepresentableCount=0, futureCount=0, sourceObservedAt=STAMP,
             latestObservedAt='2026-11-17T04:59:00.123455Z', ageMicroseconds='60000001', freshnessHash=VECTOR)
    return v


class Connection(base.Connection):
    def __init__(self, params):
        super().__init__(params)
        self.catalog.update(relname='freshness_fixture', attname='observed', data_type='timestamp with time zone', type_oid='1184')
        self.counts = counts()

    def execute(self, statement, parameters=None):
        text = statement if type(statement) is str else statement.as_string()
        if text.startswith('WITH clock AS MATERIALIZED'):
            self.queries.append((text, parameters)); self.before_query(text)
            return base.Rows(self.counts)
        return super().execute(statement, parameters)


class AdmissionTests(base.Cases):
    def test_canonical_hash_and_detached_fields(self):
        v = binding()
        self.assertEqual(v['freshnessHash'], VECTOR)
        result = quality.validate_freshness_binding(v)
        v['maximumAgeSeconds'] = 1
        self.assertEqual(result, binding())
        quality.validate_execution(source(), execution())
        for age, future in [(1, 0), (31536000, 300)]:
            self.assertEqual(quality.validate_freshness_binding(binding(age, future)), binding(age, future))

    def test_strict_bounds_scalars_and_closed_settings(self):
        for key, values in [('maximumAgeSeconds', [0, -1, 31536001, True, 1.0, '1', None, float('nan')]),
                            ('maximumFutureSkewSeconds', [-1, 301, True, 0.0, '0', None])]:
            for bad in values:
                v = binding(); v[key] = bad
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_freshness_binding(v))
        for key in quality.FRESHNESS_KEYS:
            v = binding(); del v[key]
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_freshness_binding(v))
        for key, bad in [('freshnessHash', '0'*64), ('comparison', 'per-row'), ('clock', 'client'),
                         ('nullPolicy', 'pass'), ('invalidTimestampPolicy', 'ignore'), ('sql', 'private'),
                         ('sourceObservedAt', STAMP)]:
            v = binding(); v[key] = bad
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_freshness_binding(v))

    def test_refusal_before_secret_destination_or_connect(self):
        for extra in ['reference', 'range', 'sourceObservedAt', 'maximumNullBasisPoints']:
            v = execution(); v[extra] = {}
            with patch.object(quality, '_connection_parameters') as destination, patch.object(quality.psycopg, 'connect') as connect:
                self.failure('QUALITY_INPUT_INVALID', lambda: quality.execute(source(), secret(), 'tenant-one', v))
                destination.assert_not_called(); connect.assert_not_called()
        import test_reference_quality, test_uniqueness_quality, test_range_quality
        for factory in [base.execution, test_reference_quality.execution, test_uniqueness_quality.execution, test_range_quality.execution]:
            v = factory(); quality.validate_execution(source(), v)
            v['freshness'] = binding()
            self.failure('QUALITY_INPUT_INVALID', lambda: quality.validate_execution(source(), v))

    def test_microsecond_calendar_bounds_without_float_or_rounding(self):
        self.assertEqual(quality._micro_instant('0001-01-01T00:00:00.000000Z'), -62135596800000000)
        self.assertEqual(quality._micro_instant('9999-12-31T23:59:59.999999Z'), 253402300799999999)
        self.assertEqual(quality._micro_instant('1970-01-01T00:00:00.000001Z'), 1)
        self.assertEqual(quality._micro_instant('1969-12-31T23:59:59.999999Z'), -1)
        for bad in [STAMP[:-1], STAMP+'\n', STAMP.replace('Z','+00:00'), STAMP.replace('.123456','.123'),
                    '0000-01-01T00:00:00.000000Z', '2026-02-29T00:00:00.000000Z',
                    '2024-02-30T00:00:00.000000Z', '2026-01-01T00:00:60.000000Z', 'infinity', 1, True]:
            self.failure('SOURCE_DATABASE_ERROR', lambda: quality._micro_instant(bad))
        quality._micro_instant('2024-02-29T00:00:00.000000Z')

    def test_clock_envelope_exact_allowance_and_backward_worker_clock(self):
        for source_at in ['2026-11-17T04:59:55.123000Z', '2026-11-17T05:00:05.123000Z']:
            quality._freshness_clock_envelope({'sourceObservedAt': source_at}, WALL, WALL)
        for source_at in ['2026-11-17T04:59:55.122999Z', '2026-11-17T05:00:05.123001Z']:
            self.failure('QUALITY_CLOCK_SKEW', lambda: quality._freshness_clock_envelope({'sourceObservedAt': source_at}, WALL, WALL))
        self.failure('QUALITY_CLOCK_SKEW', lambda: quality._freshness_clock_envelope({'sourceObservedAt': STAMP}, WALL, '2026-11-17T04:59:59.999Z'))


class ExecutorTests(base.Cases):
    setUp = base.ExecutorTests.setUp
    assert_closed = base.ExecutorTests.assert_closed
    assert_no_aggregate = base.ExecutorTests.assert_no_aggregate

    def connect(self, **params):
        conn = Connection(params); self.connections.append(conn); self.configure(conn)
        return conn

    def run_freshness(self, value=None):
        with patch.object(quality, '_stamp', return_value=WALL):
            return quality.execute(source(), secret(), 'tenant-one', execution() if value is None else value)

    def test_exact_template_native_max_and_statement_clock(self):
        result = self.run_freshness()
        self.assertEqual(set(result), set(measurement()))
        for key in ['kind','queryTemplate','rowCount','nullCount','nonFiniteCount','unrepresentableCount','futureCount',
                    'sourceObservedAt','latestObservedAt','ageMicroseconds','freshnessHash']:
            self.assertEqual(result[key], measurement()[key])
        conn = self.assert_closed()
        self.assertEqual(conn.queries[0][0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        query, params = next((s,p) for s,p in conn.queries if s.startswith('WITH clock'))
        self.assertEqual(params, (100001, '0 seconds'))
        self.assertEqual(query.count('pg_catalog.statement_timestamp()'), 1)
        self.assertIn('max(value) FILTER', query)
        self.assertIn('FROM ONLY "catalog"."freshness_fixture" LIMIT %s', query)
        self.assertIn('pg_catalog.isfinite(value)', query)
        self.assertIn('10000-01-01 00:00:00+00', query)
        self.assertIn('HH24:MI:SS.US', query)
        for forbidden in ['clock_timestamp(', 'transaction_timestamp(', 'value::', 'EXPLAIN ANALYZE']:
            self.assertNotIn(forbidden, query)
        planned = next((s,p) for s,p in conn.queries if s.startswith('EXPLAIN '))
        self.assertEqual(planned, ('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) '+query, params))
        self.assertEqual(conn.params['sslmode'], 'verify-full')

    def test_qualified_future_operator_groups_timestamp_before_comparison(self):
        # Native attempt1 exposed boolean+interval (42883): qualified operators
        # do not retain the usual unqualified arithmetic/comparison precedence.
        for tolerance in (0, 1, 300):
            value = execution(); value['freshness'] = binding(future=tolerance)
            self.run_freshness(value)
            conn = self.assert_closed()
            query, params = next((s,p) for s,p in conn.queries if s.startswith('WITH clock'))
            self.assertIn('value OPERATOR(pg_catalog.>) (clock.at OPERATOR(pg_catalog.+) %s::pg_catalog.interval)', query)
            self.assertEqual(params, (100001, str(tolerance) + ' seconds'))

    def test_empty_allnull_allinvalid_are_distinct_closed_measurements(self):
        for value in [counts(row_count=0, null_count=0, latest_observed_at=None, age_microseconds=None),
                      counts(row_count=6, null_count=6, latest_observed_at=None, age_microseconds=None),
                      counts(row_count=6, null_count=1, non_finite_count=2, unrepresentable_count=3,
                             latest_observed_at=None, age_microseconds=None)]:
            self.configure = lambda conn: setattr(conn, 'counts', value)
            result = self.run_freshness()
            self.assertIsNone(result['latestObservedAt']); self.assertIsNone(result['ageMicroseconds'])
            self.assertEqual(result['nonFiniteCount'], value['non_finite_count']); self.assert_closed()

    def test_microsecond_age_boundary_and_future_equality_remain_exact(self):
        cases = [('2026-11-17T04:59:00.123456Z', '60000000', 0),
                 ('2026-11-17T04:59:00.123455Z', '60000001', 0),
                 ('2026-11-17T05:05:00.123456Z', '-300000000', 0),
                 ('2026-11-17T05:05:00.123457Z', '-300000001', 1)]
        v = execution(); v['freshness'] = binding(60,300)
        for latest, age, future in cases:
            self.configure = lambda conn: setattr(conn, 'counts', counts(latest_observed_at=latest,age_microseconds=age,future_count=future))
            m = self.run_freshness(v)
            self.assertEqual((m['latestObservedAt'], m['ageMicroseconds'], m['futureCount']), (latest,age,future))
            self.assert_closed()

    def test_invalid_count_age_null_and_future_protocol_never_commits_measurement(self):
        variants = [counts(row_count=True),counts(null_count=7),counts(non_finite_count=6),counts(future_count=6),
                    counts(future_count=1),counts(non_finite_count=3,unrepresentable_count=3),
                    counts(age_microseconds='60000000'), counts(age_microseconds=60000001),counts(age_microseconds='060000001'),
                    counts(age_microseconds='-0'),counts(age_microseconds='1e6'),counts(age_microseconds='9'*19),
                    counts(latest_observed_at=None),counts(row_count=0,null_count=0),counts(source_observed_at='private'),
                    counts(source_observed_at='2026-11-17T05:00:00.123456Z\n'),dict(counts(),row='private')]
        for value in variants:
            self.configure = lambda conn: setattr(conn, 'counts', value)
            self.failure('SOURCE_DATABASE_ERROR', self.run_freshness); self.assert_closed()

    def test_native_oid1184_precisions_only_and_stale_pins(self):
        for name in ['timestamp with time zone','timestamp(0) with time zone','timestamp(3) with time zone','timestamp(6) with time zone']:
            v=execution();v['target']['dataType']=name
            self.configure=lambda conn: conn.catalog.update(data_type=name)
            self.assertEqual(self.run_freshness(v)['rowCount'],6);self.assert_closed()
        for key,bad in [('type_oid',v) for v in ['1114','1082','25','20','1185','80000']]+[
                ('typtype','d'),('type_namespace','public'),('relrowsecurity',True),('inherited',True),
                ('relispartition',True),('relkind','v'),('relkind','f')]:
            self.configure=lambda conn:conn.catalog.update({key:bad})
            self.failure('QUALITY_TARGET_UNSUPPORTED',self.run_freshness);self.assert_no_aggregate(self.assert_closed())
        for key,bad in [('relation_oid','66'),('schema_oid','19'),('attnum',2),('attname','other'),
                         ('data_type','timestamp without time zone'),('relname','other'),('nspname','other'),('locked',False)]:
            self.configure=lambda conn:conn.catalog.update({key:bad})
            self.failure('QUALITY_TARGET_STALE',self.run_freshness);self.assert_no_aggregate(self.assert_closed())

    def test_plan_row_limits_and_source_clock_skew_refuse_after_owned_cleanup(self):
        self.configure=lambda conn:setattr(conn,'counts',counts(row_count=100001,null_count=1))
        self.failure('QUALITY_RESOURCE_LIMIT',self.run_freshness);self.assert_closed()
        for plan in [base.plan(cost=1000001),base.plan(rows=100000,width=1000)]:
            self.configure=lambda conn:setattr(conn,'plan',plan)
            self.failure('QUALITY_RESOURCE_LIMIT',self.run_freshness)
            self.assertFalse(any(q.startswith('WITH clock') for q,_ in self.assert_closed().queries))
        self.configure=lambda conn:setattr(conn,'counts',counts(source_observed_at='2026-11-18T05:00:00.123456Z',age_microseconds='86460000001'))
        self.failure('QUALITY_CLOCK_SKEW',self.run_freshness);self.assert_closed()

    def test_actual_deadline_and_closed_driver_failures(self):
        v=execution();v['budget']['maximumSeconds']=3
        def configure(conn):
            conn.before_query=lambda text:time.sleep(3.2) if text.startswith('WITH clock') else None
        self.configure=configure
        started=time.monotonic()
        self.failure('SOURCE_DEADLINE_EXCEEDED',lambda:self.run_freshness(v))
        self.assertLess(time.monotonic()-started,4.5);self.assert_closed()
        for error,code in [(psycopg.errors.QueryCanceled,'QUALITY_RESOURCE_LIMIT'),
                           (psycopg.errors.LockNotAvailable,'QUALITY_RESOURCE_LIMIT'),
                           (psycopg.errors.InsufficientPrivilege,'SOURCE_SCOPE_DENIED'),
                           (psycopg.OperationalError,'SOURCE_DATABASE_ERROR')]:
            def configure(conn):
                def fail(text):
                    if text.startswith('WITH clock'):raise error('private timestamp and password')
                conn.before_query=fail
            self.configure=configure
            caught=self.failure(code,self.run_freshness)
            self.assertIsNone(caught.__cause__);self.assertTrue(caught.__suppress_context__);self.assert_closed()


class HTTPTests(unittest.TestCase):
    setUp=http.WorkerHTTPTest.setUp
    write_fixture=http.WorkerHTTPTest.write_fixture
    request=http.WorkerHTTPTest.request

    def test_actual_loopback_closed_freshness_and_16k_admission(self):
        self.payload=payload();self.write_fixture('postgres')
        raw=json.dumps(self.payload).encode();raw+=b' '*(16384-len(raw))
        with patch.object(server,'execute_quality',return_value=measurement()) as execute:
            self.assertEqual(self.request(raw,path='/quality'),(200,{'measurement':measurement()}))
            self.assertEqual(execute.call_args.args[3],self.payload['execution'])
        with patch.object(server,'resolve') as resolve,patch.object(server,'execute_quality') as execute:
            self.assertEqual(self.request(raw+b' ',path='/quality'),(413,{'code':'REQUEST_SIZE'}))
            resolve.assert_not_called();execute.assert_not_called()

    def test_duplicate_binding_mixed_family_and_clock_failure_are_closed(self):
        self.payload=payload();self.write_fixture('postgres')
        v=payload();v['execution']['freshness']['maximumAgeSeconds']=1
        mixed=payload();mixed['execution']['range']={}
        raw=json.dumps(payload()).encode().replace(b'"maximumAgeSeconds": 3600',b'"maximumAgeSeconds":1,"maximumAgeSeconds":3600')
        with patch.object(server,'resolve') as resolve:
            for body in [json.dumps(v).encode(),json.dumps(mixed).encode(),raw]:self.assertEqual(self.request(body,path='/quality')[0],400)
            resolve.assert_not_called()
        with patch.object(server,'execute_quality',side_effect=quality.ScanFailure('QUALITY_CLOCK_SKEW')):
            self.assertEqual(self.request(path='/quality'),(422,{'code':'QUALITY_CLOCK_SKEW'}))


if __name__=='__main__':unittest.main()
