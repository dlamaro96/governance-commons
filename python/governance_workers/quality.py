# SPDX-License-Identifier: Apache-2.0
"""Exact bounded SQL-NULL completeness for one pinned PostgreSQL column.

No source-authored SQL or business rows cross this interface. Planner costs and
widths are estimates, never a claim to enforce physical I/O or byte consumption.
The initial profile excludes RLS, inheritance and nonbuiltin scalar columns.
"""
import json
import math
import re
import time
from datetime import datetime, timezone

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import set_json_loads

from .postgresql import ScanFailure, _connection_parameters
from .deadline import deadline
from .postgres_targets import TargetPolicyError, _Resources, _blocked_alarm, _remaining

MAX_ROWS = 100000
MAX_SECONDS = 30
MAX_STATEMENT_MS = 15000
MAX_ESTIMATED_COST = 1000000
MAX_ESTIMATED_BYTES = 67108864
MAX_PLAN_BYTES = 65536
MAX_PLAN_NODES = 64
TARGET_KEYS = frozenset(('databaseOid', 'schemaOid', 'relationOid', 'attributeNumber',
                         'schemaName', 'tableName', 'columnName', 'dataType'))
BUDGETS = {'maximumRows': MAX_ROWS, 'maximumSeconds': MAX_SECONDS,
           'statementTimeoutMs': MAX_STATEMENT_MS, 'maximumEstimatedCost': MAX_ESTIMATED_COST,
           'maximumEstimatedBytes': MAX_ESTIMATED_BYTES}


def _fail(code='QUALITY_INPUT_INVALID'):
    raise ScanFailure(code)


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()


def _text(value, maximum, *, bytes_limit=False):
    if type(value) is not str or not value or '\0' in value or len(value) > maximum:
        _fail()
    try:
        encoded = value.encode('utf-8')
    except UnicodeError:
        _fail()
    if bytes_limit and len(encoded) > maximum:
        _fail()


def _integer(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        _fail()


def validate_execution(source, execution):
    """Closed fixed-shape JSON admission, before credentials or connection use."""
    _keys(source, ('connectorId', 'host', 'port', 'database', 'schema', 'secretRef'))
    if source['connectorId'] != 'postgresql':
        _fail('QUALITY_TARGET_UNSUPPORTED')
    _text(source['host'], 253, bytes_limit=True)
    _integer(source['port'], 65535)
    for key in ('database', 'schema'):
        _text(source[key], 63, bytes_limit=True)
    if type(source['secretRef']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', source['secretRef']):
        _fail()
    _keys(execution, ('formatVersion', 'kind', 'target', 'budget'))
    if type(execution['formatVersion']) is not int or execution['formatVersion'] != 1 or execution['kind'] != 'completeness':
        _fail()
    target, budget = execution['target'], execution['budget']
    _keys(target, TARGET_KEYS)
    _keys(budget, BUDGETS)
    for key in ('databaseOid', 'schemaOid', 'relationOid'):
        value = target[key]
        if type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,9}', value) or int(value) > 4294967295:
            _fail()
    _integer(target['attributeNumber'], 32767)
    for key in ('schemaName', 'tableName', 'columnName'):
        _text(target[key], 63, bytes_limit=True)
    _text(target['dataType'], 256)
    if target['schemaName'] != source['schema']:
        _fail('QUALITY_TARGET_STALE')
    for key, maximum in BUDGETS.items():
        value = budget[key]
        if key == 'maximumEstimatedCost':
            if type(value) not in (int, float) or not 0 < value <= maximum or not math.isfinite(value):
                _fail()
        else:
            _integer(value, maximum)
    # Detach the admitted scalars; callers cannot change the execution mid-query.
    return dict(source), dict(target), dict(budget)


def _stamp():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _plan_json(raw):
    if len(raw) > MAX_PLAN_BYTES:
        _fail('QUALITY_RESOURCE_LIMIT')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail('SOURCE_DATABASE_ERROR')
            result[key] = value
        return result
    try:
        text = raw.decode('utf-8', 'strict') if type(raw) is not str else raw
        result = json.loads(text, object_pairs_hook=pairs,
                            parse_constant=lambda _: _fail('SOURCE_DATABASE_ERROR'))
        pending, nodes = [(result, 1)], 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if nodes > 1024 or depth > 32:
                _fail('SOURCE_DATABASE_ERROR')
            if type(value) is dict:
                pending.extend((child, depth + 1) for child in value.values())
            elif type(value) is list:
                pending.extend((child, depth + 1) for child in value)
            elif type(value) is str:
                value.encode('utf-8', 'strict')
        return result
    except (ValueError, UnicodeError, RecursionError):
        _fail('SOURCE_DATABASE_ERROR')


def _estimates(value, budget):
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict or type(value[0].get('Plan')) is not dict:
        _fail('SOURCE_DATABASE_ERROR')
    root = value[0]['Plan']
    pending, nodes, estimated_bytes = [root], 0, 0
    while pending:
        node = pending.pop()
        nodes += 1
        if nodes > MAX_PLAN_NODES:
            _fail('QUALITY_RESOURCE_LIMIT')
        if type(node) is not dict:
            _fail('SOURCE_DATABASE_ERROR')
        rows, width, cost = node.get('Plan Rows'), node.get('Plan Width'), node.get('Total Cost')
        if (type(rows) is not int or rows < 0 or type(width) is not int or width < 0
                or type(cost) not in (int, float) or not 0 <= cost <= 1e300 or not math.isfinite(cost)):
            _fail('SOURCE_DATABASE_ERROR')
        estimated_bytes += rows * width
        if estimated_bytes > budget['maximumEstimatedBytes']:
            _fail('QUALITY_RESOURCE_LIMIT')
        children = node.get('Plans', [])
        if type(children) is not list or len(children) + nodes + len(pending) > MAX_PLAN_NODES:
            _fail('QUALITY_RESOURCE_LIMIT')
        pending.extend(children)
    if root['Total Cost'] > budget['maximumEstimatedCost']:
        _fail('QUALITY_RESOURCE_LIMIT')
    return root['Total Cost'], estimated_bytes


def _query(conn, statement, parameters, budget, deadline_at):
    remaining_ms = math.floor(_remaining(deadline_at) * 1000)
    if remaining_ms < 1:
        _fail('SOURCE_DEADLINE_EXCEEDED')
    # SET does not take the catalog snapshot before the relation lock. Values
    # are generated integers, still quoted by the driver rather than interpolated.
    conn.execute(sql.SQL('SET LOCAL statement_timeout = {}').format(sql.Literal(str(min(budget['statementTimeoutMs'], remaining_ms)) + 'ms')))
    conn.execute(sql.SQL('SET LOCAL lock_timeout = {}').format(sql.Literal(str(min(2000, remaining_ms)) + 'ms')))
    result = conn.execute(statement, parameters)
    _remaining(deadline_at)
    return result


def _measure(conn, target, budget, deadline_at):
    conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
    relation = sql.Identifier(target['schemaName'], target['tableName'])
    # Lock by safely quoted name, then independently prove that the lock belongs
    # to the pinned OID. A replacement relation cannot satisfy that proof.
    _query(conn, sql.SQL('LOCK TABLE ONLY {} IN ACCESS SHARE MODE').format(relation), None, budget, deadline_at)
    identity = _query(conn, """SELECT d.oid::text AS database_oid,
        current_setting('server_version_num') AS version, r.rolsuper, r.rolbypassrls
        FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_roles r
        WHERE d.datname=current_database() AND r.rolname=current_user""", None, budget, deadline_at).fetchone()
    if not identity or identity['database_oid'] != target['databaseOid']:
        _fail('QUALITY_TARGET_STALE')
    if identity['rolsuper'] is not False or identity['rolbypassrls'] is not False:
        _fail('SOURCE_PRIVILEGE_TOO_BROAD')
    version = identity['version']
    if type(version) is not str or not re.fullmatch(r'[0-9]{5,16}', version):
        _fail('SOURCE_DATABASE_ERROR')
    row = _query(conn, """SELECT c.oid::text AS relation_oid,n.oid::text AS schema_oid,
        n.nspname,c.relname,c.relkind,c.relispartition,c.relrowsecurity,
        EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS inherited,
        has_schema_privilege(n.oid,'USAGE') AS schema_allowed,has_table_privilege(c.oid,'SELECT') AS table_allowed,
        a.attnum,a.attname,a.attisdropped,format_type(a.atttypid,a.atttypmod) AS data_type,
        t.typtype,t.typcategory,t.typelem::text AS type_element,tn.nspname AS type_namespace,
        EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
          AND l.locktype='relation' AND l.relation=c.oid AND l.mode='AccessShareLock' AND l.granted) AS locked
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=%s
        LEFT JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
        LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace WHERE c.oid=%s::oid""",
        (target['attributeNumber'], target['relationOid']), budget, deadline_at).fetchone()
    if (not row or row['relation_oid'] != target['relationOid'] or row['schema_oid'] != target['schemaOid']
            or row['nspname'] != target['schemaName'] or row['relname'] != target['tableName']
            or row['attnum'] != target['attributeNumber'] or row['attname'] != target['columnName']
            or row['attisdropped'] is not False or row['data_type'] != target['dataType'] or row['locked'] is not True):
        _fail('QUALITY_TARGET_STALE')
    if row['schema_allowed'] is not True or row['table_allowed'] is not True:
        _fail('SOURCE_SCOPE_DENIED')
    if (row['relkind'] != 'r' or row['relispartition'] is not False or row['relrowsecurity'] is not False
            or row['inherited'] is not False or row['type_namespace'] != 'pg_catalog' or row['typtype'] != 'b'
            or row['typcategory'] in ('A', 'C', 'P') or row['type_element'] != '0'):
        _fail('QUALITY_TARGET_UNSUPPORTED')
    aggregate = sql.SQL('SELECT count(*) AS row_count, count(*) FILTER (WHERE missing) AS null_count '
                        'FROM (SELECT {} IS NULL AS missing FROM ONLY {} LIMIT %s) AS bounded').format(
                            sql.Identifier(target['columnName']), relation)
    parameters = (budget['maximumRows'] + 1,)
    plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + aggregate,
                  parameters, budget, deadline_at).fetchone()
    cost, estimated_bytes = _estimates(plan.get('QUERY PLAN') if type(plan) is dict else None, budget)
    counts = _query(conn, aggregate, parameters, budget, deadline_at).fetchone()
    if (type(counts) is not dict or set(counts) != {'row_count', 'null_count'}
            or type(counts['row_count']) is not int or type(counts['null_count']) is not int
            or not 0 <= counts['null_count'] <= counts['row_count'] <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    if counts['row_count'] > budget['maximumRows']:
        _fail('QUALITY_RESOURCE_LIMIT')
    return counts['row_count'], counts['null_count'], version, cost, estimated_bytes


def execute(source, secret, tenant_id, execution):
    started, observed_started = time.monotonic(), _stamp()
    source, target, budget = validate_execution(source, execution)
    deadline_at = started + budget['maximumSeconds']
    try:
        with deadline(_remaining(deadline_at)):
            with _connection_parameters(source, secret, tenant_id, deadline_at) as params:
                with _Resources() as resources:
                    with _blocked_alarm():
                        remaining = _remaining(deadline_at)
                        if remaining < 2:
                            _fail('SOURCE_DEADLINE_EXCEEDED')
                        kwargs = dict(params)
                        kwargs['connect_timeout'] = min(5, math.floor(remaining))
                        conn = psycopg.connect(**kwargs, row_factory=dict_row)
                        resources.own(conn.close)
                    set_json_loads(_plan_json, context=conn)
                    rows, nulls, version, cost, estimated_bytes = _measure(conn, target, budget, deadline_at)
            # Connection close (rollback) and CA cleanup are inside the original
            # wall deadline. No connection context manager can print DB details.
            _remaining(deadline_at)
            return {'formatVersion': 1, 'kind': 'completeness', 'strategy': 'exact-bounded-role-scope',
                    'rowCount': rows, 'nullCount': nulls, 'observedStartedAt': observed_started,
                    'observedFinishedAt': _stamp(), 'elapsedMs': math.floor((time.monotonic() - started) * 1000),
                    'sourceVersion': version, 'adapterVersion': '1', 'queryTemplate': 'postgresql-completeness-v1',
                    'estimatedCost': cost, 'estimatedBytes': estimated_bytes}
    except TargetPolicyError as error:
        raise ScanFailure(error.code) from None
    except psycopg.Error as error:
        if error.sqlstate in ('42P01', '42703', '3F000'):
            raise ScanFailure('QUALITY_TARGET_STALE') from None
        if error.sqlstate == '42501':
            raise ScanFailure('SOURCE_SCOPE_DENIED') from None
        if error.sqlstate in ('57014', '55P03'):
            raise ScanFailure('QUALITY_RESOURCE_LIMIT') from None
        raise ScanFailure('SOURCE_DATABASE_ERROR') from None
