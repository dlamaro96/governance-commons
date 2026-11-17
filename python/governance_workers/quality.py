# SPDX-License-Identifier: Apache-2.0
"""Exact bounded quality measurements for one pinned column.

No source-authored SQL or business rows cross this interface. Planner costs and
widths are estimates, never a claim to enforce physical I/O or byte consumption.
The initial profile excludes RLS, inheritance and nonbuiltin scalar columns.
"""
import hashlib
import hmac
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
REFERENCE_KIND = 'reference-allowed-values'
UNIQUENESS_KIND = 'uniqueness'
MAX_VALUE_BYTES = 4096
MAX_TOTAL_VALUE_BYTES = 67108864
MAX_REFERENCE_CODES = 256
REFERENCE_KEYS = frozenset(('setId', 'version', 'publicationHash', 'asOf',
                            'codeStatus', 'codes', 'bindingHash'))
TARGET_KEYS = frozenset(('databaseOid', 'schemaOid', 'relationOid', 'attributeNumber',
                         'schemaName', 'tableName', 'columnName', 'dataType'))
BUDGETS = {'maximumRows': MAX_ROWS, 'maximumSeconds': MAX_SECONDS,
           'statementTimeoutMs': MAX_STATEMENT_MS, 'maximumEstimatedCost': MAX_ESTIMATED_COST,
           'maximumEstimatedBytes': MAX_ESTIMATED_BYTES}
UNIQUENESS_BUDGETS = dict(BUDGETS, maximumValueBytes=MAX_VALUE_BYTES,
                         maximumTotalValueBytes=MAX_TOTAL_VALUE_BYTES)


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


def validate_reference_binding(value):
    """Verify the complete canonical detached binding before credential access.

    Only closed ASCII scalars and integer versions reach the canonical encoder,
    so compact sorted-key JSON matches the domain/SQL UTF-8 hash preimage.
    Selection, publication provenance and current authority are server duties;
    this worker verifies the retained binding, not a fresh reference head.
    """
    _keys(value, REFERENCE_KEYS)
    set_id = value['setId']
    if (type(set_id) is not str or not re.fullmatch(
            r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', set_id)
            or set_id == '00000000-0000-0000-0000-000000000000'):
        _fail()
    _integer(value['version'], 2147483647)
    for key in ('publicationHash', 'bindingHash'):
        if type(value[key]) is not str or not re.fullmatch(r'[a-f0-9]{64}', value[key]):
            _fail()
    instant = value['asOf']
    if type(instant) is not str or not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z', instant):
        _fail()
    try:
        parsed = datetime.fromisoformat(instant)
        if parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') != instant:
            _fail()
    except ValueError:
        _fail()
    if type(value['codeStatus']) is not str or value['codeStatus'] != 'active':
        _fail()
    codes = value['codes']
    if type(codes) is not list or len(codes) > MAX_REFERENCE_CODES:
        _fail()
    previous = None
    for code in codes:
        if (type(code) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', code)
                or (previous is not None and previous >= code)):
            _fail()
        previous = code
    detached = {key: value[key] for key in REFERENCE_KEYS if key != 'bindingHash'}
    detached['codes'] = list(codes)
    encoded = json.dumps(detached, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    expected = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(expected, value['bindingHash']):
        _fail()
    detached['bindingHash'] = expected
    return detached


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
    if type(execution) is not dict or type(execution.get('kind')) is not str:
        _fail()
    kind = execution['kind']
    _keys(execution, ('formatVersion', 'kind', 'target', 'budget', 'reference')
          if kind == REFERENCE_KIND else ('formatVersion', 'kind', 'target', 'budget'))
    if type(execution['formatVersion']) is not int or execution['formatVersion'] != 1 or kind not in ('completeness', REFERENCE_KIND, UNIQUENESS_KIND):
        _fail()
    if kind == REFERENCE_KIND:
        validate_reference_binding(execution['reference'])
    target, budget = execution['target'], execution['budget']
    _keys(target, TARGET_KEYS)
    ceilings = UNIQUENESS_BUDGETS if kind == UNIQUENESS_KIND else BUDGETS
    _keys(budget, ceilings)
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
    for key, maximum in ceilings.items():
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


def _measure_uniqueness(conn, relation, target, budget, deadline_at):
    # octet_length(text) measures logical bytes without constructing each UTF-8
    # bytea key. On UTF8 servers this is the exact later convert_to length.
    encoding = _query(conn, "SELECT current_setting('server_encoding') AS encoding",
                      None, budget, deadline_at).fetchone()
    if type(encoding) is not dict or set(encoding) != {'encoding'} or encoding['encoding'] != 'UTF8':
        _fail('QUALITY_TARGET_UNSUPPORTED')
    bounded = sql.SQL('SELECT {} AS value FROM ONLY {} LIMIT %s').format(
        sql.Identifier(target['columnName']), relation)
    preflight = sql.SQL(
        'SELECT count(*) AS row_count, count(*) FILTER (WHERE value IS NULL) AS null_count, '
        'coalesce(sum(pg_catalog.octet_length(value)),0)::bigint AS total_value_bytes, '
        'coalesce(max(pg_catalog.octet_length(value)),0) AS largest_value_bytes '
        'FROM ({}) AS bounded').format(bounded)
    parameters = (budget['maximumRows'] + 1,)
    first_plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + preflight,
                        parameters, budget, deadline_at).fetchone()
    cost, estimated_bytes = _estimates(first_plan.get('QUERY PLAN') if type(first_plan) is dict else None, budget)
    counts = _query(conn, preflight, parameters, budget, deadline_at).fetchone()
    fields = {'row_count', 'null_count', 'total_value_bytes', 'largest_value_bytes'}
    if (type(counts) is not dict or set(counts) != fields
            or any(type(counts[key]) is not int for key in fields)
            or not 0 <= counts['null_count'] <= counts['row_count'] <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    rows, nulls = counts['row_count'], counts['null_count']
    nonnull = rows - nulls
    total, largest = counts['total_value_bytes'], counts['largest_value_bytes']
    if not 0 <= largest <= total <= nonnull * largest:
        _fail('SOURCE_DATABASE_ERROR')
    if (rows > budget['maximumRows'] or largest > budget['maximumValueBytes']
            or total > budget['maximumTotalValueBytes']):
        _fail('QUALITY_RESOURCE_LIMIT')
    # The preceding whole-column preflight proved that this repeatable-read
    # snapshot fits all limits. No key conversion/grouping precedes that check.
    aggregate = sql.SQL(
        'SELECT count(*) AS distinct_count, '
        'count(*) FILTER (WHERE group_size > 1) AS duplicate_group_count, '
        'coalesce(sum(group_size) FILTER (WHERE group_size > 1),0)::bigint AS duplicate_row_count '
        'FROM (SELECT count(*) AS group_size FROM ({}) AS bounded '
        "WHERE value IS NOT NULL GROUP BY pg_catalog.convert_to(value,'UTF8')) AS grouped").format(bounded)
    second_plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + aggregate,
                         parameters, budget, deadline_at).fetchone()
    second_cost, second_bytes = _estimates(second_plan.get('QUERY PLAN') if type(second_plan) is dict else None, budget)
    cost, estimated_bytes = cost + second_cost, estimated_bytes + second_bytes
    if cost > budget['maximumEstimatedCost'] or estimated_bytes > budget['maximumEstimatedBytes']:
        _fail('QUALITY_RESOURCE_LIMIT')
    groups = _query(conn, aggregate, parameters, budget, deadline_at).fetchone()
    group_fields = {'distinct_count', 'duplicate_group_count', 'duplicate_row_count'}
    if (type(groups) is not dict or set(groups) != group_fields
            or any(type(groups[key]) is not int or not 0 <= groups[key] <= nonnull for key in group_fields)):
        _fail('SOURCE_DATABASE_ERROR')
    distinct, duplicates, duplicate_rows = (groups[key] for key in
                                           ('distinct_count', 'duplicate_group_count', 'duplicate_row_count'))
    if (distinct != nonnull - duplicate_rows + duplicates or duplicate_rows < 2 * duplicates
            or (duplicate_rows == 0) != (duplicates == 0)
            or (distinct == 0) != (nonnull == 0)):
        _fail('SOURCE_DATABASE_ERROR')
    return rows, nulls, cost, estimated_bytes, {
        'distinctCount': distinct, 'duplicateGroupCount': duplicates, 'duplicateRowCount': duplicate_rows,
        'totalValueBytes': total, 'largestValueBytes': largest}


def _measure(conn, target, budget, deadline_at, reference=None, *, uniqueness=False):
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
        t.oid::text AS type_oid,t.typtype,t.typcategory,t.typelem::text AS type_element,tn.nspname AS type_namespace,
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
    if uniqueness:
        if row['type_oid'] not in ('25', '1043'):
            _fail('QUALITY_TARGET_UNSUPPORTED')
        rows, nulls, cost, estimated_bytes, metrics = _measure_uniqueness(conn, relation, target, budget, deadline_at)
        return rows, nulls, version, cost, estimated_bytes, metrics
    if reference is not None:
        # Actual built-in OIDs, not a name/category check, exclude domains,
        # char padding, extension types and user-authored casts/operators.
        if row['type_oid'] not in ('25', '1043'):
            _fail('QUALITY_TARGET_UNSUPPORTED')
        aggregate = sql.SQL(
            'SELECT count(*) AS row_count, count(*) FILTER (WHERE value IS NULL) AS null_count, '
            'count(*) FILTER (WHERE value IS NOT NULL AND NOT '
            '(pg_catalog.convert_to(value, \'UTF8\') OPERATOR(pg_catalog.=) ANY (%s::pg_catalog.bytea[]))) AS invalid_count '
            'FROM (SELECT {} AS value FROM ONLY {} LIMIT %s) AS bounded').format(
                sql.Identifier(target['columnName']), relation)
        parameters = ([code.encode('ascii') for code in reference['codes']], budget['maximumRows'] + 1)
    else:
        aggregate = sql.SQL('SELECT count(*) AS row_count, count(*) FILTER (WHERE missing) AS null_count '
                            'FROM (SELECT {} IS NULL AS missing FROM ONLY {} LIMIT %s) AS bounded').format(
                                sql.Identifier(target['columnName']), relation)
        parameters = (budget['maximumRows'] + 1,)
    plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + aggregate,
                  parameters, budget, deadline_at).fetchone()
    cost, estimated_bytes = _estimates(plan.get('QUERY PLAN') if type(plan) is dict else None, budget)
    counts = _query(conn, aggregate, parameters, budget, deadline_at).fetchone()
    expected_counts = {'row_count', 'null_count', 'invalid_count'} if reference is not None else {'row_count', 'null_count'}
    if (type(counts) is not dict or set(counts) != expected_counts
            or type(counts['row_count']) is not int or type(counts['null_count']) is not int
            or not 0 <= counts['null_count'] <= counts['row_count'] <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    if reference is not None and (type(counts['invalid_count']) is not int
            or not 0 <= counts['invalid_count'] <= counts['row_count'] - counts['null_count']):
        _fail('SOURCE_DATABASE_ERROR')
    if counts['row_count'] > budget['maximumRows']:
        _fail('QUALITY_RESOURCE_LIMIT')
    result = (counts['row_count'], counts['null_count'], version, cost, estimated_bytes)
    return result + (counts['invalid_count'],) if reference is not None else result


def execute(source, secret, tenant_id, execution):
    started, observed_started = time.monotonic(), _stamp()
    source, target, budget = validate_execution(source, execution)
    reference = validate_reference_binding(execution['reference']) if execution['kind'] == REFERENCE_KIND else None
    uniqueness = execution['kind'] == UNIQUENESS_KIND
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
                    measured = _measure(conn, target, budget, deadline_at, reference, uniqueness=uniqueness)
                    rows, nulls, version, cost, estimated_bytes = measured[:5]
            # Connection close (rollback) and CA cleanup are inside the original
            # wall deadline. No connection context manager can print DB details.
            _remaining(deadline_at)
            result = {'formatVersion': 1, 'kind': UNIQUENESS_KIND if uniqueness else REFERENCE_KIND if reference is not None else 'completeness', 'strategy': 'exact-bounded-role-scope',
                    'rowCount': rows, 'nullCount': nulls, 'observedStartedAt': observed_started,
                    'observedFinishedAt': _stamp(), 'elapsedMs': math.floor((time.monotonic() - started) * 1000),
                    'sourceVersion': version, 'adapterVersion': '1',
                    'queryTemplate': 'postgresql-uniqueness-v1' if uniqueness else 'postgresql-reference-allowed-values-v1' if reference is not None else 'postgresql-completeness-v1',
                    'estimatedCost': cost, 'estimatedBytes': estimated_bytes}
            if reference is not None:
                result.update(invalidCount=measured[5], referenceBindingHash=reference['bindingHash'])
            if uniqueness:
                result.update(measured[5])
            return result
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
