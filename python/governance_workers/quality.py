# SPDX-License-Identifier: Apache-2.0
"""Exact bounded quality measurements for one pinned column or whole table.

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
RANGE_KIND = 'range'
FRESHNESS_KIND = 'freshness'
VOLUME_KIND = 'volume'
VOLUME_KEYS = frozenset(('minimumRows', 'maximumRows', 'comparison', 'scope', 'volumeHash'))
TABLE_TARGET_KEYS = frozenset(('kind', 'databaseOid', 'schemaOid', 'relationOid', 'schemaName', 'tableName'))
FRESHNESS_KEYS = frozenset(('maximumAgeSeconds', 'maximumFutureSkewSeconds', 'comparison',
                            'clock', 'nullPolicy', 'invalidTimestampPolicy', 'freshnessHash'))
MAX_AGE_SECONDS = 31536000
MAX_FUTURE_SKEW_SECONDS = 300
CLOCK_ALLOWANCE_US = 5000000
RANGE_KEYS = frozenset(('minimum', 'maximum', 'comparison', 'nullPolicy', 'rangeHash'))
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


def validate_range_binding(value):
    """Canonical signed-int64 strings and a closed, detached bound hash.

    Python integers preserve every bit; floats and JSON numbers are never
    admitted. The hash preimage is shared with the protected SQL/domain layer.
    """
    _keys(value, RANGE_KEYS)
    bounds = []
    for key in ('minimum', 'maximum'):
        bound = value[key]
        if (type(bound) is not str or len(bound) > 20
                or not re.fullmatch(r'(?:0|-[1-9][0-9]*|[1-9][0-9]*)', bound)):
            _fail()
        integer = int(bound)
        if not -9223372036854775808 <= integer <= 9223372036854775807:
            _fail()
        bounds.append(integer)
    if bounds[0] > bounds[1]:
        _fail()
    if (type(value['comparison']) is not str or value['comparison'] != 'int64-inclusive'
            or type(value['nullPolicy']) is not str or value['nullPolicy'] != 'exclude'
            or type(value['rangeHash']) is not str or not re.fullmatch(r'[a-f0-9]{64}', value['rangeHash'])):
        _fail()
    detached = {key: value[key] for key in RANGE_KEYS if key != 'rangeHash'}
    preimage = dict(detached, formatVersion=1, kind=RANGE_KIND)
    encoded = json.dumps(preimage, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    expected = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(expected, value['rangeHash']):
        _fail()
    detached['rangeHash'] = expected
    return detached


def validate_freshness_binding(value):
    """Static immutable rule settings; no supplied clock, SQL or source sample."""
    _keys(value, FRESHNESS_KEYS)
    _integer(value['maximumAgeSeconds'], MAX_AGE_SECONDS)
    if (type(value['maximumFutureSkewSeconds']) is not int
            or not 0 <= value['maximumFutureSkewSeconds'] <= MAX_FUTURE_SKEW_SECONDS
            or any(type(value[k]) is not str for k in ('comparison', 'clock', 'nullPolicy', 'invalidTimestampPolicy'))
            or value['comparison'] != 'latest-timestamptz' or value['clock'] != 'source-statement-start'
            or value['nullPolicy'] != 'exclude' or value['invalidTimestampPolicy'] != 'fail'
            or type(value['freshnessHash']) is not str
            or not re.fullmatch(r'[a-f0-9]{64}', value['freshnessHash'])):
        _fail()
    detached = {key: value[key] for key in FRESHNESS_KEYS if key != 'freshnessHash'}
    preimage = dict(detached, formatVersion=1, kind=FRESHNESS_KIND)
    expected = hashlib.sha256(json.dumps(preimage, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    if not hmac.compare_digest(expected, value['freshnessHash']):
        _fail()
    return dict(detached, freshnessHash=expected)


def _micro_instant(value):
    # Aggregate clocks/MAX are text, so infinity and PostgreSQL's much wider
    # date range can never enter the driver's datetime decoder. No float epoch.
    if type(value) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z', value):
        _fail('SOURCE_DATABASE_ERROR')
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.isoformat(timespec='microseconds').replace('+00:00', 'Z') != value:
            _fail('SOURCE_DATABASE_ERROR')
        delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return delta.days * 86400000000 + delta.seconds * 1000000 + delta.microseconds
    except (ValueError, OverflowError):
        _fail('SOURCE_DATABASE_ERROR')


def _freshness_aggregate(relation, target, budget, binding):
    # Qualified OPERATOR forms have equal left-associative precedence; the
    # clock-plus-interval operand must be grouped before the comparison.
    # Both bounds and operators are fixed native timestamptz operations. MAX
    # includes representable future timestamps; invalid rows force failure in
    # the canonical verdict and cannot be discarded to fabricate freshness.
    finite = "pg_catalog.isfinite(value)"
    representable = (finite + " AND value OPERATOR(pg_catalog.>=) '0001-01-01 00:00:00+00'::pg_catalog.timestamptz"
                     " AND value OPERATOR(pg_catalog.<) '10000-01-01 00:00:00+00'::pg_catalog.timestamptz")
    aggregate = sql.SQL(
        "WITH clock AS MATERIALIZED (SELECT pg_catalog.statement_timestamp() AS at), "
        "bounded AS MATERIALIZED (SELECT {} AS value FROM ONLY {} LIMIT %s), "
        "counts AS (SELECT count(*) AS row_count, count(*) FILTER (WHERE value IS NULL) AS null_count, "
        "count(*) FILTER (WHERE value IS NOT NULL AND NOT " + finite + ") AS non_finite_count, "
        "count(*) FILTER (WHERE " + finite + " AND NOT (" + representable + ")) AS unrepresentable_count, "
        "count(*) FILTER (WHERE " + representable + " AND value OPERATOR(pg_catalog.>) "
        "(clock.at OPERATOR(pg_catalog.+) %s::pg_catalog.interval)) AS future_count, "
        "max(value) FILTER (WHERE " + representable + ") AS latest FROM bounded CROSS JOIN clock) "
        "SELECT row_count,null_count,non_finite_count,unrepresentable_count,future_count, "
        "pg_catalog.to_char(clock.at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS source_observed_at, "
        "pg_catalog.to_char(latest AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS latest_observed_at, "
        "((EXTRACT(EPOCH FROM clock.at) OPERATOR(pg_catalog.-) EXTRACT(EPOCH FROM latest)) "
        "OPERATOR(pg_catalog.*) 1000000)::pg_catalog.int8::pg_catalog.text AS age_microseconds "
        "FROM counts CROSS JOIN clock").format(sql.Identifier(target['columnName']), relation)
    # The interval parameter is generated from an admitted bounded integer only;
    # integral seconds are exact and introduce no calendar/DST arithmetic.
    return aggregate, (budget['maximumRows'] + 1, str(binding['maximumFutureSkewSeconds']) + ' seconds')


def _measure_freshness(conn, relation, target, budget, deadline_at, binding):
    aggregate, parameters = _freshness_aggregate(relation, target, budget, binding)
    plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + aggregate,
                  parameters, budget, deadline_at).fetchone()
    cost, estimated_bytes = _estimates(plan.get('QUERY PLAN') if type(plan) is dict else None, budget)
    value = _query(conn, aggregate, parameters, budget, deadline_at).fetchone()
    keys = {'row_count', 'null_count', 'non_finite_count', 'unrepresentable_count', 'future_count',
            'source_observed_at', 'latest_observed_at', 'age_microseconds'}
    if type(value) is not dict or set(value) != keys:
        _fail('SOURCE_DATABASE_ERROR')
    rows, nulls = value['row_count'], value['null_count']
    if (type(rows) is not int or type(nulls) is not int
            or not 0 <= nulls <= rows <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    if rows > budget['maximumRows']:
        _fail('QUALITY_RESOURCE_LIMIT')
    nonfinite, unrepresentable, future = (value[k] for k in ('non_finite_count', 'unrepresentable_count', 'future_count'))
    if any(type(v) is not int or not 0 <= v <= rows-nulls for v in (nonfinite, unrepresentable, future)):
        _fail('SOURCE_DATABASE_ERROR')
    represented = rows - nulls - nonfinite - unrepresentable
    if represented < 0 or future > represented:
        _fail('SOURCE_DATABASE_ERROR')
    clock = _micro_instant(value['source_observed_at'])
    latest, age = value['latest_observed_at'], value['age_microseconds']
    if represented == 0:
        if latest is not None or age is not None:
            _fail('SOURCE_DATABASE_ERROR')
    else:
        instant = _micro_instant(latest)
        if (type(age) is not str or not re.fullmatch(r'(?:0|-?[1-9][0-9]{0,17})', age)
                or int(age) != clock-instant
                or (future > 0) != (instant > clock + binding['maximumFutureSkewSeconds'] * 1000000)):
            _fail('SOURCE_DATABASE_ERROR')
    return rows, nulls, cost, estimated_bytes, {
        'nonFiniteCount': nonfinite, 'unrepresentableCount': unrepresentable, 'futureCount': future,
        'sourceObservedAt': value['source_observed_at'], 'latestObservedAt': latest,
        'ageMicroseconds': age, 'freshnessHash': binding['freshnessHash']}


def _freshness_clock_envelope(metrics, observed_started, observed_finished):
    def wall(value):
        if type(value) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z', value):
            _fail('SOURCE_DATABASE_ERROR')
        return _micro_instant(value[:-1] + '000Z')
    started, finished = wall(observed_started), wall(observed_finished)
    source_at = _micro_instant(metrics['sourceObservedAt'])
    if (finished < started or source_at < started-CLOCK_ALLOWANCE_US
            or source_at > finished+CLOCK_ALLOWANCE_US):
        _fail('QUALITY_CLOCK_SKEW')


def validate_volume_binding(value):
    """Closed static threshold hash; thresholds do not control query resources."""
    _keys(value, VOLUME_KEYS)
    for key in ('minimumRows', 'maximumRows'):
        if type(value[key]) is not int or not 0 <= value[key] <= MAX_ROWS:
            _fail()
    if (value['minimumRows'] > value['maximumRows']
            or value['comparison'] != 'row-count-inclusive' or value['scope'] != 'entire-table'
            or type(value['volumeHash']) is not str
            or not re.fullmatch(r'[a-f0-9]{64}', value['volumeHash'])):
        _fail()
    detached = {key: value[key] for key in VOLUME_KEYS if key != 'volumeHash'}
    encoded = json.dumps(dict(detached, formatVersion=1, kind=VOLUME_KIND),
                         sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    expected = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(expected, value['volumeHash']):
        _fail()
    return dict(detached, volumeHash=expected)


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
          if kind == REFERENCE_KIND else ('formatVersion', 'kind', 'target', 'budget', 'range')
          if kind == RANGE_KIND else ('formatVersion', 'kind', 'target', 'budget', 'freshness')
          if kind == FRESHNESS_KIND else ('formatVersion', 'kind', 'target', 'budget', 'volume')
          if kind == VOLUME_KIND else ('formatVersion', 'kind', 'target', 'budget'))
    if type(execution['formatVersion']) is not int or execution['formatVersion'] != 1 or kind not in ('completeness', REFERENCE_KIND, UNIQUENESS_KIND, RANGE_KIND, FRESHNESS_KIND, VOLUME_KIND):
        _fail()
    if kind == REFERENCE_KIND:
        validate_reference_binding(execution['reference'])
    if kind == RANGE_KIND:
        validate_range_binding(execution['range'])
    if kind == FRESHNESS_KIND:
        validate_freshness_binding(execution['freshness'])
    if kind == VOLUME_KIND:
        validate_volume_binding(execution['volume'])
    target, budget = execution['target'], execution['budget']
    _keys(target, TABLE_TARGET_KEYS if kind == VOLUME_KIND else TARGET_KEYS)
    ceilings = UNIQUENESS_BUDGETS if kind == UNIQUENESS_KIND else BUDGETS
    _keys(budget, ceilings)
    for key in ('databaseOid', 'schemaOid', 'relationOid'):
        value = target[key]
        if type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,9}', value) or int(value) > 4294967295:
            _fail()
    if kind == VOLUME_KIND:
        if target['kind'] != 'table':
            _fail()
    else:
        _integer(target['attributeNumber'], 32767)
        _text(target['dataType'], 256)
    for key in ('schemaName', 'tableName') if kind == VOLUME_KIND else ('schemaName', 'tableName', 'columnName'):
        _text(target[key], 63, bytes_limit=True)
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


def _measure_volume(conn, target, budget, deadline_at):
    # This branch intentionally never loads column names/types/values. Table
    # authority and an exact source relation pin suffice for a whole-row count.
    conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
    relation = sql.Identifier(target['schemaName'], target['tableName'])
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
        n.nspname,c.relname,c.relkind,c.relispartition,c.relrowsecurity,c.relforcerowsecurity,
        EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS inherited,
        has_schema_privilege(n.oid,'USAGE') AS schema_allowed,has_table_privilege(c.oid,'SELECT') AS table_allowed,
        EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
          AND l.locktype='relation' AND l.relation=c.oid AND l.mode='AccessShareLock' AND l.granted) AS locked
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE c.oid=%s::oid""", (target['relationOid'],), budget, deadline_at).fetchone()
    if (not row or row['relation_oid'] != target['relationOid'] or row['schema_oid'] != target['schemaOid']
            or row['nspname'] != target['schemaName'] or row['relname'] != target['tableName']
            or row['locked'] is not True):
        _fail('QUALITY_TARGET_STALE')
    if row['schema_allowed'] is not True or row['table_allowed'] is not True:
        _fail('SOURCE_SCOPE_DENIED')
    if (row['relkind'] != 'r' or row['relispartition'] is not False or row['relrowsecurity'] is not False
            or row['relforcerowsecurity'] is not False or row['inherited'] is not False):
        _fail('QUALITY_TARGET_UNSUPPORTED')
    # Count+1 is bounded by the admitted execution resource budget, never by a
    # rule threshold. Six rows with authored maximum5 is a valid measurement.
    aggregate = sql.SQL('SELECT pg_catalog.count(*) AS row_count '
                        'FROM (SELECT 1 FROM ONLY {} LIMIT %s) AS bounded').format(relation)
    parameters = (budget['maximumRows'] + 1,)
    plan = _query(conn, sql.SQL('EXPLAIN (FORMAT JSON, ANALYZE FALSE, COSTS TRUE) ') + aggregate,
                  parameters, budget, deadline_at).fetchone()
    cost, estimated_bytes = _estimates(plan.get('QUERY PLAN') if type(plan) is dict else None, budget)
    counts = _query(conn, aggregate, parameters, budget, deadline_at).fetchone()
    if (type(counts) is not dict or set(counts) != {'row_count'} or type(counts['row_count']) is not int
            or not 0 <= counts['row_count'] <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    if counts['row_count'] > budget['maximumRows']:
        _fail('QUALITY_RESOURCE_LIMIT')
    return counts['row_count'], version, cost, estimated_bytes


def _measure(conn, target, budget, deadline_at, reference=None, *, uniqueness=False, range_binding=None, freshness=None):
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
    if freshness is not None:
        if row['type_oid'] != '1184':
            _fail('QUALITY_TARGET_UNSUPPORTED')
        rows, nulls, cost, estimated_bytes, metrics = _measure_freshness(conn, relation, target, budget, deadline_at, freshness)
        return rows, nulls, version, cost, estimated_bytes, metrics
    if uniqueness:
        if row['type_oid'] not in ('25', '1043'):
            _fail('QUALITY_TARGET_UNSUPPORTED')
        rows, nulls, cost, estimated_bytes, metrics = _measure_uniqueness(conn, relation, target, budget, deadline_at)
        return rows, nulls, version, cost, estimated_bytes, metrics
    if range_binding is not None:
        # Exact built-in integer OIDs exclude domains and every source-defined
        # cast/operator. Only bound parameters are cast to the fixed int8 type;
        # the pinned source column is never cast or interpolated as SQL text.
        if row['type_oid'] not in ('20', '21', '23'):
            _fail('QUALITY_TARGET_UNSUPPORTED')
        aggregate = sql.SQL(
            'SELECT count(*) AS row_count, count(*) FILTER (WHERE value IS NULL) AS null_count, '
            'count(*) FILTER (WHERE value OPERATOR(pg_catalog.<) %s::pg_catalog.int8) AS below_count, '
            'count(*) FILTER (WHERE value OPERATOR(pg_catalog.>) %s::pg_catalog.int8) AS above_count '
            'FROM (SELECT {} AS value FROM ONLY {} LIMIT %s) AS bounded').format(
                sql.Identifier(target['columnName']), relation)
        parameters = (range_binding['minimum'], range_binding['maximum'], budget['maximumRows'] + 1)
    elif reference is not None:
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
    expected_counts = ({'row_count', 'null_count', 'below_count', 'above_count'} if range_binding is not None
                       else {'row_count', 'null_count', 'invalid_count'} if reference is not None else {'row_count', 'null_count'})
    if (type(counts) is not dict or set(counts) != expected_counts
            or type(counts['row_count']) is not int or type(counts['null_count']) is not int
            or not 0 <= counts['null_count'] <= counts['row_count'] <= budget['maximumRows'] + 1):
        _fail('SOURCE_DATABASE_ERROR')
    if reference is not None and (type(counts['invalid_count']) is not int
            or not 0 <= counts['invalid_count'] <= counts['row_count'] - counts['null_count']):
        _fail('SOURCE_DATABASE_ERROR')
    if range_binding is not None and (type(counts['below_count']) is not int or type(counts['above_count']) is not int
            or counts['below_count'] < 0 or counts['above_count'] < 0
            or counts['below_count'] + counts['above_count'] > counts['row_count'] - counts['null_count']):
        _fail('SOURCE_DATABASE_ERROR')
    if counts['row_count'] > budget['maximumRows']:
        _fail('QUALITY_RESOURCE_LIMIT')
    result = (counts['row_count'], counts['null_count'], version, cost, estimated_bytes)
    if range_binding is not None:
        return result + ({'belowCount': counts['below_count'], 'aboveCount': counts['above_count'],
                          'rangeHash': range_binding['rangeHash']},)
    return result + (counts['invalid_count'],) if reference is not None else result


def execute(source, secret, tenant_id, execution):
    started, observed_started = time.monotonic(), _stamp()
    source, target, budget = validate_execution(source, execution)
    reference = validate_reference_binding(execution['reference']) if execution['kind'] == REFERENCE_KIND else None
    uniqueness = execution['kind'] == UNIQUENESS_KIND
    range_binding = validate_range_binding(execution['range']) if execution['kind'] == RANGE_KIND else None
    freshness = validate_freshness_binding(execution['freshness']) if execution['kind'] == FRESHNESS_KIND else None
    volume = validate_volume_binding(execution['volume']) if execution['kind'] == VOLUME_KIND else None
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
                    if volume is not None:
                        rows, version, cost, estimated_bytes = _measure_volume(conn, target, budget, deadline_at)
                    else:
                        measured = _measure(conn, target, budget, deadline_at, reference, uniqueness=uniqueness, range_binding=range_binding, freshness=freshness)
                        rows, nulls, version, cost, estimated_bytes = measured[:5]
            # Connection close (rollback) and CA cleanup are inside the original
            # wall deadline. No connection context manager can print DB details.
            _remaining(deadline_at)
            observed_finished = _stamp()
            if volume is not None:
                return {'formatVersion': 1, 'kind': VOLUME_KIND, 'strategy': 'exact-bounded-role-scope',
                        'rowCount': rows, 'volumeHash': volume['volumeHash'],
                        'observedStartedAt': observed_started, 'observedFinishedAt': observed_finished,
                        'elapsedMs': math.floor((time.monotonic() - started) * 1000),
                        'sourceVersion': version, 'adapterVersion': '1', 'queryTemplate': 'postgresql-volume-v1',
                        'estimatedCost': cost, 'estimatedBytes': estimated_bytes}
            if freshness is not None:
                _freshness_clock_envelope(measured[5], observed_started, observed_finished)
                _remaining(deadline_at)
            result = {'formatVersion': 1, 'kind': FRESHNESS_KIND if freshness is not None else RANGE_KIND if range_binding is not None else UNIQUENESS_KIND if uniqueness else REFERENCE_KIND if reference is not None else 'completeness', 'strategy': 'exact-bounded-role-scope',
                    'rowCount': rows, 'nullCount': nulls, 'observedStartedAt': observed_started,
                    'observedFinishedAt': observed_finished, 'elapsedMs': math.floor((time.monotonic() - started) * 1000),
                    'sourceVersion': version, 'adapterVersion': '1',
                    'queryTemplate': 'postgresql-freshness-v1' if freshness is not None else 'postgresql-range-v1' if range_binding is not None else 'postgresql-uniqueness-v1' if uniqueness else 'postgresql-reference-allowed-values-v1' if reference is not None else 'postgresql-completeness-v1',
                    'estimatedCost': cost, 'estimatedBytes': estimated_bytes}
            if reference is not None:
                result.update(invalidCount=measured[5], referenceBindingHash=reference['bindingHash'])
            if uniqueness or range_binding is not None or freshness is not None:
                result.update(measured[5])
            return result
    except TargetPolicyError as error:
        raise ScanFailure(error.code) from None
    except psycopg.Error as error:
        # LOCK rejects non-table relation kinds before catalog inspection. Keep
        # that refusal specific to the new table-only family; old mappings stay.
        if volume is not None and error.sqlstate == '42809':
            raise ScanFailure('QUALITY_TARGET_UNSUPPORTED') from None
        if error.sqlstate in ('42P01', '42703', '3F000'):
            raise ScanFailure('QUALITY_TARGET_STALE') from None
        if error.sqlstate == '42501':
            raise ScanFailure('SOURCE_SCOPE_DENIED') from None
        if error.sqlstate in ('57014', '55P03'):
            raise ScanFailure('QUALITY_RESOURCE_LIMIT') from None
        raise ScanFailure('SOURCE_DATABASE_ERROR') from None
