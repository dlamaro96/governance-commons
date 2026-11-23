# SPDX-License-Identifier: Apache-2.0
"""Host controls for snapshot transport and admission; no database execution.

Load the actual sibling snapshot function without the runtime gate's import
chain. SQL results are synthetic transport responses, not PostgreSQL evidence.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).with_name('runtime-test-authority-read-upgrade.py')
TREE = ast.parse(SOURCE.read_text(), filename=str(SOURCE))
FUNCTIONS = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == 'snapshot']
if len(FUNCTIONS) != 1:
    raise RuntimeError('Exactly one snapshot implementation required')


def require(value, message):
    if not value:
        raise RuntimeError(message)


namespace = {'json': json, 're': re, 'require': require}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(SOURCE), 'exec'), namespace)
snapshot = namespace['snapshot']

# Frozen original query: the candidate may add an identifying output field,
# but must not change any part of the row representation or digest expression.
ORIGINAL_SQL = "WITH rows AS MATERIALIZED(SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) value FROM {table} r) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM rows;"


def tables(count):
    return ['public.table_' + chr(97 + index // 26) + chr(97 + index % 26) for index in range(count)]


def row(table, count=0):
    return {'table': table, 'rows': count, 'sha256': hashlib.sha256(table.encode()).hexdigest()}


class Transport:
    def __init__(self, response=None):
        self.calls = []
        self.response = response

    def sql(self, statement):
        self.calls.append(statement)
        if self.response is not None:
            return self.response(statement, len(self.calls))
        names = re.findall(r"jsonb_build_object\('table','([^']+)'", statement)
        return '\n'.join(json.dumps(row(name, index)) for index, name in enumerate(names))


class SnapshotBatchingControls(unittest.TestCase):
    def rejected_output(self, output, requested=None):
        transport = Transport(lambda statement, call: output)
        with self.assertRaises(RuntimeError):
            snapshot(transport, requested or ['public.assets'])
        self.assertEqual(len(transport.calls), 1)

    def test_all_three_namespaces_keep_original_return_shape(self):
        requested = ['public.assets', 'gc_authn.sessions', 'gc_authority.tenant_heads']
        original = list(requested)
        result = snapshot(Transport(), requested)
        self.assertEqual(list(result), requested)
        self.assertEqual(result, {name: {'rows': index, 'sha256': row(name)['sha256']}
                                  for index, name in enumerate(requested)})
        self.assertEqual(requested, original)

    def test_exact_original_digest_query_only_adds_table_identity(self):
        requested = ['public.assets', 'gc_authn.sessions', 'gc_authority.tenant_heads']
        transport = Transport()
        snapshot(transport, requested)
        lines = transport.calls[0].splitlines()
        self.assertEqual(lines[0], 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;')
        self.assertEqual(lines[-1], 'COMMIT;')
        self.assertEqual(len(lines), len(requested) + 2)
        for name, actual in zip(requested, lines[1:-1]):
            self.assertEqual(actual.replace("'table','" + name + "',", '', 1), ORIGINAL_SQL.format(table=name))

    def test_transport_batches_are_at_most_sixteen_complete_tables(self):
        for count, sizes in [(1, [1]), (16, [16]), (17, [16, 1]), (32, [16, 16]), (33, [16, 16, 1]), (512, [16] * 32)]:
            with self.subTest(count=count):
                requested = tables(count)
                transport = Transport()
                result = snapshot(transport, requested)
                self.assertEqual(list(result), requested)
                self.assertEqual([len(call.splitlines()) - 2 for call in transport.calls], sizes)
                observed = []
                for call in transport.calls:
                    self.assertTrue(call.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'))
                    self.assertTrue(call.endswith('\nCOMMIT;'))
                    observed.extend(re.findall(r"jsonb_build_object\('table','([^']+)'", call))
                self.assertEqual(observed, requested)

    def test_empty_inventory_keeps_empty_result_without_sql(self):
        transport = Transport()
        self.assertEqual(snapshot(transport, []), {})
        self.assertEqual(transport.calls, [])

    def test_non_list_inventory_refused_before_sql(self):
        for requested in (None, 'public.assets', ('public.assets',), {'public.assets'}, iter(['public.assets'])):
            with self.subTest(kind=type(requested).__name__):
                transport = Transport()
                with self.assertRaises(RuntimeError):
                    snapshot(transport, requested)
                self.assertEqual(transport.calls, [])

    def test_inventory_over_512_refused_before_sql(self):
        transport = Transport()
        with self.assertRaises(RuntimeError):
            snapshot(transport, tables(513))
        self.assertEqual(transport.calls, [])

    def test_duplicate_requested_table_refused_before_sql(self):
        transport = Transport()
        with self.assertRaises(RuntimeError):
            snapshot(transport, tables(16) + [tables(16)[0]])
        self.assertEqual(transport.calls, [])

    def test_all_table_identifiers_admitted_before_first_batch(self):
        invalid = [None, True, 3, [], {}, 'pg_catalog.pg_class', 'public.assets;SELECT 1',
                   'public.assets\n', 'public.Assets', 'assets', 'public.assets.extra',
                   'public."assets"', 'public.asset_1', 'public.']
        for name in invalid:
            with self.subTest(name=repr(name)):
                transport = Transport()
                with self.assertRaises(RuntimeError):
                    snapshot(transport, tables(16) + [name])
                self.assertEqual(transport.calls, [])

    def test_missing_result_is_refused(self):
        self.rejected_output('', ['public.assets'])
        self.rejected_output(json.dumps(row('public.assets')), ['public.assets', 'public.jobs'])

    def test_extra_result_is_refused(self):
        self.rejected_output(json.dumps(row('public.assets')) + '\n' + json.dumps(row('public.jobs')))

    def test_duplicate_result_identity_is_refused(self):
        output = '\n'.join([json.dumps(row('public.assets'))] * 2)
        self.rejected_output(output, ['public.assets', 'public.jobs'])

    def test_wrong_or_reordered_result_identity_is_refused(self):
        self.rejected_output(json.dumps(row('public.jobs')))
        self.rejected_output('\n'.join(json.dumps(row(name)) for name in ['public.jobs', 'public.assets']),
                             ['public.assets', 'public.jobs'])

    def test_non_string_table_identity_is_refused(self):
        for identity in (None, True, 1, ['public.assets'], {'name': 'public.assets'}):
            value = row('public.assets')
            value['table'] = identity
            self.rejected_output(json.dumps(value))

    def test_malformed_json_and_non_objects_are_refused(self):
        for output in ('{', 'null', 'true', '1', '"row"', '[]', '[{}]', '{}{}', '   '):
            with self.subTest(output=output):
                self.rejected_output(output)

    def test_duplicate_json_keys_are_refused_even_when_values_match(self):
        valid = row('public.assets')
        for key in ('table', 'rows', 'sha256'):
            output = json.dumps(valid)[:-1] + ',' + json.dumps(key) + ':' + json.dumps(valid[key]) + '}'
            with self.subTest(key=key):
                self.rejected_output(output)

    def test_missing_and_extra_fields_are_refused(self):
        valid = row('public.assets')
        for key in valid:
            value = dict(valid)
            del value[key]
            self.rejected_output(json.dumps(value))
        self.rejected_output(json.dumps({**valid, 'ignored': None}))

    def test_rows_count_requires_nonnegative_integer_not_bool(self):
        for count in (-1, 0.0, 1.5, True, False, None, '1', [], {}, float('nan'), float('inf')):
            value = row('public.assets')
            value['rows'] = count
            with self.subTest(count=repr(count)):
                self.rejected_output(json.dumps(value))

    def test_zero_and_large_integer_counts_and_digest_pass_through(self):
        for count in (0, 1, 2**63 - 1):
            value = row('public.assets', count)
            value['sha256'] = 'a' * 64
            result = snapshot(Transport(lambda statement, call: json.dumps(value)), ['public.assets'])
            self.assertEqual(result, {'public.assets': {'rows': count, 'sha256': 'a' * 64}})

    def test_digest_requires_exact_lowercase_sha256_shape(self):
        for digest in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 64 + '\n', None, True, 0, [], {}):
            value = row('public.assets')
            value['sha256'] = digest
            with self.subTest(digest=repr(digest)):
                self.rejected_output(json.dumps(value))

    def test_extra_blank_lines_and_command_tags_are_refused(self):
        valid = json.dumps(row('public.assets'))
        for output in ('\n' + valid, valid + '\n\n', 'BEGIN\n' + valid, valid + '\nCOMMIT'):
            self.rejected_output(output)

    def test_first_batch_transport_failure_propagates(self):
        failure = RuntimeError('Transport refused')
        def response(statement, call):
            raise failure
        transport = Transport(response)
        with self.assertRaises(RuntimeError) as raised:
            snapshot(transport, tables(17))
        self.assertIs(raised.exception, failure)
        self.assertEqual(len(transport.calls), 1)

    def test_later_batch_transport_failure_never_returns_successful_prefix(self):
        failure = RuntimeError('Later statement refused after earlier SQL output')
        def response(statement, call):
            if call == 2:
                raise failure
            return '\n'.join(json.dumps(row(name)) for name in tables(16))
        transport = Transport(response)
        with self.assertRaises(RuntimeError) as raised:
            snapshot(transport, tables(33))
        self.assertIs(raised.exception, failure)
        self.assertEqual(len(transport.calls), 2)

    def test_later_batch_malformed_result_refuses_and_stops(self):
        def response(statement, call):
            if call == 2:
                return json.dumps(row('public.unrequested'))
            return '\n'.join(json.dumps(row(name)) for name in tables(16))
        transport = Transport(response)
        with self.assertRaises(RuntimeError):
            snapshot(transport, tables(33))
        self.assertEqual(len(transport.calls), 2)


if __name__ == '__main__':
    unittest.main()
