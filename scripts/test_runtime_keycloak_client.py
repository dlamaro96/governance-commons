#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host controls for explicit local client registration; no IdP or Docker access."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_keycloak_client_controls', ROOT/'scripts/runtime-keycloak-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
PASSWORD = 'synthetic-private-admin-password'
TOKEN = 'synthetic-private-admin-token'
CLIENT_PATH = '/admin/realms/governance/clients?clientId=governance-protected-web'


class LocalClientTransportTests(unittest.TestCase):
    def request_with_response(self, raw, *args, **kwargs):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = raw
        opener = Mock()
        opener.open.return_value = response
        with patch.object(client.urllib.request, 'build_opener', return_value=opener) as build:
            result = client.request(*args, **kwargs)
        return result, build, opener, response

    def test_admin_credentials_use_only_fixed_local_origin_with_environment_proxies_disabled(self):
        with patch.dict(os.environ, {'HTTP_PROXY':'http://untrusted.invalid:8080', 'HTTPS_PROXY':'http://untrusted.invalid:8080',
                                     'ALL_PROXY':'http://untrusted.invalid:8080', 'http_proxy':'http://untrusted.invalid:8080'}):
            result, build, opener, response = self.request_with_response(
                b'{"access_token":"synthetic-token"}', '/realms/master/protocol/openid-connect/token',
                'POST', {'username':'local-admin', 'password':PASSWORD}, form=True)
        self.assertEqual(result, {'access_token':'synthetic-token'})
        handlers = build.call_args.args
        self.assertEqual(len(handlers), 2)
        self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], client.NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'http://localhost:4311/realms/master/protocol/openid-connect/token')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.get_header('Content-type'), 'application/x-www-form-urlencoded')
        self.assertEqual(urllib.parse.parse_qs(request.data.decode()), {'username':['local-admin'], 'password':[PASSWORD]})
        self.assertIsNone(request.get_header('Authorization'))
        self.assertEqual(opener.open.call_args.kwargs, {'timeout':15})
        response.read.assert_called_once_with(65537)

    def test_authenticated_client_query_has_bearer_header_and_no_credentials_in_url(self):
        result, _, opener, _ = self.request_with_response(b'[]', CLIENT_PATH, token=TOKEN)
        self.assertEqual(result, [])
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'http://localhost:4311'+CLIENT_PATH)
        self.assertEqual(request.get_header('Authorization'), 'Bearer '+TOKEN)
        self.assertIsNone(request.data)
        self.assertNotIn(TOKEN, request.full_url)
        self.assertNotIn(PASSWORD, request.full_url)

    def test_redirect_handler_refuses_same_origin_and_external_redirects(self):
        request = urllib.request.Request('http://localhost:4311/admin/realms/governance/clients',
                                         data=b'synthetic-private-body', headers={'Authorization':'Bearer '+TOKEN})
        for status in (301, 302, 303, 307, 308):
            for destination in ('http://localhost:4311/other', 'https://untrusted.invalid/credentials'):
                with self.subTest(status=status, destination=destination):
                    with self.assertRaisesRegex(ValueError, 'Redirect refused'):
                        client.NoRedirect().redirect_request(request, None, status, 'Redirect', {}, destination)

    def test_absolute_urls_and_header_injection_are_rejected_before_transport(self):
        for path in ('https://untrusted.invalid/', 'http://localhost:4311/', 'admin/clients', '/admin\r\nAuthorization: injected'):
            with self.subTest(path=path), patch.object(client.urllib.request, 'build_opener') as build:
                with self.assertRaises(ValueError): client.request(path, token=TOKEN)
                build.assert_not_called()

    def test_response_size_and_json_must_be_valid(self):
        for raw in (b'x'*65537, b'{', b'\xff'):
            with self.subTest(size=len(raw)):
                with self.assertRaises((ValueError, UnicodeError)):
                    self.request_with_response(raw, CLIENT_PATH, token=TOKEN)
        result, _, _, _ = self.request_with_response(b'', '/admin/realms/governance/clients', 'POST', client.CLIENT, TOKEN)
        self.assertIsNone(result)


class LocalClientRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gc-local-client-controls-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        local = self.root/'.local';local.mkdir(mode=0o700)
        self.bootstrap = local/'bootstrap.json'
        self.bootstrap.write_text(json.dumps({'KEYCLOAK_ADMIN_PASSWORD':PASSWORD}))
        self.bootstrap.chmod(0o600)
        self.root_patch = patch.object(client, 'ROOT', self.root)
        self.root_patch.start();self.addCleanup(self.root_patch.stop)
        self.gates = SimpleNamespace(require_local=Mock(), require_bootstrap=Mock())
        self.module_patch = patch.dict(sys.modules, {'runtime':self.gates})
        self.module_patch.start();self.addCleanup(self.module_patch.stop)

    def run_main(self, responses):
        output = io.StringIO()
        with patch.object(client, 'request', side_effect=responses) as request, contextlib.redirect_stdout(output):
            client.main()
        self.assertNotIn(PASSWORD, output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())
        self.gates.require_local.assert_called_once_with()
        self.gates.require_bootstrap.assert_called_once_with()
        return request, output.getvalue()

    def test_matching_existing_client_is_verified_without_mutation(self):
        row = {**copy.deepcopy(client.CLIENT), 'id':'synthetic-keycloak-id', 'protocol':'openid-connect'}
        row['attributes']['keycloak-generated-default'] = 'preserved'
        request, output = self.run_main([{'access_token':TOKEN}, [row]])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].args[0:2], ('/realms/master/protocol/openid-connect/token', 'POST'))
        self.assertEqual(request.call_args_list[0].args[2]['password'], PASSWORD)
        self.assertEqual(request.call_args_list[1].args, (CLIENT_PATH,))
        self.assertEqual(request.call_args_list[1].kwargs, {'token':TOKEN})
        self.assertIn('verified', output)

    def test_absent_client_is_created_once_then_read_back_before_success(self):
        request, output = self.run_main([{'access_token':TOKEN}, [], None, [copy.deepcopy(client.CLIENT)]])
        self.assertEqual(request.call_count, 4)
        create = request.call_args_list[2]
        self.assertEqual(create.args, ('/admin/realms/governance/clients', 'POST', client.CLIENT, TOKEN))
        self.assertEqual(request.call_args_list[3].args, (CLIENT_PATH,))
        self.assertIn('verified', output)

    def test_ambiguous_or_changed_existing_client_is_never_updated(self):
        wrong = {**copy.deepcopy(client.CLIENT), 'redirectUris':['https://untrusted.invalid/callback']}
        for rows in ([wrong], [{**client.CLIENT, 'enabled':1}], [{**client.CLIENT, 'protocol':'saml'}], [client.CLIENT, client.CLIENT], {}, None):
            with self.subTest(rows=type(rows).__name__), patch.object(client, 'request', side_effect=[{'access_token':TOKEN}, rows]) as request:
                with self.assertRaises(ValueError): client.main()
                self.assertEqual(request.call_count, 2)
                self.assertEqual(request.call_args_list[-1].args, (CLIENT_PATH,))

    def test_creation_requires_exact_readback_and_does_not_repair_conflicts(self):
        wrong = {**copy.deepcopy(client.CLIENT), 'directAccessGrantsEnabled':True}
        for rows in ([], [wrong], [client.CLIENT, client.CLIENT]):
            with self.subTest(rows=len(rows)), patch.object(client, 'request', side_effect=[{'access_token':TOKEN}, [], None, rows]) as request:
                with self.assertRaises(ValueError): client.main()
                self.assertEqual(request.call_count, 4)
                self.assertEqual(sum(call.args[1:2]==('POST',) and call.args[0]=='/admin/realms/governance/clients'
                                     for call in request.call_args_list), 1)

    def test_invalid_admin_token_never_queries_or_changes_clients(self):
        for response in (None, {}, {'access_token':''}, {'access_token':True}, {'access_token':'x'*32769}):
            with self.subTest(response=type(response).__name__), patch.object(client, 'request', return_value=response) as request:
                with self.assertRaises(ValueError): client.main()
                self.assertEqual(request.call_count, 1)

    def test_bootstrap_symlink_public_permissions_and_oversize_are_rejected_before_network(self):
        external = self.root/'operator-bootstrap.json'
        external.write_bytes(self.bootstrap.read_bytes());external.chmod(0o600)
        original = self.bootstrap.read_bytes()
        for kind in ('symlink', 'public', 'oversize', 'directory', 'fifo'):
            with self.subTest(kind=kind):
                self.bootstrap.unlink()
                if kind=='symlink':self.bootstrap.symlink_to(external)
                elif kind=='directory':self.bootstrap.mkdir()
                elif kind=='fifo':os.mkfifo(self.bootstrap, 0o600)
                else:
                    self.bootstrap.write_bytes(b'x'*65537 if kind=='oversize' else original)
                    self.bootstrap.chmod(0o644 if kind=='public' else 0o600)
                with patch.object(client, 'request') as request:
                    with self.assertRaises((OSError, ValueError)): client.main()
                    request.assert_not_called()
                self.assertEqual(external.read_bytes(), original)
                self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o600)
                if kind=='directory':self.bootstrap.rmdir()
                else:self.bootstrap.unlink()
                self.bootstrap.write_bytes(original);self.bootstrap.chmod(0o600)

    def test_local_configuration_gates_run_before_secret_read_or_network(self):
        self.bootstrap.unlink()
        self.gates.require_local.side_effect = SystemExit('synthetic local guard')
        with patch.object(client, 'request') as request:
            with self.assertRaisesRegex(SystemExit, 'synthetic local guard'): client.main()
            request.assert_not_called()
        self.gates.require_bootstrap.assert_called_once_with()
        self.gates.require_local.assert_called_once_with()


class LocalClientMatchTests(unittest.TestCase):
    def test_every_registration_field_and_security_flow_is_bound(self):
        self.assertTrue(client.matches(copy.deepcopy(client.CLIENT)))
        for key in client.CLIENT:
            with self.subTest(missing=key):
                row = copy.deepcopy(client.CLIENT);del row[key]
                self.assertFalse(client.matches(row))
        changes = {'clientId':'another-client', 'name':'another-name', 'enabled':False, 'publicClient':False,
                   'standardFlowEnabled':False, 'directAccessGrantsEnabled':True, 'serviceAccountsEnabled':True,
                   'redirectUris':['http://127.0.0.1:4310/authn/callback', 'https://untrusted.invalid/callback'],
                   'webOrigins':['*'], 'attributes':{'pkce.code.challenge.method':'plain'},
                   'implicitFlowEnabled':True, 'bearerOnly':True, 'consentRequired':True}
        for key, value in changes.items():
            with self.subTest(changed=key):
                self.assertFalse(client.matches({**copy.deepcopy(client.CLIENT), key:value}))
        for row in (None, [], 'invalid'):
            self.assertFalse(client.matches(row))

    def test_boolean_fields_do_not_accept_numeric_or_string_coercions(self):
        for key, expected in client.CLIENT.items():
            if type(expected) is not bool:continue
            for value in (int(expected), float(expected), str(expected).lower(), None):
                with self.subTest(field=key, value=value):
                    self.assertFalse(client.matches({**copy.deepcopy(client.CLIENT), key:value}))
        for key in ('implicitFlowEnabled', 'bearerOnly', 'consentRequired'):
            for value in (0, 0.0, 'false', None):
                with self.subTest(field=key, value=value):
                    self.assertFalse(client.matches({**copy.deepcopy(client.CLIENT), key:value}))

    def test_non_oidc_or_missing_protocol_is_not_admitted(self):
        for protocol in ('saml', '', None, True):
            with self.subTest(protocol=protocol):
                self.assertFalse(client.matches({**copy.deepcopy(client.CLIENT), 'protocol':protocol}))
        row=copy.deepcopy(client.CLIENT);del row['protocol']
        self.assertFalse(client.matches(row))

    def test_registration_binds_application_origin_separately_from_identity_provider(self):
        self.assertEqual(client.CLIENT['redirectUris'], ['http://127.0.0.1:4310/authn/callback'])
        self.assertEqual(client.CLIENT['webOrigins'], ['http://127.0.0.1:4310'])
        self.assertEqual(client.ORIGIN, 'http://localhost:4311')


if __name__ == '__main__': unittest.main()
