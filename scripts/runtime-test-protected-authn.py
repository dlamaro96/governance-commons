#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned, fresh PostgreSQL/Keycloak/edge qualification; cached images only.

No shared-core fallback, build, pull, credential logging, bearer artifacts or
historical screenshot overwrite. Native SQL tests and real browser journeys are
reported separately. A failed run is preserved and never automatically retried.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import time
import urllib.request
import urllib.parse
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local/evidence'
REPORT = LOCAL / 'protected-authn.json'
COMPOSE = ROOT / 'deploy/protected-authn/compose.yaml'
DATABASE = 'gc_protected_qualification'
OWNER = 'gc_owner'
ORIGIN = 'http://localhost:4314'
ISSUER = 'http://localhost:4315/realms/governance'
APP_IMAGE = 'sha256:b82f4d0b692cf9c7dbf338068eec5cded03909e76f1ffbb89f4187edc9d1d6b1'
MIB, GIB = 1024**2, 1024**3

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

base = load(ROOT / 'scripts/runtime-test-authority-authn-foundation.py', 'protected_bounded_commands')
require, sha, literal = base.require, base.sha, base.literal


# The runner and independent publisher share the exact admitted inventory.
sys.path.insert(0, str(ROOT / 'policies'))
publication = load(ROOT / 'policies/protected_authn_evidence.py', 'protected_publication_inventory')
image_tools = load(ROOT / 'scripts/protected_authn_image.py', 'protected_immutable_image')

def sources():
    return publication.source_inventory(ROOT)

def binary_sha(path):
    require(path.is_file() and path.stat().st_size <= 256*MIB, 'Bounded existing tool binary required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            digest.update(block)
    return digest.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Isolated readback redirect refused before forwarding credentials')


class Harness(base.Harness):
    def __init__(self):
        os.umask(0o077)
        LOCAL.mkdir(parents=True, exist_ok=True)
        self.id = 'gc-protected-' + uuid.uuid4().hex[:12]
        self.folder = LOCAL / ('protected-authn-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + self.id[-12:])
        self.folder.mkdir(mode=0o700)
        self.phase, self.serial, self.owned, self.created = 'admission', 0, [], False
        self.private_ready = False
        self.app_image, self.evidence_mode, self.compose_override = APP_IMAGE, 'mounted-source', None
        self.deadline, self.cleanup_deadline = time.monotonic() + 1600, None
        self.output_bytes, self.resources_before, self.private_values = 0, None, []
        self.secret_path = self.folder / 'private-config.json'
        self.compose_env = self.folder / 'compose.env'
        self.started = datetime.now(timezone.utc).isoformat()
        self.report = {'schema_version': 1, 'result': 'RUNNING', 'started_at': self.started,
                       'command': './dev test --suite protected-authn', 'profile': 'isolated-protected-authn',
                       'checks': [], 'containerImages': [], 'testLogs': {}, 'limitations': ['Local HTTP and isolated fresh services only; no production TLS, shared-core ingress, content authority or release qualification.',
                         'Controlled signed-token HTTP probes are distinct from the two actual Keycloak browser journeys.',
                         'Rendered screenshots require explicit subsequent human/model inspection; automated browser assertions do not imply visual inspection.']}
        if REPORT.exists():
            (self.folder / 'previous-report.json').write_bytes(REPORT.read_bytes())
        self.save()

    def admission(self):
        super().admission()
        require(shutil.disk_usage(ROOT).free >= 2*GIB, 'Protected profile host free space below2GiB floor')

    def scrub_browser_artifacts(self):
        folder = self.folder / 'browser'
        if not folder.exists():
            return
        def clean(text):
            for value in self.private_values:
                text = text.replace(value, '[private value omitted]')
            text = re.sub(r'https?://[^\s<>"\']+', '[URL omitted]', text)
            return re.sub(r'[A-Za-z0-9_-]{32,}', '[opaque value omitted]', text)
        for path in folder.rglob('*'):
            if path.is_file() and (path.name == 'results.json' or path.suffix in ('.md', '.txt')):
                if path.suffix == '.json':
                    def walk(value):
                        if isinstance(value, str): return clean(value)
                        if isinstance(value, list): return [walk(x) for x in value]
                        if isinstance(value, dict): return {k: walk(v) for k, v in value.items()}
                        return value
                    path.write_text(json.dumps(walk(json.loads(path.read_text())), indent=2)+'\n')
                else:
                    path.write_text(clean(path.read_text()))

    def save(self, final=False):
        if not final:
            self.admission()
        data = (json.dumps(self.report, indent=2) + '\n').encode()
        (self.folder / 'report.json').write_bytes(data)
        REPORT.write_bytes(data)
        REPORT.chmod(0o600)

    def compose(self, *args, **kwargs):
        files = ['-f', str(COMPOSE)]
        if self.compose_override is not None:
            files += ['-f', str(self.compose_override)]
        return self.docker('compose', '--project-name', self.id, '--env-file', str(self.compose_env), *files, *args, **kwargs)

    def inventory(self):
        result = super().inventory()
        result['networks'] = self.docker('network', 'ls', '--format', '{{.ID}} {{.Name}}', sensitive=True).stdout.splitlines()
        return {key: sorted(value) for key, value in result.items()}

    def sql_result(self, body, role='postgres', database=DATABASE, allow_failure=False):
        require(bool(re.fullmatch(r'[a-f0-9]{64}', self.pg_container)), 'Exact owned database ID required')
        label = self.docker('inspect', '--format', '{{index .Config.Labels "com.docker.compose.project"}}', self.pg_container, sensitive=True).stdout.strip()
        require(label == self.id, 'Database observer escaped owned Compose project')
        return self.docker('exec', '-i', self.pg_container, 'psql', '-X', '-qAt', '--set', 'ON_ERROR_STOP=1', '-U', role, '-d', database,
                           input=body, sensitive=True, allow_failure=allow_failure)

    def record_container(self, role, name, *, compose=False):
        require(role in publication.ROLES, 'Exact application evidence role required')
        template = '{"id":{{json .Id}},"image":{{json .Image}},"mounts":{{json .Mounts}},"labels":{{json .Config.Labels}}}'
        observed = json.loads(self.docker('inspect', '--format', template, name, sensitive=True).stdout)
        labels = observed['labels']
        if compose:
            require(labels.get('com.docker.compose.project') == self.id and labels.get('com.docker.compose.service') == role,
                'Application image readback escaped owned Compose service')
        else:
            require(labels.get('org.governance-commons.protected-run') == self.id, 'Helper image readback escaped owned container')
        require(re.fullmatch('[a-f0-9]{64}', observed['id']) and observed['image'] == self.app_image,
            'Application container differs from exact selected image')
        mounts = observed['mounts']
        require(type(mounts) is list and len(mounts) <= 32, 'Unexpected application mount count')
        if self.evidence_mode == 'immutable-image':
            private_mounts = []
            for mount in mounts:
                if mount['Type'] == 'tmpfs':
                    require(mount['Destination'] == '/tmp', 'Unexpected immutable tmpfs destination')
                else:
                    require(role in ('owner-tool', 'helper') and mount['Type'] == 'volume'
                        and mount['Name'] == self.id + '_qualification-private'
                        and mount['Destination'] == '/run/authn-private'
                        and mount['RW'] is (role == 'owner-tool'), 'Immutable application has an unexpected mount')
                    private_mounts.append(mount)
            require(len(private_mounts) == (1 if role in ('owner-tool', 'helper') else 0), 'Required private volume missing')
        row = {'role': role, 'containerId': observed['id'], 'imageId': observed['image']}
        prior = [r for r in self.report['containerImages'] if r['containerId'] == row['containerId']]
        require(not prior or prior == [row], 'Container identity changed evidence role')
        if not prior:
            self.report['containerImages'].append(row)
        safe = {'role': role, 'id': observed['id'], 'image': observed['image'], 'mounts': [
            {k: m[k] for k in ('Type', 'Destination', 'RW', 'Name') if k in m} for m in mounts]}
        data = ('phase=image-readback\nexit=0\n' + json.dumps(safe) + '\n').encode()
        require(len(data) <= 64*1024, 'Bounded image readback exceeded64KiB')
        self.admission()
        (self.folder / f'{self.serial:03d}-image-readback.log').write_bytes(data)
        self.output_bytes += len(data)
        return observed['id']

    def remove_temporary(self, name):
        previous = self.cleanup_deadline
        self.cleanup_deadline = time.monotonic() + 20
        try:
            observed = self.docker('inspect', '--format', '{{index .Config.Labels "org.governance-commons.protected-run"}}', name,
                sensitive=True, allow_failure=True, cleanup=True, timeout=5)
            if observed.returncode == 0:
                require(observed.stdout.strip() == self.id, 'Refusing non-owned temporary cleanup')
                self.docker('rm', '-f', name, sensitive=True, cleanup=True, timeout=15)
        finally:
            self.cleanup_deadline = previous

    def start_attached(self, name, *, input=None, sensitive=False, allow_failure=False, timeout=120):
        result = self.docker('start', '-a', '-i', name, input=input, sensitive=sensitive, allow_failure=True, timeout=timeout)
        ended = json.loads(self.docker('inspect', '--format', '{"running":{{.State.Running}},"exitCode":{{.State.ExitCode}}}', name, sensitive=True).stdout)
        require(ended['running'] is False and type(ended['exitCode']) is int and 0 <= ended['exitCode'] <= 255, 'Exact terminated container exit status required')
        result.returncode = ended['exitCode'] if result.returncode == 0 else result.returncode
        require(result.returncode == 0 or allow_failure, 'Qualification container failed; retained bounded diagnostic')
        return result

    def owner_tool(self):
        self.compose('--profile', 'tools', 'create', '--no-build', '--pull', 'never', '--no-recreate', 'owner-tool', timeout=30)
        name = self.id + '-owner-tool-1'
        self.record_container('owner-tool', name, compose=True)
        return self.start_attached(name, timeout=180)

    def helper(self, args, timeout=120, sensitive=False, input=None, allow_failure=False):
        require(self.private_ready, 'Owned private volume must be admitted before native helpers')
        name = self.id + '-probe-' + str(self.serial)
        self.owned.append(name)
        command = ['create', '-i', '--pull', 'never', '--name', name, '--label', 'org.governance-commons.protected-run=' + self.id,
                   '--network', self.id + '_default', '--memory', '384m', '--memory-swap', '384m', '--cpus', '1', '--pids-limit', '128',
                   '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777', '--workdir', '/app',
                   '--env-file', str(self.folder / 'helper.env'), '--volume', f'{self.id}_qualification-private:/run/authn-private:ro']
        if self.evidence_mode == 'mounted-source':
            for folder in ('apps/login-broker', 'apps/session-api', 'apps/authn-edge', 'apps/api/src', 'packages/authn', 'packages/authority/src',
                           'packages/db/src', 'packages/db/migrations', 'packages/domain/src', 'packages/authz/src', 'tests/fixtures', 'tests/qualification'):
                command += ['--volume', f'{ROOT / folder}:/app/{folder}:ro']
            for file in ('scripts/authentication-install.ts', 'docs/execution/authentication-legacy-function-census.json', 'package.json', 'tsconfig.json'):
                command += ['--volume', f'{ROOT / file}:/app/{file}:ro']
        try:
            self.docker(*command, self.app_image, *args, timeout=30, sensitive=True)
            self.record_container('helper', name)
            return self.start_attached(name, timeout=timeout, sensitive=sensitive, input=input, allow_failure=allow_failure)
        finally:
            self.remove_temporary(name)

    def js(self, body, **kwargs):
        prefix = "import fs from 'node:fs';const config=JSON.parse(fs.readFileSync('/run/authn-private/config.json','utf8'));"
        return self.helper(['node', '--import', 'tsx', '--input-type=module'], input=prefix + body, **kwargs)

    def private_reader(self, mode, *, cleanup=False):
        require(mode in ('verify', 'plan'), 'Fixed private-reader operation required')
        name = self.id + '-private-reader-' + str(self.serial)
        self.owned.append(name)
        script = """import fs from 'node:fs';import {createHash} from 'node:crypto';
const mode=process.argv[1],root='/run/authn-private';
const fail=()=>{throw Error('PRIVATE_STORAGE_REJECTED');};
const directory=path=>{const s=fs.lstatSync(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700)fail();};
const read=path=>{const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.size>65536)fail();const b=Buffer.alloc(65537);let n=0,k;while((k=fs.readSync(fd,b,n,b.length-n,null))>0){n+=k;if(n>65536)fail();}return b.subarray(0,n);}finally{fs.closeSync(fd);}};
try{directory(root);directory(root+'/batch');if(mode==='verify'){const b=read(root+'/config.json');process.stdout.write(JSON.stringify({uid:process.getuid(),gid:process.getgid(),configMode:384,batchMode:448,configSha256:createHash('sha256').update(b).digest('hex')}));}else{try{process.stdout.write(read(root+'/batch/plan.json'));}catch(e){if(e.code!=='ENOENT')throw e;}}}catch{process.stderr.write('PRIVATE_STORAGE_REJECTED\\n');process.exitCode=1;}
"""
        return self.docker('run', '--rm', '--pull', 'never', '--name', name,
            '--label', 'org.governance-commons.protected-run='+self.id, '--network', 'none',
            '--memory', '128m', '--memory-swap', '128m', '--pids-limit', '32', '--read-only',
            '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'NODE_OPTIONS=--max-old-space-size=32',
            '--volume', f'{self.id}_qualification-private:/run/authn-private:ro',
            '--entrypoint', 'node', self.app_image, '--input-type=module', '-e', script, mode,
            sensitive=True, timeout=20, cleanup=cleanup)

    def prepare_private(self):
        require(self.secret_path.stat().st_size <= 65536, 'Private native configuration exceeded64KiB')
        self.compose('run', '--rm', '--no-deps', 'qualification-private-bootstrap', timeout=30)
        label = self.docker('volume', 'inspect', '--format', '{{index .Labels "com.docker.compose.project"}}', self.id+'_qualification-private', sensitive=True).stdout.strip()
        require(label == self.id, 'Private volume is not owned by this exact project')
        observed = json.loads(self.private_reader('verify').stdout)
        require(observed == {'uid': os.getuid(), 'gid': os.getgid(), 'configMode': 0o600, 'batchMode': 0o700,
                             'configSha256': sha(self.secret_path.read_bytes())}, 'Nonroot private-volume metadata or content differs')
        self.private_ready = True
        self.report['privateStorage'] = {'namedVolume': True, 'nonrootUid': observed['uid'], 'nonrootGid': observed['gid'],
            'configMode': '0600', 'batchDirectoryMode': '0700', 'bootstrapNetwork': 'none', 'bootstrapCapabilities': ['CHOWN'],
            'readerNetwork': 'none', 'helperMount': 'read-only'}

    def export_plan(self, *, required=False, cleanup=False):
        if not self.private_ready:
            require(not required, 'Private volume unavailable for exact plan export')
            return
        data = self.private_reader('plan', cleanup=cleanup).stdout.encode()
        if not data:
            require(not required, 'Installer did not persist a private batch')
            return
        require(len(data) <= 65536, 'Private batch export exceeded64KiB')
        json.loads(data)  # syntax only; installer owns exact semantic admission
        path = self.folder/'installation/plan.json'
        if path.exists():
            if path.read_bytes() != data:
                (self.folder/'installation/changed-plan-observation.json').write_bytes(data)
                raise RuntimeError('Named-volume batch changed after first immutable export')
        else:
            path.write_bytes(data)
            path.chmod(0o600)

    def http(self, url, *, data=None, token=None):
        require(url.startswith(('http://localhost:4315/', 'http://localhost:4314/')), 'Only isolated HTTP endpoints admitted')
        request = urllib.request.Request(url, data=data)
        if token:
            request.add_header('Authorization', 'Bearer ' + token)
        if data is not None:
            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urllib.request.build_opener(NoRedirect).open(request, timeout=8) as response:
            require(response.url == url, 'Unexpected HTTP redirect')
            value = response.read(1024*1024 + 1)
            require(len(value) <= 1024*1024, 'Bounded HTTP readback exceeded 1MiB')
            return value

    def capture_service_diagnostics(self):
        # Failure-only, private and bounded. Never inspect Config.Env or unrelated resources.
        self.admission()
        self.cleanup_deadline = time.monotonic() + 30
        previous_phase = self.phase
        self.phase = 'service-diagnostics'
        records = []
        def clean(value):
            for secret in self.private_values:
                value = value.replace(secret, '[private value omitted]')
            value = re.sub(r'(?:https?|postgres(?:ql)?)://[^\s<>"\']+', '[URL omitted]', value)
            return re.sub(r'[A-Za-z0-9_-]{32,}', '[opaque value omitted]', value)
        try:
            for service in ('session-api', 'login-broker', 'authn-edge', 'keycloak', 'postgres'):
                name = self.id + '-' + service + '-1'
                template = ('{"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"status":{{json .State.Status}},"running":{{.State.Running}},"exitCode":{{.State.ExitCode}},'
                    '"oomKilled":{{.State.OOMKilled}},"health":{{json .State.Health}}}')
                observed = self.docker('inspect', '--format', template, name, sensitive=True,
                    allow_failure=True, timeout=3, cleanup=True)
                if observed.returncode:
                    records.append({'service': service, 'observation': 'container-unavailable'})
                    continue
                state = json.loads(observed.stdout)
                require(state.pop('project') == self.id and state.pop('service') == service,
                    'Diagnostic container escaped exact owned project/service')
                output = self.docker('logs', '--tail', '80', name, sensitive=True,
                    allow_failure=True, timeout=3, cleanup=True)
                # Preserve only bounded redacted state and log text; not raw inspect/env.
                raw = output.stdout + '\n' + output.stderr
                encoded = clean(raw).encode()
                log = encoded[:65536].decode(errors='replace')
                record = {'service': service, 'state': json.loads(clean(json.dumps(state))),
                    'healthStatus': state.get('health', {}).get('Status') if isinstance(state.get('health'), dict) else None,
                    'logsExitCode': output.returncode, 'logTruncated': len(encoded) > 65536, 'log': log}
                data = (json.dumps(record, indent=2) + '\n').encode()
                require(len(data) <= 96*1024, 'Private service diagnostic exceeded96KiB')
                self.admission()
                path = self.folder / ('service-diagnostic-' + service + '.json')
                path.write_bytes(data)
                path.chmod(0o600)
                self.output_bytes += len(data)
                records.append({'service': service, 'path': str(path.relative_to(ROOT)), 'sha256': sha(data)})
        finally:
            self.report['privateServiceDiagnostics'] = records
            self.phase = previous_phase

    def cleanup(self):
        self.cleanup_deadline = time.monotonic() + 90
        export_failed = False
        if self.private_ready:
            try:
                self.export_plan(cleanup=True)
            except BaseException:
                export_failed = True
                self.report['privatePlanExportFailure'] = 'Exact private batch export was not confirmed; cleanup still attempted'
        for name in reversed(self.owned):
            label = self.docker('inspect', '--format', '{{index .Config.Labels "org.governance-commons.protected-run"}}', name, allow_failure=True, sensitive=True, cleanup=True)
            if label.returncode:
                continue
            require(label.stdout.strip() == self.id, 'Refusing non-owned helper cleanup')
            self.docker('rm', '-f', name, cleanup=True)
        if self.created:
            self.compose('--profile', 'tools', 'down', '--volumes', '--remove-orphans', '--timeout', '10', cleanup=True, timeout=60)
        residual = self.docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + self.id, cleanup=True).stdout.strip()
        require(not residual, 'Owned Compose containers remain')
        residual_volumes = self.docker('volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + self.id, cleanup=True).stdout.strip()
        require(not residual_volumes, 'Owned Compose volumes remain')
        # Remove generated credentials only after bounded diagnostics and resource cleanup.
        for path in [self.secret_path, *(self.folder.glob('*.env')), self.folder / 'realm.json', self.folder / 'browser-private.json']:
            path.unlink(missing_ok=True)
        self.report['cleanup'] = {'ownedRemoved': True, 'generatedCredentialsRemoved': True}
        if export_failed:
            self.report['result'] = 'FAIL'


def configure(h):
    password = {name: secrets.token_hex(24) for name in ('postgres', OWNER, 'gc_app', 'keycloak', 'gc_authn_login', 'gc_authn_api', 'admin')}
    url = lambda role, secret: f'postgresql://{role}:{secret}@postgres:5432/{DATABASE}'
    definitions, slots = [], []
    for index in range(48):
        slot = {}
        for field, kind in [('login', 'login'), ('api', 'api'), ('nextLogin', 'login'), ('nextApi', 'api')]:
            name, secret = f'gc_af_{field.lower()}_{index:02}', secrets.token_hex(24)
            definitions.append({'name': name, 'kind': kind, 'password': secret})
            slot[field] = {'name': name, 'url': url(name, secret)}
        slots.append(slot)
    unregistered = {'name': 'gc_af_unregistered', 'kind': 'api', 'password': secrets.token_hex(24)}
    definitions += [unregistered, *({'name': 'gc_authn_' + kind, 'kind': kind, 'password': password['gc_authn_' + kind]} for kind in ('login', 'api'))]
    h.private_values = [*password.values(), *(r['password'] for r in definitions)]
    cfg = {'owner': url(OWNER, password[OWNER]), 'admin': url('postgres', password['postgres']), 'legacy': url('gc_app', password['gc_app']),
           'login': url('gc_authn_login', password['gc_authn_login']), 'api': url('gc_authn_api', password['gc_authn_api']),
           'unregistered': {'name': unregistered['name'], 'url': url(unregistered['name'], unregistered['password'])}, 'slots': slots, 'suiteOffset': 0}
    h.secret_path.write_text(json.dumps(cfg))
    def env(name, values):
        require(all('\n' not in str(v) and '\r' not in str(v) for v in values.values()), 'Invalid private env scalar')
        (h.folder / name).write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    env('compose.env', {'AUTHN_APP_IMAGE': h.app_image, 'LOCAL_UID': os.getuid(), 'LOCAL_GID': os.getgid(), 'AUTHN_RUN_DIR': h.folder})
    common = {'AUTHN_ENVIRONMENT': 'isolated-test', 'PUBLIC_AUTHN_ORIGIN': ORIGIN, 'HOST': '0.0.0.0'}
    suffixes = ['/.well-known/openid-configuration', '/protocol/openid-connect/token', '/protocol/openid-connect/certs']
    aliases = {ISSUER + s: 'http://keycloak:8080/realms/governance' + s for s in suffixes}
    env('login.env', {**common, 'PORT': 4312, 'AUTHN_LOGIN_DATABASE_URL': cfg['login'], 'OIDC_ISSUER': ISSUER, 'OIDC_CLIENT_ID': 'governance-protected-web',
                     'OIDC_REDIRECT_URI': ORIGIN + '/authn/callback', 'OIDC_AUTHORIZATION_ENDPOINT': ISSUER + '/protocol/openid-connect/auth',
                     'OIDC_TOKEN_ENDPOINT': ISSUER + suffixes[1], 'OIDC_JWKS_URI': ISSUER + suffixes[2], 'OIDC_TRANSPORT_ALIASES_JSON': json.dumps(aliases, separators=(',', ':'))})
    env('session.env', {**common, 'PORT': 4313, 'AUTHN_API_DATABASE_URL': cfg['api']})
    env('owner.env', {**common, 'MIGRATION_DATABASE_URL': cfg['owner'], 'OIDC_ISSUER': ISSUER})
    env('helper.env', {'HOME': '/tmp', 'NODE_OPTIONS': '--max-old-space-size=256', 'AUTHN_FOUNDATION_CONFIG': '/run/authn-private/config.json',
                      'AUTHN_PROTECTED_CONFIG': '/run/authn-private/config.json', 'DATABASE_URL': cfg['legacy'], 'MIGRATION_DATABASE_URL': cfg['owner'], 'OIDC_ISSUER': ISSUER})
    env('keycloak.env', {'KC_DB_PASSWORD': password['keycloak'], 'KC_BOOTSTRAP_ADMIN_USERNAME': 'qualification-admin', 'KC_BOOTSTRAP_ADMIN_PASSWORD': password['admin']})
    users = []
    for index, username in enumerate(('steward', 'owner', 'consumer', 'auditor', 'summit', 'engineer')):
        users.append({'id': '10000000-0000-4000-8000-' + str(index+1).zfill(12), 'username': username, 'password': secrets.token_hex(20)})
    dual = {'id': str(uuid.uuid4()), 'username': 'protected-dual', 'password': secrets.token_hex(20)}
    unbound = {'id': str(uuid.uuid4()), 'username': 'protected-unbound', 'password': secrets.token_hex(20)}
    h.private_values += [u['password'] for u in [*users, dual, unbound]]
    protected_client = {'clientId': 'governance-protected-web', 'enabled': True, 'publicClient': True, 'standardFlowEnabled': True,
        'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'redirectUris': [ORIGIN + '/authn/callback'], 'webOrigins': [ORIGIN],
        'attributes': {'pkce.code.challenge.method': 'S256', 'id.token.signed.response.alg': 'RS256'}, 'defaultClientScopes': ['basic']}
    legacy_client = {'clientId': 'governance-web', 'enabled': True, 'publicClient': True, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
        'redirectUris': [ORIGIN + '/auth/callback'], 'webOrigins': [ORIGIN], 'attributes': {'pkce.code.challenge.method': 'S256'}}
    realm = {'realm': 'governance', 'enabled': True, 'registrationAllowed': False, 'resetPasswordAllowed': False, 'loginWithEmailAllowed': False,
        'bruteForceProtected': True, 'sslRequired': 'none', 'clients': [legacy_client, protected_client],
        'users': [{'id': u['id'], 'username': u['username'], 'enabled': True, 'emailVerified': True, 'email': u['username']+'@example.invalid',
                   'firstName': 'Synthetic', 'lastName': u['username'], 'requiredActions': [], 'credentials': [{'type': 'password', 'value': u['password'], 'temporary': False}]} for u in [*users, dual, unbound]]}
    (h.folder / 'realm.json').write_text(json.dumps(realm))
    (h.folder / 'installation').mkdir(mode=0o700)
    return password, definitions, users, dual, unbound, protected_client


def execute(h):
    h.report['sources'] = sources()
    h.evidence_mode = os.environ.get('GC_PROTECTED_AUTHN_MODE', 'mounted-source')
    require(h.evidence_mode in ('mounted-source', 'immutable-image'), 'Explicit protected evidence mode required')
    selected = os.environ.get('GC_PROTECTED_AUTHN_IMAGE')
    require(h.evidence_mode != 'immutable-image' or selected is not None, 'Immutable mode requires an exact selected image')
    require(h.evidence_mode != 'mounted-source' or selected is None, 'Image override requires immutable mode')
    h.app_image = image_tools.image_id(selected or APP_IMAGE)
    h.report.update(evidenceMode=h.evidence_mode, imageAttestation=None)
    h.report['commit'] = h.command(['git', 'rev-parse', 'HEAD'], sensitive=True).stdout.strip()
    require(re.fullmatch('[a-f0-9]{40}', h.report['commit']), 'Invalid immutable source base')
    context = json.loads(h.docker('context', 'inspect', sensitive=True).stdout)[0]['Endpoints']['docker']['Host']
    require(context.startswith(('unix://', 'npipe://')) and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith(('unix://', 'npipe://'))), 'Only local Docker admitted')
    h.resources_before = h.inventory()
    (h.folder/'resources-before.json').write_text(json.dumps(h.resources_before, indent=2)+'\n')
    require(not any(h.id in value for group in h.resources_before.values() for value in group), 'Fresh project collided with existing resources')
    h.report['memoryAdmission'] = h.memory_admission()
    h.report['dockerVersion'] = h.docker('version', '--format', '{{.Server.Version}}').stdout.strip()
    h.report['composeVersion'] = h.docker('compose', 'version', '--short').stdout.strip()
    if h.evidence_mode == 'immutable-image':
        version = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?', h.report['composeVersion'])
        require(version and tuple(map(int, version.groups())) >= (2, 24, 4), 'Compose2.24.4+ required for fixed immutable mounts')
        h.compose_override = h.folder / 'immutable-compose.yaml'
        h.compose_override.write_text('services:\n  login-broker:\n    volumes: !override []\n  session-api:\n    volumes: !override []\n  authn-edge:\n    volumes: !override []\n  owner-tool:\n    volumes: !override\n      - qualification-private:/run/authn-private\n')
    node = Path(os.environ.get('GC_PINNED_NODE', ROOT/'.local/toolchain/node/bin/node'))
    chrome = Path(os.environ.get('GC_BROWSER_EXECUTABLE', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'))
    require(node.is_file() and chrome.is_file(), 'Set explicit GC_PINNED_NODE and existing Chrome before starting the isolated profile')
    h.report['hostNode'] = {'path': str(node.resolve()), 'version': h.command([str(node), '--version']).stdout.strip()}
    require(h.report['hostNode']['version'] == 'v24.22.3', 'Host browser runner requires pinned Node24.22.3')
    h.report['browserVersion'] = h.command([str(chrome), '--version']).stdout.strip()
    h.report['toolHashes'] = {'node': binary_sha(node), 'browser': binary_sha(chrome)}
    #2GiB available plus1GiB daemon reserve covers 384+640+576+384MiB, never an unlimited default.
    for port in (4314, 4315):
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                raise RuntimeError('Isolated qualification port already occupied') from None
    images = re.findall(r'^\s+image: ([^\s$][^\s]+)$', COMPOSE.read_text(), re.MULTILINE)
    h.report['images'] = {'application': h.docker('image', 'inspect', '--format', '{{.Id}}', h.app_image).stdout.strip()}
    for reference in sorted(set(images)):
        h.report['images'][reference] = h.docker('image', 'inspect', '--format', '{{.Id}}', reference).stdout.strip()
    require(h.report['images']['application'] == h.app_image, 'Inspected image differs from exact selected image')
    if h.evidence_mode == 'immutable-image':
        h.phase = 'immutable-image-admission'
        h.report['imageAttestation'] = image_tools.attest_image(h, ROOT, h.app_image, h.report['sources'], h.report['commit'])
    password, definitions, users, dual, unbound, expected_client = configure(h)
    h.phase = 'owned-postgres'
    h.created = True
    h.compose('up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '60', 'postgres', timeout=90)
    h.pg_container = h.compose('ps', '-q', 'postgres', sensitive=True).stdout.strip()
    h.pg_container = h.docker('inspect', '--format', '{{.Id}}', h.pg_container, sensitive=True).stdout.strip()
    setup = f"ALTER ROLE postgres PASSWORD {literal(password['postgres'])};\n"
    for role in (OWNER, 'gc_app', 'keycloak'):
        setup += f'CREATE ROLE {role} LOGIN PASSWORD {literal(password[role])} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;\n'
    setup += f'CREATE DATABASE {DATABASE} OWNER {OWNER};CREATE DATABASE keycloak OWNER keycloak;'
    h.sql(setup, database='postgres')
    h.sql(f'REVOKE ALL ON DATABASE {DATABASE} FROM PUBLIC;GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER},gc_app;REVOKE CREATE ON SCHEMA public FROM PUBLIC;ALTER SCHEMA public OWNER TO {OWNER};')
    roles = load(ROOT / 'scripts/authentication_roles.py', 'protected_role_provisioner')
    h.phase = 'private-volume-preparation'
    h.prepare_private()
    h.phase = 'native-migration'
    try:
        h.sql(roles.prepare_sql(OWNER, DATABASE))
        migration = h.js("await import('./packages/db/src/migrate.ts');", timeout=180)
        require(re.findall(r'^Applied (.+)$', migration.stdout, re.MULTILINE) == base.NAMES, 'Fresh database did not apply exact SQL001–012')
    finally:
        h.sql(roles.finish_sql(OWNER))
    h.sql(roles.executor_sql(DATABASE, definitions))
    h.report['migrations'] = json.loads(h.sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
    require(h.report['migrations'] == [{'name': n, 'sha256': sha((ROOT/'packages/db/migrations'/n).read_bytes())} for n in base.NAMES], 'Applied checksum mismatch')
    h.phase = 'canonical-seed'
    h.js("await import('./packages/db/src/seed.ts');", timeout=180)
    snapshot_sql = "SELECT json_agg(to_jsonb(m) ORDER BY tenant_id,identity_id) FROM public.memberships m WHERE identity_id::text LIKE '10000000-0000-4000-8000-%';"
    seeded = h.sql(snapshot_sql)
    require(len(json.loads(seeded)) == 6, 'Canonical six-membership seed absent')
    h.phase = 'explicit-installation'
    try:
        h.owner_tool()
    finally:
        h.export_plan()
    installation_before = h.sql("SELECT json_agg(to_jsonb(r) ORDER BY recorded_at,id) FROM gc_authn.installation_receipts r;")
    require(len(json.loads(installation_before)) == 13, 'Explicit installation is not exactly13 receipts')
    try:
        h.owner_tool()
    finally:
        h.export_plan()
    require(h.sql("SELECT json_agg(to_jsonb(r) ORDER BY recorded_at,id) FROM gc_authn.installation_receipts r;") == installation_before, 'Exact batch replay changed receipts')
    h.export_plan(required=True)
    plan_path = h.folder/'installation/plan.json'
    plan = json.loads(plan_path.read_text())
    h.report['installation'] = {'operations': 13, 'exactReplay': True, 'renewed': False, 'privatePlanSha256': sha(plan_path.read_bytes()),
        'manifestHashes': [row['manifest_hash'] for row in json.loads(installation_before)]}
    h.phase = 'dual-tenant-fixture'
    # This new identity owns its two test memberships; all original six remain byte-exact.
    h.sql(f"INSERT INTO identities(id,issuer,subject,name) VALUES({literal(dual['id'])},{literal(ISSUER)},{literal(dual['id'])},'Synthetic protected dual tenant');INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',{literal(dual['id'])},'synthetic','[]'),('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',{literal(dual['id'])},'synthetic','[]');")
    binding_manifest = {**plan['manifests'][-1], 'requestId': str(uuid.uuid4()), 'predecessorManifestHash': next(r['manifest_hash'] for r in json.loads(installation_before) if r['request_id'] == plan['manifests'][-1]['requestId']),
        'operation': {'type': 'bind-identity', 'bindingId': str(uuid.uuid4()), 'issuerId': plan['manifests'][4]['operation']['issuerId'], 'identityId': dual['id'],
                      'expectedCanonicalIssuer': ISSUER, 'expectedCanonicalSubject': dual['id'], 'expiresAt': plan['manifests'][0]['operation']['expiresAt']}}
    (h.folder/'installation/dual-binding.json').write_text(json.dumps(binding_manifest))
    receipt = h.helper(['node', '--import', 'tsx', 'scripts/authentication-install.ts', '--stdin'], input=json.dumps(binding_manifest), sensitive=True)
    require(json.loads(receipt.stdout)['result'] == 'COMMITTED_INACTIVE', 'Fresh fixture binding not confirmed')
    require(h.sql(snapshot_sql) == seeded, 'Fresh fixture changed seeded memberships')
    h.report['checks'].append('Native owner applied exact001–012 with temporary definer grant removed; canonical seed and exact13-manifest replay preserved all six original memberships')
    h.phase = 'keycloak-services'
    h.compose('create', '--no-build', '--pull', 'never', '--no-recreate', 'login-broker', 'session-api', 'authn-edge', timeout=60)
    for service in ('login-broker', 'session-api', 'authn-edge'):
        h.record_container(service, h.id + '-' + service + '-1', compose=True)
    h.compose('up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '180', 'identity-bootstrap', 'keycloak', 'login-broker', 'session-api', 'authn-edge', timeout=210)
    for service in ('login-broker', 'session-api', 'authn-edge'):
        h.record_container(service, h.id + '-' + service + '-1', compose=True)
    token = json.loads(h.http('http://localhost:4315/realms/master/protocol/openid-connect/token', data=urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'qualification-admin', 'password': password['admin']}).encode()))['access_token']
    clients = json.loads(h.http('http://localhost:4315/admin/realms/governance/clients?clientId=governance-protected-web', token=token))
    require(len(clients) == 1, 'Protected client is missing or ambiguous')
    client = clients[0]
    for key in ('clientId', 'enabled', 'publicClient', 'standardFlowEnabled', 'implicitFlowEnabled', 'directAccessGrantsEnabled', 'serviceAccountsEnabled', 'redirectUris', 'webOrigins'):
        require(client.get(key) == expected_client[key], 'Keycloak client readback mismatch: ' + key)
    for key, value in expected_client['attributes'].items():
        require(client.get('attributes', {}).get(key) == value, 'Keycloak PKCE/algorithm readback mismatch')
    default_scopes = json.loads(h.http('http://localhost:4315/admin/realms/governance/clients/'+client['id']+'/default-client-scopes', token=token))
    basic = [row for row in default_scopes if row['name'] == 'basic']
    require(len(basic) == 1, 'Actual protected client lacks built-in basic scope')
    mappers = json.loads(h.http('http://localhost:4315/admin/realms/governance/client-scopes/'+basic[0]['id']+'/protocol-mappers/models', token=token))
    auth_time = [m for m in mappers if m.get('protocolMapper') == 'oidc-usermodel-attribute-mapper' and m.get('config', {}).get('claim.name') == 'auth_time']
    # Pinned26.8.1 OIDCLoginProtocolFactory creates basic/auth_time with
    # UserSessionNoteMapper, protected AUTH_TIME note and long JSON type.
    # https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java#L380
    # Never accept a user-attribute/static substitute.
    builtin = [m for m in mappers if m.get('name') == 'auth_time' and m.get('protocolMapper') == 'oidc-usersessionmodel-note-mapper' and m.get('config', {}).get('claim.name') == 'auth_time' and m.get('config', {}).get('user.session.note') == 'AUTH_TIME' and m.get('config', {}).get('jsonType.label') == 'long']
    require(len(builtin) == 1 and not auth_time and builtin[0].get('config', {}).get('id.token.claim') == 'true', 'Actual built-in auth_time ID-token mapper absent')
    public_config = {'client': {key: client[key] for key in expected_client if key != 'defaultClientScopes'}, 'defaultScopes': sorted(x['name'] for x in default_scopes),
                     'authTimeMapper': {key: builtin[0].get(key) for key in ('name', 'protocol', 'protocolMapper', 'config')},
                     'discovery': json.loads(h.http(ISSUER+'/.well-known/openid-configuration'))}
    require(public_config['discovery']['issuer'] == ISSUER, 'Keycloak public issuer disagrees')
    (h.folder/'keycloak-readback.json').write_text(json.dumps(public_config, indent=2)+'\n')
    h.report['keycloakReadback'] = {'path': str((h.folder/'keycloak-readback.json').relative_to(ROOT)), 'sha256': sha((h.folder/'keycloak-readback.json').read_bytes())}
    del token
    h.report['checks'].append('Real Keycloak protected public client readback confirms exact callback/origin, S256,RS256 and built-in basic/auth_time mapper')
    h.phase = 'native-http-tests'
    expected = len(re.findall(r'^test\(', (ROOT/'tests/qualification/protected-authn-http.test.ts').read_text(), re.MULTILINE))
    result = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', 'tests/qualification/protected-authn-http.test.ts'], timeout=240, allow_failure=True)
    (h.folder/'native-http.tap').write_text(result.stdout)
    h.report['testLogs']['nativeHttp'] = {'path': str((h.folder/'native-http.tap').relative_to(ROOT)), 'sha256': sha((h.folder/'native-http.tap').read_bytes())}
    require(result.returncode == 0, 'Native HTTP/SQL qualification failed')
    h.report['nativeHttp'] = base.tap_summary(result.stdout, expected)
    h.report['checks'].append('Actual bounded signed-token HTTP probes and native SCRAM SQL lifecycle/privilege/concurrency cases passed with no skipped cases')
    h.phase = 'served-source-binding'
    assets = json.loads(h.js("import {PAGE,STYLE,SCRIPT} from './apps/session-api/src/ui.ts';import {createHash} from 'node:crypto';console.log(JSON.stringify(Object.fromEntries(Object.entries({html:PAGE,css:STYLE,js:SCRIPT}).map(([k,v])=>[k,createHash('sha256').update(v).digest('hex')]))));").stdout)
    (h.folder/'served').mkdir()
    h.report['servedAssetFiles'] = {}
    for kind, suffix in [('html', '/authn/'), ('css', '/authn/ui.css'), ('js', '/authn/ui.js')]:
        data = h.http(ORIGIN+suffix)
        require(sha(data) == assets[kind], 'Served UI bytes differ from bound source')
        path = h.folder / publication.SERVED[kind]
        h.admission()
        path.write_bytes(data)
        h.output_bytes += len(data)
        h.report['servedAssetFiles'][kind] = {'path': str(path.relative_to(ROOT)), 'sha256': sha(data)}
    h.report['servedAssets'] = assets
    h.report['runtime'] = json.loads(h.js("import {createHash} from 'node:crypto';console.log(JSON.stringify({node:process.version,pg:JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version,jose:JSON.parse(fs.readFileSync('node_modules/jose/package.json')).version,tsx:JSON.parse(fs.readFileSync('node_modules/tsx/package.json')).version,packageSha256:createHash('sha256').update(fs.readFileSync('package.json')).digest('hex'),lockSha256:createHash('sha256').update(fs.readFileSync('pnpm-lock.yaml')).digest('hex')}));").stdout)
    require(h.report['runtime']['lockSha256'] == sha((ROOT/'pnpm-lock.yaml').read_bytes()), 'Cached dependency lock differs from tested source')
    h.phase = 'real-browser'
    browser_config = {'project': h.id, 'postgres': h.pg_container, 'database': DATABASE, 'dual': dual, 'steward': users[0], 'unbound': unbound}
    private_browser = h.folder/'browser-private.json'
    private_browser.write_text(json.dumps(browser_config))
    browser_output = h.folder/'browser'
    browser_output.mkdir()
    env = ['env', 'AUTHN_BROWSER_CONFIG='+str(private_browser), 'AUTHN_BROWSER_OUTPUT='+str(browser_output), 'GC_BROWSER_EXECUTABLE='+str(chrome)]
    result = h.command([*env, str(node), 'node_modules/@playwright/test/cli.js', 'test', '--config', 'tests/e2e-protected/playwright.config.ts'], timeout=300, allow_failure=True, sensitive=True)
    h.scrub_browser_artifacts()
    browser_report = json.loads((browser_output/'results.json').read_text())
    h.report['browser'] = browser_report['stats']
    h.report['testLogs']['browser'] = {'path': str((browser_output/'results.json').relative_to(ROOT)), 'sha256': sha((browser_output/'results.json').read_bytes())}
    require(result.returncode == 0 and h.report['browser']['expected'] == 2 and all(h.report['browser'][k] == 0 for k in ('unexpected', 'skipped', 'flaky')), 'Required two real browser journeys failed or incomplete')
    captures = sorted((browser_output/'captures').glob('*.png'))
    require(len(captures) == 8, 'Required eight current lifecycle captures missing')
    h.report['captures'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in captures]
    require(h.sql(snapshot_sql) == seeded, 'Qualification altered any original seeded membership')
    h.report['checks'].append('Two real Keycloak browser journeys passed: fresh code+PKCE, exact private provenance, CSRF/version switch, stale/cross-tenant/unbound denial, member-revoked logout, keyboard/axe EN/AR desktop/mobile; eight fresh captures retained')
    require(h.report['sources'] == sources(), 'Bound source changed during qualification')
    require(h.report['toolHashes'] == {'node': binary_sha(node), 'browser': binary_sha(chrome)}, 'Selected tool binary changed during qualification')
    require({r['role'] for r in h.report['containerImages']} == publication.ROLES, 'Actual application image roles incomplete')
    h.report['sourceUnchanged'] = True
    h.report['isolation'] = {'project': h.id, 'newDatabase': True, 'sharedCoreUntouched': True, 'cachedImagesOnly': True,
        'ports': [4314, 4315], 'postgresMemoryBytes': 384*MIB, 'keycloakMemoryBytes': 640*MIB, 'applicationServicesMemoryBytes': 576*MIB, 'helperMemoryBytes': 384*MIB,
        'hostFloorBytes': 2*GIB, 'outputCapBytes': 100*MIB, 'diagnosticCapBytes': 4*MIB, 'browserTrace': False, 'browserVideo': False}


def main():
    h = Harness()
    try:
        execute(h)
        h.report['result'] = 'PASS'
    except BaseException as error:
        h.report['result'] = 'FAIL'
        # Exception text from transport/SQL/browser can contain secrets; retain only a bounded local phase/code.
        h.report['failure'] = {'phase': h.phase, 'type': type(error).__name__, 'message': str(error)[:256] if isinstance(error, RuntimeError) else 'Unexpected qualification failure; inspect bounded private diagnostics'}
    finally:
        if h.report['result'] == 'FAIL' and h.created:
            try:
                h.capture_service_diagnostics()
            except BaseException:
                h.report['privateServiceDiagnosticsFailure'] = 'Bounded private service diagnostics incomplete; cleanup still attempted'
        try:
            h.scrub_browser_artifacts()
        except BaseException:
            h.report['result'] = 'FAIL'
            h.report['artifactSafetyFailure'] = 'Browser text artifact sanitization incomplete; private artifacts must not be published'
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                h.phase = 'resource-readback'
                h.deadline = time.monotonic() + 30
                resources_after = h.inventory()
                (h.folder/'resources-after.json').write_text(json.dumps(resources_after, indent=2)+'\n')
                h.report['privateResourceInventories'] = [{'path': str((h.folder/name).relative_to(ROOT)), 'sha256': sha((h.folder/name).read_bytes())} for name in ('resources-before.json', 'resources-after.json')]
                require(resources_after == h.resources_before, 'Preexisting Docker resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved'] = True
        except BaseException:
            h.report['result'] = 'FAIL'
            h.report['cleanupFailure'] = 'Owned cleanup or exact preexisting inventory verification was not confirmed'
        h.report['recorded_at'] = datetime.now(timezone.utc).isoformat()
        h.report['evidence_directory'] = str(h.folder.relative_to(ROOT))
        h.report['privateLogs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'report': str(REPORT.relative_to(ROOT)), 'evidenceDirectory': str(h.folder.relative_to(ROOT))}))
    return 0 if h.report['result'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
