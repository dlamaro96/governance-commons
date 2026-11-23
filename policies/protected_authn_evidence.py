#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revalidate protected-authentication evidence; export a closed coordinate view.

No scanner, browser, Docker or application execution occurs here. Hosted reports
require baked/unmounted image evidence; mounted-source reports can only be read
through the explicit local API and can never qualify the hosted collector.
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta
import math
from pathlib import Path
import re
import struct
from authentication_evidence import (MIB, MIGRATIONS as AUTHENTICATION_MIGRATIONS, declarations, digest, exact,
                                    hashed, integer, read_file, require, strict_json,
                                    tap_summary, timestamp)

MAX_REPORT = 4*MIB
COMMAND = './dev test --suite protected-authn'
PROFILE = 'isolated-protected-authn'
NATIVE = 'tests/qualification/protected-authn-http.test.ts'
BROWSER = 'tests/e2e-protected/protected-authn.spec.ts'
COMPOSE = 'deploy/protected-authn/compose.yaml'
# Current protected transport is qualified on the exact integrated schema.
# The separate SQL012 foundation gate and its historical evidence keep their
# original prefix; new migrations require an explicit protected-gate update.
MIGRATIONS = (
    *AUTHENTICATION_MIGRATIONS,
    '013_authority_foundation.sql',
    '014_source_connectors.sql',
    '015_approval_workflows.sql',
    '016_glossary_publication.sql',
    '017_relation_scope_candidates.sql',
    '018_glossary_nominal_candidates.sql',
    '019_quality_execution.sql',
    '020_native_lineage.sql',
    '021_classification_review.sql',
    '022_reference_publication.sql',
    '023_reference_quality.sql',
    '024_reference_structures.sql',
    '025_quality_uniqueness.sql',
    '026_quality_range.sql',
    '027_quality_monitoring.sql',
    '028_quality_freshness.sql',
    '029_quality_freshness_scheduling.sql',
    '030_quality_volume.sql',
    '031_authority_read_grants.sql',
    '032_relation_candidate_validation.sql',
    '033_content_security_revisions.sql',
)
FIXED_SOURCES = (
    'CONTRIBUTING.md', 'dev', 'scripts/runtime.py', 'scripts/authentication_roles.py',
    'scripts/runtime-test-authority-authn-foundation.py', 'scripts/runtime-test-protected-authn.py',
    'scripts/authentication-install.ts', 'scripts/authentication-install-demo.ts',
    'scripts/runtime-protected-ci.py', 'scripts/protected_authn_image.py', 'scripts/test_protected_authn_image.py',
    'scripts/protected_browser_process.py', 'scripts/test_protected_browser_process.py',
    'scripts/test_protected_authn_bootstrap.py',
    'tests/fixtures/authority-authn-foundation.ts',
    'docs/execution/PROTECTED_BROKER_CONTRACT.md', 'docs/execution/AUTHENTICATION_FOUNDATION_CONTRACT.md',
    'docs/execution/authentication-legacy-function-census.json', 'docs/development/protected-authentication.md',
    'README.md', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
    'apps/web/package.json', 'packages/ui/package.json', 'tsconfig.json', 'Dockerfile', '.dockerignore', COMPOSE,
    'policies/protected_authn_evidence.py', 'policies/test_protected_authn_evidence.py',
    'policies/authentication_evidence.py', 'policies/api_evidence.py',
    'policies/ci_evidence.py', 'policies/test_ci_evidence.py', '.github/workflows/ci.yml',
)
SOURCE_FOLDERS = ('apps/login-broker', 'apps/session-api', 'apps/authn-edge', 'apps/api/src',
                  'packages/authn', 'packages/authority/src', 'packages/db/src', 'packages/domain/src',
                  'packages/authz/src', 'tests/e2e-protected')
CAPTURES = tuple(sorted(name+'.png' for name in (
    'protected-session-en-desktop', 'protected-selected-en-desktop', 'protected-selected-ar-desktop',
    'protected-selected-ar-mobile', 'protected-revoked-ar-mobile', 'protected-steward-en-mobile',
    'protected-tenant-denied-en-mobile', 'protected-unbound-denied-en-desktop')))
SERVED = {'html': 'served/index.html', 'css': 'served/ui.css', 'js': 'served/ui.js'}
ROLES = {'login-broker', 'session-api', 'authn-edge', 'owner-tool', 'helper'}
CHECKS = [
    'Native owner applied exact001–033 with temporary definer grant removed; canonical seed and exact13-manifest replay preserved all six original memberships; full migration ledger remained unchanged',
    'Real Keycloak protected public client readback confirms exact callback/origin, S256,RS256 and built-in basic/auth_time mapper',
    'Actual bounded signed-token HTTP probes and native SCRAM SQL lifecycle/privilege/concurrency cases passed with no skipped cases',
    'Two real Keycloak browser journeys passed: fresh code+PKCE, exact private provenance, CSRF/version switch, stale/cross-tenant/unbound denial, member-revoked logout, keyboard/axe EN/AR desktop/mobile; eight fresh captures retained',
]
LIMITATIONS = [
    'Isolated fresh PostgreSQL and Keycloak over explicit loopback HTTP; no production TLS, shared-core ingress, content authority activation or release qualification.',
    'Controlled signed-token native HTTP cases and two real Keycloak browser journeys are separate executions; neither is substituted for the other.',
    'Only reviewed source coordinates, counters, source/image/tool hashes and allowlisted capture references are exported. Raw titles, errors, logs, identities, sessions, credentials and installation manifests remain private.',
    'Executable hashes identify the selected Node and browser binaries, not every browser installation file. Resource observations do not guarantee host or Docker VM swap behavior.',
    'Automated accessibility/assertion results and capture hashes do not assert visual inspection or human/linguistic accessibility approval.',
]


def source_inventory(root):
    directory = root/'packages/db/migrations'
    require(directory.is_dir() and not directory.is_symlink())
    require(tuple(sorted(p.name for p in directory.glob('*.sql'))) == MIGRATIONS)
    names = set(FIXED_SOURCES) | {'packages/db/migrations/'+name for name in MIGRATIONS}
    for folder in SOURCE_FOLDERS:
        directory = root/folder
        require(directory.is_dir() and not directory.is_symlink())
        require(not any(p.is_symlink() for p in directory.rglob('*')))
        names.update(str(p.relative_to(root)) for p in directory.rglob('*.ts'))
    directory = root/'tests/qualification'
    require(directory.is_dir() and not directory.is_symlink())
    names.update(str(p.relative_to(root)) for p in directory.glob('protected-authn*.ts'))
    require({NATIVE, BROWSER} <= names and len(names) <= 4096)
    require(all(len(n) <= 512 and re.fullmatch(r'[A-Za-z0-9_./-]+', n) for n in names))
    return [{'path': n, 'sha256': digest(read_file(root, n, 16*MIB))} for n in sorted(names)]


def finite(value, maximum):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum)
    return value


def image(value):
    require(type(value) is str and re.fullmatch('sha256:[a-f0-9]{64}', value))
    return value


def text(value, limit=512):
    require(type(value) is str and 0 < len(value.encode('utf-8')) <= limit and not any(ord(c) < 32 for c in value))
    return value


def browser_results(data, rows):
    require(type(data) is dict and type(data.get('suites')) is list and not data.get('errors'))
    stats = data.get('stats')
    exact(stats, ('startTime', 'duration', 'expected', 'skipped', 'unexpected', 'flaky'))
    require(type(stats['startTime']) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', stats['startTime']))
    finite(stats['duration'], 300_000)
    for key in ('expected', 'skipped', 'unexpected', 'flaky'): integer(stats[key], 0, 10000)
    require(stats['expected'] == len(rows) == 2 and all(stats[k] == 0 for k in ('skipped', 'unexpected', 'flaky')))
    observed = []
    nodes = 0
    def walk(suites, depth=0):
        nonlocal nodes
        require(type(suites) is list and len(suites) <= 32 and depth <= 8)
        for suite in suites:
            nodes += 1
            require(nodes <= 64 and type(suite) is dict)
            walk(suite.get('suites', []), depth+1)
            specs = suite.get('specs', [])
            require(type(specs) is list and len(specs) <= 2)
            for spec in specs:
                require(type(spec) is dict and spec.get('ok') is True)
                # Playwright JSON uses either the testDir-relative or repository-relative file.
                require(spec.get('file') in ('protected-authn.spec.ts', BROWSER))
                line = integer(spec.get('line'), 1, 1_000_000)
                require(type(spec.get('title')) is str)
                tests = spec.get('tests')
                require(type(tests) is list and len(tests) == 1)
                test = tests[0]
                require(type(test) is dict and test.get('status') == 'expected' and test.get('expectedStatus') == 'passed')
                results = test.get('results')
                require(type(results) is list and len(results) == 1)
                result = results[0]
                require(type(result) is dict and result.get('status') == 'passed' and result.get('retry') == 0
                        and type(result.get('retry')) is int and not result.get('error') and not result.get('errors'))
                duration = finite(result.get('duration'), 120_000)
                observed.append({'file': BROWSER, 'line': line, 'title': spec['title'], 'duration_ms': duration})
    walk(data['suites'])
    require([(r['file'],r['line'],r['title']) for r in observed] == [(r['file'],r['line'],r['title']) for r in rows])
    return [dict(file=r['file'],line=r['line'],status='passed',attempts=1,duration_ms=r['duration_ms']) for r in observed], dict(stats)




# Exact local batch subset of the adopted typed gc-authn-install/v1 codec.
# Names/types are ordered SQL scalar arguments, not JSON key iteration.
_COMMON=(('request_id','uuid','requestId'),('release_ref','text','releaseReference'),
    ('operator_ref','text','deploymentOperatorReference'),('expected_db_oid','oid','expectedDatabaseOid'),
    ('expected_owner_oid','oid','expectedOwnerRoleOid'),('predecessor_hash','text','predecessorManifestHash'))
_OPERATIONS={
 'register-executor':(('registration_id','uuid','registrationId'),('channel_id','uuid','channelId'),('role_name','text','roleName'),('expected_role_oid','oid','expectedRoleOid'),('kind','text','kind'),('generation','integer','generation'),('expires_at','timestamptz','expiresAt')),
 'advance-generation':(('kind','text','kind'),('channel_id','uuid','channelId'),('registration_id','uuid','registrationId'),('expected_previous_registration_id','uuid','expectedPreviousRegistrationId'),('expected_head_version','integer','expectedHeadVersion')),
 'register-issuer':(('issuer_id','uuid','issuerId'),('registration_id','uuid','registrationId'),('generation','integer','generation'),('issuer','text','issuer'),('client_id','text','clientId'),('redirect_uri','text','redirectUri'),('environment','text','environment'),('expires_at','timestamptz','expiresAt')),
 'bind-identity':(('binding_id','uuid','bindingId'),('issuer_id','uuid','issuerId'),('identity_id','uuid','identityId'),('expected_issuer','text','expectedCanonicalIssuer'),('expected_subject','text','expectedCanonicalSubject'),('expires_at','timestamptz','expiresAt')),
 'initialize-tenant':(('tenant_id','uuid','tenantId'),('generation','integer','generation')),
}

def uuid(value):
    require(type(value) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value))
    require(value != '00000000-0000-0000-0000-000000000000')
    return value

def millis(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z',value))
    return datetime.fromisoformat(value.replace('Z','+00:00'))

def installation_manifest_hash(manifest):
    """Bounded closed batch syntax and typed-byte hash, independently of Node."""
    exact(manifest, ('formatVersion',*(r[2] for r in _COMMON),'operation'))
    require(type(manifest['formatVersion']) is int and manifest['formatVersion']==1)
    operation=manifest['operation'];require(type(operation) is dict and operation.get('type') in _OPERATIONS)
    spec=_OPERATIONS[operation['type']];exact(operation,('type',*(r[2] for r in spec)))
    def string(value):return 'S'+str(len(value.encode('utf-8')))+':'+value
    encoded='gc-authn-install/v1;'+string(operation['type'])
    for owner,entries in ((manifest,_COMMON),(operation,spec)):
        for name,kind,key in entries:
            value=owner[key];encoded+=string(name)
            if value is None:
                require(key in ('predecessorManifestHash','expectedPreviousRegistrationId','expectedHeadVersion'))
                encoded+='N;'
            elif kind=='uuid':encoded+='U'+uuid(value)+';'
            elif kind in ('integer','oid'):encoded+='I'+str(integer(value,1,4294967295 if kind=='oid' else 2147483647))+';'
            elif kind=='timestamptz':millis(value);encoded+='T'+value+';'
            else:encoded+=string(text(value,2048))
    raw=encoded.encode('utf-8');require(len(raw)<=65536)
    return digest(raw)

def installation_plan(plan,receipt_hashes):
    exact(plan,('version','config','target','manifests'))
    require(type(plan['version']) is int and plan['version']==1)
    config=plan['config'];exact(config,('issuer','publicOrigin','environment'))
    require(config=={'issuer':'http://localhost:4315/realms/governance','publicOrigin':'http://localhost:4314','environment':'isolated-test'})
    target=plan['target'];exact(target,('databaseOid','ownerRoleOid','loginRoleOid','apiRoleOid'))
    for value in target.values():integer(value,1,4294967295)
    require(len({target[k] for k in ('ownerRoleOid','loginRoleOid','apiRoleOid')})==3)
    manifests=plan['manifests'];require(type(manifests) is list and len(manifests)==13)
    hashes=[];requests=set();predecessor=None
    for manifest in manifests:
        h=installation_manifest_hash(manifest)
        require(manifest['requestId'] not in requests);requests.add(manifest['requestId'])
        require(manifest['expectedDatabaseOid']==target['databaseOid'] and manifest['expectedOwnerRoleOid']==target['ownerRoleOid'])
        require(manifest['releaseReference']=='governance-commons/protected-authentication-local/v1'
            and manifest['deploymentOperatorReference']=='explicit-local-development-installation')
        require(manifest['predecessorManifestHash']==predecessor)
        predecessor=h;hashes.append(h)
    operations=[m['operation'] for m in manifests]
    login,login_head,api,api_head,issuer=operations[:5]
    require([x['type'] for x in operations]==['register-executor','advance-generation','register-executor','advance-generation','register-issuer']+['bind-identity']*6+['initialize-tenant']*2)
    for role,head,kind,oid in ((login,login_head,'login',target['loginRoleOid']),(api,api_head,'api',target['apiRoleOid'])):
        require(role['kind']==kind and role['roleName']=='gc_authn_'+kind and role['expectedRoleOid']==oid and role['generation']==1 and role['expiresAt']==login['expiresAt'])
        require(head['kind']==kind and head['channelId']==role['channelId'] and head['registrationId']==role['registrationId'] and head['expectedPreviousRegistrationId'] is None and head['expectedHeadVersion'] is None)
    require(login['registrationId']!=api['registrationId'] and login['channelId']!=api['channelId'])
    require(issuer['registrationId']==login['registrationId'] and issuer['generation']==1 and issuer['issuer']==config['issuer']
        and issuer['clientId']=='governance-protected-web' and issuer['redirectUri']==config['publicOrigin']+'/authn/callback'
        and issuer['environment']==config['environment'] and issuer['expiresAt']==login['expiresAt'])
    bindings=set()
    for index,operation in enumerate(operations[5:11],1):
        identity='10000000-0000-4000-8000-'+str(index).zfill(12)
        require(operation['bindingId'] not in bindings);bindings.add(operation['bindingId'])
        require(operation['issuerId']==issuer['issuerId'] and operation['identityId']==identity and operation['expectedCanonicalIssuer']==config['issuer']
            and operation['expectedCanonicalSubject']==identity and operation['expiresAt']==login['expiresAt'])
    for operation,tenant in zip(operations[11:],('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')):
        require(operation['tenantId']==tenant and operation['generation']==1)
    require(len(set(hashes))==13 and sorted(hashes)==sorted(receipt_hashes))


def keycloak_readback(value):
    """Independently bind the isolated provider's required live client settings."""
    exact(value, ('client','defaultScopes','authTimeMapper','discovery'))
    origin='http://localhost:4314'; issuer='http://localhost:4315/realms/governance'
    client=value['client']
    expected={'clientId':'governance-protected-web','enabled':True,'publicClient':True,
        'standardFlowEnabled':True,'implicitFlowEnabled':False,'directAccessGrantsEnabled':False,
        'serviceAccountsEnabled':False,'redirectUris':[origin+'/authn/callback'],'webOrigins':[origin]}
    exact(client, (*expected,'attributes'))
    for key,want in expected.items():
        require(client[key] is want if type(want) is bool else client[key] == want)
    attrs=client['attributes']; require(type(attrs) is dict)
    require(attrs.get('pkce.code.challenge.method') == 'S256' and attrs.get('id.token.signed.response.alg') == 'RS256')
    scopes=value['defaultScopes']
    require(type(scopes) is list and 0 < len(scopes) <= 64 and all(type(x) is str for x in scopes))
    require(scopes == sorted(set(scopes)) and 'basic' in scopes)
    mapper=value['authTimeMapper']; exact(mapper, ('name','protocol','protocolMapper','config'))
    require(mapper['name'] == 'auth_time' and mapper['protocol'] == 'openid-connect'
        and mapper['protocolMapper'] == 'oidc-usersessionmodel-note-mapper')
    cfg=mapper['config']; require(type(cfg) is dict)
    require(all(cfg.get(k) == v for k,v in {'claim.name':'auth_time','user.session.note':'AUTH_TIME',
        'jsonType.label':'long','id.token.claim':'true'}.items()))
    discovery=value['discovery']; require(type(discovery) is dict)
    require(discovery.get('issuer') == issuer)
    for key,suffix in {'authorization_endpoint':'auth','token_endpoint':'token','jwks_uri':'certs'}.items():
        require(discovery.get(key) == issuer+'/protocol/openid-connect/'+suffix)


def _safe_report(root, value, commit, require_image):
    required = {'schema_version','result','started_at','recorded_at','command','profile','checks','limitations',
        'sources','commit','memoryAdmission','dockerVersion','composeVersion','hostNode','browserVersion','images',
        'migrations','installation','keycloakReadback','nativeHttp','servedAssets','runtime','browser','captures',
        'sourceUnchanged','isolation','cleanup','evidence_directory','privateLogs','evidenceMode','imageAttestation',
        'containerImages','toolHashes','testLogs','privateResourceInventories','servedAssetFiles','hostBrowserCleanup','migrationLedger'}
    require(type(value) is dict and required <= set(value) and set(value) <= required | {'privateStorage'})
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['result'] == 'PASS')
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit) and value['commit'] == commit)
    require(value['command'] == COMMAND and value['profile'] == PROFILE and value['sourceUnchanged'] is True)
    require(timestamp(value['started_at']) <= timestamp(value['recorded_at']))
    require(value['checks'] == CHECKS)
    require(type(value['limitations']) is list and len(value['limitations']) <= 16)
    for item in value['limitations']: text(item, 2048)
    sources = source_inventory(root)
    require(value['sources'] == sources)
    hashes = {r['path']:r['sha256'] for r in sources}
    migrations = [{'name':n,'sha256':hashes['packages/db/migrations/'+n]} for n in MIGRATIONS]
    require(value['migrations'] == migrations)
    folder = value['evidence_directory']
    require(type(folder) is str and re.fullmatch(r'\.local/evidence/protected-authn-\d{8}T\d{6}-[a-f0-9]{12}', folder))
    cached, total = {}, 0
    def private(ref, suffix=None, cap=4*MIB):
        nonlocal total
        exact(ref, ('path','sha256'))
        name = ref['path']
        require(type(name) is str and name.startswith(folder+'/'))
        if suffix is not None: require(name == folder+'/'+suffix)
        if name not in cached:
            data = read_file(root,name,cap)
            total += len(data)
            require(total <= 100*MIB)
            cached[name] = data
        data = cached[name]
        require(len(data) <= cap and digest(data) == hashed(ref['sha256']))
        return data
    exact(value['migrationLedger'], ('before','after'))
    ledgers = [strict_json(private(value['migrationLedger'][phase], 'migrations-'+phase+'.json', 65536))
               for phase in ('before','after')]
    for ledger in ledgers:
        require(type(ledger) is list and len(ledger) == len(MIGRATIONS))
        for row, expected in zip(ledger, migrations):
            exact(row, ('name','checksum','applied_at'))
            require(row['name'] == expected['name'] and row['checksum'] == expected['sha256'])
            require(timestamp(value['started_at']) <= timestamp(row['applied_at']) <= timestamp(value['recorded_at']))
    require(ledgers[0] == ledgers[1])
    logs = value['privateLogs']
    require(type(logs) is list and 0 < len(logs) <= 2048)
    seen = set()
    for row in logs:
        require(type(row) is dict and type(row.get('path')) is str and re.fullmatch(re.escape(folder)+r'/[0-9]{3,6}-[a-z_-]+\.log',row['path']) and row['path'] not in seen)
        seen.add(row['path']); private(row)
    exact(value['testLogs'], ('nativeHttp','browser'))
    native_rows = declarations(root, NATIVE)
    raw = private(value['testLogs']['nativeHttp'],'native-http.tap')
    require(not re.search(rb'^Bail out!',raw,re.M))
    counts = tap_summary(b'phase=nativeHttp\nexit=0\n'+raw, 'nativeHttp', native_rows)
    # The private TAP independently proves suites=0; the runner omits that field.
    native = value['nativeHttp']
    exact(native, ('tests','pass','fail','cancelled','skipped','todo','duration_ms'))
    require(native == counts)
    for k,v in native.items():
        finite(v,240_000) if k == 'duration_ms' else integer(v,0,10000)
    browser_data = strict_json(private(value['testLogs']['browser'],'browser/results.json'))
    browser, stats = browser_results(browser_data, declarations(root,BROWSER))
    require(value['browser'] == stats)
    browser_start=millis(stats['startTime'])
    require(timestamp(value['started_at']) <= browser_start
            and browser_start+timedelta(milliseconds=stats['duration']) <= timestamp(value['recorded_at']))
    captures = value['captures']
    require(type(captures) is list and len(captures) == 8)
    require([r.get('path') if type(r) is dict else None for r in captures] == [folder+'/browser/captures/'+n for n in CAPTURES])
    safe_captures = []
    for name, row in zip(CAPTURES,captures):
        data = private(row,'browser/captures/'+name,16*MIB)
        require(len(data) >= 33 and data[:8] == b'\x89PNG\r\n\x1a\n' and data[12:16] == b'IHDR')
        width,height = struct.unpack('>II',data[16:24])
        require(1 <= width <= 8192 and 1 <= height <= 32768)
        safe_captures.append({'name':name,'sha256':row['sha256'],'bytes':len(data),'width':width,'height':height})
    exact(value['servedAssets'],SERVED); exact(value['servedAssetFiles'],SERVED)
    for kind,suffix in SERVED.items():
        data = private(value['servedAssetFiles'][kind],suffix,MIB)
        require(digest(data) == hashed(value['servedAssets'][kind]))
    # Re-read exact before/after inventories; report booleans alone cannot qualify cleanup.
    refs = value['privateResourceInventories']
    require(type(refs) is list and len(refs) == 2)
    inventories=[]
    for ref,name in zip(refs,('resources-before.json','resources-after.json')):
        inventory = strict_json(private(ref,name))
        exact(inventory,('containers','running','images','volumes','networks'))
        for rows in inventory.values():
            require(type(rows) is list and len(rows) <= 4096 and all(type(r) is str for r in rows))
            require(rows == sorted(set(rows)))
            for row in rows: text(row,1024)
        inventories.append(inventory)
    require(inventories[0] == inventories[1])
    exact(value['cleanup'],('ownedRemoved','generatedCredentialsRemoved','resourceInventoryPreserved','ownedHostProcessesRemoved'))
    require(all(v is True for v in value['cleanup'].values()))
    # This records exact registered POSIX groups and observed descendants, not
    # arbitrary unobserved adversarial double-forks outside that ownership set.
    host_cleanup = strict_json(private(value['hostBrowserCleanup'],'browser/host-process-cleanup.json'))
    host_counts = ('registeredBrowserGroups','trackedProcesses','termSignals','killSignals',
                   'remainingLive','identityConflicts','unresolvedGroups')
    exact(host_cleanup,('schema_version','scope','result','trigger',*host_counts,'registryClosed'))
    require(type(host_cleanup['schema_version']) is int and host_cleanup['schema_version'] == 1)
    require(host_cleanup['scope'] == 'registered-posix-groups-and-observed-descendants'
            and host_cleanup['result'] == 'PASS' and host_cleanup['trigger'] == 'normal'
            and host_cleanup['registryClosed'] is True)
    for key in host_counts: integer(host_cleanup[key],0,4096)
    require(host_cleanup['registeredBrowserGroups'] >= 1)
    require(host_cleanup['registeredBrowserGroups'] <= host_cleanup['trackedProcesses'])
    require(host_cleanup['termSignals'] <= host_cleanup['trackedProcesses'])
    require(host_cleanup['killSignals'] <= host_cleanup['trackedProcesses'])
    require(all(host_cleanup[key] == 0 for key in ('remainingLive','identityConflicts','unresolvedGroups')))
    compose = read_file(root,COMPOSE,MIB).decode('utf-8')
    refs = sorted(set(re.findall(r'^\s+image: ([^\s$][^\s]+)$',compose,re.M)))
    require(len(refs) == 2 and all(re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}',r) for r in refs))
    exact(value['images'],['application',*refs])
    for ident in value['images'].values(): image(ident)
    app = value['images']['application']
    mode=value['evidenceMode']
    require(mode in ('mounted-source','immutable-image') and (not require_image or mode == 'immutable-image'))
    if mode == 'immutable-image':
        attestation=value['imageAttestation']
        exact(attestation,('imageId','sourceMode','commit','sources','packageSha256','lockSha256'))
        require(attestation['imageId'] == app and attestation['sourceMode'] == 'baked-unmounted' and attestation['commit'] == commit and attestation['sources'] == sources)
        require(attestation['packageSha256'] == hashes['package.json'] and attestation['lockSha256'] == hashes['pnpm-lock.yaml'])
    else: require(value['imageAttestation'] is None)
    containers=value['containerImages']
    require(type(containers) is list and 5 <= len(containers) <= 2048)
    seen=set(); roles=set()
    for row in containers:
        exact(row,('role','containerId','imageId'))
        require(row['role'] in ROLES and row['imageId'] == app)
        ident=hashed(row['containerId']); require(ident not in seen); seen.add(ident); roles.add(row['role'])
    require(roles == ROLES)
    exact(value['toolHashes'],('node','browser'))
    for h in value['toolHashes'].values(): hashed(h)
    exact(value['hostNode'],('path','version'))
    text(value['hostNode']['path'],4096); require(value['hostNode']['version'] == 'v24.22.3')
    require(type(value['browserVersion']) is str and re.fullmatch(r'(?:Google Chrome(?: for Testing)?|Chromium) \d{1,4}(?:\.\d{1,6}){3}',value['browserVersion']))
    for key in ('dockerVersion','composeVersion'):
        require(type(value[key]) is str and re.fullmatch(r'v?\d{1,3}\.\d{1,3}\.\d{1,3}(?:[-+][A-Za-z0-9.-]{1,64})?',value[key]))
    runtime=value['runtime']; exact(runtime,('node','pg','jose','tsx','packageSha256','lockSha256'))
    package=strict_json(read_file(root,'package.json',MIB)); require(runtime['node'] == 'v24.22.3')
    for dependency in ('pg','jose','tsx'):
        expected=package.get('dependencies',{}).get(dependency,package.get('devDependencies',{}).get(dependency))
        require(type(expected) is str and re.fullmatch(r'\d+\.\d+\.\d+',expected) and runtime[dependency] == expected)
    require(runtime['packageSha256'] == hashes['package.json'] and runtime['lockSha256'] == hashes['pnpm-lock.yaml'])
    memory=value['memoryAdmission']; exact(memory,('total_bytes','observed_working_bytes','daemon_reserve_bytes'))
    for n in memory.values(): integer(n)
    require(memory['daemon_reserve_bytes'] == 1024*MIB and memory['total_bytes']-memory['observed_working_bytes']-memory['daemon_reserve_bytes'] >= 2048*MIB)
    isolation=value['isolation']
    exact(isolation,('project','newDatabase','sharedCoreUntouched','cachedImagesOnly','ports','postgresMemoryBytes','keycloakMemoryBytes','applicationServicesMemoryBytes','helperMemoryBytes','hostFloorBytes','outputCapBytes','diagnosticCapBytes','browserTrace','browserVideo'))
    require(isolation['project'] == 'gc-protected-'+folder[-12:])
    require(all(isolation[k] is True for k in ('newDatabase','sharedCoreUntouched','cachedImagesOnly')))
    require(isolation['ports'] == [4314,4315] and isolation['browserTrace'] is False and isolation['browserVideo'] is False)
    expected_limits={'postgresMemoryBytes':384*MIB,'keycloakMemoryBytes':640*MIB,'applicationServicesMemoryBytes':576*MIB,'helperMemoryBytes':384*MIB,'hostFloorBytes':2048*MIB,'outputCapBytes':100*MIB,'diagnosticCapBytes':4*MIB}
    for key,n in expected_limits.items(): require(integer(isolation[key]) == n)
    installation=value['installation']; exact(installation,('operations','exactReplay','renewed','privatePlanSha256','manifestHashes'))
    require(type(installation['operations']) is int and installation['operations'] == 13 and installation['exactReplay'] is True and installation['renewed'] is False)
    hashed(installation['privatePlanSha256']); require(type(installation['manifestHashes']) is list and len(installation['manifestHashes']) == 13)
    require(len({hashed(x) for x in installation['manifestHashes']}) == 13)
    keycloak_readback(strict_json(private(value['keycloakReadback'],'keycloak-readback.json')))
    plan = strict_json(private({'path':folder+'/installation/plan.json', 'sha256':installation['privatePlanSha256']},
                               'installation/plan.json', 65_536))
    installation_plan(plan, installation['manifestHashes'])
    # Private storage details are not evidence of additional tested behavior and
    # never enter public output. Bound any diagnostic descriptor without echoing it.
    if 'privateStorage' in value: require(type(value['privateStorage']) is dict and len(json.dumps(value['privateStorage']).encode()) <= 8192)
    require(source_inventory(root) == sources)
    return {'schema_version':1,'purpose':'PROTECTED_AUTHENTICATION_COORDINATES_ONLY','outcome':'PASS',
        'commit':commit,'started_at':value['started_at'],'recorded_at':value['recorded_at'],'command':COMMAND,'profile':PROFILE,
        'evidence_mode':mode,'baked_image_verified':mode == 'immutable-image',
        'native_http':{'counts':dict(native),'tests':[{'file':r['file'],'line':r['line'],'status':'passed'} for r in native_rows]},
        'browser':{'stats':stats,'tests':browser},'captures':safe_captures,'served_assets':dict(value['servedAssets']),
        'sources':sources,'migrations':migrations,'images':dict(value['images']),
        'migration_ledger':{'rows':len(MIGRATIONS),'unchanged':True,
                            'digests':{k:v['sha256'] for k,v in value['migrationLedger'].items()}},
        'container_image_counts':{role:sum(r['role']==role for r in containers) for role in sorted(ROLES)},
        'runtime':dict(runtime),'tools':{'node':{'version':value['hostNode']['version'],'sha256':value['toolHashes']['node']},'browser':{'version':value['browserVersion'],'sha256':value['toolHashes']['browser']},'docker':value['dockerVersion'],'compose':value['composeVersion']},
        'cleanup':dict(value['cleanup']),'preserved_resource_counts':{k:len(v) for k,v in inventories[0].items()},
        'resource_inventory_digests':[r['sha256'] for r in value['privateResourceInventories']],
        'host_browser_cleanup':{'scope':host_cleanup['scope'],'counts':{k:host_cleanup[k] for k in host_counts},
                                'sha256':value['hostBrowserCleanup']['sha256']},
        'test_log_digests':{k:v['sha256'] for k,v in value['testLogs'].items()},'limitations':list(LIMITATIONS)+([] if mode=='immutable-image' else ['Mounted-source local execution only; no baked application-image or hosted qualification.'])}


def safe_report(root, value, commit, *, require_image=True):
    try: return _safe_report(root,value,commit,require_image)
    except (OSError,ValueError,TypeError,KeyError,SyntaxError,RecursionError,OverflowError,UnicodeError,struct.error): return None


def load_report(root, commit, *, require_image=True):
    try: return safe_report(root,strict_json(read_file(root,'.local/evidence/protected-authn.json',MAX_REPORT)),commit,require_image=require_image)
    except (OSError,ValueError,TypeError,RecursionError,OverflowError): return None


def copy_captures(root, value, dest, validated):
    """Only called after full validation; recheck bytes immediately before staging."""
    require(not dest.is_symlink())
    folder=value['evidence_directory']
    require(type(folder) is str and re.fullmatch(r'\.local/evidence/protected-authn-\d{8}T\d{6}-[a-f0-9]{12}',folder))
    require(len(value['captures']) == len(validated['captures']) == 8)
    for row,expected in zip(value['captures'],validated['captures']):
        exact(row,('path','sha256'))
        name=expected['name']
        require(name in CAPTURES and row['path'] == folder+'/browser/captures/'+name and row['sha256'] == expected['sha256'])
        data=read_file(root,row['path'],16*MIB);require(digest(data)==row['sha256'])
        target=dest/name;require(not target.exists() and not target.is_symlink())
        target.write_bytes(data)
