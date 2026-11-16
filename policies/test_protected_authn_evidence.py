#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic publication-boundary fixtures; these do not qualify authentication."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
import protected_authn_evidence as evidence

COMMIT='a'*40
PNG=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII=')



def installation_fixture():
    def uid(n):return '10000000-0000-4000-8000-'+str(n).zfill(12)
    config={'issuer':'http://localhost:4315/realms/governance','publicOrigin':'http://localhost:4314','environment':'isolated-test'}
    target={'databaseOid':123,'ownerRoleOid':456,'loginRoleOid':789,'apiRoleOid':790};expiry='2026-11-17T10:00:00.000Z'
    operations=[]
    for kind,n,oid in (('login',20,789),('api',22,790)):
        operations.extend([{'type':'register-executor','registrationId':uid(n),'channelId':uid(n+1),'roleName':'gc_authn_'+kind,'expectedRoleOid':oid,'kind':kind,'generation':1,'expiresAt':expiry},
            {'type':'advance-generation','kind':kind,'channelId':uid(n+1),'registrationId':uid(n),'expectedPreviousRegistrationId':None,'expectedHeadVersion':None}])
    operations.append({'type':'register-issuer','issuerId':uid(24),'registrationId':uid(20),'generation':1,'issuer':config['issuer'],'clientId':'governance-protected-web','redirectUri':config['publicOrigin']+'/authn/callback','environment':'isolated-test','expiresAt':expiry})
    operations.extend({'type':'bind-identity','bindingId':uid(30+n),'issuerId':uid(24),'identityId':uid(n),'expectedCanonicalIssuer':config['issuer'],'expectedCanonicalSubject':uid(n),'expiresAt':expiry} for n in range(1,7))
    operations.extend({'type':'initialize-tenant','tenantId':t,'generation':1} for t in ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'))
    manifests=[];hashes=[];previous=None
    for n,operation in enumerate(operations,100):
        manifest={'formatVersion':1,'requestId':uid(n),'releaseReference':'governance-commons/protected-authentication-local/v1',
            'deploymentOperatorReference':'explicit-local-development-installation','expectedDatabaseOid':target['databaseOid'],
            'expectedOwnerRoleOid':target['ownerRoleOid'],'predecessorManifestHash':previous,'operation':operation}
        previous=evidence.installation_manifest_hash(manifest);hashes.append(previous);manifests.append(manifest)
    return {'version':1,'config':config,'target':target,'manifests':manifests},hashes


def fixture(root):
    for name in evidence.FIXED_SOURCES:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():path.write_text('synthetic source\n')
    for folder in evidence.SOURCE_FOLDERS:
        (root/folder).mkdir(parents=True,exist_ok=True)
    (root/'tests/qualification').mkdir(parents=True,exist_ok=True)
    for name in evidence.MIGRATIONS:
        p=root/'packages/db/migrations'/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists():p.write_text('-- immutable synthetic fixture\n')
    package_path=root/'package.json'
    try: package=json.loads(package_path.read_text())
    except (ValueError,TypeError):package={}
    package.setdefault('dependencies',{}).update({'pg':'8.23.1','jose':'6.2.17'})
    package.setdefault('devDependencies',{}).setdefault('tsx','4.23.15')
    package_path.write_text(json.dumps(package))
    image_refs=['postgres:17@sha256:'+'b'*64,'quay.io/keycloak/keycloak:26@sha256:'+'c'*64]
    (root/evidence.COMPOSE).write_text('services:\n  postgres:\n    image: '+image_refs[0]+'\n  keycloak:\n    image: '+image_refs[1]+'\n')
    titles=['PRIVATE_SYNTHETIC native one','PRIVATE_SYNTHETIC native two']
    (root/evidence.NATIVE).write_text(''.join("test('"+t+"',async()=>{});\n" for t in titles))
    browser_titles=['PRIVATE_SYNTHETIC browser one','PRIVATE_SYNTHETIC browser two']
    (root/evidence.BROWSER).write_text(''.join("test('"+t+"',async()=>{});\n" for t in browser_titles))
    folder='.local/evidence/protected-authn-20261116T100000-123456abcdef'
    def write(name,data):
        p=root/folder/name;p.parent.mkdir(parents=True,exist_ok=True)
        if isinstance(data,dict):data=(json.dumps(data)+'\n').encode()
        if isinstance(data,str):data=data.encode()
        p.write_bytes(data);return {'path':str(p.relative_to(root)),'sha256':evidence.digest(data)}
    log=write('001-admission.log','PRIVATE_SYNTHETIC diagnostic')
    tap='TAP version 13\n'+''.join(f'ok {i} - {t}\n' for i,t in enumerate(titles,1))
    tap+='1..2\n# tests 2\n# suites 0\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1.5\n'
    native_log=write('native-http.tap',tap)
    stats={'startTime':'2026-11-16T10:00:01.000Z','duration':2.5,'expected':2,'skipped':0,'unexpected':0,'flaky':0}
    specs=[{'title':t,'file':'protected-authn.spec.ts','line':i,'ok':True,'tests':[{'status':'expected','expectedStatus':'passed','results':[{'status':'passed','retry':0,'duration':1.0,'stdout':['PRIVATE_SYNTHETIC_output']}]}]} for i,t in enumerate(browser_titles,1)]
    browser_log=write('browser/results.json',{'suites':[{'specs':specs}],'stats':stats,'errors':[]})
    captures=[write('browser/captures/'+name,PNG) for name in evidence.CAPTURES]
    served={k:write(v,('PRIVATE_SYNTHETIC served '+k)) for k,v in evidence.SERVED.items()}
    inventory={k:[] for k in ('containers','running','images','volumes','networks')}
    inventory['images']=['PRIVATE_SYNTHETIC existing image']
    inventories=[write(name,inventory) for name in ('resources-before.json','resources-after.json')]
    origin='http://localhost:4314';issuer='http://localhost:4315/realms/governance'
    readback=write('keycloak-readback.json',{'client':{'clientId':'governance-protected-web','enabled':True,'publicClient':True,
        'standardFlowEnabled':True,'implicitFlowEnabled':False,'directAccessGrantsEnabled':False,'serviceAccountsEnabled':False,
        'redirectUris':[origin+'/authn/callback'],'webOrigins':[origin],
        'attributes':{'pkce.code.challenge.method':'S256','id.token.signed.response.alg':'RS256'}},
        'defaultScopes':['basic'],'authTimeMapper':{'name':'auth_time','protocol':'openid-connect','protocolMapper':'oidc-usersessionmodel-note-mapper',
        'config':{'claim.name':'auth_time','user.session.note':'AUTH_TIME','jsonType.label':'long','id.token.claim':'true'}},
        'discovery':{'issuer':issuer,**{key:issuer+'/protocol/openid-connect/'+suffix for key,suffix in
        {'authorization_endpoint':'auth','token_endpoint':'token','jwks_uri':'certs'}.items()}}})
    batch,receipt_hashes=installation_fixture()
    plan=write('installation/plan.json',batch)
    sources=evidence.source_inventory(root);hashes={r['path']:r['sha256'] for r in sources}
    app='sha256:'+'d'*64
    runtime={'node':'v24.22.3','pg':'8.23.1','jose':'6.2.17','tsx':package['devDependencies']['tsx'],'packageSha256':hashes['package.json'],'lockSha256':hashes['pnpm-lock.yaml']}
    report={'schema_version':1,'result':'PASS','started_at':'2026-11-16T10:00:00+00:00','recorded_at':'2026-11-16T10:00:10+00:00',
        'command':evidence.COMMAND,'profile':evidence.PROFILE,'checks':list(evidence.CHECKS),'limitations':['PRIVATE_SYNTHETIC limitation'],
        'sources':sources,'commit':COMMIT,'memoryAdmission':{'total_bytes':8*1024*evidence.MIB,'observed_working_bytes':1024*evidence.MIB,'daemon_reserve_bytes':1024*evidence.MIB},
        'dockerVersion':'29.0.2','composeVersion':'v2.40.0','hostNode':{'path':'/PRIVATE_SYNTHETIC/node','version':'v24.22.3'},'browserVersion':'Chromium 141.0.7000.0',
        'images':{'application':app,image_refs[0]:'sha256:'+'e'*64,image_refs[1]:'sha256:'+'f'*64},
        'migrations':[{'name':n,'sha256':hashes['packages/db/migrations/'+n]} for n in evidence.MIGRATIONS],
        'installation':{'operations':13,'exactReplay':True,'renewed':False,'privatePlanSha256':plan['sha256'],'manifestHashes':receipt_hashes},
        'keycloakReadback':readback,'nativeHttp':{'tests':2,'pass':2,'fail':0,'cancelled':0,'skipped':0,'todo':0,'duration_ms':1.5},
        'servedAssets':{k:v['sha256'] for k,v in served.items()},'servedAssetFiles':served,'runtime':runtime,'browser':stats,'captures':captures,'sourceUnchanged':True,
        'isolation':{'project':'gc-protected-123456abcdef','newDatabase':True,'sharedCoreUntouched':True,'cachedImagesOnly':True,'ports':[4314,4315],
            'postgresMemoryBytes':384*evidence.MIB,'keycloakMemoryBytes':640*evidence.MIB,'applicationServicesMemoryBytes':576*evidence.MIB,'helperMemoryBytes':384*evidence.MIB,
            'hostFloorBytes':2048*evidence.MIB,'outputCapBytes':100*evidence.MIB,'diagnosticCapBytes':4*evidence.MIB,'browserTrace':False,'browserVideo':False},
        'cleanup':{'ownedRemoved':True,'generatedCredentialsRemoved':True,'resourceInventoryPreserved':True},'evidence_directory':folder,'privateLogs':[log],
        'evidenceMode':'immutable-image','imageAttestation':{'imageId':app,'sourceMode':'baked-unmounted','commit':COMMIT,'sources':sources,'packageSha256':hashes['package.json'],'lockSha256':hashes['pnpm-lock.yaml']},
        'containerImages':[{'role':role,'containerId':f'{i:064x}','imageId':app} for i,role in enumerate(sorted(evidence.ROLES),1)],
        'toolHashes':{'node':'2'*64,'browser':'3'*64},'testLogs':{'nativeHttp':native_log,'browser':browser_log},'privateResourceInventories':inventories}
    return report


class ProtectedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='gc-protected-evidence-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.report=fixture(self.root)

    def validate(self,report=None,**kwargs):
        return evidence.safe_report(self.root,self.report if report is None else report,COMMIT,**kwargs)

    def alter(self,ref,transform,json_data=True):
        p=self.root/ref['path'];raw=p.read_bytes();data=json.loads(raw) if json_data else raw.decode()
        result=transform(data)
        if result is not None:data=result
        raw=(json.dumps(data)+'\n').encode() if json_data else data.encode()
        p.write_bytes(raw);ref['sha256']=evidence.digest(raw)

    def test_complete_exact_report_has_closed_public_projection(self):
        result=self.validate();self.assertIsNotNone(result)
        self.assertEqual(result['native_http']['counts']['tests'],2)
        self.assertEqual(len(result['browser']['tests']),2);self.assertEqual(len(result['captures']),8)
        self.assertTrue(result['baked_image_verified'])
        output=json.dumps(result)
        for forbidden in ('PRIVATE_SYNTHETIC','privateLogs','containerId','manifestHashes','"installation":','/node','evidence_directory','"identity":','csrfToken'):
            self.assertNotIn(forbidden,output)
        dest=self.root/'safe';dest.mkdir();evidence.copy_captures(self.root,self.report,dest,result)
        self.assertEqual(sorted(p.name for p in dest.iterdir()),list(evidence.CAPTURES))

    def test_mounted_source_can_only_return_explicit_local_scope(self):
        self.report.update(evidenceMode='mounted-source',imageAttestation=None)
        self.assertIsNone(self.validate())
        local=self.validate(require_image=False);self.assertIsNotNone(local);self.assertFalse(local['baked_image_verified'])
        self.assertIn('Mounted-source',local['limitations'][-1])

    def test_forged_pass_missing_or_unknown_top_level_fields_fail(self):
        for mutate in (lambda r:r.update(result='FAIL'),lambda r:r.update(commit='b'*40),lambda r:r.update(secret='PRIVATE_SYNTHETIC'),lambda r:r.pop('testLogs'),lambda r:r.update(sourceUnchanged=False),lambda r:r.update(schema_version=True)):
            with self.subTest(mutate=mutate):
                r=copy.deepcopy(self.report);mutate(r);self.assertIsNone(self.validate(r))

    def test_image_overlay_stale_hash_wrong_revision_or_role_cannot_attest_image(self):
        mutations=[lambda r:r['imageAttestation'].update(sourceMode='mounted'),lambda r:r['imageAttestation'].update(commit='b'*40),
            lambda r:r['imageAttestation'].update(imageId='sha256:'+'0'*64),lambda r:r['imageAttestation']['sources'].pop(),
            lambda r:r['imageAttestation'].update(packageSha256='0'*64),lambda r:r['containerImages'].pop(),
            lambda r:r['containerImages'][0].update(imageId='sha256:'+'0'*64),lambda r:r['containerImages'][0].update(role='postgres'),
            lambda r:r['containerImages'][0].update(containerId=r['containerImages'][1]['containerId'])]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                r=copy.deepcopy(self.report);mutate(r);self.assertIsNone(self.validate(r))

    def test_changed_source_or_dependency_pin_invalidates_bound_execution(self):
        for name in ('package.json',evidence.NATIVE,'.github/workflows/ci.yml'):
            with self.subTest(name=name):
                p=self.root/name;original=p.read_bytes();p.write_bytes(original+b'\n')
                self.assertIsNone(self.validate());p.write_bytes(original)
        r=copy.deepcopy(self.report);r['runtime']['jose']='0.0.0';self.assertIsNone(self.validate(r))

    def test_source_added_after_run_is_not_silently_excluded(self):
        (self.root/'packages/authn/new.ts').write_text('new source')
        self.assertIsNone(self.validate())

    def test_exact_twelve_migration_checksums_required(self):
        for mutate in (lambda r:r['migrations'].pop(),lambda r:r['migrations'][0].update(sha256='0'*64),lambda r:r['migrations'].append(r['migrations'][0])):
            r=copy.deepcopy(self.report);mutate(r);self.assertIsNone(self.validate(r))

    def test_tap_filtered_duplicate_unknown_skip_and_forged_totals_rejected(self):
        raw=(self.root/self.report['testLogs']['nativeHttp']['path']).read_text()
        bad=[raw.replace('ok 2 - PRIVATE_SYNTHETIC native two\n',''),raw.replace('ok 2 - PRIVATE_SYNTHETIC native two','ok 2 - PRIVATE_SYNTHETIC native one'),
             raw.replace('native two','unregistered'),raw.replace('native two','native two # SKIP'),raw.replace('# pass 2','# pass 1'),raw.replace('1..2','1..1'),raw+'# pass 2\n']
        for data in bad:
            with self.subTest(data=data[-30:]):
                self.alter(self.report['testLogs']['nativeHttp'],lambda _:data,False);self.assertIsNone(self.validate())
        self.alter(self.report['testLogs']['nativeHttp'],lambda _:raw,False);self.assertIsNotNone(self.validate())

    def test_browser_filtered_duplicate_retry_unrun_and_wrong_coordinates_rejected(self):
        original=json.loads((self.root/self.report['testLogs']['browser']['path']).read_text())
        mutations=[lambda d:d['suites'][0]['specs'].pop(),lambda d:d['suites'][0]['specs'][1].update(line=1),lambda d:d['suites'][0]['specs'][0].update(file='other.spec.ts'),
            lambda d:d['suites'][0]['specs'][0]['tests'][0].update(results=[]),lambda d:d['suites'][0]['specs'][0]['tests'][0]['results'].append({'status':'passed','retry':1,'duration':1}),
            lambda d:d['suites'][0]['specs'][0]['tests'][0]['results'][0].update(retry=1),lambda d:d['suites'][0]['specs'][0]['tests'][0]['results'][0].update(status='skipped'),
            lambda d:d['suites'][0]['specs'][0]['tests'][0].update(status='flaky'),lambda d:d['suites'][0]['specs'][0].update(title='unknown'),lambda d:d.update(errors=[{'private':'failure'}])]
        for mutate in mutations:
            d=copy.deepcopy(original);mutate(d);self.alter(self.report['testLogs']['browser'],lambda _:d)
            self.assertIsNone(self.validate())
        self.alter(self.report['testLogs']['browser'],lambda _:original);self.assertIsNotNone(self.validate())

    def test_only_eight_named_current_captures_with_matching_bytes_are_allowed(self):
        for mutate in (lambda r:r['captures'].pop(),lambda r:r['captures'].append(r['captures'][0]),lambda r:r['captures'][0].update(sha256='0'*64),lambda r:r['captures'][0].update(path=r['evidence_directory']+'/login-password.png')):
            r=copy.deepcopy(self.report);mutate(r);self.assertIsNone(self.validate(r))
        ref=self.report['captures'][0];p=self.root/ref['path'];p.write_text('not PNG');ref['sha256']=evidence.digest(p.read_bytes());self.assertIsNone(self.validate())

    def test_three_served_files_must_match_reported_bytes(self):
        r=copy.deepcopy(self.report);r['servedAssets']['js']='0'*64;self.assertIsNone(self.validate(r))
        r=copy.deepcopy(self.report);r['servedAssetFiles']['js']=r['servedAssetFiles']['html'];self.assertIsNone(self.validate(r))
        r=copy.deepcopy(self.report);r['servedAssets']['extra']='0'*64;self.assertIsNone(self.validate(r))

    def test_cleanup_flags_and_real_inventory_equality_are_required(self):
        for key in self.report['cleanup']:
            r=copy.deepcopy(self.report);r['cleanup'][key]=False;self.assertIsNone(self.validate(r))
        self.alter(self.report['privateResourceInventories'][1],lambda d:d['containers'].append('surviving synthetic container'))
        self.assertIsNone(self.validate())

    def test_bad_private_paths_symlinks_stale_logs_and_duplicates_refuse(self):
        for path in ('/etc/passwd','../outside',self.report['evidence_directory']+'/../native-http.tap',self.report['evidence_directory']+'/browser/../../native-http.tap'):
            r=copy.deepcopy(self.report);r['testLogs']['nativeHttp']['path']=path;self.assertIsNone(self.validate(r))
        p=self.root/self.report['testLogs']['nativeHttp']['path'];data=p.read_bytes();p.unlink();target=self.root/'other';target.write_bytes(data);p.symlink_to(target);self.assertIsNone(self.validate())
        p.unlink();p.write_bytes(data)
        r=copy.deepcopy(self.report);r['privateLogs'].append(r['privateLogs'][0]);self.assertIsNone(self.validate(r))
        r=copy.deepcopy(self.report);r['testLogs']['browser']['sha256']='0'*64;self.assertIsNone(self.validate(r))

    def test_report_loader_refuses_duplicate_json_and_missing_file(self):
        self.assertIsNone(evidence.load_report(self.root,COMMIT))
        p=self.root/'.local/evidence/protected-authn.json';p.write_text(json.dumps(self.report));self.assertIsNotNone(evidence.load_report(self.root,COMMIT))
        p.write_text('{"result":"PASS",'+json.dumps(self.report)[1:]);self.assertIsNone(evidence.load_report(self.root,COMMIT))
        p.unlink();p.symlink_to(self.root/self.report['testLogs']['browser']['path']);self.assertIsNone(evidence.load_report(self.root,COMMIT))

    def test_keycloak_missing_or_wrong_client_mapper_and_endpoint_readback_refuses(self):
        original=json.loads((self.root/self.report['keycloakReadback']['path']).read_text())
        mutations=[lambda d:d.clear(),lambda d:d['client'].update(clientId='other'),lambda d:d['client'].update(publicClient=False),
            lambda d:d['client'].update(enabled=1),lambda d:d['client'].update(implicitFlowEnabled=True),
            lambda d:d['client'].update(redirectUris=['http://localhost:4314/*']),lambda d:d['client'].update(webOrigins=['*']),
            lambda d:d['client']['attributes'].update({'pkce.code.challenge.method':'plain'}),
            lambda d:d['client']['attributes'].update({'id.token.signed.response.alg':'HS256'}),
            lambda d:d.update(defaultScopes=[]),lambda d:d.update(defaultScopes=['basic','basic']),
            lambda d:d['authTimeMapper'].update(protocolMapper='oidc-usermodel-attribute-mapper'),
            lambda d:d['authTimeMapper']['config'].update({'user.session.note':'user_attribute','id.token.claim':'false'}),
            lambda d:d['authTimeMapper']['config'].update({'jsonType.label':'String'}),
            lambda d:d['discovery'].update(issuer='https://other.invalid'),
            *[lambda d,key=key:d['discovery'].update({key:'http://other.invalid'}) for key in ('authorization_endpoint','token_endpoint','jwks_uri')]]
        for mutate in mutations:
            data=copy.deepcopy(original);mutate(data)
            self.alter(self.report['keycloakReadback'],lambda _:data)
            self.assertIsNone(self.validate())
        self.alter(self.report['keycloakReadback'],lambda _:original);self.assertIsNotNone(self.validate())

    def test_original_private_installation_plan_is_required_and_digest_bound(self):
        p=self.root/self.report['evidence_directory']/'installation/plan.json';data=p.read_bytes()
        p.write_bytes(data+b' ');self.assertIsNone(self.validate())
        p.unlink();self.assertIsNone(self.validate())
        other=self.root/'other-plan';other.write_bytes(data);p.symlink_to(other);self.assertIsNone(self.validate())
        p.unlink();p.write_bytes(data);self.assertIsNotNone(self.validate())

    def test_browser_actual_window_must_be_contained_without_clock_tolerance(self):
        original=json.loads((self.root/self.report['testLogs']['browser']['path']).read_text())
        for start,duration in (('2020-01-01T00:00:00.000Z',2.5),('2026-11-16T10:00:09.999Z',2.5),('2026-02-30T10:00:01.000Z',2.5)):
            data=copy.deepcopy(original);data['stats'].update(startTime=start,duration=duration)
            self.alter(self.report['testLogs']['browser'],lambda _:data);self.report['browser']=data['stats'];self.assertIsNone(self.validate())
        self.alter(self.report['testLogs']['browser'],lambda _:original);self.report['browser']=original['stats'];self.assertIsNotNone(self.validate())

    def test_installation_codec_matches_independently_spelled_typed_vector(self):
        request='10000000-0000-4000-8000-000000000001';tenant='10000000-0000-4000-8000-000000000007'
        manifest={'formatVersion':1,'requestId':request,'releaseReference':'release/123','deploymentOperatorReference':'operator/ref',
            'expectedDatabaseOid':123,'expectedOwnerRoleOid':456,'predecessorManifestHash':None,
            'operation':{'type':'initialize-tenant','tenantId':tenant,'generation':1}}
        raw=('gc-authn-install/v1;S17:initialize-tenant'+'S10:request_idU'+request+';'+'S11:release_refS11:release/123'+
             'S12:operator_refS12:operator/refS15:expected_db_oidI123;S18:expected_owner_oidI456;S16:predecessor_hashN;'+
             'S9:tenant_idU'+tenant+';S10:generationI1;')
        self.assertEqual(evidence.installation_manifest_hash(manifest),evidence.digest(raw.encode()))

    def test_empty_relinked_wrong_batch_or_unrelated_receipt_hashes_cannot_pass(self):
        path=self.root/self.report['evidence_directory']/'installation/plan.json';original=json.loads(path.read_text());old_hashes=self.report['installation']['manifestHashes']
        changes=[lambda p:p.clear(),lambda p:p['manifests'].pop(),lambda p:p['manifests'][0]['operation'].update(roleName='gc_app'),
            lambda p:p['manifests'][4]['operation'].update(redirectUri='http://localhost:4314/other'),
            lambda p:p['manifests'][5]['operation'].update(identityId='10000000-0000-4000-8000-000000000099'),
            lambda p:p['manifests'][6]['operation'].update(bindingId=p['manifests'][5]['operation']['bindingId']),
            lambda p:p['manifests'][12]['operation'].update(tenantId=p['manifests'][11]['operation']['tenantId']),
            lambda p:p['target'].update(loginRoleOid=p['target']['apiRoleOid']),lambda p:p['manifests'][1].update(requestId=p['manifests'][0]['requestId'])]
        for change in changes:
            batch=copy.deepcopy(original);change(batch)
            # Even internally rehashed malicious plans must obey the exact semantic batch.
            hashes=[];previous=None
            for manifest in batch.get('manifests',[]):
                manifest['predecessorManifestHash']=previous;previous=evidence.installation_manifest_hash(manifest);hashes.append(previous)
            data=(json.dumps(batch)+'\n').encode();path.write_bytes(data)
            self.report['installation'].update(privatePlanSha256=evidence.digest(data),manifestHashes=hashes)
            self.assertIsNone(self.validate())
        data=(json.dumps(original)+'\n').encode();path.write_bytes(data)
        self.report['installation'].update(privatePlanSha256=evidence.digest(data),manifestHashes=['a'*64]+old_hashes[1:]);self.assertIsNone(self.validate())
        self.report['installation']['manifestHashes']=old_hashes;self.assertIsNotNone(self.validate())

    def test_boolean_counts_nan_or_unbounded_duration_cannot_pass(self):
        for mutate in (lambda r:r['nativeHttp'].update(tests=True),lambda r:r['nativeHttp'].update(duration_ms=float('nan')),lambda r:r['browser'].update(duration=500_000),lambda r:r['memoryAdmission'].update(daemon_reserve_bytes=True)):
            r=copy.deepcopy(self.report);mutate(r);self.assertIsNone(self.validate(r))


if __name__=='__main__':unittest.main()
