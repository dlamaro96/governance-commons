#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Closed CI assignment. Shards never derive obligations from missing results."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

COMMON = ('bootstrap', 'services', 'object_store', 'seed')
SHARDS = {'foundation': ('connectors',
                'security',
                'model_upgrade',
                'asset_type_upgrade',
                'type_migration_upgrade',
                'relations_upgrade',
                'relation_participation_upgrade',
                'business_domains_upgrade',
                'authority_authn_foundation',
                'authority_read_original',
                'authority_read_current',
                'authority_asset_context',
                'content_security_revision',
                'classification_label_identities',
                'reviewed_classification_facts',
                'source_connectors_upgrade',
                'postgres_targets'),
 'governance': ('relation_candidate_original',
                'relation_candidate_current',
                'glossary_upgrade',
                'relation_scope_upgrade',
                'glossary_population_repaired_upgrade',
                'lineage_repaired_upgrade',
                'classification_repaired_upgrade'),
 'quality-basics': ('quality_repaired_upgrade',
                    'quality_worker',
                    'lineage_worker',
                    'reference_repaired_upgrade',
                    'reference_quality_repaired_upgrade',
                    'reference_quality_worker',
                    'reference_structure_repaired_upgrade',
                    'reference_import'),
 'quality-freshness-volume': ('uniqueness_upgrade',
                              'uniqueness_worker',
                              'range_upgrade',
                              'range_worker',
                              'monitoring_upgrade',
                              'freshness_upgrade',
                              'freshness_worker',
                              'freshness_scheduling_upgrade',
                              'volume_upgrade',
                              'volume_worker'),
 'browser': ('business_domain_seed', 'browser', 'protected_authn')}
COMMANDS = {'bootstrap': './dev bootstrap',
 'services': './dev up --profile core',
 'object_store': './dev test --suite object-store',
 'seed': './dev seed --dataset harbor-demo',
 'connectors': './dev test --suite connectors',
 'security': './dev test --suite security',
 'model_upgrade': './dev test --suite model-upgrade',
 'asset_type_upgrade': './dev test --suite asset-type-upgrade',
 'type_migration_upgrade': './dev test --suite type-migration-upgrade',
 'relations_upgrade': './dev test --suite relations-upgrade',
 'relation_participation_upgrade': './dev test --suite relation-participation-upgrade',
 'business_domains_upgrade': './dev test --suite business-domains-upgrade',
 'authority_authn_foundation': './dev test --suite authority-authn-foundation',
 'authority_read_original': './dev test --suite authority-read-original',
 'authority_read_current': './dev test --suite authority-read-current',
 'authority_asset_context': './dev test --suite authority-asset-context',
 'content_security_revision': './dev test --suite content-security-revision',
 'classification_label_identities': './dev test --suite classification-label-identities',
 'reviewed_classification_facts': './dev test --suite reviewed-classification-facts',
 'source_connectors_upgrade': './dev test --suite source-connectors-upgrade',
 'postgres_targets': './dev test --suite postgres-targets',
 'relation_candidate_original': './dev test --suite relation-candidate-original',
 'relation_candidate_current': './dev test --suite relation-candidate-current',
 'glossary_upgrade': './dev test --suite glossary-upgrade',
 'relation_scope_upgrade': './dev test --suite relation-scope-upgrade',
 'glossary_population_repaired_upgrade': './dev test --suite glossary-population-repaired-upgrade',
 'lineage_repaired_upgrade': './dev test --suite lineage-repaired-upgrade',
 'classification_repaired_upgrade': './dev test --suite classification-repaired-upgrade',
 'quality_repaired_upgrade': './dev test --suite quality-repaired-upgrade',
 'quality_worker': './dev test --suite quality-worker',
 'lineage_worker': './dev test --suite lineage-worker',
 'reference_repaired_upgrade': './dev test --suite reference-repaired-upgrade',
 'reference_quality_repaired_upgrade': './dev test --suite reference-quality-repaired-upgrade',
 'reference_quality_worker': './dev test --suite reference-quality-worker',
 'reference_structure_repaired_upgrade': './dev test --suite reference-structure-repaired-upgrade',
 'reference_import': './dev test --suite reference-import',
 'uniqueness_upgrade': './dev test --suite uniqueness-upgrade',
 'uniqueness_worker': './dev test --suite uniqueness-worker',
 'range_upgrade': './dev test --suite range-upgrade',
 'range_worker': './dev test --suite range-worker',
 'monitoring_upgrade': './dev test --suite monitoring-upgrade',
 'freshness_upgrade': './dev test --suite freshness-upgrade',
 'freshness_worker': './dev test --suite freshness-worker',
 'freshness_scheduling_upgrade': './dev test --suite freshness-scheduling-upgrade',
 'volume_upgrade': './dev test --suite volume-upgrade',
 'volume_worker': './dev test --suite volume-worker',
 'business_domain_seed': './dev test --suite business-domain-seed',
 'browser': 'pnpm exec playwright test --config .github/playwright.ci.config.ts '
            'tests/e2e/vertical-slice.spec.ts tests/e2e/catalog-sorting.spec.ts tests/e2e/ui-accessibility.spec.ts tests/e2e/models.spec.ts '
            'tests/e2e/model-migrations.spec.ts tests/e2e/asset-types.spec.ts '
            'tests/e2e/asset-type-migrations.spec.ts tests/e2e/relations.spec.ts '
            'tests/e2e/relation-migrations.spec.ts tests/e2e/business-domains.spec.ts '
            'tests/e2e/source-connectors.spec.ts tests/e2e/postgres-configuration.spec.ts '
            'tests/e2e/approvals.spec.ts tests/e2e/glossary.spec.ts tests/e2e/quality.spec.ts '
            'tests/e2e/lineage.spec.ts tests/e2e/classification.spec.ts tests/e2e/reference-data.spec.ts '
            'tests/e2e/reference-quality.spec.ts tests/e2e/reference-structures.spec.ts '
            'tests/e2e/reference-import.spec.ts tests/e2e/quality-uniqueness.spec.ts '
            'tests/e2e/quality-range.spec.ts tests/e2e/quality-monitoring.spec.ts '
            'tests/e2e/quality-freshness.spec.ts tests/e2e/quality-freshness-monitoring.spec.ts '
            'tests/e2e/quality-volume.spec.ts',
 'protected_authn': 'python3 scripts/runtime-protected-ci.py'}
SUPERSEDED = {'authority_foundation': {'status': 'HISTORICAL_NOT_EXECUTED',
                          'retainedCommand': './dev test --suite authority-foundation',
                          'retainedSchema': 'SQL001–013',
                          'replacedBy': ['authority_read_original', 'authority_read_current'],
                          'limitation': 'Original SQL013 hosted deadline failure is retained. This run '
                                        'neither reruns it nor reports it as PASS.'}}
AUTHORITY_SCOPES = {'authority_read_original': {'command': './dev test --suite authority-read-original',
                             'profile': 'isolated-authority-read-original',
                             'schemaScope': 'SQL001–013 application/refusal/replay, then SQL031 before '
                                            'unchanged original authority assertions',
                             'evidence': 'STEP_OUTCOME_ONLY'},
 'authority_read_current': {'command': './dev test --suite authority-read-current',
                            'profile': 'isolated-authority-read-current',
                            'schemaScope': 'Populated SQL001–030 to SQL031 application, full preservation '
                                           'and inert replay',
                            'evidence': 'STEP_OUTCOME_ONLY'}}
ASSET_CONTEXT_SCOPES = {'authority_asset_context': {
    'command': './dev test --suite authority-asset-context',
    'runner': 'scripts/runtime-test-authority-asset-context.py',
    'arguments': ['--run-local'],
    'profile': 'isolated-inactive-asset-context-sql032',
    'report': 'authority-asset-context.json',
    'schemaScope': 'Isolated SQL001–030, then SQL031/032 with preservation and replay; current-source inactive canonical asset-context cases',
    'outerTimeoutSeconds': 900,
    'contentAuthority': False,
    'evidence': 'STEP_OUTCOME_ONLY'}}
CONTENT_REVISION_SCOPES = {'content_security_revision': {
    'command': './dev test --suite content-security-revision',
    'runner': 'scripts/runtime-test-content-security-revision.py',
    'arguments': ['--run-local'],
    'profile': 'isolated-content-security-revision-sql033',
    'report': 'content-security-revision.json',
    'schemaScope': 'Populated SQL001–032 to SQL033; private content revision, concurrency, snapshot, preservation and replay',
    'outerTimeoutSeconds': 900,
    'contentAuthority': False,
    'evidence': 'STEP_OUTCOME_ONLY'}}
CLASSIFICATION_LABEL_SCOPES = {'classification_label_identities': {
    'command': './dev test --suite classification-label-identities',
    'runner': 'scripts/runtime-test-classification-label-identities.py',
    'arguments': ['--run-local'],
    'profile': 'isolated-classification-label-identities-sql034',
    'report': 'classification-label-identities.json',
    'schemaScope': 'Populated SQL001–033 to SQL034; current-pin identity baseline, terminal retirement, concurrency, preservation and replay',
    'outerTimeoutSeconds': 900,
    'contentAuthority': False,
    'evidence': 'STEP_OUTCOME_ONLY'}}
REVIEWED_CLASSIFICATION_SCOPES = {'reviewed_classification_facts': {
    'command': './dev test --suite reviewed-classification-facts',
    'runner': 'scripts/runtime-test-reviewed-classification-producer.py',
    'arguments': ['--run-local'],
    'profile': 'isolated-reviewed-classification-facts-sql035',
    'report': 'reviewed-classification-producer.json',
    'schemaScope': 'Populated SQL001–034 to SQL035; private producer bindings and inactive reviewed classification facts, complete partition validation, preservation and replay',
    'expectedNativeTests': {'predecessor': 50, 'producerBinding': 23, 'reviewedFacts': 25, 'total': 98},
    'outerTimeoutSeconds': 900,
    'contentAuthority': False,
    'evidence': 'STEP_OUTCOME_ONLY'}}
SUPERSEDED.update({'glossary_population_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                                 'retainedCommand': './dev test --suite glossary-population-upgrade',
                                 'retainedSchema': 'SQL001–018',
                                 'replacedBy': ['glossary_population_repaired_upgrade'],
                                 'limitation': 'Original SQL018 population deadline failure and original '
                                               'commands remain historical. This explicitly repaired chain '
                                               'applies SQL032 before the unchanged population assertions; '
                                               'an old outcome cannot substitute.'},
 'quality_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                     'retainedCommand': './dev test --suite quality-upgrade',
                     'retainedSchema': 'SQL001–019',
                     'replacedBy': ['quality_repaired_upgrade'],
                     'limitation': 'Original SQL018 population deadline failure and original commands remain '
                                   'historical. This explicitly repaired chain applies SQL032 before the '
                                   'unchanged population assertions; an old outcome cannot substitute.'},
 'lineage_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                     'retainedCommand': './dev test --suite lineage-upgrade',
                     'retainedSchema': 'SQL001–020',
                     'replacedBy': ['lineage_repaired_upgrade'],
                     'limitation': 'Original SQL018 population deadline failure and original commands remain '
                                   'historical. This explicitly repaired chain applies SQL032 before the '
                                   'unchanged population assertions; an old outcome cannot substitute.'},
 'classification_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                            'retainedCommand': './dev test --suite classification-upgrade',
                            'retainedSchema': 'SQL001–021',
                            'replacedBy': ['classification_repaired_upgrade'],
                            'limitation': 'Original SQL018 population deadline failure and original commands '
                                          'remain historical. This explicitly repaired chain applies SQL032 '
                                          'before the unchanged population assertions; an old outcome cannot '
                                          'substitute.'},
 'reference_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                       'retainedCommand': './dev test --suite reference-upgrade',
                       'retainedSchema': 'SQL001–022',
                       'replacedBy': ['reference_repaired_upgrade'],
                       'limitation': 'Original SQL018 population deadline failure and original commands '
                                     'remain historical. This explicitly repaired chain applies SQL032 '
                                     'before the unchanged population assertions; an old outcome cannot '
                                     'substitute.'},
 'reference_quality_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                               'retainedCommand': './dev test --suite reference-quality-upgrade',
                               'retainedSchema': 'SQL001–023',
                               'replacedBy': ['reference_quality_repaired_upgrade'],
                               'limitation': 'Original SQL018 population deadline failure and original '
                                             'commands remain historical. This explicitly repaired chain '
                                             'applies SQL032 before the unchanged population assertions; an '
                                             'old outcome cannot substitute.'},
 'reference_structure_upgrade': {'status': 'HISTORICAL_NOT_EXECUTED',
                                 'retainedCommand': './dev test --suite reference-structure-upgrade',
                                 'retainedSchema': 'SQL001–024',
                                 'replacedBy': ['reference_structure_repaired_upgrade'],
                                 'limitation': 'Original SQL018 population deadline failure and original '
                                               'commands remain historical. This explicitly repaired chain '
                                               'applies SQL032 before the unchanged population assertions; '
                                               'an old outcome cannot substitute.'}})
RELATION_SCOPES = {'glossary_population_repaired_upgrade': {'command': './dev test --suite '
                                                     'glossary-population-repaired-upgrade',
                                          'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                                          'arguments': ['--run-local', '--through', '018'],
                                          'profile': 'isolated-governance-repaired-sql018',
                                          'report': 'glossary-population-repaired-upgrade.json',
                                          'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 '
                                                         'before unchanged population assertions; inherited '
                                                         'upgrades and assertions retained through SQL018',
                                          'outerTimeoutSeconds': 1500,
                                          'evidence': 'STEP_OUTCOME_ONLY'},
 'quality_repaired_upgrade': {'command': './dev test --suite quality-repaired-upgrade',
                              'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                              'arguments': ['--run-local', '--through', '019'],
                              'profile': 'isolated-governance-repaired-sql019',
                              'report': 'quality-repaired-upgrade.json',
                              'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 before '
                                             'unchanged population assertions; inherited upgrades and '
                                             'assertions retained through SQL019',
                              'outerTimeoutSeconds': 1800,
                              'evidence': 'STEP_OUTCOME_ONLY'},
 'lineage_repaired_upgrade': {'command': './dev test --suite lineage-repaired-upgrade',
                              'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                              'arguments': ['--run-local', '--through', '020'],
                              'profile': 'isolated-governance-repaired-sql020',
                              'report': 'lineage-repaired-upgrade.json',
                              'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 before '
                                             'unchanged population assertions; inherited upgrades and '
                                             'assertions retained through SQL020',
                              'outerTimeoutSeconds': 1800,
                              'evidence': 'STEP_OUTCOME_ONLY'},
 'classification_repaired_upgrade': {'command': './dev test --suite classification-repaired-upgrade',
                                     'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                                     'arguments': ['--run-local', '--through', '021'],
                                     'profile': 'isolated-governance-repaired-sql021',
                                     'report': 'classification-repaired-upgrade.json',
                                     'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 '
                                                    'before unchanged population assertions; inherited '
                                                    'upgrades and assertions retained through SQL021',
                                     'outerTimeoutSeconds': 2100,
                                     'evidence': 'STEP_OUTCOME_ONLY'},
 'reference_repaired_upgrade': {'command': './dev test --suite reference-repaired-upgrade',
                                'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                                'arguments': ['--run-local', '--through', '022'],
                                'profile': 'isolated-governance-repaired-sql022',
                                'report': 'reference-repaired-upgrade.json',
                                'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 before '
                                               'unchanged population assertions; inherited upgrades and '
                                               'assertions retained through SQL022',
                                'outerTimeoutSeconds': 2400,
                                'evidence': 'STEP_OUTCOME_ONLY'},
 'reference_quality_repaired_upgrade': {'command': './dev test --suite reference-quality-repaired-upgrade',
                                        'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                                        'arguments': ['--run-local', '--through', '023'],
                                        'profile': 'isolated-governance-repaired-sql023',
                                        'report': 'reference-quality-repaired-upgrade.json',
                                        'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 '
                                                       'before unchanged population assertions; inherited '
                                                       'upgrades and assertions retained through SQL023',
                                        'outerTimeoutSeconds': 2700,
                                        'evidence': 'STEP_OUTCOME_ONLY'},
 'reference_structure_repaired_upgrade': {'command': './dev test --suite '
                                                     'reference-structure-repaired-upgrade',
                                          'runner': 'scripts/runtime-test-governance-repaired-upgrade.py',
                                          'arguments': ['--run-local', '--through', '024'],
                                          'profile': 'isolated-governance-repaired-sql024',
                                          'report': 'reference-structure-repaired-upgrade.json',
                                          'schemaScope': 'SQL001–018 application/refusal/replay, then SQL032 '
                                                         'before unchanged population assertions; inherited '
                                                         'upgrades and assertions retained through SQL024',
                                          'outerTimeoutSeconds': 3000,
                                          'evidence': 'STEP_OUTCOME_ONLY'},
 'relation_candidate_original': {'command': './dev test --suite relation-candidate-original',
                                 'runner': 'scripts/runtime-test-relation-candidate-upgrade.py',
                                 'arguments': ['--run-local', '--scope', 'original'],
                                 'profile': 'isolated-relation-candidate-original',
                                 'report': 'relation-candidate-original.json',
                                 'schemaScope': 'SQL001–018 to SQL032 application, complete row '
                                                'preservation, inert replay and unchanged population '
                                                'assertions',
                                 'outerTimeoutSeconds': 900,
                                 'evidence': 'STEP_OUTCOME_ONLY'},
 'relation_candidate_current': {'command': './dev test --suite relation-candidate-current',
                                'runner': 'scripts/runtime-test-relation-candidate-upgrade.py',
                                'arguments': ['--run-local', '--scope', 'current'],
                                'profile': 'isolated-relation-candidate-current',
                                'report': 'relation-candidate-current.json',
                                'schemaScope': 'SQL001–031 to SQL032 application, complete row preservation, '
                                               'inert replay and unchanged population assertions',
                                'outerTimeoutSeconds': 900,
                                'evidence': 'STEP_OUTCOME_ONLY'}}
RETIRED_REPORTS = ('authority-foundation.json', 'glossary-population-upgrade.json', 'quality-upgrade.json', 'lineage-upgrade.json', 'classification-upgrade.json', 'reference-upgrade.json', 'reference-quality-upgrade.json', 'reference-structure-upgrade.json')
STEPS = tuple(COMMANDS)
OUTCOMES = frozenset(("success", "failure", "cancelled", "skipped"))
EVIDENCE = {'security': ('api-summary.json',),
 'authority_authn_foundation': ('authority-authn-foundation.json',),
 'authority_read_original': ('authority-read-original.json',),
 'authority_read_current': ('authority-read-current.json',),
 'authority_asset_context': ('authority-asset-context.json',),
 'content_security_revision': ('content-security-revision.json',),
 'classification_label_identities': ('classification-label-identities.json',),
 'reviewed_classification_facts': ('reviewed-classification-producer.json',),
 'glossary_population_repaired_upgrade': ('glossary-population-repaired-upgrade.json',),
 'quality_repaired_upgrade': ('quality-repaired-upgrade.json',),
 'lineage_repaired_upgrade': ('lineage-repaired-upgrade.json',),
 'classification_repaired_upgrade': ('classification-repaired-upgrade.json',),
 'reference_repaired_upgrade': ('reference-repaired-upgrade.json',),
 'reference_quality_repaired_upgrade': ('reference-quality-repaired-upgrade.json',),
 'reference_structure_repaired_upgrade': ('reference-structure-repaired-upgrade.json',),
 'relation_candidate_original': ('relation-candidate-original.json',),
 'relation_candidate_current': ('relation-candidate-current.json',),
 'protected_authn': ('protected-authn.json',),
 'browser': ('playwright-results.json',)}

def required_steps(shard):
    if shard is None:
        return frozenset(STEPS)
    if shard not in SHARDS:
        raise ValueError('Unknown behavior shard')
    return frozenset((*COMMON, *SHARDS[shard]))

def assignment_hash():
    return hashlib.sha256(json.dumps({'common':COMMON,'shards':SHARDS,'commands':COMMANDS,'superseded':SUPERSEDED,'authorityScopes':AUTHORITY_SCOPES,'assetContextScopes':ASSET_CONTEXT_SCOPES,'contentRevisionScopes':CONTENT_REVISION_SCOPES,'classificationLabelScopes':CLASSIFICATION_LABEL_SCOPES,'reviewedClassificationScopes':REVIEWED_CLASSIFICATION_SCOPES,'relationScopes':RELATION_SCOPES},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def collect_outcomes(environment, shard):
    required = required_steps(shard)
    result, valid = {}, not any('GC_'+step.upper()+'_RESULT' in environment for step in SUPERSEDED)
    for step in STEPS:
        value = environment.get('GC_'+step.upper()+'_RESULT')
        if step not in required:
            # GitHub reports false step conditions as skipped. Success/error
            # from another assignment is contradictory, never ignored.
            valid = valid and value in (None, 'skipped')
            result[step] = 'NOT_IN_SHARD'
        else:
            result[step] = 'skipped' if value is None else value if value in OUTCOMES else 'unknown'
            valid = valid and value == 'success'
    return result, valid

def foreign_evidence(root, shard):
    # Historical artifacts remain on their original runs; never opportunistically publish them here.
    if any((root/'.local/evidence'/name).exists() or (root/'.local/evidence'/name).is_symlink() for name in RETIRED_REPORTS):
        return True
    if shard is None:
        return False
    required = required_steps(shard)
    return any((root/'.local/evidence'/name).exists() or (root/'.local/evidence'/name).is_symlink()
               for step,names in EVIDENCE.items() if step not in required for name in names)

def checkout_identity(root, environment, shard):
    if shard is None:
        return None
    required_steps(shard)
    expected = environment.get('GITHUB_SHA', '')
    repository = environment.get('GITHUB_REPOSITORY', '')
    run_id = environment.get('GITHUB_RUN_ID', '')
    attempt = environment.get('GITHUB_RUN_ATTEMPT', '')
    if not (re.fullmatch(r'[0-9a-f]{40}', expected) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            and all(re.fullmatch(r'[1-9][0-9]{0,19}', value) for value in (run_id,attempt))):
        raise ValueError('Invalid shard execution identity')
    try:
        checked = subprocess.run(['git','rev-parse','--verify','HEAD'],cwd=root,check=True,capture_output=True,text=True,timeout=5).stdout.strip()
    except (OSError,subprocess.SubprocessError) as error:
        raise ValueError('Checkout identity unavailable') from error
    if checked != expected:
        raise ValueError('Checkout revision mismatch')
    return {'shard':shard,'commit':expected,'repository':repository,'run_id':run_id,'run_attempt':attempt,'assignment_sha256':assignment_hash()}

def validate_workflow(text):
    """Require the reviewed literal job/step shape; no dynamic matrix or dispatcher."""
    def require(value):
        if not value:raise ValueError('Workflow shard contract differs')
    require(text.count('\njobs:\n')==1)
    job_text=text.split('\njobs:\n',1)[1]
    jobs = re.findall(r'^  ([a-z_]+):$',job_text,re.M)
    require(len(jobs)==len(set(jobs)) and set(jobs)=={'quality','secrets','required','behavior','behavior_shards'})
    blocks={m.group(1):m.group(2) for m in re.finditer(r'^  ([a-z_]+):\n(.*?)(?=^  [a-z_]+:|\Z)',job_text,re.M|re.S)}
    # Aggregate never downloads or executes any evidence artifact.
    aggregate = '    name: behavior\n    if: always()\n    needs: [behavior_shards]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 2\n    permissions: {}\n    steps:\n      - name: Require every fixed behavior shard to succeed\n        env:\n          SHARDS_RESULT: ${{ needs.behavior_shards.result }}\n        run: test "$SHARDS_RESULT" = success\n'
    require(blocks['behavior']==aggregate)
    required = '    name: required\n    if: always()\n    needs: [quality, secrets, behavior]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 2\n    permissions: {}\n    steps:\n      - name: Require every mandatory child to succeed\n        env:\n          QUALITY_RESULT: ${{ needs.quality.result }}\n          SECRETS_RESULT: ${{ needs.secrets.result }}\n          BEHAVIOR_RESULT: ${{ needs.behavior.result }}\n        run: |\n          test "$QUALITY_RESULT" = success\n          test "$SECRETS_RESULT" = success\n          test "$BEHAVIOR_RESULT" = success\n'
    require(blocks['required']==required)
    body=blocks['behavior_shards']
    header = "    name: behavior (${{ matrix.shard }})\n    runs-on: ubuntu-24.04\n    timeout-minutes: 90\n    strategy:\n      fail-fast: false\n      max-parallel: 5\n      matrix:\n        shard: ["+', '.join(SHARDS)+"]\n    steps:\n"
    require(body.startswith(header))
    require('continue-on-error:' not in body and 'download-artifact' not in body and 'permissions:' not in body)
    steps=re.split(r'^      - ',body[len(header):],flags=re.M)[1:]
    expected_meta = ['uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n'
 '        with:\n'
 '          persist-credentials: false\n',
 'uses: pnpm/action-setup@73e46992e05b19abd31f2f3c20e0e7370d762115 # v6.1.1\n'
 '        with:\n'
 '          version: 10.32.1\n'
 '          run_install: false\n',
 'uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0\n'
 '        with:\n'
 '          node-version: 24.22.3\n'
 '          package-manager-cache: false\n',
 'uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0\n'
 '        with:\n'
 '          python-version: 3.14.5\n',
 'name: Install exact dependency lock\n        run: pnpm install --frozen-lockfile\n',
 'name: Install browser and Linux dependencies\n'
 "        if: success() && matrix.shard == 'browser'\n"
 '        run: pnpm exec playwright install --with-deps chromium\n',
 'name: Collect bounded redacted evidence\n'
 '        if: always()\n'
 '        env:\n'
 '          GC_BEHAVIOR_SHARD: ${{ matrix.shard }}\n'
 '          GC_BOOTSTRAP_RESULT: ${{ steps.bootstrap.outcome }}\n'
 '          GC_SERVICES_RESULT: ${{ steps.services.outcome }}\n'
 '          GC_OBJECT_STORE_RESULT: ${{ steps.object_store.outcome }}\n'
 '          GC_SEED_RESULT: ${{ steps.seed.outcome }}\n'
 '          GC_CONNECTORS_RESULT: ${{ steps.connectors.outcome }}\n'
 '          GC_SECURITY_RESULT: ${{ steps.security.outcome }}\n'
 '          GC_MODEL_UPGRADE_RESULT: ${{ steps.model_upgrade.outcome }}\n'
 '          GC_ASSET_TYPE_UPGRADE_RESULT: ${{ steps.asset_type_upgrade.outcome }}\n'
 '          GC_TYPE_MIGRATION_UPGRADE_RESULT: ${{ steps.type_migration_upgrade.outcome }}\n'
 '          GC_RELATIONS_UPGRADE_RESULT: ${{ steps.relations_upgrade.outcome }}\n'
 '          GC_RELATION_PARTICIPATION_UPGRADE_RESULT: ${{ steps.relation_participation_upgrade.outcome }}\n'
 '          GC_BUSINESS_DOMAINS_UPGRADE_RESULT: ${{ steps.business_domains_upgrade.outcome }}\n'
 '          GC_BUSINESS_DOMAIN_SEED_RESULT: ${{ steps.business_domain_seed.outcome }}\n'
 '          GC_AUTHORITY_AUTHN_FOUNDATION_RESULT: ${{ steps.authority_authn_foundation.outcome }}\n'
 '          GC_AUTHORITY_READ_ORIGINAL_RESULT: ${{ steps.authority_read_original.outcome }}\n'
 '          GC_AUTHORITY_READ_CURRENT_RESULT: ${{ steps.authority_read_current.outcome }}\n'
 '          GC_AUTHORITY_ASSET_CONTEXT_RESULT: ${{ steps.authority_asset_context.outcome }}\n'
 '          GC_CONTENT_SECURITY_REVISION_RESULT: ${{ steps.content_security_revision.outcome }}\n'
 '          GC_CLASSIFICATION_LABEL_IDENTITIES_RESULT: ${{ steps.classification_label_identities.outcome }}\n'
 '          GC_REVIEWED_CLASSIFICATION_FACTS_RESULT: ${{ steps.reviewed_classification_facts.outcome }}\n'
 '          GC_SOURCE_CONNECTORS_UPGRADE_RESULT: ${{ steps.source_connectors_upgrade.outcome }}\n'
 '          GC_POSTGRES_TARGETS_RESULT: ${{ steps.postgres_targets.outcome }}\n'
 '          GC_RELATION_CANDIDATE_ORIGINAL_RESULT: ${{ steps.relation_candidate_original.outcome }}\n'
 '          GC_RELATION_CANDIDATE_CURRENT_RESULT: ${{ steps.relation_candidate_current.outcome }}\n'
 '          GC_GLOSSARY_UPGRADE_RESULT: ${{ steps.glossary_upgrade.outcome }}\n'
 '          GC_RELATION_SCOPE_UPGRADE_RESULT: ${{ steps.relation_scope_upgrade.outcome }}\n'
 '          GC_GLOSSARY_POPULATION_REPAIRED_UPGRADE_RESULT: ${{ steps.glossary_population_repaired_upgrade.outcome }}\n'
 '          GC_QUALITY_REPAIRED_UPGRADE_RESULT: ${{ steps.quality_repaired_upgrade.outcome }}\n'
 '          GC_QUALITY_WORKER_RESULT: ${{ steps.quality_worker.outcome }}\n'
 '          GC_LINEAGE_REPAIRED_UPGRADE_RESULT: ${{ steps.lineage_repaired_upgrade.outcome }}\n'
 '          GC_LINEAGE_WORKER_RESULT: ${{ steps.lineage_worker.outcome }}\n'
 '          GC_CLASSIFICATION_REPAIRED_UPGRADE_RESULT: ${{ steps.classification_repaired_upgrade.outcome }}\n'
 '          GC_REFERENCE_REPAIRED_UPGRADE_RESULT: ${{ steps.reference_repaired_upgrade.outcome }}\n'
 '          GC_REFERENCE_QUALITY_REPAIRED_UPGRADE_RESULT: ${{ steps.reference_quality_repaired_upgrade.outcome }}\n'
 '          GC_REFERENCE_QUALITY_WORKER_RESULT: ${{ steps.reference_quality_worker.outcome }}\n'
 '          GC_REFERENCE_STRUCTURE_REPAIRED_UPGRADE_RESULT: ${{ steps.reference_structure_repaired_upgrade.outcome }}\n'
 '          GC_REFERENCE_IMPORT_RESULT: ${{ steps.reference_import.outcome }}\n'
 '          GC_UNIQUENESS_UPGRADE_RESULT: ${{ steps.uniqueness_upgrade.outcome }}\n'
 '          GC_UNIQUENESS_WORKER_RESULT: ${{ steps.uniqueness_worker.outcome }}\n'
 '          GC_RANGE_UPGRADE_RESULT: ${{ steps.range_upgrade.outcome }}\n'
 '          GC_RANGE_WORKER_RESULT: ${{ steps.range_worker.outcome }}\n'
 '          GC_MONITORING_UPGRADE_RESULT: ${{ steps.monitoring_upgrade.outcome }}\n'
 '          GC_FRESHNESS_UPGRADE_RESULT: ${{ steps.freshness_upgrade.outcome }}\n'
 '          GC_FRESHNESS_SCHEDULING_UPGRADE_RESULT: ${{ steps.freshness_scheduling_upgrade.outcome }}\n'
 '          GC_FRESHNESS_WORKER_RESULT: ${{ steps.freshness_worker.outcome }}\n'
 '          GC_VOLUME_UPGRADE_RESULT: ${{ steps.volume_upgrade.outcome }}\n'
 '          GC_VOLUME_WORKER_RESULT: ${{ steps.volume_worker.outcome }}\n'
 '          GC_BROWSER_RESULT: ${{ steps.browser.outcome }}\n'
 '          GC_PROTECTED_AUTHN_RESULT: ${{ steps.protected_authn.outcome }}\n'
 '        run: python3 policies/ci_evidence.py --shard "$GC_BEHAVIOR_SHARD"\n',
 'name: Preserve only safe behavior summary and catalog screenshots\n'
 '        if: always()\n'
 '        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n'
 '        with:\n'
 '          name: behavior-${{ matrix.shard }}-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
 '}}\n'
 '          path: .local/ci-artifacts/\n'
 '          include-hidden-files: true\n'
 '          retention-days: 14\n'
 '          if-no-files-found: error\n',
 'name: Stop only this Compose project and preserve volumes\n'
 "        if: always() && steps.bootstrap.outcome == 'success'\n"
 '        run: ./dev down\n']
    require([block for block in steps if not re.search(r'^        id:',block,re.M)]==expected_meta)
    identified={}
    for block in steps:
        ids=re.findall(r'^        id: (\w+)$',block,re.M)
        require(len(ids)<=1)
        if not ids:continue
        step=ids[0];require(step in COMMANDS and step not in identified);identified[step]=block
        owner=next((name for name,assigned in SHARDS.items() if step in assigned),None)
        expected_if=[] if owner is None else ["success() && matrix.shard == '"+owner+"'"]
        require(re.findall(r'^        if: (.+)$',block,re.M)==expected_if)
        require(re.findall(r'^        run: (.+)$',block,re.M)==[COMMANDS[step]])
        # No additional per-step keys may silently replace commands or budgets.
        require(all(line.startswith(('        id: ','        if: ','        run: ')) for line in block.splitlines()[1:] if line))
    require(set(identified)==set(STEPS))
    required_fragments = ['      - name: Collect bounded redacted evidence\n        if: always()\n        env:\n          GC_BEHAVIOR_SHARD: ${{ matrix.shard }}', '        run: python3 policies/ci_evidence.py --shard "$GC_BEHAVIOR_SHARD"', '          name: behavior-${{ matrix.shard }}-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}', '          path: .local/ci-artifacts/\n          include-hidden-files: true\n          retention-days: 14\n          if-no-files-found: error', "      - name: Stop only this Compose project and preserve volumes\n        if: always() && steps.bootstrap.outcome == 'success'\n        run: ./dev down", "      - name: Install browser and Linux dependencies\n        if: success() && matrix.shard == 'browser'\n        run: pnpm exec playwright install --with-deps chromium"]
    for fragment in required_fragments:require(body.count(fragment)==1)
    for step in STEPS:require(body.count('GC_'+step.upper()+'_RESULT: ${{ steps.'+step+'.outcome }}')==1)
    require('permissions:\n  contents: read\n' in text and text.count('permissions:')==3)
    require('run: python3 policies/test_ci_shards.py' in blocks['quality'])
    require('run: python3 scripts/test_authority_read_upgrade.py' in blocks['quality'])
    context_control = ('      - name: Inactive asset-context lifecycle qualification controls\n'
                       '        run: python3 scripts/test_authority_asset_context.py\n')
    require(re.findall(r'^      - name: Inactive asset-context lifecycle qualification controls\n.*?(?=^      - |\Z)',
                       blocks['quality'], re.M | re.S) == [context_control])
    require(text.count('run: python3 scripts/test_authority_asset_context.py') == 1)
    require('        run: python3 scripts/test_authority_read_upgrade.py\n' + context_control in blocks['quality'])
    revision_control = ('      - name: Content-security revision lifecycle controls\n'
                        '        run: python3 scripts/test_content_security_revision.py\n')
    require(re.findall(r'^      - name: Content-security revision lifecycle controls\n.*?(?=^      - |\Z)',
                       blocks['quality'], re.M | re.S) == [revision_control])
    require(text.count('run: python3 scripts/test_content_security_revision.py') == 1)
    require(context_control + revision_control in blocks['quality'])
    identity_control = ('      - name: Classification label identity lifecycle controls\n'
                        '        run: python3 scripts/test_classification_label_identities.py\n')
    require(re.findall(r'^      - name: Classification label identity lifecycle controls\n.*?(?=^      - |\Z)',
                       blocks['quality'], re.M | re.S) == [identity_control])
    require(text.count('run: python3 scripts/test_classification_label_identities.py') == 1)
    require(revision_control + identity_control in blocks['quality'])
    reviewed_control = ('      - name: Reviewed classification producer and fact qualification controls\n'
                        '        run: python3 scripts/test_reviewed_classification_producer.py\n')
    require(re.findall(r'^      - name: Reviewed classification producer and fact qualification controls\n.*?(?=^      - |\Z)',
                       blocks['quality'], re.M | re.S) == [reviewed_control])
    require(text.count('run: python3 scripts/test_reviewed_classification_producer.py') == 1)
    require(identity_control + reviewed_control in blocks['quality'])
    for step in SUPERSEDED:
        require('GC_'+step.upper()+'_RESULT' not in body and 'id: '+step+'\n' not in body)
    for control in ('test_relation_candidate_upgrade.py','test_governance_repaired_chain.py','test_runtime_routing.py'):
        require('run: python3 scripts/'+control in blocks['quality'])
    require(body.index('id: authority_authn_foundation\n')<body.index('id: authority_read_original\n')<body.index('id: authority_read_current\n')<body.index('id: authority_asset_context\n')<body.index('id: content_security_revision\n')<body.index('id: classification_label_identities\n')<body.index('id: reviewed_classification_facts\n')<body.index('id: source_connectors_upgrade\n'))
    require(body.index('id: browser\n')<body.index('id: protected_authn\n')<body.index('name: Collect bounded redacted evidence')<body.index('name: Stop only this Compose'))
    return True
