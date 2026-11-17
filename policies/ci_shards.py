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
                'source_connectors_upgrade',
                'postgres_targets'),
 'governance': ('glossary_upgrade',
                'relation_scope_upgrade',
                'glossary_population_upgrade',
                'lineage_upgrade',
                'classification_upgrade'),
 'quality-basics': ('quality_upgrade',
                    'quality_worker',
                    'lineage_worker',
                    'reference_upgrade',
                    'reference_quality_upgrade',
                    'reference_quality_worker',
                    'reference_structure_upgrade',
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
 'source_connectors_upgrade': './dev test --suite source-connectors-upgrade',
 'postgres_targets': './dev test --suite postgres-targets',
 'glossary_upgrade': './dev test --suite glossary-upgrade',
 'relation_scope_upgrade': './dev test --suite relation-scope-upgrade',
 'glossary_population_upgrade': './dev test --suite glossary-population-upgrade',
 'lineage_upgrade': './dev test --suite lineage-upgrade',
 'classification_upgrade': './dev test --suite classification-upgrade',
 'quality_upgrade': './dev test --suite quality-upgrade',
 'quality_worker': './dev test --suite quality-worker',
 'lineage_worker': './dev test --suite lineage-worker',
 'reference_upgrade': './dev test --suite reference-upgrade',
 'reference_quality_upgrade': './dev test --suite reference-quality-upgrade',
 'reference_quality_worker': './dev test --suite reference-quality-worker',
 'reference_structure_upgrade': './dev test --suite reference-structure-upgrade',
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
            'tests/e2e/vertical-slice.spec.ts tests/e2e/ui-accessibility.spec.ts tests/e2e/models.spec.ts '
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
RETIRED_REPORTS = ('authority-foundation.json',)
STEPS = tuple(COMMANDS)
OUTCOMES = frozenset(("success", "failure", "cancelled", "skipped"))
EVIDENCE = {'security': ('api-summary.json',),
 'authority_authn_foundation': ('authority-authn-foundation.json',),
 'authority_read_original': ('authority-read-original.json',),
 'authority_read_current': ('authority-read-current.json',),
 'glossary_population_upgrade': ('glossary-population-upgrade.json',),
 'protected_authn': ('protected-authn.json',),
 'browser': ('playwright-results.json',)}

def required_steps(shard):
    if shard is None:
        return frozenset(STEPS)
    if shard not in SHARDS:
        raise ValueError('Unknown behavior shard')
    return frozenset((*COMMON, *SHARDS[shard]))

def assignment_hash():
    return hashlib.sha256(json.dumps({'common':COMMON,'shards':SHARDS,'commands':COMMANDS,'superseded':SUPERSEDED,'authorityScopes':AUTHORITY_SCOPES},sort_keys=True,separators=(',',':')).encode()).hexdigest()

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
 '          GC_SOURCE_CONNECTORS_UPGRADE_RESULT: ${{ steps.source_connectors_upgrade.outcome }}\n'
 '          GC_POSTGRES_TARGETS_RESULT: ${{ steps.postgres_targets.outcome }}\n'
 '          GC_GLOSSARY_UPGRADE_RESULT: ${{ steps.glossary_upgrade.outcome }}\n'
 '          GC_RELATION_SCOPE_UPGRADE_RESULT: ${{ steps.relation_scope_upgrade.outcome }}\n'
 '          GC_GLOSSARY_POPULATION_UPGRADE_RESULT: ${{ steps.glossary_population_upgrade.outcome }}\n'
 '          GC_QUALITY_UPGRADE_RESULT: ${{ steps.quality_upgrade.outcome }}\n'
 '          GC_QUALITY_WORKER_RESULT: ${{ steps.quality_worker.outcome }}\n'
 '          GC_LINEAGE_UPGRADE_RESULT: ${{ steps.lineage_upgrade.outcome }}\n'
 '          GC_LINEAGE_WORKER_RESULT: ${{ steps.lineage_worker.outcome }}\n'
 '          GC_CLASSIFICATION_UPGRADE_RESULT: ${{ steps.classification_upgrade.outcome }}\n'
 '          GC_REFERENCE_UPGRADE_RESULT: ${{ steps.reference_upgrade.outcome }}\n'
 '          GC_REFERENCE_QUALITY_UPGRADE_RESULT: ${{ steps.reference_quality_upgrade.outcome }}\n'
 '          GC_REFERENCE_QUALITY_WORKER_RESULT: ${{ steps.reference_quality_worker.outcome }}\n'
 '          GC_REFERENCE_STRUCTURE_UPGRADE_RESULT: ${{ steps.reference_structure_upgrade.outcome }}\n'
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
    require('GC_AUTHORITY_FOUNDATION_RESULT' not in body and 'id: authority_foundation\n' not in body)
    require(body.index('id: authority_authn_foundation\n')<body.index('id: authority_read_original\n')<body.index('id: authority_read_current\n')<body.index('id: source_connectors_upgrade\n'))
    require(body.index('id: browser\n')<body.index('id: protected_authn\n')<body.index('name: Collect bounded redacted evidence')<body.index('name: Stop only this Compose'))
    return True
