#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only shard admission and actual collector controls; no Docker or network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import ci_shards as policy
import test_ci_evidence as evidence_tests

ROOT = Path(__file__).resolve().parents[1]


class AssignmentTests(unittest.TestCase):
    def environment(self, shard):
        return {'GC_'+step.upper()+'_RESULT':'success' if step in policy.required_steps(shard) else 'skipped' for step in policy.STEPS}

    def test_exact_closed_union_and_shared_setup(self):
        self.assertEqual(tuple(policy.SHARDS), ('foundation','governance','quality-basics','quality-freshness-volume','browser'))
        self.assertEqual(policy.COMMON, ('bootstrap','services','object_store','seed'))
        assigned=[step for group in policy.SHARDS.values() for step in group]
        self.assertEqual(len(assigned),len(set(assigned)))
        self.assertFalse(set(assigned)&set(policy.COMMON))
        self.assertEqual(set((*policy.COMMON,*assigned)),set(policy.STEPS))
        self.assertEqual(len(policy.STEPS),45)

    def test_each_shard_requires_all_its_results(self):
        for shard in policy.SHARDS:
            env=self.environment(shard)
            results,valid=policy.collect_outcomes(env,shard)
            self.assertTrue(valid)
            self.assertEqual({k for k,v in results.items() if v=='success'},policy.required_steps(shard))
            for step in policy.required_steps(shard):
                for invalid in (None,'skipped','failure','cancelled','unknown','NOT_IN_SHARD','SUCCESS',''):
                    with self.subTest(shard=shard,step=step,value=invalid):
                        changed=dict(env)
                        if invalid is None:changed.pop('GC_'+step.upper()+'_RESULT')
                        else:changed['GC_'+step.upper()+'_RESULT']=invalid
                        self.assertFalse(policy.collect_outcomes(changed,shard)[1])

    def test_foreign_success_failure_and_caller_supplied_sentinel_refuse(self):
        for shard in policy.SHARDS:
            env=self.environment(shard)
            for step in set(policy.STEPS)-policy.required_steps(shard):
                for invalid in ('success','failure','cancelled','unknown','NOT_IN_SHARD'):
                    with self.subTest(shard=shard,step=step,value=invalid):
                        changed={**env,'GC_'+step.upper()+'_RESULT':invalid}
                        self.assertFalse(policy.collect_outcomes(changed,shard)[1])

    def test_unknown_shard_never_infers_an_empty_subset(self):
        for name in ('','all','browser,foundation','Browser','quality','$(anything)'):
            with self.assertRaises(ValueError):policy.required_steps(name)

    def test_unsharded_mode_still_requires_all_work(self):
        env={'GC_'+step.upper()+'_RESULT':'success' for step in policy.STEPS}
        self.assertTrue(policy.collect_outcomes(env,None)[1])
        for step in policy.STEPS:
            changed=dict(env);changed.pop('GC_'+step.upper()+'_RESULT')
            self.assertFalse(policy.collect_outcomes(changed,None)[1])

    def test_foreign_evidence_is_closed_including_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'.local/evidence';folder.mkdir(parents=True)
            for step,names in policy.EVIDENCE.items():
                owner=next(shard for shard in policy.SHARDS if step in policy.required_steps(shard))
                for name in names:
                    file=folder/name;file.write_text('{}')
                    self.assertFalse(policy.foreign_evidence(root,owner))
                    for shard in policy.SHARDS:
                        if shard!=owner:self.assertTrue(policy.foreign_evidence(root,shard))
                    file.unlink();file.symlink_to(folder/'missing')
                    for shard in policy.SHARDS:
                        if shard!=owner:self.assertTrue(policy.foreign_evidence(root,shard))
                    file.unlink()


class IdentityTests(unittest.TestCase):
    def test_real_checkout_identity_and_wrong_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subprocess.run(['git','init','--quiet',str(root)],check=True,capture_output=True,timeout=10)
            subprocess.run(['git','-c','user.name=Synthetic test','-c','user.email=synthetic@example.invalid','-c','commit.gpgsign=false','commit','--allow-empty','--quiet','-m','Synthetic identity'],cwd=root,check=True,capture_output=True,timeout=10)
            commit=subprocess.run(['git','rev-parse','HEAD'],cwd=root,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
            env={'GITHUB_SHA':commit,'GITHUB_REPOSITORY':'fixture/repository','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'2'}
            identity=policy.checkout_identity(root,env,'foundation')
            self.assertEqual(identity,{'commit':commit,'repository':'fixture/repository','run_id':'1','run_attempt':'2','shard':'foundation','assignment_sha256':policy.assignment_hash()})
            for key,value in [('GITHUB_SHA','0'*40),('GITHUB_REPOSITORY','bad/value/extra'),('GITHUB_RUN_ID','01'),('GITHUB_RUN_ATTEMPT','0')]:
                with self.subTest(key=key),self.assertRaises(ValueError):policy.checkout_identity(root,{**env,key:value},'foundation')

    def test_checkout_failure_and_timeout_fail_closed(self):
        env={'GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY':'fixture/repository','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1'}
        for error in (OSError(),subprocess.TimeoutExpired('git',5),subprocess.CalledProcessError(1,'git')):
            with patch.object(policy.subprocess,'run',side_effect=error),self.assertRaises(ValueError):policy.checkout_identity(ROOT,env,'browser')


class WorkflowTests(unittest.TestCase):
    def test_current_workflow_matches_static_reviewed_contract(self):
        self.assertTrue(policy.validate_workflow((ROOT/'.github/workflows/ci.yml').read_text()))

    def test_mutations_cannot_omit_reroute_mask_or_import_evidence(self):
        text=(ROOT/'.github/workflows/ci.yml').read_text()
        replacements=[
            ('fail-fast: false','fail-fast: true'),('max-parallel: 5','max-parallel: 4'),
            ('shard: [foundation, governance, quality-basics, quality-freshness-volume, browser]','shard: [foundation, governance, quality-basics, browser]'),
            ('shard: [foundation, governance, quality-basics, quality-freshness-volume, browser]','shard: [foundation, governance, governance, quality-freshness-volume, browser]'),
            ('needs: [behavior_shards]','needs: [quality]'),('needs: [quality, secrets, behavior]','needs: [quality, secrets]'),
            ('run: test "$SHARDS_RESULT" = success','run: true'),
            ('if: success() && matrix.shard == \'foundation\'','if: success() && matrix.shard == \'browser\''),
            ('run: ./dev test --suite security','run: true'),
            ('run: ./dev test --suite security','continue-on-error: true\n        run: ./dev test --suite security'),
            ('run: python3 policies/ci_evidence.py --shard "$GC_BEHAVIOR_SHARD"','run: python3 policies/ci_evidence.py'),
            ('name: Collect bounded redacted evidence\n        if: always()','name: Collect bounded redacted evidence\n        if: false'),
            ('GC_SECURITY_RESULT: ${{ steps.security.outcome }}','GC_SECURITY_RESULT: success'),
            ('path: .local/ci-artifacts/','path: .local/'),
            ('name: behavior-${{ matrix.shard }}-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}','name: behavior-${{ github.sha }}'),
            ('run: ./dev down','run: true'),('permissions:\n  contents: read','permissions:\n  contents: write'),
            ('      - name: Install exact dependency lock\n        run: pnpm install --frozen-lockfile','      - uses: actions/download-artifact@untrusted'),
            ('if: always() && steps.bootstrap.outcome == \'success\'','if: false'),
        ]
        for before,after in replacements:
            with self.subTest(before=before):
                self.assertIn(before,text)
                with self.assertRaises(ValueError):policy.validate_workflow(text.replace(before,after))
        for step in policy.STEPS:
            with self.subTest(omitted=step),self.assertRaises(ValueError):policy.validate_workflow(text.replace('        id: '+step+'\n',''))


class CollectorTests(unittest.TestCase):
    def collect(self,**kwargs):return evidence_tests.EvidenceGateTests(methodName='runTest').collect(**kwargs)

    def test_all_five_actual_collectors_pass_only_assigned_evidence(self):
        for shard in policy.SHARDS:
            with self.subTest(shard=shard):
                code,report=self.collect(shard=shard)
                self.assertEqual(code,0);self.assertEqual(report['outcome'],'PASS')
                self.assertEqual(report['shard']['shard'],shard)
                self.assertEqual(report['shard']['assignment_sha256'],policy.assignment_hash())
                self.assertEqual(len(report['tests']),37 if shard=='browser' else 0)
                for step,value in report['steps'].items():self.assertEqual(value,'success' if step in policy.required_steps(shard) else 'NOT_IN_SHARD')

    def test_each_actual_collector_refuses_missing_assigned_and_foreign_success(self):
        for shard,steps in policy.SHARDS.items():
            with self.subTest(shard=shard):
                code,report=self.collect(shard=shard,omitted_step=steps[0])
                self.assertEqual(code,1);self.assertEqual(report['outcome'],'NOT_PASSED')
                foreign=next(s for s in policy.STEPS if s not in policy.required_steps(shard))
                code,report=self.collect(shard=shard,shard_environment={'GC_'+foreign.upper()+'_RESULT':'success'})
                self.assertEqual(code,1)

    def test_actual_collector_refuses_foreign_artifacts_without_publishing_them(self):
        for name in ('api-summary.json','authority-authn-foundation.json','authority-read-original.json','authority-read-current.json','authority-foundation.json','protected-authn.json','playwright-results.json'):
            code,report=self.collect(shard='quality-basics',retained_foreign=name)
            self.assertEqual(code,1);self.assertEqual(report['foreign_evidence'],'REFUSED')
            self.assertEqual(report['tests'],[]);self.assertEqual(report['screenshots'],[])

    def test_api_and_authentication_owner_still_requires_exact_evidence(self):
        for kwargs in ({'omit_api':True},{'api_mutation':lambda x:x.update(commit='b'*40)},{'omit_authn':True},{'authn_mutation':lambda x:x['cleanup'].update(ownedRemoved=False)}):
            code,report=self.collect(shard='foundation',**kwargs)
            self.assertEqual(code,1);self.assertEqual(report['outcome'],'NOT_PASSED')

    def test_browser_owner_keeps_exact_journeys_attempts_and_protected_image(self):
        for mutation in (lambda rows:rows.pop(),lambda rows:rows.append(rows[-1]),lambda rows:rows[-1]['tests'][0]['results'].append({'status':'passed'}),lambda rows:rows[-1]['tests'][0].update(status='skipped')):
            code,report=self.collect(shard='browser',mutation=mutation)
            self.assertEqual(code,1)
        code,report=self.collect(shard='browser',protected_mutation=lambda r:r.update(evidenceMode='mounted-source',imageAttestation=None))
        self.assertEqual(code,1)


class AuthorityTransitionTests(unittest.TestCase):
    def test_explicit_transition_and_distinct_scope_contracts(self):
        self.assertNotIn('authority_foundation',policy.STEPS)
        self.assertIn('authority_foundation',policy.SUPERSEDED)
        history=policy.SUPERSEDED['authority_foundation']
        self.assertEqual(history['status'],'HISTORICAL_NOT_EXECUTED')
        self.assertEqual(history['retainedCommand'],'./dev test --suite authority-foundation')
        self.assertEqual(history['replacedBy'],['authority_read_original','authority_read_current'])
        self.assertIn('authority-foundation.json',policy.RETIRED_REPORTS)
        self.assertEqual(set(policy.AUTHORITY_SCOPES),set(history['replacedBy']))
        for scope in ('original','current'):
            step='authority_read_'+scope
            self.assertIn(step,policy.SHARDS['foundation'])
            self.assertEqual(policy.COMMANDS[step],'./dev test --suite authority-read-'+scope)
            self.assertEqual(policy.EVIDENCE[step],('authority-read-'+scope+'.json',))
            self.assertEqual(policy.AUTHORITY_SCOPES[step]['profile'],'isolated-authority-read-'+scope)
            self.assertEqual(policy.AUTHORITY_SCOPES[step]['evidence'],'STEP_OUTCOME_ONLY')
        self.assertNotEqual(policy.AUTHORITY_SCOPES['authority_read_original']['schemaScope'],policy.AUTHORITY_SCOPES['authority_read_current']['schemaScope'])

    def test_no_legacy_environment_value_can_substitute_or_coexist(self):
        for shard in (None,*policy.SHARDS):
            env={'GC_'+step.upper()+'_RESULT':'success' if step in policy.required_steps(shard) else 'skipped' for step in policy.STEPS}
            self.assertTrue(policy.collect_outcomes(env,shard)[1])
            for value in ('success','failure','skipped','cancelled','NOT_IN_SHARD','',None):
                with self.subTest(shard=shard,value=value):
                    self.assertFalse(policy.collect_outcomes({**env,'GC_AUTHORITY_FOUNDATION_RESULT':value},shard)[1])

    def test_retired_report_refuses_every_shard_and_unsharded_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'.local/evidence';folder.mkdir(parents=True)
            file=folder/'authority-foundation.json'
            for symlink in (False,True):
                if symlink:file.symlink_to(folder/'absent-private-report')
                else:file.write_text('{}')
                for shard in (None,*policy.SHARDS):self.assertTrue(policy.foreign_evidence(root,shard))
                file.unlink()

    def test_real_collector_discloses_both_scopes_without_ingesting_raw_reports(self):
        collect=evidence_tests.EvidenceGateTests(methodName='runTest').collect
        code,report=collect(shard='foundation')
        self.assertEqual(code,0)
        self.assertNotIn('authority_foundation',report['steps'])
        self.assertEqual(report['superseded_outcomes'],policy.SUPERSEDED)
        self.assertEqual(report['authority_foundation_diagnostic'],'HISTORICAL_NOT_EXECUTED')
        for step in policy.AUTHORITY_SCOPES:
            self.assertEqual(report['authority_qualifications'][step],{**policy.AUTHORITY_SCOPES[step],'outcome':'success'})
            for value in (None,'failure','skipped','cancelled'):
                kwargs={'omitted_step':step} if value is None else {'failed_step':step,'failed_outcome':value}
                code,refused=collect(shard='foundation',**kwargs)
                self.assertEqual(code,1);self.assertEqual(refused['outcome'],'NOT_PASSED')
            code,_=collect(shard='foundation',omitted_step=step,shard_environment={'GC_AUTHORITY_FOUNDATION_RESULT':'success'})
            self.assertEqual(code,1)
        code,refused=collect(shard='foundation',shard_environment={'GC_AUTHORITY_FOUNDATION_RESULT':'success'})
        self.assertEqual(code,1)

    def test_scope_crossing_duplicates_legacy_alias_and_control_omission_refuse(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        mutations=[
            ('run: ./dev test --suite authority-read-original','run: ./dev test --suite authority-read-current'),
            ('run: ./dev test --suite authority-read-current','run: ./dev test --suite authority-read-original'),
            ('id: authority_read_current','id: authority_read_original'),
            ('id: authority_read_original','id: authority_foundation'),
            ('GC_AUTHORITY_READ_CURRENT_RESULT: ${{ steps.authority_read_current.outcome }}','GC_AUTHORITY_READ_CURRENT_RESULT: ${{ steps.authority_read_original.outcome }}'),
            ('GC_AUTHORITY_READ_CURRENT_RESULT: ${{ steps.authority_read_current.outcome }}','GC_AUTHORITY_FOUNDATION_RESULT: success'),
            ('run: python3 scripts/test_authority_read_upgrade.py','run: true'),
        ]
        for before,after in mutations:
            with self.subTest(before=before),self.assertRaises(ValueError):policy.validate_workflow(workflow.replace(before,after))


class RepairedRelationTransitionTests(unittest.TestCase):
    OLD = ('glossary_population_upgrade','quality_upgrade','lineage_upgrade','classification_upgrade',
           'reference_upgrade','reference_quality_upgrade','reference_structure_upgrade')
    NEW = tuple(step.replace('_upgrade','_repaired_upgrade') for step in OLD)

    def test_exact_seven_replacements_and_two_new_scopes(self):
        self.assertEqual(set(policy.SUPERSEDED),{'authority_foundation',*self.OLD})
        self.assertEqual(set(policy.RELATION_SCOPES),{*self.NEW,'relation_candidate_original','relation_candidate_current'})
        self.assertEqual(len(policy.SHARDS['governance']),7)
        for index,(old,new) in enumerate(zip(self.OLD,self.NEW),18):
            history=policy.SUPERSEDED[old];scope=policy.RELATION_SCOPES[new]
            self.assertNotIn(old,policy.STEPS);self.assertIn(new,policy.STEPS)
            self.assertEqual(history['retainedCommand'],'./dev test --suite '+old.replace('_','-'))
            self.assertEqual(history['status'],'HISTORICAL_NOT_EXECUTED');self.assertEqual(history['replacedBy'],[new])
            self.assertEqual(scope['runner'],'scripts/runtime-test-governance-repaired-upgrade.py')
            self.assertEqual(scope['arguments'],['--run-local','--through',str(index).zfill(3)])
            self.assertEqual(scope['profile'],'isolated-governance-repaired-sql'+str(index).zfill(3))
            self.assertEqual(scope['evidence'],'STEP_OUTCOME_ONLY')
        for name in ('original','current'):
            step='relation_candidate_'+name;scope=policy.RELATION_SCOPES[step]
            self.assertIn(step,policy.SHARDS['governance'])
            self.assertEqual(scope['arguments'],['--run-local','--scope',name])
            self.assertEqual(scope['runner'],'scripts/runtime-test-relation-candidate-upgrade.py')
            self.assertEqual(scope['outerTimeoutSeconds'],900)
        self.assertNotEqual(policy.RELATION_SCOPES['relation_candidate_original']['schemaScope'],policy.RELATION_SCOPES['relation_candidate_current']['schemaScope'])

    def test_every_historical_environment_outcome_refuses_substitution_and_coexistence(self):
        for shard in (None,*policy.SHARDS):
            env={'GC_'+step.upper()+'_RESULT':'success' if step in policy.required_steps(shard) else 'skipped' for step in policy.STEPS}
            for old in self.OLD:
                for value in ('success','failure','skipped','cancelled','NOT_IN_SHARD','',None):
                    with self.subTest(shard=shard,old=old,value=value):
                        self.assertFalse(policy.collect_outcomes({**env,'GC_'+old.upper()+'_RESULT':value},shard)[1])

    def test_historical_reports_never_become_repaired_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'.local/evidence';folder.mkdir(parents=True)
            for old in self.OLD:
                path=folder/(old.replace('_','-')+'.json')
                for symlink in (False,True):
                    if symlink:path.symlink_to(folder/'absent')
                    else:path.write_text('{"outcome":"PASS"}')
                    for shard in (None,*policy.SHARDS):self.assertTrue(policy.foreign_evidence(root,shard))
                    path.unlink()

    def test_new_report_ownership_allows_nested_private_stage_records_but_not_foreign_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'.local/evidence';folder.mkdir(parents=True)
            nested=folder/'synthetic-owned-stage';nested.mkdir();(nested/'report.json').write_text('{"phase":"predecessor"}')
            for step,scope in policy.RELATION_SCOPES.items():
                file=folder/scope['report'];file.write_text('{"private":"not ingested"}')
                owner=next(shard for shard,steps in policy.SHARDS.items() if step in steps)
                self.assertFalse(policy.foreign_evidence(root,owner))
                for other in set(policy.SHARDS)-{owner}:self.assertTrue(policy.foreign_evidence(root,other))
                file.unlink()

    def test_real_collector_missing_failure_cancelled_and_historical_substitution_all_fail(self):
        collect=evidence_tests.EvidenceGateTests(methodName='runTest').collect
        for step in policy.RELATION_SCOPES:
            owner=next(shard for shard,steps in policy.SHARDS.items() if step in steps)
            for invalid in (None,'failure','cancelled','skipped','NOT_IN_SHARD'):
                options={'omitted_step':step} if invalid is None else {'failed_step':step,'failed_outcome':invalid}
                code,report=collect(shard=owner,**options)
                self.assertEqual(code,1);self.assertEqual(report['outcome'],'NOT_PASSED')
            old=next((old for old,new in zip(self.OLD,self.NEW) if new==step),self.OLD[0])
            code,_=collect(shard=owner,omitted_step=step,shard_environment={'GC_'+old.upper()+'_RESULT':'success'})
            self.assertEqual(code,1)

    def test_scope_disclosure_does_not_publish_native_reports_or_historical_diagnostics(self):
        collect=evidence_tests.EvidenceGateTests(methodName='runTest').collect
        for shard in ('governance','quality-basics'):
            code,report=collect(shard=shard)
            self.assertEqual(code,0)
            self.assertEqual(report['glossary_population_diagnostic'],'HISTORICAL_NOT_EXECUTED')
            self.assertEqual(report['relation_qualifications'],{step:{**scope,'outcome':'success' if step in policy.required_steps(shard) else 'NOT_IN_SHARD'} for step,scope in policy.RELATION_SCOPES.items()})
            self.assertEqual(report['tests'],[]);self.assertEqual(report['screenshots'],[])

    def test_workflow_wrong_scope_alias_duplicate_omitted_controls_and_crosswired_results_refuse(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        for step,scope in policy.RELATION_SCOPES.items():
            alternate='relation_candidate_current' if step!='relation_candidate_current' else 'relation_candidate_original'
            for before,after in (
                ('run: '+scope['command'],'run: '+policy.COMMANDS[alternate]),
                ('id: '+step+'\n','id: glossary_population_upgrade\n'),
                ('GC_'+step.upper()+'_RESULT: ${{ steps.'+step+'.outcome }}','GC_'+step.upper()+'_RESULT: ${{ steps.'+alternate+'.outcome }}'),
            ):
                with self.subTest(step=step,before=before),self.assertRaises(ValueError):policy.validate_workflow(workflow.replace(before,after))
        for name in ('test_relation_candidate_upgrade.py','test_governance_repaired_chain.py','test_runtime_routing.py'):
            with self.assertRaises(ValueError):policy.validate_workflow(workflow.replace('run: python3 scripts/'+name,'run: true'))

    def test_assignment_digest_binds_repaired_profile_and_clock_budget(self):
        original=policy.assignment_hash()
        for field,value in (('profile','wrong-profile'),('outerTimeoutSeconds',9999),('arguments',['--run-local','--through','017'])):
            with patch.dict(policy.RELATION_SCOPES['quality_repaired_upgrade'],{field:value}):self.assertNotEqual(policy.assignment_hash(),original)
        self.assertEqual(policy.assignment_hash(),original)

if __name__=='__main__':unittest.main()
