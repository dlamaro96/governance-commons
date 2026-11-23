#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject incomplete image scans and preserve unfixed/low/unknown findings."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
import unittest
import scan_images as scan

IMAGE = 'sha256:'+'a'*64


def report(profile='application'):
    return {'SchemaVersion':2,'ArtifactType':'container_image','ArtifactName':IMAGE,'Trivy':{'Version':scan.PIN['version']},
            'Metadata':{'ImageID':IMAGE,'ImageConfig':{'os':'linux','architecture':'arm64'},'OS':{'Family':'debian'}},
            'Results':[{'Type':kind,'Class':scope,'Packages':[{'Name':'synthetic-package','Version':'1'}]}
                       for kind,scope in ([('debian','os-pkgs'),('node-pkg','lang-pkgs')] if profile=='application'
                                          else [('alpine','os-pkgs'),('python-pkg','lang-pkgs')])]}


class ScanTests(unittest.TestCase):
    def test_real_profiles_need_os_and_language_inventory(self):
        for profile in ('application','python-worker'):
            self.assertEqual(scan.assess(report(profile),IMAGE,profile)['outcome'],'PASS')
            for index in range(2):
                value=report(profile);value['Results'].pop(index)
                with self.assertRaises(ValueError):scan.assess(value,IMAGE,profile)

    def test_all_high_and_critical_findings_fail_even_without_a_fix(self):
        for severity in ('HIGH','CRITICAL'):
            for status in ('affected','will_not_fix','fixed'):
                value=report();value['Results'][0]['Vulnerabilities']=[{
                    'VulnerabilityID':'CVE-synthetic','PkgName':'synthetic-package','InstalledVersion':'1',
                    'Severity':severity,'Status':status}]
                result=scan.assess(value,IMAGE,'application')
                self.assertEqual(result['outcome'],'FAIL');self.assertEqual(result['counts'][severity],1)
                self.assertEqual(result['findings'][0]['Status'],status)

    def test_lower_and_unknown_findings_remain_visible(self):
        value=report();value['Results'][0]['Vulnerabilities']=[{
            'VulnerabilityID':'CVE-synthetic-'+s,'PkgName':'synthetic-package','InstalledVersion':'1','Severity':s}
            for s in ('LOW','MEDIUM','UNKNOWN')]
        result=scan.assess(value,IMAGE,'application')
        self.assertEqual(result['outcome'],'PASS');self.assertEqual(len(result['findings']),3)

    def test_wrong_or_incomplete_image_never_passes(self):
        mutations=[lambda v:v.update(SchemaVersion=1),lambda v:v.update(ArtifactName='mutable:tag'),
                   lambda v:v.update(Trivy={'Version':'unknown'}),
                   lambda v:v.update(ArtifactType='filesystem'),lambda v:v.update(Results=[]),
                   lambda v:v['Metadata'].update(ImageID='sha256:'+'b'*64),
                   lambda v:v['Metadata']['OS'].update(EOSL=True),
                   lambda v:v['Metadata']['ImageConfig'].update(architecture='unknown'),
                   lambda v:v['Results'][0].update(Packages=[]),
                   lambda v:v['Results'][0].update(Packages=[None]),
                   lambda v:v['Results'][0].update(Packages=[{'Name':'unknown'}]),
                   lambda v:v.update(Metadata=None),
                   lambda v:v['Metadata'].update(OS=[]),
                   lambda v:v['Metadata'].update(ImageConfig=[]),
                   lambda v:v['Results'][0].update(Vulnerabilities={}),
                   lambda v:v['Results'][0].update(ExperimentalModifiedFindings=[{'ignored':True}]),
                   lambda v:v['Results'][0].update(Vulnerabilities=[{'Severity':'high'}])]
        for change in mutations:
            value=report();change(value)
            with self.assertRaises(ValueError):scan.assess(value,IMAGE,'application')

    def test_database_missing_old_future_or_naive_rejects(self):
        now=datetime.now(timezone.utc)
        self.assertEqual(scan.database({'Version':2,'UpdatedAt':now.isoformat()},now),now.isoformat())
        for delta in (timedelta(hours=49),-timedelta(minutes=6)):
            with self.assertRaises(ValueError):scan.database({'Version':2,'UpdatedAt':(now-delta).isoformat()},now)
        with self.assertRaises(ValueError):scan.database({'Version':2,'UpdatedAt':'2026-01-01T00:00:00'},now)
        with self.assertRaises(ValueError):scan.database({'Version':1,'UpdatedAt':now.isoformat()},now)

    def test_duplicate_nonfinite_symlink_and_oversize_reports_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.json'
            for text in ('{"a":1,"a":2}','{"a":NaN}','{"a":Infinity}'):
                p.write_text(text)
                with self.assertRaises(ValueError):scan.read_json(p)
            p.write_text('{}')
            with self.assertRaises(ValueError):scan.read_json(p,1)
            link=Path(tmp)/'link.json';link.symlink_to(p)
            with self.assertRaises(ValueError):scan.read_json(link)


if __name__=='__main__':
    unittest.main()
