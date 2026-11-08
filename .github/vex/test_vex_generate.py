import unittest
from vex_generate import generate, MAPPING

class Vex(unittest.TestCase):
    def setUp(self):
        self.data = dict(alert_number='5',ghsa_id='GHSA-9wv6-86v2-598j',cve_id='CVE-2024-45296',package_name='path-to-regexp',package_ecosystem='npm',severity='high',summary='path-to-regexp outputs backtracking regular expressions',dismissed_reason='not_used')
        self.manifest = dict(name='vex-auto-generator',version='1.0.0')
    def make(self):
        return generate(self.data,self.manifest,'owner/repo','2026-11-08T00:00:00Z')
    def test_published_semantic_fields(self):
        r=self.make()['document']['statements'][0]
        self.assertEqual(r['status'],'not_affected')
        self.assertEqual(r['justification'],'vulnerable_code_not_present')
        self.assertEqual(r['products'],[{'@id':'pkg:npm/vex-auto-generator@1.0.0'}])
        self.assertEqual(r['vulnerability']['name'],'CVE-2024-45296')
    def test_three_mappings(self):
        for reason, justification in MAPPING.items():
            self.data['dismissed_reason']=reason
            self.assertEqual(self.make()['document']['statements'][0]['justification'],justification)
    def test_no_bandwidth_does_not_assert_unaffected(self):
        self.data['dismissed_reason']='no_bandwidth'
        self.assertEqual(self.make()['status'],'skip')
    def test_missing_field(self):
        self.data.pop('summary')
        with self.assertRaises(ValueError): self.make()
    def test_path_injection(self):
        self.data['ghsa_id']='../../something'
        with self.assertRaises(ValueError): self.make()
    def test_unsupported_ecosystem(self):
        self.data['package_ecosystem']='maven'
        with self.assertRaises(ValueError): self.make()
    def test_scoped_package(self):
        self.manifest['name']='@scope/name'
        self.assertEqual(self.make()['document']['statements'][0]['products'][0]['@id'],'pkg:npm/%40scope/name@1.0.0')

if __name__=='__main__': unittest.main()
