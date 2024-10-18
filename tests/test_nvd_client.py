import unittest
from datetime import datetime

from nvdclient import CVE, search_cves, search_cves_all, cve_history, cve_history_all
from nvdclient.vuln_types.property_types.ChangeItem import ChangeItem, ChangeDetail


class TestNVDClient(unittest.TestCase):

    @staticmethod
    def test_empty_instantiate():
        # Simple test to ensure instantiating doesn't throw an exception.
        pass

    def test_search_for_heartbleed(self):
        res = search_cves(cveId="CVE-2014-0160")
        self.assertEqual(1, res.get("totalResults"))
        self.assertEqual("NVD_CVE", res.get("format"))
        self.assertEqual(1, len(res.get("vulnerabilities")))
        for cve in res["vulnerabilities"]:
            self.assertIsInstance(cve, CVE)

    def test_search_all_for_heartbleed(self):
        res = search_cves_all(cveId="CVE-2014-0160")
        self.assertIsInstance(res, list)
        self.assertEqual(1, len(res))
        for cve in res:
            self.assertIsInstance(cve, CVE)
            self.assertEqual("CVE-2014-0160", cve.id_str)

    def test_search_heartbleed_history(self):
        res = cve_history(cveId="CVE-2014-0160")
        self.assertEqual(28, res.get("totalResults"))
        self.assertEqual("NVD_CVEHistory", res.get("format"))
        self.assertEqual(28, len(res.get("cveChanges")))
        for change in res["cveChanges"]:
            self.assertIsInstance(change, ChangeItem)
            self.assertIsInstance(change.created, datetime)
            self.assertEqual("CVE-2014-0160", change.cve_id)
            self.assertIsInstance(change.details, list)
            for detail in change.details:
                self.assertIsInstance(detail, ChangeDetail)
                self.assertIsInstance(detail.type, str)

    def test_search_all_heartbleed_history(self):
        res = cve_history_all(cveId="CVE-2014-0160")
        self.assertIsInstance(res, list)
        self.assertEqual(28, len(res))
        for change in res:
            self.assertIsInstance(change, ChangeItem)
            self.assertIsInstance(change.created, datetime)
            self.assertEqual("CVE-2014-0160", change.cve_id)
            self.assertIsInstance(change.details, list)
            for detail in change.details:
                self.assertIsInstance(detail, ChangeDetail)
                self.assertIsInstance(detail.type, str)


if __name__ == '__main__':
    unittest.main()
