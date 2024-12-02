import unittest
from datetime import datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import requests
from requests.models import Response

from nvdinterface import CVE, search_cves, search_cves_all, cve_history, cve_history_all
from nvdinterface.vuln_types.property_types.ChangeItem import ChangeItem, ChangeDetail


class TestNVDInterface(unittest.TestCase):
    """
    Test the functionality provided by nvdinterface.nvd_interface.py.

    Importantly, this file does not and should not interact with the NVD API. All API responses are mocked using MagicMock.
    """

    def setUp(self):

        # Prepare Response objects used for mocking API responses
        with open(Path(__file__).parent / 'data' / 'CVE-2014-0160_history.json', 'rb') as fh:
            heartbleed_history_data = fh.read()
        self.heartbleed_history = Response()
        self.heartbleed_history.status_code = 200
        self.heartbleed_history.code = 'ok'
        self.heartbleed_history.raw = BytesIO(heartbleed_history_data)

        with open(Path(__file__).parent / 'data' / 'CVE-2014-0160_search.json', 'rb') as fh:
            heartbleed_search_data = fh.read()
        self.heartbleed_search = Response()
        self.heartbleed_search.status_code = 200
        self.heartbleed_search.code = 'ok'
        self.heartbleed_search.raw = BytesIO(heartbleed_search_data)

    def test_search_for_heartbleed(self):

        requests.get = MagicMock(return_value=self.heartbleed_search)

        res = search_cves(cveId="CVE-2014-0160", resultsPerPage=100)
        self.assertEqual(1, res.get("totalResults"))
        self.assertEqual("NVD_CVE", res.get("format"))
        self.assertEqual(1, len(res.get("vulnerabilities")))
        for cve in res["vulnerabilities"]:
            self.assertIsInstance(cve, CVE)

    def test_search_all_for_heartbleed(self):

        requests.get = MagicMock(return_value=self.heartbleed_search)

        res = search_cves_all(cveId="CVE-2014-0160")
        self.assertIsInstance(res, list)
        self.assertEqual(1, len(res))
        for cve in res:
            self.assertIsInstance(cve, CVE)
            self.assertEqual("CVE-2014-0160", cve.id_str)

    def test_search_heartbleed_history(self):

        requests.get = MagicMock(return_value=self.heartbleed_history)

        res = cve_history(cveId="CVE-2014-0160", resultsPerPage=100)
        self.assertGreaterEqual(res.get("totalResults"), 28)
        self.assertEqual("NVD_CVEHistory", res.get("format"))
        self.assertGreaterEqual(len(res.get("cveChanges")), 28)
        for change in res["cveChanges"]:
            self.assertIsInstance(change, ChangeItem)
            self.assertIsInstance(change.created, datetime)
            self.assertEqual("CVE-2014-0160", change.cve_id)
            self.assertIsInstance(change.details, list)
            for detail in change.details:
                self.assertIsInstance(detail, ChangeDetail)
                self.assertIsInstance(detail.type, str)

    def test_search_all_heartbleed_history(self):

        requests.get = MagicMock(return_value=self.heartbleed_history)

        res = cve_history_all(cveId="CVE-2014-0160")
        self.assertIsInstance(res, list)
        self.assertGreaterEqual(len(res), 28)
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
