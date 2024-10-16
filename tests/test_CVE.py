import json
import unittest
from datetime import datetime, date
from typing import Union

from nvdclient import CVE, CVSSMetricV2, CVSSMetricV30, CVSSMetricV31, CVSSMetricV2, CVSSMetricV40
from nvdclient.vuln_types import Reference, Weakness


class TestCVE(unittest.TestCase):
    def test_instantiate(self):
        with open("tests/data/heartbleed.json", "r") as f:
            raw_data = json.load(f)
        CVE(raw_data)

    def test_props(self):
        with open("tests/data/heartbleed.json", "r") as f:
            cve = CVE(**json.load(f))

        self.assertEqual("CVE-2014-0160", cve.id_str)
        self.assertEqual("secalert@redhat.com", cve.source_identifier)
        self.assertEqual("Analyzed", cve.vuln_status)
        self.assertEqual("2014-04-07T22:55:03.893", cve.published_str)
        self.assertIsInstance(cve.published_datetime, datetime)
        self.assertEqual("2024-07-02T16:52:39.560", cve.last_modified_str)
        self.assertIsInstance(cve.last_modified_datetime, datetime)
        self.assertIsNone(cve.evaluator_comment)
        self.assertIsNone(cve.evaluator_solution)
        self.assertIsInstance(cve.evaluator_impact, str)
        self.assertEqual("2022-05-04", cve.cisa_exploit_added_date_str)
        self.assertEqual(date.fromisoformat("2022-05-04"), cve.cisa_exploit_added_date)
        self.assertEqual("2022-05-25", cve.cisa_action_due_date_str)
        self.assertEqual(date.fromisoformat("2022-05-25"), cve.cisa_action_due_date)
        self.assertEqual("Apply updates per vendor instructions.", cve.cisa_required_action)
        self.assertEqual("OpenSSL Information Disclosure Vulnerability", cve.cisa_vulnerability_name)
        self.assertListEqual([], cve.cve_tags)
        self.assertIsInstance(cve.descriptions_list, list)
        self.assertEqual(2, len(cve.descriptions_list))
        for desc in cve.descriptions_list:
            self.assertIn(desc.language, ("en", "es"))
            self.assertIsInstance(desc.content, str)
        self.assertIsInstance(cve.references_list, list)
        for ref in cve.references_list:
            self.assertIsInstance(ref, Reference)
            self.assertIsInstance(ref.url, str)
            self.assertIsInstance(ref.tags, list)
            for tag in ref.tags:
                self.assertIsInstance(tag, str)
            self.assertIsInstance(ref.url, str)
        self.assertIsInstance(cve.metrics_list, list)
        self.assertGreater(len(cve.metrics_list), 0)
        for metric in cve.metrics_list:
            self.assertIsInstance(metric, Union[CVSSMetricV2, CVSSMetricV30, CVSSMetricV31, CVSSMetricV40])
        self.assertIsInstance(cve.weaknesses_list, list)
        self.assertEqual(1, len(cve.weaknesses_list))
        for elem in cve.weaknesses_list:
            self.assertIsInstance(elem, Weakness)
        self.assertIsNone(cve.configurations_list)
        self.assertIsNone(cve.vendor_comment_list)


if __name__ == '__main__':
    unittest.main()
