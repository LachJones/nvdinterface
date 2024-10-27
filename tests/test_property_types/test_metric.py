import json
import unittest
from warnings import warn

from nvdinterface.vuln_types import CVSSMetricV2, CVSSMetricV31
from nvdinterface.vuln_types.property_types.metrics import build_from_api_response


class TestMetrics(unittest.TestCase):

    def test_load_cvss2(self):
        with open('tests/data/heartbleed.json', 'r') as fh:
            cvss = json.load(fh).get('metrics').get('cvssMetricV2')
        for metric in cvss:
            cvss_2 = build_from_api_response(metric)
            self.assertIsInstance(cvss_2, CVSSMetricV2)

    def test_load_cvss30(self):
        warn("Not Implemented")

    def test_load_cvss31(self):
        with open('tests/data/heartbleed.json', 'r') as fh:
            cvss = json.load(fh).get('metrics').get('cvssMetricV31')
        for metric in cvss:
            cvss_31 = build_from_api_response(metric)
            self.assertIsInstance(cvss_31, CVSSMetricV31)

    def test_load_cvss40(self):
        warn("Not Implemented")

    def test_cvss2_values(self):
        with open('tests/data/heartbleed.json', 'r') as fh:
            cvss = json.load(fh).get('metrics').get('cvssMetricV2')
        for metric in cvss:
            cvss_2 = build_from_api_response(metric)
            self.assertEqual("LOW", cvss_2.access_complexity)
            self.assertEqual("NETWORK", cvss_2.access_vector)
            self.assertEqual("NONE", cvss_2.authentication)
            self.assertEqual("NONE", cvss_2.availability_impact)
            self.assertEqual(5, cvss_2.base_score)
            self.assertEqual("PARTIAL", cvss_2.confidentiality_impact)
            self.assertEqual("NONE", cvss_2.integrity_impact)
            self.assertEqual("AV:N/AC:L/Au:N/C:P/I:N/A:N", cvss_2.vector)
            self.assertEqual("2.0", cvss_2.version)

    def test_cvss31_values(self):
        with open('tests/data/heartbleed.json', 'r') as fh:
            cvss = json.load(fh).get('metrics').get('cvssMetricV31')
        for metric in cvss:
            cvss_31 = build_from_api_response(metric)
            self.assertEqual("LOW", cvss_31.attack_complexity)
            self.assertEqual("NETWORK", cvss_31.attack_vector)
            self.assertEqual("NONE", cvss_31.availability_impact)
            self.assertEqual(7.5, cvss_31.base_score)
            self.assertEqual("HIGH", cvss_31.base_severity)
            self.assertEqual("HIGH", cvss_31.confidentiality_impact)
            self.assertEqual("NONE", cvss_31.integrity_impact)
            self.assertEqual("NONE", cvss_31.privileges_required)
            self.assertEqual("UNCHANGED", cvss_31.scope)
            self.assertEqual("NONE", cvss_31.user_interaction)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_31.vector)
            self.assertEqual("3.1", cvss_31.version)


if __name__ == '__main__':
    unittest.main()
