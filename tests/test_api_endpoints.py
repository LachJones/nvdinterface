import os
import unittest

from nvdinterface.nvd_interface import _get


class TestNvdEndpoints(unittest.TestCase):
    """
    A minor test class to ensure that API endpoints are responding to minimal requests.
    Each test case should be the smallest request possible - we are not testing whether meaningful data is returned.
    """

    def test_empty_request(self):
        nvd_api_key = os.environ.get('NVD_API_KEY')

        resp = _get('/cves', params={'resultsPerPage': 1}, headers={} if nvd_api_key is None else {'nvdApiKey': nvd_api_key})

        self.assertIsInstance(resp, dict)  # add assertion here


if __name__ == '__main__':
    unittest.main()
