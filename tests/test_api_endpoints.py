import unittest

import requests

from nvdinterface.nvd_interface import _url_base


class TestNvdEndpoints(unittest.TestCase):
    """
    A minor test class to ensure that API endpoints are responding to minimal requests.
    Each test case should be the smallest request possible - we are not testing whether meaningful data is returned.
    """

    def test_empty_request(self):
        resp = requests.options(f"{_url_base}/cves/2.0")

        # ignore a 503 error, as these seem to be returned quite frequently and are not believed
        # to be caused by this library implementation.
        if resp.status_code != 503:
            resp.raise_for_status()


if __name__ == '__main__':
    unittest.main()
