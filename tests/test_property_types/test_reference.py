import json
import unittest

from nvdclient.vuln_types import Reference


class TestReference(unittest.TestCase):

    def setUp(self):
        with open('tests/data/log4shell.json', 'r', encoding='utf-8') as f:
            raw_data = json.load(f).get('references')
        self.raw_data = raw_data

    def test_instantiation(self):
        for ref in self.raw_data:
            Reference(
                ref.get('url'),
                ref.get('source'),
                ref.get('tags')
            )

if __name__ == '__main__':
    unittest.main()
