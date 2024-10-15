import json
import unittest

from vuln_types import Weakness


class TestWeakness(unittest.TestCase):

    def setUp(self):
        with open('tests/data/log4shell.json', 'r', encoding='utf-8') as f:
            raw_data = json.load(f).get('weaknesses')
        self.raw_data = raw_data


    def test_instantiate(self):
        for weakness in self.raw_data:
            Weakness(
                weakness.get('source'),
                weakness.get('type'),
                weakness.get('description'),
            )


if __name__ == '__main__':
    unittest.main()
