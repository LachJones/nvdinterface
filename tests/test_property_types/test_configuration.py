import json
import unittest

from nvdclient.vuln_types import Configuration
from nvdclient.vuln_types.property_types import CPEMatch, ConfigurationNode


class TestCPEMatch(unittest.TestCase):

    def setUp(self):
        with open('tests/data/log4shell.json', 'r', encoding='utf-8') as fh:
            raw_data = json.load(fh).get('configurations')
        raw_data = [elem for conf in raw_data for elem in conf.get('nodes', [])]
        raw_data = [elem for node in raw_data for elem in node.get('cpeMatch', [])]

        self.raw_data = raw_data

    def test_instantiation(self):
        for elem in self.raw_data:
            CPEMatch(
                elem.get('vulnerable'),
                elem.get('criteria'),
                elem.get('matchCriteriaId'),
                elem.get('versionStartExcluding'),
                elem.get('versionStartIncluding'),
                elem.get('versionEndExcluding'),
                elem.get('versionEndIncluding')
            )


class TestConfigurationNode:

    def setUp(self):
        with open('tests/data/log4shell.json', 'r') as fh:
            raw_data = json.load(fh).get('configurations')
        raw_data = [elem for conf in raw_data for elem in conf.get('nodes', [])]

        self.raw_data = raw_data

    def test_instantiation(self):
        for elem in self.raw_data:
            ConfigurationNode(
                elem.get('operator'),
                [
                    CPEMatch(
                        match.get('vulnerable'),
                        match.get('criteria'),
                        match.get('matchCriteriaId'),
                        match.get('versionStartExcluding'),
                        match.get('versionStartIncluding'),
                        match.get('versionEndExcluding'),
                        match.get('versionEndIncluding')
                    ) for match in elem.get('cpeMatch')
                ],
                elem.get('negate', False)
            )


class TestConfiguration(unittest.TestCase):

    def setUp(self):
        with open('tests/data/log4shell.json', 'r') as fh:
            raw_data = json.load(fh).get('configurations')
        self.raw_data = raw_data

    def test_instantiation(self):
        for config in self.raw_data:
            Configuration(
                [
                    ConfigurationNode(
                        node.get('operator'),
                        [
                            CPEMatch(
                                match.get('vulnerable'),
                                match.get('criteria'),
                                match.get('matchCriteriaId'),
                                match.get('versionStartExcluding'),
                                match.get('versionStartIncluding'),
                                match.get('versionEndExcluding'),
                                match.get('versionEndIncluding')
                            ) for match in node.get('cpeMatch')
                        ]
                    ) for node in config.get('nodes', [])
                ],
                config.get('operator'),
                config.get('negate', False),
            )


if __name__ == '__main__':
    unittest.main()
