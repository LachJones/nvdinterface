import json
import unittest

from nvdinterface.vuln_types import Description


class TestDescription(unittest.TestCase):

    def setUp(self):
        with open('tests/data/log4shell.json', 'r', encoding='utf-8') as fh:
            raw_data = json.load(fh).get('descriptions')
        self.raw_data = raw_data

    def test_instantiation(self):
        for desc in self.raw_data:
            Description(
                desc.get('lang'),
                desc.get('value'),
            )

    def test_values(self):
        descs = [Description(desc.get('lang'), desc.get('value')) for desc in self.raw_data]

        self.assertEqual("en", descs[0].language)
        self.assertEqual("es", descs[1].language)

        self.assertEqual("Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.", descs[0].content)
        self.assertEqual("Las características JNDI de Apache Log4j2 2.0-beta9 hasta 2.15.0 (excluyendo las versiones de seguridad 2.12.2, 2.12.3 y 2.3.1) utilizadas en la configuración, los mensajes de registro y los parámetros no protegen contra LDAP controlado por un atacante y otros puntos finales relacionados con JNDI. Un atacante que pueda controlar los mensajes de registro o los parámetros de los mensajes de registro puede ejecutar código arbitrario cargado desde servidores LDAP cuando la sustitución de la búsqueda de mensajes está habilitada. A partir de la versión 2.15.0 de log4j, este comportamiento ha sido deshabilitado por defecto. A partir de la versión 2.16.0 (junto con las versiones 2.12.2, 2.12.3 y 2.3.1), esta funcionalidad se ha eliminado por completo. Tenga en cuenta que esta vulnerabilidad es específica de log4j-core y no afecta a log4net, log4cxx u otros proyectos de Apache Logging Services", descs[1].content)


if __name__ == '__main__':
    unittest.main()
