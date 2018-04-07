import xml.etree.ElementTree as xml_tree

config_file = 'AUDCCFOIF003XML.xml'


class SecurityConfig(config_file):
    def __init__(self):
        self.logs = []
        self.alg = []
        self.flow = []
        self.nat = []
        self.policies = []
        self.zones = []
        config_tree = xml_tree.parse(config_file)
        config_root = config_tree.getroot(config_file)


