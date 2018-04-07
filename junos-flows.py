import xml.etree.ElementTree as xml_tree

config_file = 'AUDCCFOIF003XML.xml'


class SecurityConfig:
    def __init__(self, config_file):
        self.log = []
        self.alg = []
        self.flow = []
        self.nat = []
        self.policies = []
        self.zones = []
        config_tree = xml_tree.parse(config_file)
        config_root = config_tree.getroot(config_file)

    def get_log(self, config_root):
        pass


