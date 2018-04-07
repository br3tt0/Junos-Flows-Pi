import xml.etree.ElementTree as xml_tree

config_file = 'AUDCCFOIF003XML.xml'


class SecurityConfig:
    def __init__(self, config_file):
        self.log = None
        self.alg = None
        self.flow = None
        self.nat = None
        self.policies = None
        self.zones = None
        config_tree = xml_tree.parse(config_file)
        config_root = config_tree.getroot(config_file)

    def _init_log(self, config_root):
        pass

    def _init_alg(self, config_root):
        pass

    def _init_flow(self, config_root):
        pass

    def _init_nat(self, config_root):
        pass

    def _init_policies(self, config_root):
        pass

    def _init_zones(self, config_root):
        pass


