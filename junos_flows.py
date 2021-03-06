import xml.etree.ElementTree as xml_tree


def _get_junos_config(junos_root):
    config_root = None
    for child in junos_root:
        if child.tag == 'configuration':
            config_root = child

    return config_root

class SecurityConfig:
    def __init__(self, junos_config):
        self.config_security = self._get_config_security(junos_config)
        self.log = None
        self.alg = None
        self.flow = None
        self.nat = None
        self.policies = self._get_security_policies(self.config_security)
        self.zones = self._get_security_zones(self.config_security)

    def _init_log(self, config_root):
        pass

    def _init_alg(self, config_root):
        pass

    def _init_flow(self, config_root):
        pass

    def _init_nat(self, config_root):
        pass

    def _get_security_policies(self, config_security):
        policies_element = None
        for child in config_security:
            if child.tag == 'policies':
                policies_element = child

        return SecurityPolicies(policies_element)

    def _get_security_zones(self, config_security):
        zones_element = None
        for child in config_security:
            if child.tag == 'zones':
                zones_element = child

        return SecurityZones(zones_element)


    def _get_config_security(self, config_root):
        config_security = None
        for child in config_root:
            if child.tag == "security":
                config_security = child
        return config_security


class SecurityPolicies:
    def __init__(self, policies_element):
        self.policies = self._get_policies(policies_element)
        self.default_policy = self._get_defaut_policy(policies_element)

    def _get_policies(self, policies_element):
        policies = []
        for child in policies_element:
            if child.tag == 'policy':
                policies.append(SecurityPolicy(child))

        return policies

    def _get_defaut_policy(self, policies_element):
        default_policy = None
        for child in policies_element:
            if child.tag == "default-policy":
                default_policy = SecurityPolicy(child)

        return default_policy


class DefaultPolicy:
    def __init__(self, default_policy_element):
        self.action = self._get_action(default_policy_element)

    def _get_action(self, default_policy_element):
        action = None
        for child in default_policy_element:
            if child.tag == 'deny-all':
                action = 'deny-all'
            else:
                action = 'permit-all'

        return action


class SecurityPolicy:
    def __init__(self, policy_element):
        self.state = self._get_state(policy_element)
        self.from_zone_name = self._get_from_zone_name(policy_element)
        self.to_zone_name = self._get_to_zone_name(policy_element)
        self.acl_policies = self._get_acl_policies(policy_element)

    def _get_state(self, policy_element):
        state = 'active'
        if 'inactive' in list(policy_element.attrib.keys()):
            state = 'inactive'

        return state

    def _get_from_zone_name(self, policy_element):
        from_zone_name = None
        for child in policy_element:
            if child.tag == 'from-zone-name':
                from_zone_name = child.text

        return from_zone_name

    def _get_to_zone_name(self, policy_element):
        to_zone_name = None
        for child in policy_element:
            if child.tag == 'to-zone-name':
                to_zone_name = child.text

        return to_zone_name

    def _get_acl_policies(self, policy_element):
        acl_policies = []
        for child in policy_element:
            if child.tag == 'policy':
                acl_policies.append(AclPolicy(child))

        return acl_policies


class AclPolicy:
    def __init__(self, acl_policy_element):
        self.name = self._get_name(acl_policy_element)
        self.description = self._get_description(acl_policy_element)
        self.match = self._get_match_criteria(acl_policy_element)
        self.actions = self._get_actions(acl_policy_element)

    def _get_name(self, acl_policy_element):
        name = None
        for child in acl_policy_element:
            if child.tag == 'name':
                name = child.text

        return name

    def _get_description(self, acl_policy_element):
        description = None
        flag_has_desc = False
        for child in acl_policy_element:
            if child.tag == 'description':
                description = child.text
                flag_has_desc = True
        if not flag_has_desc:
            description = 'undefined'

        return description

    def _get_match_criteria(self, acl_policy_element):
        match_criteria = None
        match_criteria_element = None
        for child in acl_policy_element:
            if child.tag == 'match':
                match_criteria_element = child

        match_criteria = AclPolicyMatchCriteria(match_criteria_element)

        return match_criteria

    def _get_actions(self, acl_policy_element):
        actions = None
        actions_element = None
        for child in acl_policy_element:
            if child.tag == 'then':
                actions_element = child

        actions = AclPolicyActions(actions_element)

        return actions


class AclPolicyMatchCriteria:
    def __init__(self, match_criteria_element):
        self.source_zone_address_names = []
        self.destination_zone_address_names = []
        self.application_names = []
        self.unknown_tags = False
        for child in match_criteria_element:
            if child.tag == 'source-address':
                self.source_zone_address_names.append(child.text)
            elif child.tag == 'destination-address':
                self.destination_zone_address_names.append(child.text)
            elif child.tag == 'application':
                self.application_names.append(child.text)
            else:
                self.unknown_tags = True
                print('Unknown tags identified in match_criteria_element')


class AclPolicyActions:
    def __init__(self, acl_policy_actions_element):
        self.permit = False
        self.deny = False
        self.count = False
        self.log = False
        self.action_unknown = False
        for child in acl_policy_actions_element:
            if child.tag == 'permit':
                self.permit = True
            elif child.tag == 'deny':
                self.deny = True
            elif child.tag == 'count':
                self.count = True
            elif child.tag == 'log':
                self.log = True
            else:
                self.action_unknown = True
                print('Action Unknown: True', child.tag)

    def get_actions(self):
        actions = []
        if self.permit:
            actions.append('Permit: True')
        else:
            actions.append('Permit: False')

        if self.deny:
            actions.append('Deny: True')
        else:
            actions.append('Deny: False')

        if self.count:
            actions.append('Count: True')
        else:
            actions.append('Count: False')

        if self.log:
            actions.append('Log: True')
        else:
            actions.append('Log: False')

        return actions

class SecurityZones:
    def __init__(self, zones_element):
        self.functional_zone = self._get_functional_zones(zones_element)
        self.security_zones = self._get_security_zones(zones_element)

    def _get_functional_zones(self, zones_element):
        functional_zones_element = None
        for child in zones_element:
            if child.tag == 'functional-zone':
                functional_zones_element = child
                break
        return FunctionalZones(functional_zones_element)

    def _get_security_zones(self, zones_element):
        security_zones = []
        security_zone_elements = zones_element.findall('security-zone')
        for security_zone in security_zone_elements:
            security_zones.append(SecurityZone(security_zone))

        return security_zones

    def get_security_zone(self, zone_name):
        zone = None
        for security_zone in self.security_zones:
            if security_zone.name == zone_name:
                zone = security_zone

        return zone

    def get_ip_prefixes(self, zone_name, address_name):
        security_zone = self.get_security_zone(zone_name)
        address_book = security_zone.address_book

        return address_book.get_ip_prefixes(address_name)


class FunctionalZones:
    def __init__(self, functional_zones_element):
        self.management_zone_element = self._get_management_zone_element(functional_zones_element)
        self.management_zone = ManagementZone(self.management_zone_element)

    def _get_management_zone_element(self, functional_zones_element):
        management_zone_element = None
        for child in functional_zones_element:
            if child.tag == 'management':
                management_zone_element = child
                break

        return management_zone_element


class ManagementZone:
    def __init__(self, management_zone_element):
        self.interfaces = self._get_interfaces(management_zone_element)
        self.host_inbound_traffic = self._get_host_inbound_traffic(management_zone_element)

    def _get_interfaces(self, management_zone_element):
        interfaces = []
        for child in management_zone_element:
            if child.tag == 'interfaces':
                interfaces.append(Interface(child))
        return interfaces

    def _get_host_inbound_traffic(self, management_zone_element):
        system_services = []
        host_inbound_traffic = management_zone_element.find('host-inbound-traffic')
        for system_service in host_inbound_traffic.findall('system-services'):
            system_services.append(SystemService(system_service))


class SystemService:
    def __init__(self, system_service_element):
        self.name = system_service_element.find('name').text


class Interface:
    def __init__(self, interface_element):
        self.name = interface_element.find('name').text


class SecurityZone:
    def __init__(self, security_zone):
        self.name = self._get_name(security_zone)
        self.address_book = self._get_address_book(security_zone)
        self.host_inbound_traffic = None
        self.interfaces = None

    def _get_name(self, security_zone):

        return security_zone.find('name').text

    def _get_address_book(self, security_zone):
        address_book_element = security_zone.find('address-book')

        return AddressBook(address_book_element)


class AddressBook:
    def __init__(self, address_book_element):
        self.addresses = self._get_addresses(address_book_element)
        self.address_sets = self._get_address_sets(address_book_element)

    def _get_addresses(self, address_book_element):
        addresses = {}
        for address_element in address_book_element.findall('address'):
            address = Address(address_element)
            addresses[address.name] = address

        return addresses

    def _get_address_sets(self, address_book_element):
        address_sets = {}
        for address_set_element in address_book_element.findall('address-set'):
            address_set = AddressSet(address_set_element)
            address_sets[address_set.name] = address_set

        return address_sets

    def get_ip_prefixes(self, address_name):
        is_address_set = False
        ip_prefixes = []

        if address_name in self.address_sets:
            is_address_set = True

        if is_address_set:
            address_set = self.address_sets[address_name]
            for name in address_set.address_names:
                ip_prefixes.append(self.addresses[name].ip_prefix)
        elif address_name in self.addresses:
            ip_prefixes.append(self.addresses[address_name].ip_prefix)
        else:
            ip_prefixes.append('Error: address_name not found for address name \"' + address_name + '\"')
        return ip_prefixes


class Address:
    def __init__(self, address_element):
        self.name = address_element.find('name').text
        self.ip_prefix = address_element.find('ip-prefix').text


class AddressSet:
    def __init__(self, address_set_element):
        self.name = address_set_element.find('name').text
        self.address_names = self._get_address_names(address_set_element)

    def _get_address_names(self, address_set_element):
        address_names = []
        for address_element in address_set_element.findall('address'):
            address_names.append(address_element.find('name').text)

        return address_names

def main():
    junos_file_xml = 'AUDCCFOIF003XML.xml'
    junos_tree = xml_tree.parse(junos_file_xml)
    junos_root = junos_tree.getroot()
    junos_config = _get_junos_config(junos_root)

    sec_conf = SecurityConfig(junos_config)
    sec_policies = sec_conf.policies
    sec_zones = sec_conf.zones

    # zone = sec_zones.get_security_zone('DMZ-Content')
    # address_book = zone.address_book
    # print(address_book.addresses)
    # print(address_book.address_sets)


    for policy in sec_policies.policies:
        from_zone = policy.from_zone_name
        to_zone = policy.to_zone_name
        policy_state = policy.state
        acl_policies = policy.acl_policies
        acl_count = 0
        print('Policy:')
        print('\t', 'From Zone: '+ from_zone)
        print('\t', 'To Zone: ' + to_zone)
        print('\t', 'State: ' + policy_state)

        for acl in acl_policies:
            acl_count += 1
            source_addressnames = acl.match.source_zone_address_names
            source_ip_prefixes = []
            for address_name in source_addressnames:
                for ip_prefix in sec_zones.get_ip_prefixes(from_zone, address_name):
                    source_ip_prefixes.append(ip_prefix)

            dest_addressnames = acl.match.destination_zone_address_names
            # dest_ip_prefixes = []
            # for address_name in dest_addressnames:
            #     for ip_prefix in sec_zones.get_ip_prefixes(to_zone, address_name):
            #         dest_ip_prefixes.append(ip_prefix)

            print('\t', 'ACL:', acl_count)
            print('\t\t', 'Description:', acl.description)
            print('\t\t', 'Source Address Names:', source_addressnames)
            print('\t\t', 'Source IP Prefixes:', source_ip_prefixes)
            print('\t\t', 'Destination Address Names:', dest_addressnames)
            # print('\t\t', 'Destination IP Prefixes:', dest_ip_prefixes)
            print('\t\t', 'Application Names:', acl.match.application_names)
            print('\t\t', 'Action:', acl.actions.get_actions())

        print('\n')


if __name__ == "__main__":
    main()