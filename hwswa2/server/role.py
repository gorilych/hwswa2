import logging
import yaml
import os
import copy

import hwswa2.auxiliary as aux

logger = logging.getLogger(__name__)

# dict of roles {name: role}
roles = {}


def role_factory(name, checksdir):
    """ Factory for roles
    :param name: role name
    :param checksdir: path to directory with name.yaml
    :return: role object
    """
    global roles
    if name in roles:
        return roles[name]
    else:
        role = Role(name, checksdir)
        roles[name] = role
        return role


class RoleException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Role(object):

    def __str__(self):
        return "role " + self.name

    def __repr__(self):
        return "<Role " + self.name + ">"

    def __init__(self, name, checksdir):
        """Constructs role from checksdir/name.yaml"""
        self.name = name
        self._checksdir = checksdir
        logger.debug("Collecting details for %s" % self)
        f = os.path.join(checksdir, name.lower() + '.yaml')
        try:
            self.data = yaml.load(open(f))
        except IOError as ie:
            logger.debug("Error opening role file %s, assuming it is empty role. Exception: %s" % (f, ie))
            self.data = {}
            self._empty = True
        except yaml.YAMLError as ye:
            err_msg = "Error parsing role file %s: %s" % (f, ye)
            logger.error(err_msg)
            raise RoleException(err_msg)
        else:
            self._file = f
        self.description = self._description()
        self.includes = self._includes()
        self.parameters = self._parameters()
        self.firewall = self._firewall()
        self.requirements = self._requirements()
        logger.debug("Finished collecting details for %s" % self)

    def _description(self):
        if 'description' in self.data:
            return self.data['description']
        else:
            return None

    def _includes(self):
        includes = []
        if 'includes' in self.data:
            for name in self.data['includes']:
                # WE DO NOT PROTECT FROM CYCLED INCLUDES!!!
                r = role_factory(name, self._checksdir)
                includes.append(r)
        return includes

    def _parameters(self):
        parameters = {}
        if 'parameters' in self.data:
            parameters = self.data['parameters']
        parameters['_type'] = 'dictionary'
        included_parameters = {}
        for role in self.includes:
            rp = copy.deepcopy(role.parameters)
            rp.update(included_parameters)
            included_parameters = rp
        included_parameters.update(parameters)
        return included_parameters

    def _requirements(self):
        requirements = {}
        if 'requirements' in self.data:
            requirements = self.data['requirements']
        included_requirements = {}
        for role in self.includes:
            rq = copy.deepcopy(role.requirements)
            rq.update(included_requirements)
            included_requirements = rq
        included_requirements.update(requirements)
        return included_requirements

    @staticmethod
    def _unroll_fw_groups(firewall):
        rulegroups = [g for g in firewall if ('group' in g) and g['group']]
        rules = [r for r in firewall if (not ('group' in r)) or (not r['group'])]
        for rg in rulegroups:
            common_props = [key for key in ['connect_with', 'type', 'ports',
                                            'protos', 'networks', 'direction',
                                            'policy'] if key in rg]
            for r in rg['rules']:
                for key in common_props:
                    if not (key in r):
                        r[key] = rg[key]
                rules.append(r)
        return rules

    def _firewall(self):
        firewall = []
        if 'firewall' in self.data:
            firewall = self.data['firewall']
        for role in self.includes:
            rf = copy.deepcopy(role.firewall)
            firewall.extend(rf)
        firewall = Role._unroll_fw_groups(firewall)
        return firewall

    def all_included_roles(self):
        air = [r.name for r in self.includes]
        for r in self.includes:
            air.extend(r.all_included_roles())
        return air

    def collect_incoming_fw_rules(self, other):
        """Collect firewall rules for incoming connections from other role

        :param other: other role
        :return: list of rules [{network: .., proto: .., ports: ..,}, ...]
        """
        role_names = self.all_included_roles()
        role_names.append(self.name)
        other_role_names = other.all_included_roles()
        other_role_names.append(other.name)
        incoming_rules = []
        # first check incoming rules in our firewall
        for rule in self.firewall:
            if rule['direction'] == 'incoming' and rule['type'] == 'infra':
                for r in rule['connect_with']['roles']:
                    if r.lower() in other_role_names:
                        for proto in rule['protos']:
                            for network in rule['networks']:
                                incoming_rules.append({'network': network,
                                                       'proto': proto.lower(),
                                                       'ports': str(rule['ports'])})
        # now check outgoing rules in other firewall
        for rule in other.firewall:
            if rule['direction'] == 'outgoing' and rule['type'] == 'infra':
                for r in rule['connect_with']['roles']:
                    if r.lower() in role_names:
                        for proto in rule['protos']:
                            for network in rule['networks']:
                                incoming_rules.append({'network': network,
                                                       'proto': proto.lower(),
                                                       'ports': str(rule['ports'])})
        # join ports for the same rules, so not to check twice
        joined_rules = []
        for rule in incoming_rules:
            joined_rule = next((jr for jr in joined_rules
                                if jr['network'] == rule['network'] and
                                   jr['proto'] == rule['proto']), None)
            if joined_rule is None:
                joined_rules.append(rule)
            else:
                joined_rule['ports'] = aux.joinranges(joined_rule['ports'], rule['ports'])
        return joined_rules


class RoleCollection(Role):
    """Collection of roles, which can be assigned to a server"""

    def __init__(self, roles, checksdir):
        self.name = ''
        self._roles= ' '.join(roles)
        self.data = {'includes': roles}
        self._checksdir = checksdir
        self.includes = self._includes()
        self.parameters = self._parameters()
        self.firewall = self._firewall()
        self.requirements = self._requirements()

    def __str__(self):
        return "role collection: " + self._roles

    def __repr__(self):
        return "<RoleCollection: " + self._roles + ">"

