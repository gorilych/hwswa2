import logging
import yaml
import os
import copy

logger = logging.getLogger(__name__)

# dict of roles {name: role}
roles = {}


class RoleException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


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

    def _firewall(self):
        firewall = []
        if 'firewall' in self.data:
            firewall = self.data['firewall']
        for role in self.includes:
            rf = copy.deepcopy(role.firewall)
            firewall.extend(rf)
        return firewall


class RoleCollection(Role):
    """Collection of roles, which can be assigned to a server"""

    def __init__(self, roles, checksdir):
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

