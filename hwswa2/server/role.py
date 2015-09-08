import logging
import yaml
import os
import copy

import hwswa2.auxiliary as aux
import hwswa2
from hwswa2.server.req import reqs_factory

__all__ = ['Role', 'RoleCollection']

logger = logging.getLogger(__name__)

# dict of roles {name: role}
roles = {}

def _alias_to_name(alias):
    name_aliases = hwswa2.config.get('role-aliases', list())
    for name in name_aliases:
        # name_aliases[name] can be a list of aliases or a single alias
        aliases = name_aliases[name]
        if not isinstance(aliases, list):
            aliases = [aliases]
        for a in aliases:
            if alias.lower() == a.lower():
                return name.lower()
    # not found in aliases? should be a name itself then
    return alias.lower()

def role_factory(name):
    """ Factory for roles
    :param name: role name
    :return: role object
    """
    global roles
    # name can be alias
    nm = _alias_to_name(name)
    if nm in roles:
        return roles[nm]
    else:
        role = Role(nm)
        roles[nm] = role
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

    def __init__(self, name):
        """Constructs role from checksdir/name.yaml"""
        self.name = name.lower()

    @property
    def data(self):
        if not hasattr(self, '_data'):
            logger.debug("Postponed reading of yaml file for %s started" % self)
            self._init_data()
        return self._data

    @property
    def internal(self):
        if not hasattr(self, '_internal'):
            self._internal = self.data.get('internal')
            # if internal flag is not mentioned in data - it is None
            # this is ok, because internal is False by default
        return self._internal

    @property
    def description(self):
        return self.data.get('description')

    @property
    def ostype(self):
        if not hasattr(self, '_ostype'):
            self._ostype = self.data.get('ostype')
            if self._ostype is None:  # not in data? 
                for role in self.includes:  # try to find in included roles
                    if role.ostype is not None:
                        self._ostype = role.ostype
                        break  # use the first found ostype
        return self._ostype

    @property
    def includes(self):
        if not hasattr(self, '_includes'):
            logger.debug("Postponed initialization of included roles for %s started" % self)
            self._init_includes()
            logger.debug("Included roles for %s: %s" % (self, self._includes))
        return self._includes

    @property
    def parameters(self):
        if not hasattr(self, '_parameters'):
            logger.debug("Postponed initialization of parameters for %s started" % self)
            self._init_parameters()
        return self._parameters

    @property
    def firewall(self):
        if not hasattr(self, '_firewall'):
            logger.debug("Postponed initialization of firewall rules for %s started" % self)
            self._init_firewall()
        return self._firewall

    @property
    def requirements(self):
        if not hasattr(self, '_requirements'):
            logger.debug("Postponed initialization of requirements for %s started" % self)
            self._init_requirements()
        return self._requirements

    def _init_data(self):
        f = os.path.join(hwswa2.config['checksdir'], self.name + '.yaml')
        try:
            self._data = yaml.load(open(f))
        except IOError as ie:
            logger.error("Error opening role file %s, assuming it is empty role. Exception: %s" % (f, ie))
            self._data = {}
        except yaml.YAMLError as ye:
            err_msg = "Error parsing role file %s: %s" % (f, ye)
            logger.error(err_msg)
            raise RoleException(err_msg)

    def _init_includes(self):
        self._includes = []
        for name in self.data.get('includes', list()):
            # WE DO NOT PROTECT FROM CYCLED INCLUDES!!!
            r = role_factory(name)
            self._includes.append(r)

    def _init_parameters(self):
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
        self._parameters = included_parameters

    def _init_requirements(self):
        reqs_body = self.data.get('requirements', {})
        incl_reqs = []
        for role in self.includes:
            incl_reqs.extend(role.requirements)
        reqs = reqs_factory(self.name, reqs_body, incl_reqs)
        logger.debug("Requirements for %s: %s" % (self, map(str,[r for r in reqs if not r.istemplate()])))
        self._requirements = reqs

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

    def connects_with_roles(self):
        roles = []
        for rule in self.firewall:
            try:
                add_roles = [role for role in rule['connect_with']['roles'] if role not in roles]
            except KeyError:
                pass
            else:
                roles.extend(add_roles)
        return roles

    def _init_firewall(self):
        firewall = self.data.get('firewall', [])
        for role in self.includes:
            rf = copy.deepcopy(role.firewall)
            firewall.extend(rf)
        firewall = Role._unroll_fw_groups(firewall)
        for rule in firewall:
            try:
                roles = rule['connect_with']['roles']
            except KeyError:
                pass
            else:
                rule['connect_with']['roles'] = [role.lower() for role in roles]
            rule.setdefault('policy', 'allow')
            rule.setdefault('direction', 'incoming')
            rule.setdefault('protos', ['TCP'])
            rule.setdefault('type', 'infra')
        self._firewall = firewall

    @staticmethod
    def _get_param_value(param, param_cmd, param_script, deps=None):
        """Get param using passed functions

        :param param: parameter
        :param param_cmd: function to execute parameter' command
        :param param_script: function to execute parameter' script
        :param
        :return: generator of { param: param, progress: progress, failures: failures }
        """
        if deps is None:
            deps = {}
        mydeps = copy.deepcopy(deps)
        myparam = copy.deepcopy(param)
        progress = 0
        curprogress = 0
        if isinstance(myparam, (str, unicode)):
            if mydeps:
                cmd = myparam % mydeps
            else:
                cmd = myparam
            status, output, failure = param_cmd(cmd)
            yield {'param': output, 'progress': 1, 'failures': failure}
        else:  # non-scalar type
            if not '_type' in myparam: # dictionary is default type
                myparam['_type'] = 'dictionary'
            # different type processing
            if myparam['_type'] == 'dictionary':
                val = {}
                failures = {}
                progress = 0
                if '_keys' in myparam:
                    if '_command' in myparam:
                        if mydeps:
                            cmd = myparam['_command'] % mydeps
                        else:
                            cmd = myparam['_command']
                        status, rows, failure = param_cmd(cmd)
                    elif '_script' in myparam:
                        if mydeps:
                            script = myparam['_script'] % mydeps
                        else:
                            script = myparam['_script']
                        status, line, failure = param_script(script)
                    else:
                        status, line, failure = False, None, "Parameter of type dictionary has _keys but no _command or _script"
                    progress = 1
                    if not status:
                        val['_keys'] = line
                        failures['_keys'] = failure
                    else:
                        myparam.setdefault('_separator', ' ')
                        maxsplit = len(myparam['_keys']) - 1
                        val = dict(zip(myparam['_keys'], row.split(myparam['_separator'], maxsplit)))
                    yield {'param': val, 'progress': progress, 'failures': failures or None}
                for p in myparam:
                    if not p.startswith('_'):
                        for pv in Role._get_param_value(myparam[p], param_cmd, param_script, mydeps):
                            val[p] = copy.deepcopy(pv['param'])
                            curprogress = progress + pv['progress']
                            if pv['failures'] is not None:
                                failures[p] = copy.deepcopy(pv['failures'])
                            curfailures = copy.deepcopy(failures) or None
                            yield {'param': val, 'progress': curprogress, 'failures': curfailures}
                        progress = curprogress
                yield {'param': val, 'progress': progress, 'failures': failures or None}
            elif myparam['_type'] == 'table':
                val = []
                if '_command' in myparam:
                    if mydeps:
                        cmd = myparam['_command'] % mydeps
                    else:
                        cmd = myparam['_command']
                    status, rows, failure = param_cmd(cmd)
                elif '_script' in myparam:
                    if mydeps:
                        script = myparam['_script'] % mydeps
                    else:
                        script = myparam['_script']
                    status, rows, failure = param_script(script)
                else:
                    status, rows, failure = False, None, "Parameter of type table has no _command or _script"
                if not status:
                    yield {'param': rows, 'progress': 1, 'failures': failure}
                else:
                    myparam.setdefault('_separator', ' ')
                    if not rows == '':
                        maxsplit = len(myparam['_fields']) - 1
                        for row in rows.split('\n'):
                            val.append(dict(zip(myparam['_fields'], row.split(myparam['_separator'], maxsplit))))
                    yield {'param': val, 'progress': 1, 'failures': failure}
            elif myparam['_type'] == 'list':
                # evaluate generator first
                for generator in myparam['_generator']:  # there should be only one
                    placeholder = myparam['_generator'][generator]
                    if mydeps:
                        cmd = myparam[generator] % mydeps
                    else:
                        cmd = myparam[generator]
                    status, gen_values, failure = param_cmd(cmd)
                    if not status:
                        yield {'param': gen_values, 'progress': 1, 'failures': failure}
                    else:
                        gen_values = gen_values.split('\n')
                        del myparam[generator]
                        val = []
                        failures = []
                        progress = 1
                        for gen_value in gen_values:
                            mydeps[placeholder] = gen_value
                            elem = {generator: gen_value}
                            failure = {}
                            # evaluate other parameters based on generator
                            for p in myparam:
                                if not p.startswith('_'):
                                    curval = copy.deepcopy(val)
                                    curfailures = copy.deepcopy(failures)
                                    for pv in Role._get_param_value(myparam[p], param_cmd, param_script, mydeps):
                                        curval = copy.deepcopy(val)
                                        curfailures = copy.deepcopy(failures)
                                        elem[p] = pv['param']
                                        if pv['failures'] is not None:
                                            failure[p] = pv['failures']
                                        curval.append(elem)
                                        if failure == {}:
                                            curfailures.append(None)
                                        else:
                                            curfailures.append(failure)
                                        curprogress = progress + pv['progress']
                                        if [f for f in curfailures if f is not None]:
                                            report_failures = curfailures
                                        else:
                                            report_failures = None
                                        yield {'param': curval, 'progress': curprogress, 'failures': report_failures}
                                progress = curprogress
                            val = curval
                            failures = curfailures
            else:  # unclear type
                yield {'param': None,
                       'progress': 1,
                       'failures': "Unexpected _type for parameter: %s" % myparam['_type']}

    def all_included_roles(self):
        air = [r.name for r in self.includes]
        for r in self.includes:
            air.extend(r.all_included_roles())
        return air

    def collect_outgoing_internet_rules(self):
        """Collect firewall rules for outgoing TCP connections to Internet hosts

        :return: dict of address->ports to check { 'address1': 'ports', 'address2': 'ports', ...}
        """
        rules = {}
        for rule in self.firewall:
            if rule['direction'] == 'outgoing' and rule['type'] == 'internet' and \
               'tcp' in [p.lower() for p in rule['protos']] and \
               'hosts' in rule['connect_with'] and isinstance(rule['connect_with']['hosts'], list):
                for host in rule['connect_with']['hosts']:
                    if host not in rules:
                        rules[host] = rule['ports']
                    else:
                        rules[host] = aux.joinranges(rules[host], rule['ports'])
        return rules

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
                    if r in other_role_names:
                        for proto in rule['protos']:
                            for network in rule['networks']:
                                incoming_rules.append({'network': network,
                                                       'proto': proto.lower(),
                                                       'ports': str(rule['ports'])})
        # now check outgoing rules in other firewall
        for rule in other.firewall:
            if rule['direction'] == 'outgoing' and rule['type'] == 'infra':
                for r in rule['connect_with']['roles']:
                    if r in role_names:
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

    def collect_parameters(self, param_cmd, param_script):
        """Collect parameters using passed functions

        :param param_cmd: function to execute parameter' command
        :param param_script: function to execute parameter' script
        :return: generator of { parameters: parameters, progress: progress, failures: failures }
        """
        parameters = copy.deepcopy(self.parameters)
        for result in Role._get_param_value(parameters, param_cmd, param_script):
            my_result = copy.deepcopy(result)
            my_result['parameters'] = my_result['param']
            del my_result['param']
            yield my_result


class RoleCollection(Role):
    """Collection of roles, which can be assigned to a server"""

    def __init__(self, roles):
        self.name = None
        self._roles = ' '.join(roles)
        self._data = {'includes': roles}

    def __str__(self):
        return "role collection: |" + self._roles + "|"

    def __repr__(self):
        return "<RoleCollection: " + self._roles + ">"
