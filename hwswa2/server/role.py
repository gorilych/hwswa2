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
                for p in myparam:
                    if not p.startswith('_'):
                        for pv in Role._get_param_value(myparam[p], param_cmd, param_script, mydeps):
                            val[p] = copy.deepcopy(pv['param'])
                            curprogress = progress + pv['progress']
                            if pv['failures'] is not None:
                                failures[p] = copy.deepcopy(pv['failures'])
                            if failures:
                                curfailures = copy.deepcopy(failures)
                            else:
                                curfailures = None
                            yield {'param': val, 'progress': curprogress, 'failures': curfailures}
                        progress = curprogress

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
                    if not '_separator' in myparam:
                        myparam['_separator'] = ' '
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

    def __init__(self, roles, checksdir):
        self.name = ''
        self._roles = ' '.join(roles)
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

