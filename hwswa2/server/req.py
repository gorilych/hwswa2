import logging

__all__ = ['reqs_factory']

logger = logging.getLogger(__name__)

def reqs_factory(role, body, incl_reqs):
    """Generate list of requirements for role from requirements body and join 
    with requirements from included roles
    """
    role_reqs = []
    for (req_name, req_body) in body.iteritems():
        role_reqs.append(_req_factory(req_name, role, req_body, incl_reqs))
    role_reqs = _merge(role_reqs, incl_reqs)
    return role_reqs


# these global variables get updated after class and function
# definitions later in this module
_type_class = {}
_default_compare_type = ''
_join_functions = {}
_default_join_rule = ''


def _register_req_class(cls):
    """Register requirement class for compare type string
    """
    global _type_class
    _type_class[cls.compare_type] = cls


def _req_class(compare_type):
    global _type_class
    return _type_class[compare_type]


def _register_join_function(join_rule, func):
    """Register join function for join rule string
    """
    global _join_functions
    _join_functions[join_rule] = func


def _join_function(join_rule):
    global _join_functions
    return _join_functions[join_rule]


def _merge(reqs, incl_reqs):
    merged_rs = reqs
    for cls in _BaseReq.__subclasses__():
        merged_rs = cls.merge(merged_rs, incl_reqs)
    return merged_rs


def _req_factory(name, role, body, incl_reqs):
    """Create requirement object from body
    
    body can be a dict with keys 'type', 'value', 'join-rule', 'parameter'
    or body can represent a value, in this case we will find requirement
    attributes by checking included requirements with the same name or 
    (if there are no such requirements) will use defaults    
    """
    if isinstance(body, dict) and 'type' in body:
        compare_type = body['type']
        join_rule = body.get('join-rule', None)
        parameter = body.get('parameter', None)
        value = body.get('value', None)
        (t_compare_type, t_join_rule, t_parameter) = _find_template(name, incl_reqs)
        if t_compare_type == 'manual':
            compare_type = 'manual'
        if compare_type != 'manual' and t_compare_type is not None and compare_type != t_compare_type:
            raise ReqException("different compare types for req %s exist: %s and %s" % (name, compare_type, t_compare_type))
        if join_rule is not None:
            if t_join_rule is not None and join_rule != t_join_rule:
                raise ReqException("different join rules for req %s exist: %s and %s" % (name, join_rule, t_join_rule))
        else:
            join_rule = t_join_rule
        if parameter is not None:
            if t_parameter is not None and parameter != t_parameter:
                raise ReqException("different parameters for req %s exist: %s and %s" % (name, parameter, t_parameter))
        else:
            parameter = t_parameter
    else:
        value = body
        (compare_type, join_rule, parameter) = _find_template(name, incl_reqs)
    compare_type = compare_type or _default_compare_type
    join_rule = join_rule or _default_join_rule
    parameter = parameter or name
    cls = _req_class(compare_type)
    return cls(name, role, join_rule, parameter, value)


def _find_template(name, reqs):
    """Find tuple (compare_type, join_rule, parameter) from reqs - should be the same for all reqs"""
    rs = []
    for r in reqs:
        if r.name == name:
            rs.append(r)
        elif r.joined:
            for jr in r.joined_from:
                if jr.name == name:
                    rs.append(jr)
    if not rs:
        #guessing compare type by name as disk
        if (name.startswith('/') or  # /, /usr, /var
            name[1] == ':'):         # C:, D:, E:, C:\logs
            return ('disk', None, None)
        else:
            return (None, None, None)
    compare_type = rs[0].compare_type
    join_rule = rs[0].join_rule
    parameter = rs[0].parameter
    if compare_type == 'manual':
        return (compare_type, None, None)
    for r in rs:
        if r.compare_type == 'manual':
            return ('manual', None, None)
        if r.compare_type != compare_type:
            raise ReqException("different compare types for req %s exist" % name)
        if r.join_rule != join_rule:
            raise ReqException("different join rules for req %s exist" % name)
        if r.parameter != parameter:
            raise ReqException("different parameters for req %s exist" % name)
    return (compare_type, join_rule, parameter)


class ReqException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class _BaseReq(object):

    def __str__(self):
        if self.istemplate():
            return "tmpl: %s %s X" % (self.name, self.compare_type)
        elif self.joined:
            return "%s %s %s (joined from %s)" % (self.name, self.compare_type, self.value, map(str, self.joined_from))
        else:
            return "%s:%s %s %s" % (self.role, self.name, self.compare_type, self.value)

    def __repr__(self):
        return "<Req " + self.name + ">"
    
    def __init__(self, name, role, join_rule, parameter, value):
        # requirement name
        self.name = name
        # role it comes from. Allows to find duplicated requirements
        self.role = role
        # how to join similar requirements if included roles have it
        self.join_rule = join_rule
        # how to find parameter
        self.parameter = parameter
        # with what to compare
        self.value = value
        # if this requirement is joined from other requirements:
        self.joined = False
        self.joined_from = []
        self.compare_result_reason = None

    def pretty_str(self):
        if self.istemplate():
            return "Template: comparing {}, compare type: {}".format(self.parameter, self.compare_type)
        return "Comparing {} with {}, compare type: {}".format(self.parameter, self.value, self.compare_type)

    def istemplate(self):
        return self.value is None

    def _issimilar(self, other):
        """Other requirement is similar if we can join self and other
        """
        return ((not self.istemplate()) and (not other.istemplate()) 
                and isinstance(other, type(self)) and other.name == self.name)

    def _issame(self, other):
        """Check if other requirement is the same
        """
        return isinstance(other, type(self)) and other.name == self.name and other.role == self.role

    def isequal(self, other):
        """Check if other requiremnt is logically the same
        """
        return isinstance(other, type(self)) and other.parameter == self.parameter and other.value == self.value

    @property
    def expected(self):
        """Return expected value"""
        return self.value

    @classmethod
    def merge(cls, reqs, incl_reqs):
        """Merge requirements of this class in reqs with requirements from included reqs

        Return reqs with updated requirements of this class
        """
        (similar_reqs, rest_reqs) = cls._find_similar(reqs, incl_reqs)
        new_reqs = [cls._join(sreqs) for sreqs in similar_reqs] + rest_reqs
        return new_reqs

    @classmethod
    def _find_similar(cls, reqs, incl_reqs):
        """Find similar reqs of this class suitable for joining

        Return pair: (list of lists of similar requirements, the rest from reqs)
        """
        rest_reqs = []
        similar_reqs = []
        this_class_reqs = []
        for r in reqs:
            if isinstance(r, cls) and not r.istemplate():
                this_class_reqs.append(r)
            else:
                rest_reqs.append(r)
        # extract joined requirements from incl_reqs
        base_incl_reqs = []
        for r in incl_reqs:
            if r.joined:
                base_incl_reqs.extend(r.joined_from)
            elif not r.istemplate():
                base_incl_reqs.append(r)
            else:
                rest_reqs.append(r)
        # remove duplicates of requirements
        filtered_base_incl_reqs = []
        for r in base_incl_reqs:
            if (isinstance(r, cls) 
                and (not any(r._issame(fr) for fr in filtered_base_incl_reqs))):
                filtered_base_incl_reqs.append(r)
        this_class_reqs = this_class_reqs + filtered_base_incl_reqs
        while this_class_reqs:
            init_req = this_class_reqs.pop(0)
            joinable_reqs = [init_req]
            rest_this_class = []
            if this_class_reqs:
                for r in this_class_reqs:
                    if init_req._issimilar(r):
                        joinable_reqs.append(r)
                    else:
                        rest_this_class.append(r)
            similar_reqs.append(joinable_reqs)
            this_class_reqs = rest_this_class
        return (similar_reqs, rest_reqs)

    @classmethod
    def _join(cls, reqs):
        """Join similar requirements into one"""
        if len(reqs) == 1:
            return reqs[0]
        join_func = _join_function(reqs[0].join_rule)
        return join_func(reqs)

    def _compare(self, value):
        raise NotImplemented

    def _convert(self, param_value):
        """Convert parameter value into comparable form"""
        try:
            result = type(self.value)(param_value)
        # trying to work around wrong guess that value is integer
        except ValueError, ve:
            if isinstance(self.value, int):
                result = float(param_value)
            else:
                raise ve
        return result

    def _find_parameter(self, parameters):
        keys = self.parameter.split(':')
        first_key = keys.pop(0)
        param_val = parameters[first_key]
        for key in keys:
            param_val = param_val[key]
        return param_val

    def actual_value(self, parameters):
        return self._convert(self._find_parameter(parameters))

    def check(self, parameters):
        """Check requirement against parameters

        Return pair (result, reason) where result is True/False and reason is string.
        """
        param_value = self._convert(self._find_parameter(parameters))
        result = self._compare(param_value)
        if self.compare_result_reason is None:
            self.compare_result_reason = str(self)
        return (result, self.compare_result_reason)


class ManualReq(_BaseReq):

    compare_type = 'manual'

    def __str__(self):
        return "%s:%s %s" % (self.role, self.name, self.compare_type)

    def pretty_str(self):
        if self.istemplate():
            return "Template: Manual {}".format(self.parameter)
        return "Manual {}: {}".format(self.parameter, self.value)

    def istemplate(self):
        return False

    def check(self, parameters):
        self.compare_result_reason = ""
        return (False, self.compare_result_reason)

    @property
    def expected(self):
        """Return expected value"""
        return "manual check"


class NetworksReq(_BaseReq):

    compare_type = 'networks'

    def __init__(self, *args, **kargs):
        super(NetworksReq, self).__init__(*args, **kargs)
        self.networks = self.value
        self.join_rule = 'set'

    def __str__(self):
        if self.istemplate():
            return "tmpl: %s" % self.compare_type
        elif self.joined:
            networks = ', '.join(self.networks)
            return "%s(%s), joined from %s" % (self.compare_type, networks, map(str, self.joined_from))
        else:
            networks = ', '.join(self.networks)
            return "%s:%s(%s)" % (self.role, self.compare_type, networks)

    def pretty_str(self):
        if self.istemplate():
            return "Template: check for networks"
        return "Required networks: {}".format(self.expected)

    @property
    def expected(self):
        """Return expected value"""
        return ', '.join(self.value)

    def actual_value(self, parameters):
        """Return nics, not just networks"""
        nic_ips = []
        try:  # can fail if no nics
            nics = parameters['network']['network_interfaces']
            for nic in nics:
                if nic.get('slaveof'):  # do not show slave nics
                    continue
                name = nic['name']
                res_str = name
                slaves = [n['name'] for n in nics
                        if n.get('slaveof') == name]
                if slaves:
                    res_str += '(' + ','.join(slaves) + ')'
                try:  # can fail if no ips
                    for ip in nic['ip']:
                        if ip['address'].find(':') == -1:  # filter out IPv6 addresses
                            try:  # can fail if no network
                                res_str += ' ' + ip['address'] + '/' + ip['network']
                                nic_ips.append(res_str)
                            except Exception:
                                logger.debug("found no network in %s" % ip)
                except Exception:
                    logger.debug("found no ips in %s" % nic)
        except Exception:
            logger.debug("found no network interfaces in %s" % parameters)
        return ' | '.join(nic_ips)


    def check(self, parameters):
        networks_in_p = []
        try:  # can fail if no nics
            for nic in parameters['network']['network_interfaces']:
                try:  # can fail if no ips
                    for ip in nic['ip']:
                        try:  # can fail if no network
                            networks_in_p.append(ip['network'])
                        except Exception:
                            logger.debug("found no network in %s" % ip)
                            pass
                except Exception:
                    logger.debug("found no ips in %s" % nic)
                    pass
        except Exception:
            logger.debug("found no network interfaces in %s" % parameters)
            pass
        not_found_networks = [network for network in self.networks if not network in networks_in_p]
        if len(not_found_networks) > 0:
            self.compare_result_reason = "not found: %s" % ', '.join(not_found_networks)
            return (False, self.compare_result_reason)
        else:
            self.compare_result_reason = "all networks found"
            return (True, self.compare_result_reason)


class EqualReq(_BaseReq):

    compare_type = 'eq'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} equals ...".format(self.parameter)
        return "{} == {}".format(self.parameter, self.value)

    def _compare(self, value):
        if not value == self.value:
            self.compare_result_reason = "actual value: %s" % value
            return False
        else:
            return True


class NotEqualReq(_BaseReq):

    compare_type = 'neq'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} is not equal ...".format(self.parameter)
        return "{} != {}".format(self.parameter, self.value or "''")

    @property
    def expected(self):
        """Return expected value"""
        if self.value:
            return 'Not' + str(self.value)
        else:
            return 'Not empty'

    def _compare(self, value):
        if not value != self.value:
            self.compare_result_reason = "actual value: %s" % value 
            return False
        else:
            return True


class LessThenReq(_BaseReq):

    compare_type = 'lt'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} is less than ...".format(self.parameter)
        return "{} < {}".format(self.parameter, self.value)

    @property
    def expected(self):
        """Return expected value"""
        return str(self.value)

    def _compare(self, value):
        if not value < self.value:
            self.compare_result_reason = "actual value: %s" % value 
            return False
        else:
            return True


class LessEqualReq(_BaseReq):

    compare_type = 'le'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} is less or equal to ...".format(self.parameter)
        return "{} <= {}".format(self.parameter, self.value)

    @property
    def expected(self):
        """Return expected value"""
        return self.value

    def _compare(self, value):
        if not value <= self.value:
            self.compare_result_reason = "actual value: %s" % value
            return False
        else:
            return True


class GreaterThenReq(_BaseReq):

    compare_type = 'gt'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} is greater than ...".format(self.parameter)
        return "{} > {}".format(self.parameter, self.value)

    @property
    def expected(self):
        """Return expected value"""
        return str(self.value)

    def _compare(self, value):
        if not value > self.value:
            self.compare_result_reason = "actual value: %s" % value
            return False
        else:
            return True


class GreaterEqualReq(_BaseReq):

    compare_type = 'ge'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} is greater or equal to ...".format(self.parameter)
        return "{} >= {}".format(self.parameter, self.value)

    @property
    def expected(self):
        """Return expected value"""
        return self.value

    def _compare(self, value):
        if not value >= self.value:
            self.compare_result_reason = "actual value: %s" % value
            return False
        else:
            return True


class RegexReq(_BaseReq):

    compare_type = 'regex'

    def pretty_str(self):
        if self.istemplate():
            return "Template: {} matches pattern ...".format(self.parameter)
        return "{} matches regex pattern {}".format(self.parameter, self.value)

    @property
    def expected(self):
        """Return expected value"""
        return self.value

    def __init__(self, *args, **kargs):
        super(RegexReq, self).__init__(*args, **kargs)
        import re
        if not self.istemplate():
            self.pattern = re.compile(self.value)
    
    def _convert(self, param_value):
        return param_value

    def _compare(self, value):
        if not self.pattern.match(value):
            self.compare_result_reason = "actual value: %s" % value
            return False
        else:
            return True


class DiskReq(_BaseReq):

    compare_type = 'disk'

    def __str__(self):
        if self.istemplate():
            return "req disk tmpl: {'%s': X}" % self.name
        else:
            return "req disk: %s" % self.path_size

    def pretty_str(self):
        if self.istemplate():
            return "Template for disk requirement for {}".format(self.parameter)
        return self.expected

    @property
    def expected(self):
        """Return expected value"""
        return ', '.join(["{} {}GB".format(path, size) for (path, size) in self.path_size.items()])

    def __init__(self, *args, **kargs):
        super(DiskReq, self).__init__(*args, **kargs)
        if isinstance(self.value, dict):
            self.path_size = self.value
        else:
            self.path_size = {self.parameter: self.value}
        self.join_rule = 'sum'

    def _issimilar(self, other):
        """All disk requirements are similar"""
        return ((not self.istemplate()) and (not other.istemplate()) 
                and isinstance(other, type(self)))

    def _find_parameter(self, parameters):
        # parameters['partitions'] is table with fields [device, size(GB), mountpoint, fs_type]
        # we need to return dict{mountpoint->size}
        parts = parameters['partitions']
        mount_size = dict([(part['mountpoint'], float(part['size(GB)'])) for part in parts])
        return mount_size

    def _convert(self, param_value):
        return param_value

    def actual_value(self, parameters):
        return ', '.join(["{} {}GB".format(path, size) for (path, size)
            in self._convert(self._find_parameter(parameters)).items()])

    @staticmethod
    def _find_mount4path(path, mounts):
        """Find mountpoint for path from mountpoints

        Example: _find_mount4path('/var/log', ['/', '/var', '/usr']) -> '/var'
        """
        def under_mount(path, mount):
            return (mount == '/' or
                    path == mount or
                    (path.startswith(mount) and (path[len(mount)] == '/'
                                                 or path[len(mount)] == '\\')))
        try:
            mount = max([m for m in mounts if under_mount(path,m)], key=len)
        except ValueError:  # max will fail for empty sequence
            return None
        else:
            return mount

    def _compare(self, mount_size):
        path_size = self.path_size  # { path1: req_size1, ..
        logger.debug("Comparing req %s with actual %s" %(path_size, mount_size))
        # mount_size = { mount1: its_size, .. }
        mounts = mount_size.keys()
        paths = path_size.keys()
        # required size for mountpoints
        mount_req_size = {}
        mount_paths = {}
        # for each path with requirement we shall find
        # under which mountpoint it is located
        # and add its required size into total requirement
        # for the mountpoint
        for (p, psize) in path_size.iteritems():
            m = self._find_mount4path(p, mounts)
            mount_req_size.setdefault(m, 0)
            mount_req_size[m] += psize
            # also we save where requirement came from
            mount_paths.setdefault(m, [])
            mount_paths[m].append(p)
        # for mountpoints which do not include any of paths
        # we shall find under which path it is located and
        # set this path requirement as requirement for the
        # mountpoint. F.e. if we require /usr to be at least
        # 20, have no specific requirement for path /usr/local
        # and have mountpoint /usr/local then it should be at least 20 too
        for m in mounts:
            if m in mount_req_size.keys() or m == '-':  # '-' means non-mounted
                continue
            p = self._find_mount4path(m, paths)
            if p:
                mount_req_size[m] = path_size[p]
                mount_paths[m] = [p]
        self.compare_result_reason = ''
        result = True
        for (m, req_size) in mount_req_size.iteritems():
            msize = mount_size[m]
            if req_size >= msize:
                if len(self.compare_result_reason) > 0:
                    self.compare_result_reason += ' | '
                self.compare_result_reason += (
                    '+'.join(["{0}({1})".format(p,path_size[p]) 
                              for p in mount_paths[m]]) +
                    " > actual: {0}({1})".format(m,msize))
                result = False
        return result
                

    @classmethod
    def _join(cls, reqs):
        """Join similar requirements into one"""
        if len(reqs) == 1:
            return reqs[0]
        join_func = _join_function(reqs[0].join_rule) # should be always _join_sum()
        #requiements for different paths
        path_reqs = {}
        for r in reqs:
            path = r.parameter
            rs = path_reqs.setdefault(path, [])
            rs.append(r)
        value = dict((path, join_func(rs).value) for (path, rs) in path_reqs.iteritems())
        new_req = cls(None, None, None, None, value)
        new_req.joined = True
        new_req.joined_from = reqs
        return new_req


class AndReq(_BaseReq):

    compare_type = 'and'

    def pretty_str(self):
        if self.istemplate():
            return "Template for AND reqs"
        return self.expected

    @property
    def expected(self):
        """Return expected value"""
        return ' AND '.join([req.pretty_str() for req in self.value])

    def actual_value(self, parameters):
        """Return actual value of the first req"""
        if self.name:
            return self.value[0].actual_value(parameters)
        else:
            return None

    def check(self, parameters):
        reqs = self.value
        for r in reqs:
            (result, reason) = r.check(parameters)
            # AndReq fails if any included req fails
            if not result:
                self.compare_result_reason = reason
                return (result, reason)
        return (True, '')


class OrReq(_BaseReq):

    compare_type = 'or'

    def pretty_str(self):
        if self.istemplate():
            return "Template for OR reqs"
        return self.expected

    @property
    def expected(self):
        """Return expected value"""
        return ' OR '.join([req.pretty_str() for req in self.value])

    def check(self, parameters):
        reqs = self.value
        for r in reqs:
            (result, reason) = r.check(parameters)
            # OrReq is OK if any included req is OK
            if result:
                self.compare_result_reason = reason
                return (result, reason)
        self.compare_result_reason = 'All fails: %s' % map(str,reqs)
        return (False, self.compare_result_reason)


def _join_override(reqs):
    return reqs[0]

def _generate_join_logical(cls):
    """Generate join function

    which join requirements inside a logical requirement of given class
    Suitable only for AND and OR, because it removes equal reqs!
    """
    def join_func(reqs):
        # filter out non-unique requirements
        unique_reqs = []
        name = None
        parameter = None
        if len(reqs) > 0:
            name = reqs[0].name
            parameter = reqs[0].parameter
        for req in reqs:
            if req.name != name:
                name = None
                parameter = None
            unique = True
            for ur in unique_reqs:
                if ur.isequal(req):
                    unique = False
            if unique:
                unique_reqs.append(req)
        if len(unique_reqs) == 1:
            return unique_reqs[0]
        new_req = cls(name, None, None, parameter, unique_reqs)
        new_req.joined = True
        new_req.joined_from = reqs
        return new_req
    return join_func

_join_and = _generate_join_logical(AndReq)
_join_or = _generate_join_logical(OrReq)


def _join_values(join_func):
    """Decorator for join functions which join requirement values
    """
    def new_join_func(reqs):
        first_req = reqs[0]
        cls = type(first_req)
        name = first_req.name
        role = None
        join_rule = first_req.join_rule
        parameter = first_req.parameter
        values = [r.value for r in reqs]
        value = join_func(values)
        new_req = cls(name, role, join_rule, parameter, value)
        new_req.joined = True
        new_req.joined_from = reqs
        return new_req
    
    return new_join_func

@_join_values
def _join_sum(values):
    return reduce(lambda x,y: x+y, values)


@_join_values
def _join_mul(values):
    return reduce(lambda x,y: x*y, values, 1)


@_join_values
def _join_avg(values):
    return reduce(lambda x,y: x+y, values) / len(values)


@_join_values
def _join_min(values):
    return min(values)


@_join_values
def _join_max(values):
    return max(values)


@_join_values
def _join_set(values):
    return reduce(lambda set1,set2: list(set(set1+set2)), values, [])


for cls in _BaseReq.__subclasses__():
    _register_req_class(cls)
_default_compare_type = EqualReq.compare_type

_register_join_function('override', _join_override)
_register_join_function('sum', _join_sum)
_register_join_function('mul', _join_mul)
_register_join_function('avg', _join_avg)
_register_join_function('min', _join_min)
_register_join_function('max', _join_max)
_register_join_function('and', _join_and)
_register_join_function('or', _join_or)
_register_join_function('set', _join_set)
_default_join_rule = 'override'


