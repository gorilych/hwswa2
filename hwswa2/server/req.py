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
        if t_compare_type is not None and compare_type != t_compare_type:
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
        return (None, None, None)
    compare_type = rs[0].compare_type
    join_rule = rs[0].join_rule
    parameter = rs[0].parameter
    for r in rs:
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
            return "req tmpl: %s %s X" % (self.name, self.compare_type)
        elif self.joined:
            return "req: %s %s %s (joined from %s)" % (self.name, self.compare_type, self.value, map(str, self.joined_from))
        else:
            return "req: %s:%s %s %s" % (self.role, self.name, self.compare_type, self.value)

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
        return type(self.value)(param_value)

    def _find_parameter(self, parameters):
        keys = self.parameter.split(':')
        first_key = keys.pop(0)
        param_val = parameters[first_key]
        for key in keys:
            param_val = param_val[key]
        return param_val

    def check(self, parameters):
        """Check requirement against parameters

        Return pair (result, reason) where result is True/False and reason is string.
        """
        param_value = self._convert(self._find_parameter(parameters))
        result = self._compare(param_value)
        if self.compare_result_reason is None:
            self.compare_result_reason = str(self)
        return (result, self.compare_result_reason)
    


class EqualReq(_BaseReq):
    compare_type = 'eq'

    def _compare(self, value):
        return value == self.value


class NotEqualReq(_BaseReq):

    compare_type = 'neq'

    def _compare(self, value):
        return value != self.value


class LessThenReq(_BaseReq):

    compare_type = 'lt'

    def _compare(self, value):
        return value < self.value


class LessEqualReq(_BaseReq):

    compare_type = 'le'

    def _compare(self, value):
        return value <= self.value


class GreaterThenReq(_BaseReq):

    compare_type = 'gt'

    def _compare(self, value):
        return value > self.value


class GreaterEqualReq(_BaseReq):

    compare_type = 'ge'

    def _compare(self, value):
        return value >= self.value


class RegexReq(_BaseReq):

    compare_type = 'regex'

    def __init__(self, *args, **kargs):
        super(RegexReq, self).__init__(*args, **kargs)
        import re
        if not self.istemplate():
            self.pattern = re.compile(self.value)
    
    def _convert(self, param_value):
        return param_value

    def _compare(self, value):
        return self.pattern.match(value)


class DiskReq(_BaseReq):

    compare_type = 'disk'

    def __str__(self):
        if self.istemplate():
            return "req disk tmpl: {'%s': X}" % self.name
        else:
            return "req disk: %s" % self.path_size

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
        mount_size = dict([(part['mountpoint'], part['size(GB)']) for part in parts])
        return mount_size

    def _convert(self, param_value):
        return param_value

    @staticmethod
    def _find_mount4path(path, mounts):
        """Find mountpoint for path from mountpoints

        Example: _find_mount4path('/var/log', ['/', '/var', '/usr']) -> '/var'
        """
        return max([m for m in mounts if path.startswith(m)], key=len)

    def _compare(self, mount_size):
        path_size = self.path_size
        mounts = [m for m in mount_size]
        # required size for mountpoints
        mount_req_size = {}
        mount_paths = {}
        for (p, psize) in path_size.iteritems():
            m = self._find_mount4path(p, mounts)
            mount_req_size.setdefault(m, 0)
            mount_req_size[m] += psize
            mount_paths.setdefault(m, [])
            mount_paths[m].append(p)
        for (m, req_size) in mount_req_size.iteritems():
            msize = mount_size[m]
            if req_size >= msize:
                self.compare_result_reason = (
                    "disk space: required: " +
                    ' '.join(["{}({})".format(p,path_size[p]) 
                              for p in mount_paths[m]]) +
                    " > actual: {}({})".format(m,msize))
                return False
        return True
                

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

    compare_type = 'and-notsupported'

    def check(self, parameters):
        reqs = self.value
        for r in reqs:
            (result, reason) = r.check()
            # AndReq fails if any included req fails
            if not result:
                self.compare_result_reason = reason
                return (result, reason)
        return (True, '')


class OrReq(_BaseReq):

    compare_type = 'or-notsupported'

    def check(self, parameters):
        reqs = self.value
        for r in reqs:
            (result, reason) = r.check()
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
    """
    def join_func(reqs):
        new_req = cls(None, None, None, None, reqs)
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
_default_join_rule = 'override'








'''

class Req(object):
    def __str__(self):
        if self.istemplate():
            return "req tmpl: " + self.name + " " + self.compare_type + " <X>"
        else:
            return "req: " + self.name + " " + self.compare_type + " " + self.value

    def __repr__(self):
        return "<Req " + self.name + ">"
    
    def __init__(self, name, value=None, param_path=None, role=None, compare_type=None, join_rule=None, joined=None, joined_from=None, orig_cmp_type=None):
        # allowed values: eq, neq, regex, lt (less-then), le (less-or-equal), gt, ge, or disk
        self.compare_type = compare_type or 'eq'
        # compare_type can be changed while joining, that's why we have orig_cmp_type
        self.orig_cmp_type = orig_cmp_type or self.compare_type
        # allowed values: override, and, or, sum, mul, avg, min, max
        if self.orig_cmp_type == 'disk':
            self.join_rule = 'sum'
        else:
            self.join_rule = join_rule or 'override'
        self.joined = joined or False
        self.joined_from = joined_from or []
        self.param_path = param_path or name
        self.name = name
        # if value is None, this requirement is a template for other requirements
        self.value = value
        self.role = role

    def istemplate(self):
        return self.value is None

    @staticmethod
    def _findtemplate(name, reqs):
        """Find tuple (compare_type, join_rule, param_path) from reqs - should be the same for all reqs"""
        rs = [r for r in reqs if r.name == name]
        if not rs:
            return (None, None, None)
        compare_type = rs[0].orig_cmp_type
        join_rule = rs[0].join_rule
        param_path = rs[0].param_path
        for r in rs:
            if r.orig_cmp_type != compare_type:
                raise ReqException("different compare types for req %s exist" % name)
            if r.join_rule != join_rule:
                raise ReqException("different join rules for req %s exist" % name)
            if r.param_path != param_path:
                raise ReqException("different parameters for req %s exist" % name)
        return (compare_type, join_rule, param_path)

    @staticmethod
    def _findbasereqs(reqs):
        """Decompose all joined reqs and filter out duplicates

        [req1, req2(joined from req3, req4, req6), req5, req6] -> 
        [req1, req3, req4, req6, req5]
        """
        joined_reqs = [r for r in reqs if r.joined]
        base_reqs = ([r for r in reqs if not r.joined] + 
                     [r for jr in joined_reqs for r in jr.joined_from])
        #filter out duplicates with the same role and name
        role_names = []
        result = []
        for r in base_reqs:
            if (r.role, r.name) not in role_names:
                roles.append((r.role, r.name))
                result.append(r)
        return result
        
    @staticmethod
    def _join(req, reqs):
        """Join requirement with requirements"""
        # filter out templates
        reqs = [r for r in reqs if not r.istemplate()]
        name = req.name
        orig_cmp_type = compare_type = req.orig_cmp_type
        if compare_type == 'disk':
            reqs = [r for r in reqs if r.compare_type == 'disk']
        else:
            reqs = [r for r in reqs if r.name == name]
        if not reqs:
            return req
        role = req.role
        param_path = req.param_path
        join_rule = req.join_rule
        value = joined = joined_from = None
        if compare_type == 'disk':
            joined = True
            same_path_reqs = [req]
            other_path_reqs = []
            for r in reqs:
                if r.compare_type == 'disk':
                    if r.param_path == param_path:
                        same_path_reqs.append(r)
                    else:
                        other_path_reqs.append(r)
            same_path_reqs = [r for r in Req._findbasereqs(same_path_reqs) if r.param_path == param_path]
            joined_from = same_path_reqs + other_path_reqs
            value = reduce(lambda x,y: x+y, [r.value for r in same_path_reqs])
        elif join_rule == 'override':
            return req
        elif join_rule == 'max':
            value = max(req.value, max([r.value for r in reqs]))
        elif join_rule == 'min':
            value = min(req.value, min([r.value for r in reqs]))
        elif join_rule in ['and', 'or']:
            compare_type = join_rule
            joined = True
            value = joined_from = [req] + Req._findbasereqs(reqs)
        elif join_rule in ['sum', 'mul', 'avg']:
            joined = True
            joined_from = [req] + Req._findbasereqs(reqs)
            if join_rule == 'sum':
                value = reduce(lambda x,y: x+y, [r.value for r in joined_from])
            elif join_rule == 'mul':
                value = reduce(lambda x,y: x+y, [r.value for r in joined_from], 1)
            elif join_rule == 'avg':
                value = reduce(lambda x,y: x+y, [r.value for r in joined_from])
                value /= len(joined_from)
        return Req(name, value, param_path, role, compare_type, join_rule, joined, joined_from, orig_cmp_type)

    @staticmethod
    def _convert(val, compare_type=None, join_rule=None, inherited_reqs=None, role=None):
        """Convert requiement value to comparable value"""
        if val is None or compare_type is None:
            return val
        elif compare_type in ['regex']:
            return val
        elif compare_type in ['le', 'lt', 'ge', 'gt', 'disk']:
            return float(val)
        elif compare_type in ['eq', 'neq']:
            if join_rule in ['sum', 'mul', 'min', 'max', 'avg']:
                return float(val)
            else:
                return val
        elif compare_type in ['and', 'or']:
            return dict((req, Req.factory(req, body, inherited_reqs, role)) for (req, body) in val.iteritems()) 
        else:
            raise ReqException("not valid compare type: %s value=%s" % (compare_type, val))

    @staticmethod
    def _findparam(param_path, parameters, compare_type):
        # process special types first
        if compare_type == 'disk':
            # parameters['partitions'] is table with fields [device, size(GB), mountpoint, fs_type]
            # we need to return dict{mountpoint->size}
            parts = parameters['partitions']
            mount_size = dict([(part[2], part[1]) for part in parts])
            return mount_size
            # find mountpoint for path param_path
            # f.e. max([path for path in ['/', '/usr', '/var'] if '/usr/test'.startswith(path)], key=len) = '/usr'
            #mountpoint = max([path for path in mount_size if param_path.startswith(path)], key=len)
            #param = mount_size[mountpoint]
        else:
            param = None
            for key in param_path.split(':'):
                if param:
                    param = param[key]
                else:
                    param = parameters[key]
        return Req._convert(param, compare_type)
                
    @classmethod
    def factory(cls, name, body, inherited_reqs=None, role=None):
        """Create requirement object from requirement body"""
        if isinstance(body, dict) and 'type' in body:
            compare_type = body['type']
            join_rule = body.get('join-rule', None)
            param_path = body.get('parameter', None)
            val = body.get('value', None)
        else:
            (compare_type, join_rule, param_path) = Req._findtemplate(name, inherited_reqs)
            val = body
        value = Req._convert(val, compare_type, join_rule, inherited_reqs, role)
        pure_req = Req(name, value, param_path, role, compare_type, join_rule)
        return Req._join(pure_req, inherited_reqs)

    def check(self, parameters=None):
        """Check requirement against particular value"""
        if self.value is None:
            raise ReqException("trying to check template requirement %s" % self)
        elif self.compare_type == 'and':
            for req in self.value:
                if not req.check(parameters):
                    return False
            return True
        elif self.compare_type == 'or':
            for req in self.value:
                if req.check(parameters):
                    return True
            return False
        param = Req._findparam(req.param_path, parameters, req.compare_type)
        if self.compare_type in ['eq', 'neq']:
            #neq, eq can be used both for strings and numbers
            #first we try to compare as strings then as numbers
            test = (self.value == param) or (float(self.value) == float(param))
            if self.compare_type == 'eq':
                return test
            else:
                return not test
        elif self.compare_type == 'regex':
            return re.match(self.value, param)
        elif self.compare_type == 'le':
            return self.value <= param
        elif self.compare_type == 'lt':
            return self.value < param
        elif self.compare_type == 'ge':
            return self.value >= param
        elif self.compare_type == 'gt':
            return self.value > param
        elif self.compare_type == 'disk':
            mountpoints = param.keys
        else:
            raise ReqException("Unknown compare type for req %s" % self)
            
'''
