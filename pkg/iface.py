#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# iface --
#    interface object
#
from collections import OrderedDict
#from json import *
import json
import logging

tickmark = ' (' + u'\u2713'.encode('utf8') + ')'
crossmark = ' (' + u'\u2717'.encode('utf8') + ')'

class ifaceFlags():
    NONE = 0x1
    FOLLOW_DEPENDENTS = 0x2

class ifaceStatus():
    """iface status """
    UNKNOWN = 0x1
    SUCCESS = 0x2
    ERROR = 0x3
    NOTFOUND = 0x4

    @classmethod
    def to_str(cls, state):
        if state == cls.UNKNOWN:
            return 'unknown'
        elif state == cls.SUCCESS:
            return 'success'
        elif state == cls.ERROR:
            return 'error'
        elif state == cls.NOTFOUND:
            return 'notfound'
    
    @classmethod
    def from_str(cls, state_str):
        if state_str == 'unknown':
            return cls.UNKNOWN
        elif state_str == 'success':
            return cls.SUCCESS
        elif state_str == 'error':
            return cls.ERROR

class ifaceState():

    """ iface states """
    UNKNOWN = 0x1
    NEW = 0x2
    PRE_UP = 0x3
    UP = 0x4
    POST_UP = 0x5
    PRE_DOWN = 0x6
    DOWN = 0x7
    POST_DOWN = 0x8

    # Pseudo states
    QUERY_CHECKCURR = 0x9
    QUERY_RUNNING = 0xa

    @classmethod
    def to_str(cls, state):
        if state == cls.UNKNOWN:
            return 'unknown'
        elif state == cls.NEW:
            return 'new'
        elif state == cls.PRE_UP:
            return 'pre-up'
        elif state == cls.UP:
            return 'up'
        elif state == cls.POST_UP:
            return 'post-up'
        elif state == cls.PRE_DOWN:
            return 'pre-down'
        elif state == cls.DOWN:
            return 'down'
        elif state == cls.POST_DOWN:
            return 'post-down'
        elif state == cls.QUERY_CHECKCURR:
            return 'query-checkcurr'
        elif state == cls.QUERY_RUNNING:
            return 'query-running'

    @classmethod
    def from_str(cls, state_str):
        if state_str == 'unknown':
            return cls.UNKNOWN
        elif state_str == 'new':
            return cls.NEW
        elif state_str == 'pre-up':
            return cls.PRE_UP
        elif state_str == 'up':
            return cls.UP
        elif state_str == 'post-up':
            return cls.POST_UP
        elif state_str == 'pre-down':
            return cls.PRE_DOWN
        elif state_str == 'down':
            return cls.DOWN
        elif state_str == 'post-down':
            return cls.POST_DOWN
        elif state_str == 'query-checkcurr':
            return cls.QUERY_CHECKCURR
        elif state_str == 'query-running':
            return cls.QUERY_RUNNING

class ifaceJsonEncoder(json.JSONEncoder):
    def default(self, o):
        retconfig = {}
        if o.config:
            for k, v in o.config.items():
                if len(v) == 1:
                    retconfig[k] = v[0]
                else:
                    retconfig[k] = v

        return OrderedDict({'name' : o.name,
                            'addr_method' : o.addr_method,
                            'addr_family' : o.addr_family,
                            'auto' : o.auto,
                            'config' : retconfig})

class iface():
    """ flags """
    # flag to indicate that the object was created from pickled state
    PICKLED = 0x1

    version = '0.1'

    def __init__(self):
        self.name = None
        self.addr_family = None
        self.addr_method = None
        self.config = OrderedDict()
        self.config_status = {}
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.flags = 0x0
        self.priv_flags = 0x0
        self.refcnt = 0
        self.lowerifaces = None
        self.upperifaces = None
        self.auto = False
        self.classes = []
        self.env = None
        self.raw_lines = []
        self.linkstate = None

    def inc_refcnt(self):
        self.refcnt += 1

    def dec_refcnt(self):
        self.refcnt -= 1

    def get_refcnt(self):
        return self.refcnt

    def set_refcnt(self, cnt):
        self.refcnt = 0

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_addr_family(self, family):
        self.addr_family = family

    def get_addr_family(self):
        return self.addr_family

    def set_addr_method(self, method):
        self.addr_method = method

    def get_addr_method(self):
        return self.addr_method

    def set_config(self, config_dict):
        self.config = config_dict

    def get_config(self):
        return self.config

    def is_config_present(self):
        addr_method = self.get_addr_method()
        if addr_method:
            if (addr_method.find('dhcp') != -1 or
                    addr_method.find('dhcp6') != -1):
                return True
        if not self.config:
            return False
        else:
            return True

    def get_auto(self):
        return self.auto

    def set_auto(self):
        self.auto = True

    def reset_auto(self):
        self.auto = False

    def get_classes(self):
        return self.classes

    def set_classes(self, classes):
        """ sets interface class list to the one passed as arg """
        self.classes = classes

    def set_class(self, classname):
        """ Appends a class to the list """
        self.classes.append(classname)

    def belongs_to_class(self, intfclass):
        if intfclass in self.classes:
            return True
        return False

    def set_priv_flags(self, priv_flags):
        self.priv_flags = priv_flags

    def get_priv_flags(self):
        return self.priv_flags

    def get_state(self):
        return self.state

    def get_state_str(self):
        return ifaceState.to_str(self.state)

    def set_state(self, state):
        self.state = state

    def get_status(self):
        return self.status

    def get_status_str(self):
        return ifaceStatus.to_str(self.status)

    def set_status(self, status):
        self.status = status

    def set_state_n_status(self, state, status):
        self.state = state
        self.status = status

    def state_str_to_hex(self, state_str):
        return self.state_str_map.get(state_str)

    def set_flag(self, flag):
        self.flags |= flag

    def clear_flag(self, flag):
        self.flags &= ~flag

    def set_lowerifaces(self, dlist):
        self.lowerifaces = dlist

    def get_lowerifaces(self):
        return self.lowerifaces

    def set_upperifaces(self, dlist):
        self.upperifaces = dlist

    def add_to_upperifaces(self, upperifacename):
        if self.upperifaces:
            if upperifacename not in self.upperifaces:
                self.upperifaces.append(upperifacename)
        else:
            self.upperifaces = [upperifacename]

    def get_upperifaces(self):
        return self.upperifaces

    def set_linkstate(self, l):
        self.linkstate = l

    def get_linkstate(self):
        return self.linkstate

    def get_attr_value(self, attr_name):
        config = self.get_config()

        return config.get(attr_name)
    
    def get_attr_value_first(self, attr_name):
        config = self.get_config()
        attr_value_list = config.get(attr_name)
        if attr_value_list:
            return attr_value_list[0]
        return None

    def get_attr_value_n(self, attr_name, attr_index):
        config = self.get_config()

        attr_value_list = config.get(attr_name)
        if attr_value_list:
            try:
                return attr_value_list[attr_index]
            except:
                return None
        return None

    def get_env(self):
        if not self.env:
            self.generate_env()
        return self.env

    def set_env(self, env):
        self.env = env

    def generate_env(self):
        env = {}
        config = self.get_config()
        env['IFACE'] = self.get_name()
        for attr, attr_value in config.items():
            attr_env_name = 'IF_%s' %attr.upper()
            env[attr_env_name] = attr_value[0]

        if env:
            self.set_env(env)

    def update_config(self, attr_name, attr_value):
        if not self.config.get(attr_name):
            self.config[attr_name] = [attr_value]
        else:
            self.config[attr_name].append(attr_value)

    def update_config_dict(self, attrdict):
        self.config.update(attrdict)

    def update_config_with_status(self, attr_name, attr_value, attr_status=0):
        if not attr_value:
            attr_value = ''

        if self.config.get(attr_name):
            self.config[attr_name].append(attr_value)
            self.config_status[attr_name].append(attr_status)
        else:
            self.config[attr_name] = [attr_value]
            self.config_status[attr_name] = [attr_status]

        # set global iface state
        if attr_status:
            self.set_status(ifaceStatus.ERROR)
        elif self.get_status() != ifaceStatus.ERROR:
            # Not already error, mark success
            self.set_status(ifaceStatus.SUCCESS)

    def get_config_attr_status(self, attr_name, idx=0):
        self.config_status.get(attr_name, [])[idx]

    def get_config_attr_status_str(self, attr_name, idx=0):
        ret = self.config_status.get(attr_name, [])[idx]
        if ret:
            return crossmark
        else:
            return tickmark

    def is_different(self, dstiface):
        if self.name != dstiface.name: return True
        if self.addr_family != dstiface.addr_family: return True
        if self.addr_method != dstiface.addr_method: return True
        if self.auto != dstiface.auto: return True
        if self.classes != dstiface.classes: return True

        if any(True for k in self.config if k not in dstiface.config):
            return True

        if any(True for k,v in self.config.items()
                    if v != dstiface.config.get(k)): return True

        return False

    def __getstate__(self):
        odict = self.__dict__.copy()
        del odict['state']
        del odict['status']
        del odict['lowerifaces']
        del odict['refcnt']
        del odict['config_status']
        del odict['flags']
        del odict['priv_flags']
        del odict['upperifaces']
        del odict['raw_lines']
        del odict['linkstate']
        del odict['env']
        return odict

    def __setstate__(self, dict):
        self.__dict__.update(dict)
        self.config_status = {}
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.refcnt = 0
        self.flags = 0
        self.lowerifaces = None
        self.upperifaces = None
        self.linkstate = None
        self.env = None
        self.priv_flags = 0
        self.raw_lines = []
        self.flags |= self.PICKLED
        
    def dump_raw(self, logger):
        indent = '  '
        print (self.raw_lines[0])
        for i in range(1, len(self.raw_lines)):
            print (indent + self.raw_lines[i])
        
    def dump(self, logger):
        indent = '\t'
        logger.info(self.get_name() + ' : {')
        logger.info(indent + 'family: %s' %self.get_addr_family())
        logger.info(indent + 'method: %s' %self.get_addr_method())
        logger.info(indent + 'flags: %x' %self.flags)
        logger.info(indent + 'state: %s'
                %ifaceState.to_str(self.get_state()))
        logger.info(indent + 'status: %s'
                %ifaceStatus.to_str(self.get_status()))
        logger.info(indent + 'refcnt: %d' %self.get_refcnt())
        d = self.get_lowerifaces()
        if d:
            logger.info(indent + 'lowerdevs: %s' %str(d))
        else:
            logger.info(indent + 'lowerdevs: None')

        logger.info(indent + 'config: ')
        config = self.get_config()
        if config:
            logger.info(indent + indent + str(config))
        logger.info('}')

    def dump_pretty(self, with_status=False):
        indent = '\t'
        outbuf = ''
        if self.get_auto():
            outbuf += 'auto %s\n' %self.get_name()
        outbuf += 'iface %s' %self.get_name()
        if self.get_addr_family():
            outbuf += ' %s' %self.get_addr_family()
        if self.get_addr_method():
            outbuf += ' %s' %self.get_addr_method()
        outbuf += '\n'
        config = self.get_config()
        if config:
            for cname, cvaluelist in config.items():
                idx = 0
                for cv in cvaluelist:
                    if with_status:
                        outbuf += indent + '%s %s %s\n' %(cname, cv,
                                    self.get_config_attr_status_str(cname, idx))
                    else:
                        outbuf += indent + '%s %s\n' %(cname, cv)
                    idx += 1

        print outbuf

    def dump_json(self, with_status=False):
        print json.dumps(self, cls=ifaceJsonEncoder, indent=4)
