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
            return 'not found'
    
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
        return OrderedDict({'name' : o.name,
                            'addr_method' : o.addr_method,
                            'addr_family' : o.addr_family,
                            'auto' : o.auto,
                            'config' : o.config})

class iface():
    """ config flags """
    AUTO = 0x1
    HOT_PLUG = 0x2

    version = '0.1'

    def __init__(self):
        self.name = None
        self.addr_family = None
        self.addr_method = None
        self.config = OrderedDict()
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.errstr = ''
        self.flags = 0x0
        self.priv_flags = 0x0
        self.refcnt = 0
        # dependents that are listed as in the
        # config file
        self.dependents = None
        # All dependents (includes dependents that
        # are not listed in the config file)
        self.realdev_dependents = None
        self.auto = False
        self.classes = []
        self.env = None
        self.config_current = {}
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
        if addr_method is not None:
            if (addr_method.find('dhcp') != -1 or
                    addr_method.find('dhcp6') != -1):
                return True

        if self.config is None:
            return False

        return (len(self.config) != 0)

    def set_config_current(self, config_current):
        self.config_current = config_current

    def get_config_current(self):
        return self.config_current

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

    def state_str_to_hex(self, state_str):
        return self.state_str_map.get(state_str)

    def set_flag(self, flag):
        self.flags |= flag

    def clear_flag(self, flag):
        self.flags &= ~flag

    def set_dependents(self, dlist):
        self.dependents = dlist

    def get_dependents(self):
        return self.dependents

    def set_realdev_dependents(self, dlist):
        self.realdev_dependents = dlist

    def get_realdev_dependents(self):
        return self.realdev_dependents

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
        if attr_value_list is not None:
            return attr_value_list[0]
        return None

    def get_attr_value_n(self, attr_name, attr_index):
        config = self.get_config()

        attr_value_list = config.get(attr_name)
        if attr_value_list is not None:
            try:
                return attr_value_list[attr_index]
            except:
                return None

        return None

    def get_env(self):
        if self.env is None or len(self.env) == 0:
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

        if len(env) > 0:
            self.set_env(env)

    def update_config(self, attr_name, attr_value):
        if self.config.get(attr_name) is None:
            self.config[attr_name] = [attr_value]
        else:
            self.config[attr_name].append(attr_value)

    def update_config_dict(self, attrdict):
        self.config.update(attrdict)

    def update_config_with_status(self, attr_name, attr_value, attr_status=0):
        if attr_value is None:
            attr_value = ''
        if attr_status:
            self.set_status(ifaceStatus.ERROR)
            new_attr_value = '%s (%s)' %(attr_value, crossmark)
        else:
            new_attr_value = '%s (%s)' %(attr_value, tickmark)
            if self.get_status() != ifaceStatus.ERROR:
                self.set_status(ifaceStatus.SUCCESS)
        if self.config.get(attr_name) is not None:
            self.config[attr_name].append(new_attr_value)
        else:
            self.config[attr_name] = [new_attr_value]

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
        del odict['dependents']
        del odict['realdev_dependents']
        del odict['refcnt']

        return odict

    def __setstate__(self, dict):
        self.__dict__.update(dict)
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.refcnt = 0
        self.dependents = None
        self.realdev_dependents = None
        self.linkstate = None
        
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
        logger.info(indent + 'state: %s'
                %ifaceState.to_str(self.get_state()))
        logger.info(indent + 'status: %s'
                %ifaceStatus.to_str(self.get_status()))
        logger.info(indent + 'refcnt: %d' %self.get_refcnt())
        d = self.get_dependents()
        if d is not None:
            logger.info(indent + 'dependents: %s' %str(d))
        else:
            logger.info(indent + 'dependents: None')

        logger.info(indent + 'realdev dependents: %s'
                    %str(self.get_realdev_dependents()))

        logger.info(indent + 'config: ')
        config = self.get_config()
        if config is not None:
            logger.info(indent + indent + str(config))
        logger.info('}')

    def dump_pretty(self):
        indent = '\t'
        outbuf = ''
        if self.get_auto():
            outbuf += 'auto %s\n' %self.get_name()
        outbuf += 'iface %s' %self.get_name()
        if self.get_addr_family() is not None:
            outbuf += ' %s' %self.get_addr_family()

        if self.get_addr_method() is not None:
            outbuf += ' %s' %self.get_addr_method()

        outbuf += '\n'

        config = self.get_config()
        if config is not None:
            for cname, cvaluelist in config.items():
                for cv in cvaluelist:
                    outbuf += indent + '%s' %cname + ' %s\n' %cv

        print outbuf

    def dump_json(self):
        print json.dumps(self, cls=ifaceJsonEncoder, indent=4)
