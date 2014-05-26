#!/usr/bin/python
#
# Copyright 2013.  Cumulus Networks, Inc.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# iface --
#    interface object
#

"""ifupdown2 network interface object

It closely resembles the 'iface' object in /etc/network/interfaces
file. But can be extended to include any other network interface format


The module contains the following public classes:

    - ifaceState -- enumerates iface object state

    - ifaceStatus -- enumerates iface object status (success/error)

    - ifaceJsonEncoder -- Json encoder for the iface object

    - iface -- network in terface object class

"""

from collections import OrderedDict
import logging
import json

class ifaceStatus():
    """Enumerates iface status """

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
    """Enumerates iface state """

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
            retconfig = dict((k, (v[0] if len(v) == 1 else v))
                             for k,v in o.config.items())
        return OrderedDict({'name' : o.name,
                            'addr_method' : o.addr_method,
                            'addr_family' : o.addr_family,
                            'auto' : o.auto,
                            'config' : retconfig})

class ifaceJsonDecoder():
    @classmethod
    def json_to_ifaceobj(cls, ifaceattrdict):
        ifaceattrdict['config'] = OrderedDict([(k, (v if isinstance(v, list)
                                                else [v]))
                                for k,v in ifaceattrdict.get('config',
                                            OrderedDict()).items()])
        return iface(attrsdict=ifaceattrdict)

class iface():
    """ ifupdown2 interface object class
    
    Attributes:
        name            Name of the interface 
        addr_family     Address family eg, inet, inet6. Can be None to indicate                         both address families
        addr_method     Address method eg, static, manual or None for static
                        address method
        config          dictionary of config lines for this interface
        state           Configuration state of an interface as defined by
                        ifaceState
        status          Configuration status of an interface as defined by
                        ifaceStatus
        flags           Internal flags used by iface processing
        priv_flags      private flags owned by module using this class
        refcnt          reference count, indicating number of interfaces
                        dependent on this iface
        lowerifaces     list of interface names lower to this interface or
                        this interface depends on
        upperifaces     list of interface names upper to this interface or
                        the interfaces that depend on this interface 
        auto            True if interface belongs to the auto class
        classes         List of classes the interface belongs to
        env             shell environment the interface needs during execution
        raw_config       raw interface config from file
    """

    # flag to indicate that the object was created from pickled state
    _PICKLED = 0x1
    HAS_SIBLINGS = 0x2

    version = '0.1'

    def __init__(self, attrsdict={}):
        self._set_attrs_from_dict(attrsdict)
        self._config_status = {}
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.flags = 0x0
        self.priv_flags = 0x0
        self.refcnt = 0
        self.lowerifaces = None
        self.upperifaces = None
        self.classes = []
        self.env = None
        self.raw_config = []
        self.linkstate = None

    def _set_attrs_from_dict(self, attrdict):
        self.auto = attrdict.get('auto', False)
        self.name = attrdict.get('name')
        self.addr_family = attrdict.get('addr_family')
        self.addr_method = attrdict.get('addr_method')
        self.config = attrdict.get('config', OrderedDict())

    def inc_refcnt(self):
        self.refcnt += 1

    def dec_refcnt(self):
        self.refcnt -= 1

    def is_config_present(self):
        addr_method = self.addr_method
        if addr_method and addr_method in ['dhcp', 'dhcp6', 'loopback']:
            return True
        if not self.config:
            return False
        else:
            return True

    def set_class(self, classname):
        """ Appends a class to the list """
        self.classes.append(classname)

    def set_state_n_status(self, state, status):
        self.state = state
        self.status = status

    def set_flag(self, flag):
        self.flags |= flag

    def clear_flag(self, flag):
        self.flags &= ~flag

    def add_to_upperifaces(self, upperifacename):
        if self.upperifaces:
            if upperifacename not in self.upperifaces:
                self.upperifaces.append(upperifacename)
        else:
            self.upperifaces = [upperifacename]

    def get_attr_value(self, attr_name):
        return self.config.get(attr_name)
    
    def get_attr_value_first(self, attr_name):
        attr_value_list = self.config.get(attr_name)
        if attr_value_list:
            return attr_value_list[0]
        return None

    def get_attr_value_n(self, attr_name, attr_index):
        attr_value_list = self.config.get(attr_name)
        if attr_value_list:
            try:
                return attr_value_list[attr_index]
            except:
                return None
        return None

    @property
    def get_env(self):
        if not self.env:
            self.generate_env()
        return self.env

    def generate_env(self):
        env = {}
        config = self.config
        env['IFACE'] = self.name
        for attr, attr_value in config.items():
            attr_env_name = 'IF_%s' %attr.upper()
            env[attr_env_name] = attr_value[0]
        if env:
            self.env = env

    def update_config(self, attr_name, attr_value):
        self.config.setdefault(attr_name, []).append(attr_value)

    def update_config_dict(self, attrdict):
        self.config.update(attrdict)

    def update_config_with_status(self, attr_name, attr_value, attr_status=0):
        if not attr_value:
            attr_value = ''

        self.config.setdefault(attr_name, []).append(attr_value)
        self._config_status.setdefault(attr_name, []).append(attr_status)

        # set global iface state
        if attr_status:
            self.status = ifaceStatus.ERROR
        elif self.status != ifaceStatus.ERROR:
            # Not already error, mark success
            self.status = ifaceStatus.SUCCESS

    def get_config_attr_status(self, attr_name, idx=0):
        return self._config_status.get(attr_name, [])[idx]

    def compare(self, dstiface):
        """ Compares two objects

        Returns True if object self is same as dstiface and False otherwise """

        if self.name != dstiface.name: return False
        if self.addr_family != dstiface.addr_family: return False
        if self.addr_method != dstiface.addr_method: return False
        if self.auto != dstiface.auto: return False
        if self.classes != dstiface.classes: return False
        if any(True for k in self.config if k not in dstiface.config):
            return False
        if any(True for k,v in self.config.items()
                    if v != dstiface.config.get(k)): return False
        return True

    def __getstate__(self):
        odict = self.__dict__.copy()
        del odict['state']
        del odict['status']
        del odict['lowerifaces']
        del odict['upperifaces']
        del odict['refcnt']
        del odict['_config_status']
        del odict['flags']
        del odict['priv_flags']
        del odict['raw_config']
        del odict['linkstate']
        del odict['env']
        return odict

    def __setstate__(self, dict):
        self.__dict__.update(dict)
        self._config_status = {}
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.refcnt = 0
        self.flags = 0
        self.lowerifaces = None
        self.upperifaces = None
        self.linkstate = None
        self.env = None
        self.priv_flags = 0
        self.raw_config = []
        self.flags |= self._PICKLED

    def dump_raw(self, logger):
        indent = '  '
        if self.auto:
            print 'auto %s' %self.name
        print (self.raw_config[0])
        for i in range(1, len(self.raw_config)):
            print(indent + self.raw_config[i])
        
    def dump(self, logger):
        indent = '\t'
        logger.info(self.name + ' : {')
        logger.info(indent + 'family: %s' %self.addr_family)
        logger.info(indent + 'method: %s' %self.addr_method)
        logger.info(indent + 'flags: %x' %self.flags)
        logger.info(indent + 'state: %s'
                %ifaceState.to_str(self.state))
        logger.info(indent + 'status: %s'
                %ifaceStatus.to_str(self.status))
        logger.info(indent + 'refcnt: %d' %self.refcnt)
        d = self.lowerifaces
        if d:
            logger.info(indent + 'lowerdevs: %s' %str(d))
        else:
            logger.info(indent + 'lowerdevs: None')

        logger.info(indent + 'config: ')
        config = self.config
        if config:
            logger.info(indent + indent + str(config))
        logger.info('}')

    def dump_pretty(self, with_status=False,
                    successstr='success', errorstr='error'):
        indent = '\t'
        outbuf = ''
        if self.auto:
            outbuf += 'auto %s\n' %self.name
        outbuf += 'iface %s' %self.name
        if self.addr_family:
            outbuf += ' %s' %self.addr_family
        if self.addr_method:
            outbuf += ' %s' %self.addr_method
        if with_status:
            if (self.status == ifaceStatus.NOTFOUND or 
                self.status == ifaceStatus.ERROR):
                outbuf += ' (%s)' %errorstr
            elif self.status == ifaceStatus.SUCCESS:
                outbuf += ' (%s)' %successstr
            if self.status == ifaceStatus.NOTFOUND:
                if with_status:
                    outbuf = (outbuf.encode('utf8')
                        if isinstance(outbuf, unicode) else outbuf)
                print outbuf + '\n'
                return
        outbuf += '\n'
        config = self.config
        if config:
            for cname, cvaluelist in config.items():
                idx = 0
                for cv in cvaluelist:
                    if not cv: continue
                    if with_status:
                        s = self.get_config_attr_status(cname, idx)
                        if s:
                            outbuf += (indent + '%s %s (%s)\n'
                                        %(cname, cv, errorstr))
                        elif s == 0:
                            outbuf += (indent + '%s %s (%s)\n'
                                        %(cname, cv, successstr))
                    else:
                        outbuf += indent + '%s %s\n' %(cname, cv)
                    idx += 1
        if with_status:
            outbuf = (outbuf.encode('utf8')
                        if isinstance(outbuf, unicode) else outbuf)
        print outbuf
