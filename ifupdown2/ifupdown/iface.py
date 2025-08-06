#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# iface --
#    interface object
#

"""ifupdown2 network interface object

It is modeled based on the 'iface' section in /etc/network/interfaces
file. But can be extended to include any other network interface format
"""

import json
import logging

from collections import OrderedDict

log = logging.getLogger()


class ifaceStatusUserStrs():
    """ This class declares strings user can see during an ifquery --check
    for example. These strings can be overridden by user defined strings from
    config file """
    SUCCESS = "success",
    FAILURE = "error",
    UNKNOWN = "unknown"

class ifaceType():
    UNKNOWN =     0x00
    IFACE =       0x01
    BRIDGE_VLAN = 0x10

class ifaceRole():
    """ ifaceRole is used to classify the ifaceobj.role of
        MASTER or SLAVE where there is a bond or bridge
        with bond-slaves or bridge-ports.  A bond in a bridge
        is both a master and slave (0x3)
    """
    UNKNOWN = 0x00
    SLAVE =   0x01
    MASTER =  0x10

class ifaceLinkKind():
    """ ifaceLlinkKind is used to identify interfaces
        in the ifaceobj.link_kind attribute. Dependents of the bridge or
        bond have an ifaceobj.role attribute of SLAVE and the bridge or
        bond itself has ifaceobj.role of MASTER.
    """
    UNKNOWN = 0x000000
    BRIDGE =  0x000001
    BOND =    0x000010
    VLAN =    0x000100
    VXLAN =   0x001000
    VRF =     0x010000
    BATMAN_ADV = 0x0100000
    # to indicate logical interface created by an external entity.
    # the 'kind' of which ifupdown2 does not really understand
    OTHER =     0x100000

    @classmethod
    def to_str(cls, kind):
        if kind == cls.BRIDGE:
            return "bridge"
        elif kind == cls.BOND:
            return "bond"
        elif kind == cls.VLAN:
            return "vlan"
        elif kind == cls.VXLAN:
            return "vxlan"
        elif kind == cls.VRF:
            return "vrf"
        else:
            return "OTHER"

class ifaceLinkPrivFlags():
    """ This corresponds to kernel netdev->priv_flags
        and can be BRIDGE_PORT, BOND_SLAVE etc """

    UNKNOWN                                 = 0b000000000000000000000
    BRIDGE_PORT                             = 0b000000000000000000001
    BOND_SLAVE                              = 0b000000000000000000010
    VRF_SLAVE                               = 0b000000000000000000100
    BRIDGE_VLAN_AWARE                       = 0b000000000000000001000
    BRIDGE_VXLAN                            = 0b000000000000000010000
    ADDRESS_VIRTUAL_SLAVE                   = 0b000000000000000100000
    LOOPBACK                                = 0b000000000000001000000
    KEEP_LINK_DOWN                          = 0b000000000000010000000
    MGMT_INTF                               = 0b000000000000100000000
    SINGLE_VXLAN                            = 0b000000000001000000000
    ES_BOND                                 = 0b000000000010000000000
    BRIDGE_l3VNI                            = 0b000000000100000000000
    L3VXI                                   = 0b000000001000000000000
    OPENVSWITCH                             = 0b000000010000000000000

    @classmethod
    def get_str(cls, flag):
        string_list = []

        if flag & cls.BRIDGE_PORT:
            string_list.append("bridge port")

        if flag & cls.BOND_SLAVE:
            string_list.append("bond slave")

        if flag & cls.VRF_SLAVE:
            string_list.append("vrf slave")

        if flag & cls.BRIDGE_VLAN_AWARE:
            string_list.append("vlan aware bridge")

        if flag & cls.BRIDGE_VXLAN:
            string_list.append("vxlan bridge")

        if flag & cls.ADDRESS_VIRTUAL_SLAVE:
            string_list.append("address virtual slave")

        if flag & cls.LOOPBACK:
            string_list.append("loopback")

        if flag & cls.KEEP_LINK_DOWN:
            string_list.append("keep link down")

        if flag & cls.ES_BOND:
            string_list.append("es bond")

        if flag & cls.OPENVSWITCH:
            string_list.append("openvswitch interface")

        if flag & cls.BRIDGE_l3VNI:
            string_list.append("bridge l3vni")

        if flag & cls.L3VXI:
            string_list.append("l3vxi")

        return ", ".join(string_list)


class ifaceLinkType():
    LINK_UNKNOWN = 0x0
    LINK_SLAVE = 0x1
    LINK_MASTER = 0x2
    LINK_NA = 0x3

class VlanProtocols():
    # Picked ID values from
    # http://www.microhowto.info/howto/configure_an_ethernet_interface_as_a_qinq_vlan_trunk.html
    ETHERTYPES_TO_ID = {
                        '802.1Q'  : '0x8100',
                        '802.1AD' : '0x88a8',
                       }
    ID_TO_ETHERTYPES = {
                        '0x8100'  : '802.1Q',
                        '0x88a8'  : '802.1AD',
                       }

class ifaceDependencyType():
    """ Indicates type of dependency.

        This class enumerates types of dependency relationships
        between interfaces.

        iface dependency relationships can be classified
        into:
         - link
         - master/slave

        In a 'link' dependency relationship, dependency can be shared
        between interfaces. example: swp1.100 and
        swp1.200 can both have 'link' swp1. swp1 is also a dependency
        of swp1.100 and swp1.200. As you can see dependency
        swp1 is shared between swp1.100 and swp1.200.

        In a master/slave relationship like bridge and
        its ports: eg: bridge br0 and its ports swp1 and swp2.
        dependency swp1 and swp2 cannot be shared with any other
        interface with the same dependency relationship.
        ie, swp1 and swp2 cannot be in a slave relationship
        with another interface. Understanding the dependency type is
        required for any semantic checks between dependencies.

    """
    UNKNOWN = 0x0
    LINK = 0x1
    MASTER_SLAVE = 0x2

class ifaceStatus():
    """Enumerates iface status """

    UNKNOWN = 0x1
    SUCCESS = 0x2
    WARNING = 0x3
    ERROR = 0x4
    NOTFOUND = 0x5

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
        retifacedict = OrderedDict([])
        if o.config:
            retconfig = dict((k, (v[0] if len(v) == 1 else v))
                             for k,v in list(o.config.items()))
        retifacedict['name'] = o.name
        if o.addr_method:
            if 'inet' in o.addr_family and 'dhcp' in o.addr_method:
                retifacedict['addr_method'] = 'dhcp'
            else:
                retifacedict['addr_method'] = o.addr_method
        if o.addr_family:
            if len(o.addr_family) > 1:
                retifacedict['addr_family'] = o.addr_family
            else:
                retifacedict['addr_family'] = ' '.join(o.addr_family)
        retifacedict['auto'] = o.auto
        retifacedict['config'] = retconfig

        return retifacedict

class ifaceJsonEncoderWithStatus(json.JSONEncoder):
    def default(self, o):
        retconfig = {}
        retconfig_status = {}
        retifacedict = OrderedDict([])
        if o.config:
            for k,v in list(o.config.items()):
                idx = 0
                vitem_status = []
                for _ in v:
                    s = o.get_config_attr_status(k, idx)
                    if s == 1:
                        status_str = ifaceStatusUserStrs.ERROR
                    elif s == 0:
                        status_str = ifaceStatusUserStrs.SUCCESS
                    else:
                        status_str = ifaceStatusUserStrs.UNKNOWN
                    vitem_status.append('%s' %status_str)
                    idx += 1
                retconfig[k] = str(v[0] if len(v) == 1 else v)
                retconfig_status[k] = vitem_status[0] if len(vitem_status) == 1 else vitem_status

        if (o.status == ifaceStatus.NOTFOUND or
                o.status == ifaceStatus.ERROR):
            status =  ifaceStatusUserStrs.ERROR
        else:
            status =  ifaceStatusUserStrs.SUCCESS

        retifacedict['name'] = o.name
        if o.addr_method:
            retifacedict['addr_method'] = o.addr_method
        if o.addr_family:
            if len(o.addr_family) > 1:
                retifacedict['addr_family'] = o.addr_family
            else:
                retifacedict['addr_family'] = ' '.join(o.addr_family)
        retifacedict['auto'] = o.auto
        retifacedict['config'] = retconfig
        retifacedict['config_status'] = retconfig_status
        retifacedict['status'] = status

        return retifacedict

class ifaceJsonDecoder():
    @classmethod
    def json_to_ifaceobj(cls, ifaceattrdict):
        ifaceattrdict['config'] = OrderedDict([(k, (v if isinstance(v, list)
                                                else [v.strip()]))
                                for k,v in list(ifaceattrdict.get('config',
                                            OrderedDict()).items())])
        return iface(attrsdict=ifaceattrdict)

class iface():
    """ ifupdown2 iface object class
    Attributes:
        **name**      Name of the interface

        **addr_family**     Address family eg, inet, inet6. Can be None to
                            indicate both address families

        **addr_method**     Address method eg, static, manual or None for
                            static address method

        **config**          dictionary of config lines for this interface

        **state**           Configuration state of an interface as defined by
                            ifaceState

        **status**          Configuration status of an interface as defined by
                            ifaceStatus

        **flags**           Internal flags used by iface processing

        **priv_flags**      private flags owned by module using this class

        **module_flags**    module flags owned by module using this class

        **refcnt**          reference count, indicating number of interfaces
                            dependent on this iface

        **lowerifaces**     list of interface names lower to this interface or
                            this interface depends on

        **upperifaces**     list of interface names upper to this interface or
                            the interfaces that depend on this interface

        **auto**            True if interface belongs to the auto class

        **classes**         List of classes the interface belongs to

        **env**             shell environment the interface needs during
                            execution

        **raw_config**      raw interface config from file
    """

    # flag to indicate that the object was created from pickled state
    # XXX: Move these flags into a separate iface flags class
    _PICKLED         = 0x00000001
    HAS_SIBLINGS     = 0x00000010
    IFACERANGE_ENTRY = 0x00000100
    IFACERANGE_START = 0x00001000
    OLDEST_SIBLING   = 0x00010000
    YOUNGEST_SIBLING   = 0x00100000

    version = '0.1'

    def __init__(self, attrsdict={}):
        self.addr_family = []

        self._set_attrs_from_dict(attrsdict)
        self._config_status = {}
        """dict with config status of iface attributes"""
        self.state = ifaceState.NEW
        """iface state (of type ifaceState) """
        self.status = ifaceStatus.UNKNOWN
        """iface status (of type ifaceStatus) """
        self.status_str = None
        """iface status str (string representing the status) """
        self.flags = 0x0
        """iface flags """
        self.priv_flags = None
        """iface module flags dictionary with module name: flags"""
        self.module_flags = {}
        """iface priv flags. can be used by the external object manager """
        self.refcnt = 0
        """iface refcnt (incremented for each dependent this interface has) """
        self.lowerifaces = None
        """lower iface list (in other words: slaves of this interface """
        self.upperifaces = None
        """upper iface list (in other words: master of this interface """
        self.classes = []
        """interface classes this iface belongs to """
        self.env = None
        """environment variable dict required for this interface to run"""
        self.raw_config = []
        """interface config/attributes in raw format (eg: as it appeared in the interfaces file)"""
        self.linkstate = None
        """linkstate of the interface"""
        self.type = ifaceType.UNKNOWN
        """interface type"""
        self.priv_data = None
        self.role = ifaceRole.UNKNOWN
        self.realname = None
        self.link_type = ifaceLinkType.LINK_UNKNOWN
        self.link_kind = ifaceLinkKind.UNKNOWN
        self.link_privflags = ifaceLinkPrivFlags.UNKNOWN

        # The below attribute is used to disambiguate between various
        # types of dependencies
        self.dependency_type = ifaceDependencyType.UNKNOWN
        self.blacklisted = False

    def __eq__(self, other):
        return (
                isinstance(other, iface) and
                self.name == other.name and
                self.config == other.config and
                self.addr_family == other.addr_family and
                self.addr_method == other.addr_method
        )

    def _set_attrs_from_dict(self, attrdict):
        self.auto = attrdict.get('auto', False)
        self.name = attrdict.get('name')
        self.addr_method = attrdict.get('addr_method')
        self.config = attrdict.get('config', OrderedDict())

        addr_family = attrdict.get('addr_family')
        if addr_family:
            self.addr_family.append(addr_family)

    def inc_refcnt(self):
        """ increment refcnt of the interface. Usually used to indicate that
        it has dependents """
        self.refcnt += 1

    def dec_refcnt(self):
        """ decrement refcnt of the interface. Usually used to indicate that
        it has lost its dependent """
        self.refcnt -= 1

    def is_config_present(self):
        """ returns true if the interface has user provided config,
        false otherwise """
        addr_method = self.addr_method
        if addr_method and addr_method in ['dhcp', 'dhcp6', 'loopback']:
            return True
        if not self.config:
            return False
        else:
            return True

    def set_class(self, classname):
        """ appends class to the interfaces class list """
        self.classes.append(classname)

    def set_state_n_status(self, state, status):
        """ sets state and status of an interface """
        self.state = state
        if status > self.status:
            self.status = status

    def set_status(self, status):
        """ sets status of an interface """
        if status > self.status:
            self.status = status

    def set_flag(self, flag):
        self.flags |= flag

    def clear_flag(self, flag):
        self.flags &= ~flag

    def add_to_upperifaces(self, upperifacename):
        """ add to the list of upperifaces """
        if self.upperifaces:
            if upperifacename not in self.upperifaces:
                self.upperifaces.append(upperifacename)
        else:
            self.upperifaces = [upperifacename]

    def add_to_lowerifaces(self, lowerifacename):
        """ add to the list of lowerifaces """
        if self.lowerifaces:
            if lowerifacename not in self.lowerifaces:
                self.lowerifaces.append(lowerifacename)
        else:
            self.lowerifaces = [lowerifacename]

    def get_attr_value(self, attr_name):
        """ add to the list of upperifaces """
        return self.config.get(attr_name)

    def get_attr_value_first(self, attr_name):
        """ get first value of the specified attr name """
        attr_value_list = self.config.get(attr_name)
        if attr_value_list:
            return attr_value_list[0]
        return None

    def get_attrs_value_first(self, attrs):
        """ get first value of the first attr in the list.
            Useful when you have multiple attrs representing the
            same thing.
        """
        for attr in attrs:
            attr_value_list = self.config.get(attr)
            if attr_value_list:
                return attr_value_list[0]
        return None

    def get_attr_value_n(self, attr_name, attr_index):
        """ get n'th value of the specified attr name """
        attr_value_list = self.config.get(attr_name)
        if attr_value_list:
            try:
                return attr_value_list[attr_index]
            except Exception:
                return None
        return None

    def get_env(self):
        """ get shell environment variables the interface must execute in """
        if not self.env:
            self.generate_env()
        return self.env

    def generate_env(self):
        """ generate shell environment variables dict interface must execute
        in. This is used to support legacy ifupdown scripts
        """
        env = {}
        config = self.config
        env['IFACE'] = self.name
        for attr, attr_value in list(config.items()):
            attr_env_name = 'IF_%s' %attr.upper().replace("-", "_")
            env[attr_env_name] = attr_value[0]
        self.env = env

    def update_config(self, attr_name, attr_value):
        """ add attribute name and value to the interface config """
        self.config.setdefault(attr_name, []).append(attr_value)

    def replace_config(self, attr_name, attr_value):
        """ add attribute name and value to the interface config """
        self.config[attr_name] = [attr_value]

    def delete_config(self, attr_name):
        """ add attribute name and value to the interface config """
        try:
            del self.config[attr_name]
        except Exception:
            pass

    def update_config_dict(self, attrdict):
        self.config.update(attrdict)

    def update_config_with_status(self, attr_name, attr_value, attr_status=0):
        """ add attribute name and value to the interface config and also
        update the config_status dict with status of this attribute config """
        if not attr_value:
            attr_value = ''
        self.config.setdefault(attr_name, []).append(attr_value)
        self._config_status.setdefault(attr_name, []).append(attr_status)
        # set global iface state
        if attr_status == 1:
            self.status = ifaceStatus.ERROR
        elif self.status != ifaceStatus.ERROR:
            # Not already error, mark success
            self.status = ifaceStatus.SUCCESS

    def check_n_update_config_with_status_many(self, ifaceobjorig, attr_names,
                                               attr_status=0):
        # set multiple attribute status to zero
        # also updates status only if the attribute is present
        for attr_name in attr_names:
            if not ifaceobjorig.get_attr_value_first(attr_name):
               continue
            self.config.setdefault(attr_name, []).append('')
            self._config_status.setdefault(attr_name, []).append(attr_status)

    def get_config_attr_status(self, attr_name, idx=0):
        """ get status of a attribute config on this interface.

        Looks at the iface _config_status dict"""
        return self._config_status.get(attr_name, [])[idx]

    def compare(self, dstiface):
        """ compares iface object with iface object passed as argument

        Returns True if object self is same as dstiface and False otherwise """

        if self.name != dstiface.name: return False
        if self.type != dstiface.type: return False
        if self.addr_family != dstiface.addr_family: return False
        if self.addr_method != dstiface.addr_method: return False
        if self.auto != dstiface.auto: return False
        if self.classes != dstiface.classes: return False
        if len(self.config) != len(dstiface.config):
            return False
        if any(True for k in self.config if k not in dstiface.config):
            return False
        if any(True for k,v in list(self.config.items())
                    if v != dstiface.config.get(k)): return False
        return True

    def squash(self, newifaceobj):
        """ This squashes the iface object """
        for attrname, attrlist in newifaceobj.config.items():
            # if allready present add it to the list
            # else add it to the end of the dictionary
            # We need to maintain order.
            if self.config.get(attrname):
                self.config[attrname].extend(attrlist)
            else:
                self.config.update([(attrname, attrlist)])
        # we now support inet and inet6 together
        self.addr_family.extend(newifaceobj.addr_family)
        # if auto %ifacename is not part of the first stanza
        # we need to squash it
        if not self.auto and newifaceobj.auto:
            self.auto = True

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
        del odict['module_flags']
        del odict['raw_config']
        del odict['linkstate']
        del odict['env']
        del odict['link_type']
        del odict['link_kind']
        #del odict['link_privflags']
        del odict['role']
        del odict['dependency_type']
        del odict['blacklisted']
        return odict

    def __setstate__(self, dict):
        self._config_status = {}
        self.state = ifaceState.NEW
        self.status = ifaceStatus.UNKNOWN
        self.refcnt = 0
        self.flags = 0
        self.lowerifaces = None
        self.upperifaces = None
        self.linkstate = None
        self.env = None
        self.role = ifaceRole.UNKNOWN
        self.priv_flags = None
        self.module_flags = {}
        self.raw_config = []
        self.flags |= self._PICKLED
        self.link_type = ifaceLinkType.LINK_NA
        self.link_kind = ifaceLinkKind.UNKNOWN
        self.link_privflags = ifaceLinkPrivFlags.UNKNOWN
        self.dependency_type = ifaceDependencyType.UNKNOWN
        self.blacklisted = False
        self.__dict__.update(dict)

    def dump_raw(self):
        indent = '  '
        if self.auto:
            print('auto %s' %self.name)
        print((self.raw_config[0]))
        for i in range(1, len(self.raw_config)):
            print((indent + self.raw_config[i]))

    def dump(self, logger):
        indent = '\t'
        logger.info(self.name + ' : {')
        logger.info(indent + 'family: %s' % ' '.join(self.addr_family))
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

        d = self.upperifaces
        if d:
            logger.info(indent + 'upperdevs: %s' %str(d))
        else:
            logger.info(indent + 'upperdevs: None')

        logger.info("%srole: %s" % (indent, {
            ifaceRole.UNKNOWN: "UNKNOWN",
            ifaceRole.SLAVE: "SLAVE",
            ifaceRole.MASTER: "MASTER"}.get(self.role)))

        logger.info("%stype: %s" % (indent, {
            ifaceType.UNKNOWN: "UNKNOWN",
            ifaceType.IFACE: "IFACE",
            ifaceType.BRIDGE_VLAN: "BRIDGE_VLAN"}.get(self.type)))

        logger.info("%slink_kind: %s" % (indent, ifaceLinkKind.to_str(self.link_kind)))

        logger.info("%slink_privflags: %s" % (indent, ifaceLinkPrivFlags.get_str(self.link_privflags)))

        if self.priv_flags and self.priv_flags.BUILTIN:
            logger.info("%spriv_flags: BUILTIN" % indent)

        logger.info(indent + 'config: ')
        config = self.config
        if config:
            logger.info(indent + indent + str(config))
        logger.info('}')

    def _dump_pretty(self, family, first, addr_method, with_status=False, use_realname=False):
        indent = '\t'
        outbuf = ''
        if use_realname and self.realname:
            name = '%s' %self.realname
        else:
            name = '%s' %self.name
        if self.auto:
            outbuf += 'auto %s\n' %name
        ifaceline = ''
        if self.type == ifaceType.BRIDGE_VLAN:
            ifaceline += 'vlan %s' %name
        else:
            ifaceline += 'iface %s' %name
        if family:
            ifaceline += ' %s' % family
        if addr_method:
            ifaceline += ' %s' % addr_method
        if with_status:
            status_str = None
            if (self.status == ifaceStatus.ERROR or
                    self.status == ifaceStatus.NOTFOUND):
                if self.status_str:
                    ifaceline += ' (%s)' %self.status_str
                status_str = '[%s]' %ifaceStatusUserStrs.ERROR
            elif self.status == ifaceStatus.SUCCESS:
                status_str = '[%s]' %ifaceStatusUserStrs.SUCCESS
            if status_str:
                outbuf += '{0:65} {1:>8}'.format(ifaceline, status_str) + '\n'
            else:
                outbuf += ifaceline + '\n'
            if self.status == ifaceStatus.NOTFOUND:
                print(outbuf + '\n')
                return
        else:
            outbuf += ifaceline + '\n'
        config = self.config
        if config and first:
            for cname, cvaluelist in list(config.items()):
                idx = 0
                for cv in cvaluelist:
                    status_str = None
                    if with_status:
                        s = self.get_config_attr_status(cname, idx)
                        if s == -1:
                            status_str = '[%s]' %ifaceStatusUserStrs.UNKNOWN
                        elif s == 1:
                            status_str = '[%s]' %ifaceStatusUserStrs.ERROR
                        elif s == 0:
                            status_str = '[%s]' %ifaceStatusUserStrs.SUCCESS
                    if status_str:
                        outbuf += (indent + '{0:55} {1:>10}'.format(
                              '%s %s' %(cname, cv), status_str)) + '\n'
                    else:
                        if cv:
                            outbuf += indent + '%s %s\n' % (cname, cv)
                    idx += 1
        print(outbuf)

    def dump_pretty(self, with_status=False, use_realname=False):
        if not self.addr_family:
            self._dump_pretty(None, True,
                              self.addr_method,
                              with_status=with_status,
                              use_realname=use_realname)
        else:
            # To allow both inet and inet6 on an interface we changed the
            # addr_family attribute, it's now a list. Depending on how
            # stanzas were squashed (and what command was used ie. ifquery -r)
            # we want to dump the ifaceobj as usual but we will output an
            # empty stanza for each additional addr_family. The config will
            # only be displayed once, in the first stanza. Example:
            # $ ifquery eth0 -r
            # auto etho
            # iface eth0 inet dhcp
            #     config...
            #
            # auto eth0
            # iface eth0 inet6 dhcp
            # $
            first = True
            for family in self.addr_family:
                addr_method = self.addr_method
                # We need to make sure we display 'dhcp' for inet family.
                # In some cases it might take the value 'dhcp6' even if it has
                # both inet and inet6 addr_family
                if addr_method and family == 'inet' and 'dhcp' in addr_method:
                    addr_method = 'dhcp'
                self._dump_pretty(family, first,
                                  addr_method=addr_method,
                                  with_status=with_status,
                                  use_realname=use_realname)
                first = False
