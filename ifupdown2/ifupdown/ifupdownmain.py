#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# ifupdownMain --
#    ifupdown main module
#

import re
import os
import logging
import itertools
import traceback
import pprint

from collections import OrderedDict

try:
    import ifupdown2.lib.nlcache as nlcache

    import ifupdown2.ifupdownaddons.mstpctlutil

    import ifupdown2.nlmanager.ipnetwork as ipnetwork

    import ifupdown2.ifupdown.policymanager
    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.ifupdownconfig as ifupdownConfig

    from ifupdown2.ifupdown.graph import *
    from ifupdown2.ifupdown.iface import ifaceStatusUserStrs, ifaceType, ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus, iface
    from ifupdown2.ifupdown.scheduler import *
    from ifupdown2.ifupdown.exceptions import *
    from ifupdown2.ifupdown.networkinterfaces import *
    from ifupdown2.ifupdown.config import ADDON_MODULES_DIR, ADDONS_CONF_PATH, IFUPDOWN2_ADDON_DROPIN_FOLDER
except ImportError:
    import lib.nlcache as nlcache

    import ifupdownaddons.mstpctlutil

    import nlmanager.ipnetwork as ipnetwork

    import ifupdown.ifupdownflags
    import ifupdown.policymanager
    import ifupdown.statemanager as statemanager
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.ifupdownconfig as ifupdownConfig

    from ifupdown.graph import *
    from ifupdown.iface import ifaceStatusUserStrs, ifaceType, ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus, iface
    from ifupdown.scheduler import *
    from ifupdown.exceptions import *
    from ifupdown.networkinterfaces import *
    from ifupdown.config import ADDON_MODULES_DIR, ADDONS_CONF_PATH, IFUPDOWN2_ADDON_DROPIN_FOLDER


"""
.. module:: ifupdownmain
:synopsis: main module for ifupdown package

.. moduleauthor:: Roopa Prabhu <roopa@cumulusnetworks.com>

"""

_tickmark = '\u2713'
_crossmark = '\u2717'
_success_sym = '(%s)' %_tickmark
_error_sym = '(%s)' %_crossmark


class MainException(Exception):
    pass


class ifupdownMainFlags():
    COMPAT_EXEC_SCRIPTS = False
    STATEMANAGER_ENABLE = True
    STATEMANAGER_UPDATE = True
    ADDONS_ENABLE = False
    DELETE_DEPENDENT_IFACES_WITH_NOCONFIG = False
    SCHED_SKIP_CHECK_UPPERIFACES = False
    CHECK_SHARED_DEPENDENTS = True

class ifacePrivFlags():
    # priv flags to mark iface objects
    BUILTIN = False
    NOCONFIG = False

    def __init__(self, builtin=False, noconfig=False):
        self.BUILTIN = builtin
        self.NOCONFIG = noconfig

class ifupdownMain:
    """ ifupdown2 main class """

    scripts_dir = '/etc/network'
    addon_modules_dir = ADDON_MODULES_DIR
    addon_modules_configfile = ADDONS_CONF_PATH

    # Handlers for ops that ifupdown2 owns
    def run_up(self, ifaceobj):
        # Skip link sets on ifaceobjs of type 'vlan' (used for l2 attrs).
        # there is no real interface behind it
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return
        if ((ifaceobj.link_kind & ifaceLinkKind.VRF) or
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE)):
            self._keep_link_down(ifaceobj)
            return
        if self._delay_admin_state:
            self._delay_admin_state_iface_queue.append(ifaceobj.name)
            return
        # If this object is a link slave, ie its link is controlled
        # by its link master interface, then dont set the link state.
        # But do allow user to change state of the link if the interface
        # is already with its link master (hence the master check).
        if ifaceobj.link_type == ifaceLinkType.LINK_SLAVE:
            if self.diff_based:
                self.logger.debug(
                    f"{ifaceobj.name}: diff based approach will try to link-up this slave device"
                )
            else:
                return
        if not self.link_exists(ifaceobj.name):
            return
        if self._keep_link_down(ifaceobj):
            return
        try:
            self.netlink.link_up(ifaceobj.name)
        except Exception:
            if ifaceobj.addr_method != 'manual':
                raise

    def _keep_link_down(self, ifaceobj):
        if ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
            # user has asked to explicitly keep the link down,
            # so, force link down
            self.logger.info('%s: keeping link down due to user config' %ifaceobj.name)
            self.netlink.link_down(ifaceobj.name)
            return True
        return False

    def run_down(self, ifaceobj):
        if ifaceobj.link_kind & ifaceLinkKind.VRF:
            return
        elif ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE:
            self.netlink.link_down(ifaceobj.name)
            return
        # Skip link sets on ifaceobjs of type 'vlan' (used for l2 attrs)
        # there is no real interface behind it
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return
        if self._delay_admin_state:
            self._delay_admin_state_iface_queue.append(ifaceobj.name)
            return
        # If this object is a link slave, ie its link is controlled
        # by its link master interface, then dont set the link state.
        # But do allow user to change state of the link if the interface
        # is already with its link master (hence the master check).
        if ifaceobj.link_type == ifaceLinkType.LINK_SLAVE:
           return
        if not self.link_exists(ifaceobj.name):
           return
        try:
            # special case for some logical interfaces:
            # - downed VLANs will be deleted via netlink no need to set them admin DOWN
            if ifaceobj.link_kind & ifaceLinkKind.VLAN:
                self.logger.debug("%s: skipping admin down (vlan will be deleted)" % ifaceobj.name)
                return

            if not ifaceobj.link_privflags & ifaceLinkPrivFlags.LOOPBACK:
                # set intf down (except loopback)
                self.netlink.link_down(ifaceobj.name)
            else:
                self.logger.info("%s: ifupdown2 cannot bring loopback interface down" % ifaceobj.name)
        except Exception:
            if ifaceobj.addr_method != 'manual':
                raise

    # ifupdown object interface operation handlers
    ops_handlers = OrderedDict([('up', run_up),
                                ('down', run_down)])

    def run_sched_ifaceobj_posthook(self, ifaceobj, op):
        if (ifaceobj.priv_flags and (ifaceobj.priv_flags.BUILTIN or
            ifaceobj.priv_flags.NOCONFIG)):
            if not self.diff_based:
                return
            else:
                self.logger.debug(f"{ifaceobj.name}: diff based approach will save this empty ifaceobj")
        if self.flags.STATEMANAGER_UPDATE:
            self.statemanager.ifaceobj_sync(ifaceobj, op)

    # ifupdown object interface scheduler pre and posthooks
    sched_hooks = {'posthook' : run_sched_ifaceobj_posthook}

    def reset_ifupdown2(self):
        self.modules = OrderedDict({})
        self.module_attrs = {}

        ifaceScheduler.reset()
        try:
            ifupdown2.ifupdown.statemanager.reset()
            ifupdown2.ifupdown.policymanager.reset()
            ifupdown2.ifupdown.ifupdownflags.reset()
            ifupdownConfig.reset()
            ifupdown2.ifupdownaddons.mstpctlutil.mstpctlutil.reset()
        except Exception:
            try:
                ifupdown.statemanager.reset()
                ifupdown.policymanager.reset()
                ifupdown.ifupdownflags.reset()
                ifupdownConfig.reset()
                ifupdownaddons.mstpctlutil.mstpctlutil.reset()
            except Exception:
                pass

    def ignore_error(self, errmsg):
        if (ifupdownflags.flags.FORCE == True or re.search(r'exists', errmsg,
            re.IGNORECASE | re.MULTILINE) is not None):
            return True
        return False

    def log_warn(self, str):
        if self.ignore_error(str) == False:
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
                traceback.print_exc()
            self.logger.warning(str)

    def log_error(self, str):
        if self.ignore_error(str) == False:
            raise MainException(str)

    def link_exists(self, ifacename):
        return os.path.exists('/sys/class/net/%s' %ifacename)

    def __init__(self, config={}, args=None,
                 daemon=False, force=False, dryrun=False, nowait=False,
                 perfmode=False, withdepends=False, njobs=1,
                 cache=False, addons_enable=True, statemanager_enable=True,
                 interfacesfile='/etc/network/interfaces',
                 interfacesfileiobuf=None,
                 interfacesfileformat='native',
                 withdefaults=False):
        """This member function initializes the ifupdownmain object.

        Kwargs:
            config (dict):  config dict from /etc/network/ifupdown2/ifupdown2.conf
            force (bool): force interface configuration
            dryrun (bool): dryrun interface configuration
            withdepends (bool): apply interface configuration on all depends
            interfacesfile (str): interfaces file. default is /etc/network/interfaces
            interfacesfileformat (str): default is 'native'. Other choices are 'json'

        Raises:
            AttributeError, KeyError """

        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

        if daemon:
            self.reset_ifupdown2()
        else:
            # init nlcache with appropriate log level
            nlcache.NetlinkListenerWithCache.init(logging.DEBUG if args.nldebug else logging.WARNING)

            # start netlink listener and cache link/addr/netconf dumps
            nlcache.NetlinkListenerWithCache.get_instance().start()

        # save reference to nlcache
        self.netlink = nlcache.NetlinkListenerWithCache.get_instance()
        self.netlink.reset_errorq()

        # iface dictionary in the below format:
        # { '<ifacename>' : [<ifaceobject1>, <ifaceobject2> ..] }
        # eg:
        # { 'swp1' : [<iface swp1>, <iface swp2> ..] }
        #
        # Each ifaceobject corresponds to a configuration block for
        # that interface
        # The value in the dictionary is a list because the network
        # interface configuration file supports more than one iface section
        # in the interfaces file
        self.ifaceobjdict = OrderedDict()

        # iface dictionary representing the curr running state of an iface
        # in the below format:
        # {'<ifacename>' : <ifaceobject>}
        self.ifaceobjcurrdict = OrderedDict()

        # Dictionary representing operation and modules
        # for every operation
        self.module_ops = OrderedDict([('pre-up', []),
                                  ('up', []),
                                  ('post-up', []),
                                  ('query-checkcurr', []),
                                  ('query-running', []),
                                  ('query-dependency', []),
                                  ('query', []),
                                  ('query-raw', []),
                                  ('pre-down', []),
                                  ('down', []),
                                  ('post-down', [])])

        # For old style /etc/network/ bash scripts
        self.script_ops = OrderedDict([('pre-up', []),
                                  ('up', []),
                                  ('post-up', []),
                                  ('pre-down', []),
                                  ('down', []),
                                  ('post-down', [])])


        self.logger = logging.getLogger('ifupdown')
        ifupdownflags.flags.FORCE = force
        ifupdownflags.flags.DRYRUN = dryrun
        ifupdownflags.flags.WITHDEFAULTS = withdefaults
        ifupdownflags.flags.NOWAIT = nowait
        ifupdownflags.flags.PERFMODE = perfmode
        ifupdownflags.flags.CACHE = cache
        ifupdownflags.flags.WITH_DEPENDS = withdepends

        # Can be used to provide hints for caching
        ifupdownflags.flags.CACHE_FLAGS = 0x0

        self.flags = ifupdownMainFlags()

        self.flags.STATEMANAGER_ENABLE = statemanager_enable
        self.interfacesfile = interfacesfile
        self.interfacesfileiobuf = interfacesfileiobuf
        self.interfacesfileformat = interfacesfileformat
        self.config = config
        self.logger.debug(self.config)
        self.blacklisted_ifaces_present = False

        self.type = ifaceType.UNKNOWN

        self.flags.DELETE_DEPENDENT_IFACES_WITH_NOCONFIG = False
        self.flags.ADDONS_ENABLE = addons_enable

        self.ifaces = OrderedDict()
        self.njobs = njobs
        self.pp = pprint.PrettyPrinter(indent=4)
        self.modules = OrderedDict({})
        self.module_attrs = {}
        self.overridden_ifupdown_scripts = []

        if self.config.get('addon_python_modules_support', '1') == '1':
            self.load_addon_modules(self.addon_modules_dir)
        if self.config.get('addon_scripts_support', '0') == '1':
            self.load_scripts(self.scripts_dir)
        self.dependency_graph = OrderedDict({})

        self._cache_no_repeats = {}

        # initialize global config object with config passed by the user
        # This makes config available to addon modules
        ifupdownConfig.config = self.config
        statemanager.statemanager_api.init()

        if self.flags.STATEMANAGER_ENABLE:
            self.statemanager = statemanager.statemanager_api
            try:
                self.statemanager.read_saved_state()
            except Exception as e:
                # if read_saved_state fails, state file might be corrupt.
                # Ignore old state and continue
                self.logger.warning('error reading state (%s)' %str(e))
                import traceback
                traceback.print_exc()
        else:
            self.flags.STATEMANAGER_UPDATE = False
        self._delay_admin_state = True if self.config.get(
                            'delay_admin_state_change', '0') == '1' else False
        self._delay_admin_state_iface_queue = []
        if self._delay_admin_state:
            self.logger.info('\'delay_admin_state_change\' is set. admin ' +
                             'state changes will be delayed till the end.')

        self._link_master_slave = True if self.config.get(
                      'link_master_slave', '0') == '1' else False
        if self._link_master_slave:
            self.logger.info('\'link_master_slave\' is set. slave admin ' +
                             'state changes will be delayed till the ' +
                             'masters admin state change.')

        # squash iface objects for same interface both internal and
        # external representation. It is off by default.
        self._ifaceobj_squash = True if self.config.get(
                            'ifaceobj_squash', '0') == '1' else False

        # squash iface objects for same interface internal
        # representation only. External representation as seen by ifquery
        # will continue to see multiple iface stanzas if it was specified
        # that way by the user. It is on by default.
        self._ifaceobj_squash_internal = True if self.config.get(
                            'ifaceobj_squash_internal', '1') == '1' else False

        self.mgmt_iface_default_prefix = self._get_mgmt_iface_default_prefix()
        self.logger.info('using mgmt iface default prefix %s' %self.mgmt_iface_default_prefix)

        self.validate_keywords = {
            '<mac>': self._keyword_mac,
            '<text>': self._keyword_text,
            '<ipv4>': self._keyword_ipv4,
            '<ipv6>': self._keyword_ipv6,
            '<ip>': self._keyword_ip,
            '<number>': self._keyword_number,
            '<interface>': self._keyword_interface,
            '<ipv4-vrf-text>': self._keyword_ipv4_vrf_text,
            '<number-ipv4-list>': self._keyword_number_ipv4_list,
            '<interface-list>': self._keyword_interface_list,
            '<ipv4/prefixlen>': self._keyword_ipv4_prefixlen,
            '<ipv6/prefixlen>': self._keyword_ipv6_prefixlen,
            '<ip/prefixlen>': self._keyword_ip_prefixlen,
            '<number-range-list>': self._keyword_number_range_list,
            '<number-comma-range-list>': self._keyword_number_comma_range_list,
            '<interface-range-list>': self._keyword_interface_range_list,
            '<interface-range-list-multiple-of-16>': self._keyword_interface_range_list_multiple_of_16,
            '<mac-ip/prefixlen-list>': self._keyword_mac_ip_prefixlen_list,
            '<number-interface-list>': self._keyword_number_interface_list,
            '<interface-yes-no-list>': self._keyword_interface_yes_no_list,
            '<interface-on-off-list>': self._keyword_interface_on_off_list,
            '<interface-yes-no-0-1-list>': self._keyword_interface_yes_no_0_1_list,
            '<interface-disabled-automatic-enabled>': self._keyword_interface_disabled_automatic_enabled_list,
            '<interface-yes-no-auto-list>': self._keyword_interface_yes_no_auto_list,
            '<interface-l2protocol-tunnel-list>': self._keyword_interface_l2protocol_tunnel_list
        }

        self.diff_based = False
        self.clagd_change_detected = False

    def _get_mgmt_iface_default_prefix(self):
        mgmt_iface_default_prefix = None
        try:
            mgmt_iface_default_prefix = ifupdown2.ifupdown.policymanager.policymanager_api.get_module_globals(
                module_name='main', attr='mgmt_intf_prefix'
            )
        except Exception:
            try:
                mgmt_iface_default_prefix = ifupdown.policymanager.policymanager_api.get_module_globals(
                    module_name='main', attr='mgmt_intf_prefix'
                )
            except Exception:
                pass
        if not mgmt_iface_default_prefix:
            mgmt_iface_default_prefix = "eth"

        return mgmt_iface_default_prefix

    def link_master_slave_ignore_error(self, errorstr):
        # If link master slave flag is set,
        # there may be cases where the lowerdev may not be
        # up resulting in 'Network is down' error
        # This can happen if the lowerdev is a LINK_SLAVE
        # of another interface which is not up yet
        # example of such a case:
        #   bringing up a vlan on a bond interface and the bond
        #   is a LINK_SLAVE of a bridge (in other words the bond is
        #   part of a bridge) which is not up yet
        return self._link_master_slave and 'Network is down' in errorstr

    def get_ifaceobjs(self, ifacename, all=False):
        if all:
            return dict(self.ifaceobjdict)
        return self.ifaceobjdict.get(ifacename)

    def get_ifaceobjs_saved(self, ifacename):
        """ Return ifaceobjects from statemanager """
        if self.flags.STATEMANAGER_ENABLE:
           return self.statemanager.get_ifaceobjs(ifacename)
        else:
           return None

    def get_ifaceobj_first(self, ifacename):
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if ifaceobjs:
            return ifaceobjs[0]
        return None

    def get_ifacenames(self):
        return list(self.ifaceobjdict.keys())

    def get_iface_obj_last(self, ifacename):
        return self.ifaceobjdict.get(ifacename)[-1]


    def must_follow_upperifaces(self, ifacename):
        #
        # XXX: This bleeds the knowledge of iface
        # types in the infrastructure module.
        # Cant think of a better fix at the moment.
        # In future maybe the module can set a flag
        # to indicate if we should follow upperifaces
        #
        ifaceobj = self.get_ifaceobj_first(ifacename)
        if ifaceobj.type == ifaceType.BRIDGE_VLAN:
            return False
        return True

    def create_n_save_ifaceobj(self, ifacename, priv_flags=None,
                               increfcnt=False):
        """ creates a iface object and adds it to the iface dictionary """
        ifaceobj = iface()
        ifaceobj.name = ifacename
        ifaceobj.priv_flags = priv_flags
        ifaceobj.auto = True
        if not self._link_master_slave:
            ifaceobj.link_type = ifaceLinkType.LINK_NA
        if increfcnt:
            ifaceobj.inc_refcnt()
        self.ifaceobjdict[ifacename] = [ifaceobj]
        return ifaceobj

    def create_n_save_ifaceobjcurr(self, ifaceobj):
        """ creates a copy of iface object and adds it to the iface
            dict containing current iface objects
        """
        ifaceobjcurr = iface()
        ifaceobjcurr.name = ifaceobj.name
        ifaceobjcurr.type = ifaceobj.type
        ifaceobjcurr.lowerifaces = ifaceobj.lowerifaces
        ifaceobjcurr.priv_flags = copy.deepcopy(ifaceobj.priv_flags)
        ifaceobjcurr.auto = ifaceobj.auto
        self.ifaceobjcurrdict.setdefault(ifaceobj.name,
                                     []).append(ifaceobjcurr)
        return ifaceobjcurr

    def get_ifaceobjcurr(self, ifacename, idx=0):
        ifaceobjlist = self.ifaceobjcurrdict.get(ifacename)
        if not ifaceobjlist:
            return None
        if not idx:
            return ifaceobjlist
        else:
            return ifaceobjlist[idx]

    def get_iface_refcnt(self, ifacename):
        """ Return iface ref count """
        max_ref = 0
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            return 0
        for i in ifaceobjs:
            if i.refcnt > max_ref:
                max_ref = i.refcnt
        return max_ref

    def is_iface_builtin_byname(self, ifacename):
        """ Returns true if iface name is a builtin interface.

        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """
        return '.' in ifacename

    def is_ifaceobj_builtin(self, ifaceobj):
        """ Returns true if iface name is a builtin interface.

        A builtin interface is an interface which ifupdown understands.
        The following are currently considered builtin ifaces:
            - vlan interfaces in the format <ifacename>.<vlanid>
        """
        if (ifaceobj.priv_flags and ifaceobj.priv_flags.BUILTIN):
            return True
        return False

    def is_ifaceobj_noconfig(self, ifaceobj):
        """ Returns true if iface object did not have a user defined config.

        These interfaces appear only when they are dependents of interfaces
        which have user defined config
        """
        return (ifaceobj.priv_flags and ifaceobj.priv_flags.NOCONFIG)

    def is_iface_noconfig(self, ifacename):
        """ Returns true if iface has no config """

        ifaceobj = self.get_ifaceobj_first(ifacename)
        if not ifaceobj: return True
        return self.is_ifaceobj_noconfig(ifaceobj)

    def check_shared_dependents(self, ifaceobj, dlist):
        """ ABSOLETE: Check if dlist intersects with any other
            interface with slave dependents.
            example: bond and bridges.
            This function logs such errors """
        setdlist = set(dlist)
        for ifacename, ifacedlist in list(self.dependency_graph.items()):
            if not ifacedlist:
                continue
            check_depends = False
            iobjs = self.get_ifaceobjs(ifacename)
            if not iobjs:
                continue
            for i in iobjs:
                if (i.dependency_type == ifaceDependencyType.MASTER_SLAVE):
                    check_depends = True
            if check_depends:
                common = set(ifacedlist).intersection(setdlist)
                if common:
                    self.logger.error('misconfig..?. iface %s and %s '
                            %(ifaceobj.name, ifacename) +
                            'seem to share dependents/ports %s' %str(list(common)))

    def _set_iface_role(self, ifaceobj, role, upperifaceobj):
        if (self.flags.CHECK_SHARED_DEPENDENTS and
            (ifaceobj.role & ifaceRole.SLAVE) and
            (role == ifaceRole.SLAVE) and (upperifaceobj.role & ifaceRole.MASTER)):
            self.logger.error("misconfig..? %s %s is enslaved to multiple interfaces %s"
                              % (ifaceobj.name,
                                 ifaceLinkPrivFlags.get_str(ifaceobj.link_privflags), str(ifaceobj.upperifaces)))
            ifaceobj.set_status(ifaceStatus.ERROR)
            return
        ifaceobj.role = role

    def _set_iface_role_n_kind(self, ifaceobj, upperifaceobj):
        if (upperifaceobj.link_kind & ifaceLinkKind.BOND):
            self._set_iface_role(ifaceobj, ifaceRole.SLAVE, upperifaceobj)
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BOND_SLAVE

        if (upperifaceobj.link_kind & ifaceLinkKind.BRIDGE):
            self._set_iface_role(ifaceobj, ifaceRole.SLAVE, upperifaceobj)
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_PORT

        if (ifaceobj.link_kind & ifaceLinkKind.VXLAN) \
                and (upperifaceobj.link_kind & ifaceLinkKind.BRIDGE):
            upperifaceobj.link_privflags |= ifaceLinkPrivFlags.BRIDGE_VXLAN

        # vrf masters get processed after slaves, which means
        # check both link_kind vrf and vrf slave
        if ((upperifaceobj.link_kind & ifaceLinkKind.VRF) or
            (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE)):
            self._set_iface_role(ifaceobj, ifaceRole.SLAVE, upperifaceobj)
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.VRF_SLAVE
        if self._link_master_slave:
            if upperifaceobj.link_type == ifaceLinkType.LINK_MASTER:
                ifaceobj.link_type = ifaceLinkType.LINK_SLAVE
        else:
            upperifaceobj.link_type = ifaceLinkType.LINK_NA
            ifaceobj.link_type = ifaceLinkType.LINK_NA

    def dump_iface_dependency_info(self):
        """ debug funtion to print raw dependency
        info - lower and upper devices"""

        for ifacename, ifaceobjs in self.ifaceobjdict.items():
            iobj = ifaceobjs[0]
            self.logger.info("%s: refcnt: %d, lower: %s, upper: %s" %(ifacename,
                             self.get_iface_refcnt(ifacename),
                             str(iobj.lowerifaces) if iobj.lowerifaces else [],
                             str(iobj.upperifaces) if iobj.upperifaces else []))


    def preprocess_dependency_list(self, upperifaceobj, dlist):
        """ We go through the dependency list and
            delete or add interfaces from the interfaces dict by
            applying the following rules:
                if flag DELETE_DEPENDENT_IFACES_WITH_NOCONFIG is True:
                    we only consider devices whose configuration was
                    specified in the network interfaces file. We delete
                    any interface whose config was not specified except
                    for vlan devices. vlan devices get special treatment.
                    Even if they are not present they are created and added
                    to the ifacesdict
                elif flag DELETE_DEPENDENT_IFACES_WITH_NOCONFIG is False:
                    we create objects for all dependent devices that are not
                    present in the ifacesdict
        """
        del_list = []

        for d in dlist:
            dilist = self.get_ifaceobjs(d)
            if not dilist:
                ni = None
                if self.is_iface_builtin_byname(d):
                    ni = self.create_n_save_ifaceobj(d,
                            ifacePrivFlags(True, True), True)
                elif not self.flags.DELETE_DEPENDENT_IFACES_WITH_NOCONFIG:
                    ni = self.create_n_save_ifaceobj(d,
                                    ifacePrivFlags(False, True), True)
                else:
                    del_list.append(d)
                if ni:
                    ni.add_to_upperifaces(upperifaceobj.name)
                    self._set_iface_role_n_kind(ni, upperifaceobj)
            else:
                for di in dilist:
                    di.inc_refcnt()
                    di.add_to_upperifaces(upperifaceobj.name)
                    self._set_iface_role_n_kind(di, upperifaceobj)
        for d in del_list:
            dlist.remove(d)

    def preprocess_upperiface(self, lowerifaceobj, ulist):
        for u in ulist:
            if (lowerifaceobj.upperifaces and
                u in lowerifaceobj.upperifaces):
                continue
            lowerifaceobj.add_to_upperifaces(u)
            uifacelist = self.get_ifaceobjs(u)
            if uifacelist:
                for ui in uifacelist:
                    lowerifaceobj.inc_refcnt()
                    self._set_iface_role_n_kind(lowerifaceobj, ui)
                    ui.add_to_lowerifaces(lowerifaceobj.name)

    def query_lowerifaces(self, ifaceobj, ops, ifacenames, old_ifaceobjs):
        """ Gets iface dependents by calling into respective modules """
        ret_dlist = []
        # Get dependents for interface by querying respective modules
        for module in list(self.modules.values()):
            try:
                if ops[0] == 'query-running':
                    if (not hasattr(module,
                        'get_dependent_ifacenames_running')):
                        continue
                    dlist = module.get_dependent_ifacenames_running(ifaceobj)
                else:
                    if (not hasattr(module, 'get_dependent_ifacenames')):
                        continue
                    dlist = module.get_dependent_ifacenames(ifaceobj,
                                        ifacenames, old_ifaceobjs)
            except Exception as e:
                self.logger.warning("%s: %s: error getting dependent interfaces (%s)" % (ifaceobj.name, module, str(e)))
                dlist = None
            if dlist: ret_dlist.extend(dlist)
        return list(set(ret_dlist))

    def query_upperifaces(self, ifaceobj, ops, ifacenames):
        """ Gets iface upperifaces by calling into respective modules """
        ret_ulist = []

        # Get upperifaces for interface by querying respective modules
        for module in list(self.modules.values()):
            try:
                if ops[0] == 'query-running':
                    if (not hasattr(module,
                        'get_upper_ifacenames_running')):
                        continue
                    ulist = module.get_upper_ifacenames_running(ifaceobj)
                else:
                    if (not hasattr(module, 'get_upper_ifacenames')):
                        continue
                    ulist = module.get_upper_ifacenames(ifaceobj, ifacenames)
            except Exception as e:
                self.logger.warning('%s: error getting upper interfaces (%s)'
                                 %(ifaceobj.name, str(e)))
                ulist = None
            if ulist: ret_ulist.extend(ulist)
        return list(set(ret_ulist))

    def _remove_circular_veth_dependencies(self, ifaceobj, dlist):
        # if ifaceobj isn't a veth link, ignore it.
        if ifaceobj.get_attr_value_first('link-type') != "veth":
            return

        for diface in dlist:
            difaceobj = self.get_ifaceobj_first(diface)
            # If the dependent iface isn't a veth link - which shouldn't
            # happen - ignore it to be save.
            if not difaceobj or (difaceobj and difaceobj.get_attr_value_first('link-type') != "veth"):
                continue

            # If the peer has a desired peer name set and this is us,
            # see if the peer has a dependency to us too and remove our
            # redundant dependency to the peer.
            diface_peer_name = difaceobj.get_attr_value_first('veth-peer-name')
            if diface_peer_name and diface_peer_name == ifaceobj.name:
                peer_dlist = difaceobj.lowerifaces
                if not peer_dlist:
                    # Not list of dependent interface on the peer.
                    continue

                # We aleady are in the peers dlist, don't add dependcy from us to peer
                if ifaceobj.name in peer_dlist:
                    dlist.remove(difaceobj.name)

    def populate_dependency_info(self, ops, ifacenames=None, old_ifaceobjs=False):
        """ recursive function to generate iface dependency info """

        if not ifacenames:
            ifacenames = list(self.ifaceobjdict.keys())

        iqueue = deque(ifacenames)
        while iqueue:
            i = iqueue.popleft()
            # Go through all modules and find dependent ifaces
            dlist = None
            ulist = None
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs:
                continue
            dependents_processed = False

            # Store all dependency info in the first ifaceobj
            # but get dependency info from all ifaceobjs
            ifaceobj = ifaceobjs[0]
            for iobj in ifaceobjs:
                ulist = self.query_upperifaces(iobj, ops, ifacenames)
                if iobj.lowerifaces:
                    dependents_processed = True
                    break
                dlist = self.query_lowerifaces(iobj, ops, ifacenames, old_ifaceobjs)
                if dlist:
                   break
            if ulist:
                self.preprocess_upperiface(ifaceobj, ulist)
            if dependents_processed:
                continue
            if dlist:
                self._remove_circular_veth_dependencies(ifaceobj, dlist)
                self.preprocess_dependency_list(ifaceobj,
                                                dlist)
                ifaceobj.lowerifaces = dlist
                [iqueue.append(d) for d in dlist]
            #if not self.dependency_graph.get(i):
            #    self.dependency_graph[i] = dlist

        for i in list(self.ifaceobjdict.keys()):
            iobj = self.get_ifaceobj_first(i)
            if (not iobj.link_kind and
               not (iobj.link_privflags & ifaceLinkPrivFlags.LOOPBACK) and
               iobj.name == 'lo'):
               iobj.link_privflags |= ifaceLinkPrivFlags.LOOPBACK
            if iobj.name.startswith(self.mgmt_iface_default_prefix):
               self.logger.debug('%s: marking interface with mgmt flag' %iobj.name)
               iobj.link_privflags |= ifaceLinkPrivFlags.MGMT_INTF
            if iobj.lowerifaces:
                self.dependency_graph[i] = iobj.lowerifaces
            else:
                self.dependency_graph[i] = []

        if not self.blacklisted_ifaces_present:
            return

        # Walk through the dependency graph and remove blacklisted
        # interfaces that were picked up as dependents
        for i in list(self.dependency_graph.keys()):
            ifaceobj = self.get_ifaceobj_first(i)
            if not ifaceobj:
                continue

            if ifaceobj.blacklisted and not ifaceobj.upperifaces:
                # if blacklisted and was not picked up as a
                # dependent of a upper interface, delete the
                # interface from the dependency graph
                dlist = ifaceobj.lowerifaces
                if dlist:
                    for d in dlist:
                        difaceobjs = self.get_ifaceobjs(d)
                        if not difaceobjs:
                            continue
                        try:
                            for d in difaceobjs:
                                d.dec_refcnt()
                                d.upperifaces.remove(i)
                        except Exception:
                            self.logger.debug('error removing %s from %s upperifaces' %(i, d))
                self.logger.debug("populate_dependency_info: deleting blacklisted interface %s" %i)
                del self.dependency_graph[i]

    def _check_config_no_repeats(self, ifaceobj):
        """ check if object has an attribute that is
        restricted to a single object in the system.
        if yes, warn and return """
        for k,v in list(self._cache_no_repeats.items()):
            iv = ifaceobj.config.get(k)
            if iv and iv[0] == v:
                self.logger.error('ignoring interface %s. ' %ifaceobj.name +
                        'Only one object with attribute ' +
                        '\'%s %s\' allowed.' %(k, v))
                return True
        for k, v in list(self.config.get('no_repeats', {}).items()):
            iv = ifaceobj.config.get(k)
            if iv and iv[0] == v:
                self._cache_no_repeats[k] = v
        return False

    def _save_iface_squash(self, ifaceobj):
        """ squash ifaceobjects belonging to same iface
        into a single object """
        if self._check_config_no_repeats(ifaceobj):
           return
        ifaceobj.priv_flags = ifacePrivFlags()
        if not self._link_master_slave:
           ifaceobj.link_type = ifaceLinkType.LINK_NA
        currentifaceobjlist = self.ifaceobjdict.get(ifaceobj.name)
        if not currentifaceobjlist:
            self.ifaceobjdict[ifaceobj.name] = [ifaceobj]
            return
        if ifaceobj.compare(currentifaceobjlist[0]):
            self.logger.warning('duplicate interface %s found' %ifaceobj.name)
            return
        for obj in self.ifaceobjdict[ifaceobj.name]:
            if obj.type == ifaceobj.type:
                obj.squash(ifaceobj)
                return
        self.ifaceobjdict[ifaceobj.name].append(ifaceobj)

    def _save_iface(self, ifaceobj):
        if self._check_config_no_repeats(ifaceobj):
           return
        ifaceobj.priv_flags = ifacePrivFlags()
        if not self._link_master_slave:
           ifaceobj.link_type = ifaceLinkType.LINK_NA
        currentifaceobjlist = self.ifaceobjdict.get(ifaceobj.name)
        if not currentifaceobjlist:
            self.ifaceobjdict[ifaceobj.name]= [ifaceobj]
            if not self._ifaceobj_squash:
                ifaceobj.flags |= ifaceobj.YOUNGEST_SIBLING
            return
        if ifaceobj.compare(currentifaceobjlist[0]):
            self.logger.warning('duplicate interface %s found' %ifaceobj.name)
            return
        if currentifaceobjlist[0].type == ifaceobj.type:
            currentifaceobjlist[0].flags |= ifaceobj.HAS_SIBLINGS
            ifaceobj.flags |= ifaceobj.HAS_SIBLINGS
        # clear the OLDEST_SIBLING from all the siblings
        for iface in self.ifaceobjdict[ifaceobj.name]:
            iface.flags &= ~ifaceobj.OLDEST_SIBLING
        # current sibling is the oldest
        ifaceobj.flags |= ifaceobj.OLDEST_SIBLING
        self.ifaceobjdict[ifaceobj.name].append(ifaceobj)

    def _keyword_text(self, value, validrange=None):
        return isinstance(value, str) and len(value) > 0

    def _keyword_mac(self, value, validrange=None):
        if value.strip().startswith('ether'):
            value = value.strip()[6:]
        return re.match('[0-9a-f]{1,2}([-:])[0-9a-f]{1,2}(\\1[0-9a-f]{1,2}){4}$',
                        value.lower())

    def _keyword_check_list(self, _list, obj, limit=None):
        try:
            if limit and limit > 0:
                for i in range(0, limit):
                    obj(_list[i])
                return len(_list) == limit
            else:
                for elem in _list:
                    obj(elem)
            return True
        except Exception as e:
            self.logger.debug('keyword: check list: %s' % str(e))
            return False

    def _keyword_ipv4(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPv4Address, limit=1)

    def _keyword_ipv4_prefixlen(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPv4Network, limit=1)

    def _keyword_ipv6(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPv6Address, limit=1)

    def _keyword_ipv6_prefixlen(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPv6Network, limit=1)

    def _keyword_ip(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPAddress, limit=1)

    def _keyword_ip_prefixlen(self, value, validrange=None):
        return self._keyword_check_list(value.split(), ipnetwork.IPNetwork, limit=1)

    def _keyword_mac_ip_prefixlen_list(self, value, validrange=None):
        """
            MAC address followed by optional list of ip addresses
            <mac> [<ip> <ip> ...]
            ex: address-virtual 00:11:22:33:44:01 11.0.1.1/24 11.0.1.2/24
        """
        try:
            res = value.split()
            if not self._keyword_mac(res[0]):
                return False
            for ip in res[1:]:
                if not self._keyword_ip_prefixlen(ip):
                    return False
            return True
        except Exception as e:
            self.logger.debug('keyword: mac ipaddr prefixlen: %s' % str(e))
            return False

    def _keyword_number_ipv4_list(self, value, validrange=None):
        """
            <number>=<ipv4> [<number>=<ipv4> ...]
            ex: bridge-mcqv4src 100=172.16.100.1 101=172.16.101.1
        """
        try:
            elements = value.split(' ')
            if not elements:
                return False
            for elem in elements:
                v = elem.split('=')
                int(v[0])
                ipnetwork.IPv4Address(v[1])
            return True
        except Exception as e:
            self.logger.debug('keyword: number ipv4: %s' % str(e))
            return False

    def _keyword_interface(self, ifacename, validrange=None):
        return self.get_ifaceobjs(ifacename)

    def _keyword_ipv4_vrf_text(self, value, validrange=None):
        """
            <ipv4> "vrf" <text>
            ex: clagd-backup-ip 10.10.10.42 vrf blue
        """
        values = value.split()
        size = len(values)

        if size > 3 or size < 1:
            return False
        try:
            ipnetwork.IPv4Address(values[0])
            if size > 1:
                if values[1] != 'vrf':
                    return False
                if size > 2 and not self._keyword_text(values[2]):
                    return False
            return True
        except Exception as e:
            self.logger.debug('keyword: ipv4 vrf text: %s' % str(e))
            return False

    def _keyword_interface_list_with_value(self, value, validvals):
        values = value.split()
        try:
            if len(values) == 1 and values[0] in validvals:
                return True
            for v in values:
                iface_value = v.split('=')
                size = len(iface_value)
                if size != 2:
                    if iface_value[0] == 'glob' or iface_value[0] == 'regex':
                        continue
                    return False
                if iface_value[1] not in validvals:
                    return False
            return True
        except Exception as e:
            self.logger.debug('keyword: interface list with value: %s' % str(e))
            return False

    def _keyword_interface_on_off_list(self, value, validrange=None):
        """
            <yes|no> | ( <interface>=<on|off> [<interface>=<on|off> ...] )
            ex: bridge-learning swp1=on swp2=off
        """
        return self._keyword_interface_list_with_value(value, ['on', 'off'])

    def _keyword_interface_yes_no_list(self, value, validrange=None):
        """
            <yes|no> | ( <interface>=<yes|no> [<interface>=<yes|no> ...] )
            ex: mstpctl-portrestrrole swp1=yes swp2=no
        """
        return self._keyword_interface_list_with_value(value, ['yes', 'no'])

    def _keyword_interface_yes_no_auto_list(self, value, validrange=None):
        """
            <yes|no|auto> |
                ( <interface>=<yes|no|auto> [<interface>=<yes|no|auto> ...] )
            ex: mstpctl-portp2p swp1=yes swp2=no swp3=auto
        """
        return self._keyword_interface_list_with_value(value,
                                                        ['yes', 'no', 'auto'])

    def _keyword_interface_l2protocol_tunnel_list(self, value, validrange=None):
        """
            bridge-l2protocol-tunnel swpX=lacp,stp swpY=cdp swpZ=all
            bridge-l2protocol-tunnel lacp stp,lldp,cdp
            bridge-l2protocol-tunnel stp lacp cdp
            bridge-l2protocol-tunnel lldp pvst
            bridge-l2protocol-tunnel stp
            bridge-l2protocol-tunnel all
        """
        try:
            if '=' in value:
                for intf_arg in value.split():
                    intf_arg_split = intf_arg.split('=')
                    for arg in intf_arg_split[1].replace(",", " ").split():
                        if arg not in ['all', 'stp', 'lldp', 'lacp', 'cdp', 'pvst']:
                            return False
            else:
                for arg in value.replace(",", " ").split():
                    if arg not in ['all', 'stp', 'lldp', 'lacp', 'cdp', 'pvst']:
                        return False
        except Exception:
            return False
        return True

    def _keyword_interface_yes_no_0_1_list(self, value, validrange=None):
        """
            <yes|no|0|1> |
                ( <interface>=<yes|no|0|1> [<interface>=<yes|no|0|1> ...] )
            ex: bridge-portmcrouter swp1=yes swp2=yes swp3=1
        """
        return self._keyword_interface_list_with_value(value,
                                                       ['yes', 'no', '1', '0', '2'])

    def _keyword_interface_disabled_automatic_enabled_list(self, value, validrange=None):
        return self._keyword_interface_list_with_value(value, [
            '0', 'disabled', 'no',
            '1', 'automatic', 'yes',
            '2', 'enabled'])

    def _keyword_interface_range_list_multiple_of_16(self, value, validrange):
        return self._keyword_interface_range_list(value, validrange, multiple=16)

    def _keyword_interface_range_list(self, value, validrange, multiple=None):
        """
            <number> | ( <interface>=<number> [ <interface>=number> ...] )
            ex: mstpctl-portpathcost swp1=0 swp2=1
        """
        values = value.split()
        try:
            if len(values) == 1 and '=' not in values[0]:
                try:
                    n = int(values[0])
                    if n < int(validrange[0]) or n > int(
                        validrange[1]):
                        raise invalidValueError('value of out range "%s":'
                                                ' valid attribute range: %s'
                                                % (values[0],
                                                   '-'.join(validrange)))

                    if multiple is not None and n % multiple != 0:
                        raise invalidValueError('invalid value %s: must be a multiple of %s' % (n, multiple))

                    return True
                except invalidValueError as e:
                    raise e
                except Exception as e:
                    self.logger.debug('keyword: interface range list: %s'
                                      % str(e))
                    return False
            for v in values:
                iface_value = v.split('=')
                size = len(iface_value)
                if size != 2:
                    return False
                number = int(iface_value[1])
                if number < int(validrange[0]) or number > int(
                        validrange[1]):
                    raise invalidValueError(
                        'value of out range "%s" for iface "%s":'
                        ' valid attribute range: %s'
                        % (iface_value[1],
                           iface_value[0],
                           '-'.join(validrange)))

                if multiple is not None and number % multiple != 0:
                    raise invalidValueError('invalid value %s: must be a multiple of %s' % (number, multiple))

            return True
        except invalidValueError as e:
            raise e
        except Exception as e:
            self.logger.debug('keyword: interface range list: %s' % str(e))
            return False

    def _keyword_interface_list(self, value, validrange=None):
        """
            [glob|regex] <interface> [ [glob|regex] <interface> ...]
            ex: bridge-ports swp1 swp2 glob swp3-5.100 regex (swp[6|7|8].100)
        """
        interface_list = value.split()
        size = len(interface_list)
        i = 0
        while i < size:
            if interface_list[i] == 'glob' or interface_list[i] == 'regex':
                i += 1
            else:
                if not self._keyword_interface(interface_list[i]):
                    return False
            i += 1
        return True

    def _keyword_number_range_list(self, value, validrange=None):
        """
            <number> [<number>-<number>]
            ex: bridge-vids 42 100-200
        """
        number_list = value.split()
        try:
            i = 0
            while i < len(number_list):
                if '-' in number_list[i]:
                    r = number_list[i].split('-')
                    a = int(r[0])
                    b = int(r[1])
                    if a > b:
                        return False
                else:
                    int(number_list[i])
                i += 1
            return True
        except Exception as e:
            self.logger.debug('keyword: number range list: %s' % str(e))
            return False

    def _keyword_number_interface_list(self, value, validrange=None):
        """
            <number> <interface> [<interface>... [<number> <interface> ... ]]
            bridge-waitport 42 swp1 swp2 swp3 9 swp4
        """
        interface_list = value.split()
        if not interface_list:
            return False
        try:
            int(interface_list[0])
            prev = True
            for elem in interface_list[1:]:
                try:
                    int(elem)
                    if prev:
                        return False
                    prev = True
                except Exception:
                    prev = False
            return not prev
        except Exception as e:
            self.logger.debug('keyword: number interface list: %s' % str(e))
            return False

    def _keyword_number(self, value, validrange=None):
        try:
            int_value = int(value)
            if validrange is not None:
                return int(validrange[0]) <= int_value <= int(validrange[1])
            return True
        except Exception as e:
            self.logger.debug('keyword: number: %s' % str(e))
            return False

    def _is_keyword(self, value):
        if isinstance(value, tuple):
            return True
        keyword_found = value in self.validate_keywords
        if value.startswith('<') and value.endswith('>') and not keyword_found:
            raise MainException('%s: invalid keyword, please make sure to use'
                            ' a valid keyword see `ifquery -s`' % value)
        return keyword_found

    def _check_validvals_value(self, value, validvals, validrange):
        if validvals and value not in validvals:
            is_valid = False
            for keyword in validvals:
                if self._is_keyword(keyword):
                    if validrange:
                        if self.validate_keywords[keyword](value, validrange):
                            return {'result': True}
                    else:
                        if self.validate_keywords[keyword](value):
                            return {'result': True}
            if not is_valid:
                return {
                    'result': False,
                    'message': 'invalid value "%s": valid attribute values: %s'
                               % (value, validvals)
                }
        elif validvals and value in validvals:
            pass
        elif validrange:
            if len(validrange) != 2:
                raise MainException('%s: invalid range in addon configuration'
                                % '-'.join(validrange))
            _value = int(value)
            if _value < int(validrange[0]) or _value > int(validrange[1]):
                return {
                    'result': False,
                    'message': 'value of out range "%s": '
                               'valid attribute range: %s'
                               % (value, '-'.join(validrange))
                }
        return {'result': True}

    def _check_validvals(self, ifacename, module_name, attrs):
        ifaceobj = self.get_ifaceobjs(ifacename)
        if not ifaceobj:
            return
        success = True
        for attrname, attrvalue in list(ifaceobj[0].config.items()):
            try:
                attrname_dict = attrs.get(attrname, {})
                validvals = attrname_dict.get('validvals', [])
                validrange = attrname_dict.get('validrange', [])
                for value in attrvalue:
                    res = self._check_validvals_value(value,
                                                      validvals,
                                                      validrange)
                    if not res['result']:
                        self.logger.warning('%s: %s: %s' %
                                         (ifacename, attrname, res['message']))
                        success = False
            except Exception as e:
                self.logger.warning('addon \'%s\': %s: %s' % (module_name,
                                                           attrname,
                                                           str(e)))
                success = False
        return success

    def _module_syntax_check(self, filtered_ifacenames):
        result = True
        for ifacename in filtered_ifacenames:
            for module in list(self.modules.values()):
                try:
                    if hasattr(module, '_modinfo'):
                        if not self._check_validvals(ifacename,
                                                     module.__class__.__name__,
                                                     module._modinfo.get('attrs', {})):
                            result = False
                    if hasattr(module, 'syntax_check') and callable(module.syntax_check):
                        if not module.syntax_check(self.get_ifaceobjs(ifacename)[0],
                                                   self.get_ifaceobjs):
                            result = False
                except Exception as e:
                    self.logger.warning('%s: %s' % (ifacename, str(e)))
                    result = False
        return result

    def _iface_configattr_syntax_checker(self, attrname, attrval):
        for m, mdict in list(self.module_attrs.items()):
            if not mdict:
                continue
            attrsdict = mdict.get('attrs')
            try:
                a = attrsdict.get(attrname)
                if a:
                    if a.get('deprecated'):
                        newa = a.get('new-attribute')
                        if newa:
                            self.logger.warning('attribute %s is deprecated. use %s instead.' %(attrname, newa))
                        else:
                            self.logger.warning('attribute %s is deprecated.'
                                             %attrname)
                    return True
                else:
                    for key in attrsdict:
                        if 'aliases' in attrsdict[key]:
                            if attrname in attrsdict[key]['aliases']:
                                return True
            except AttributeError:
                pass
        return False

    def _ifaceobj_syntax_checker(self, ifaceobj):
        ret = True
        for attrname, attrvalue in list(ifaceobj.config.items()):
            found = False
            for k, v in list(self.module_attrs.items()):
                if v and v.get('attrs', {}).get(attrname):
                    found = True
                    break
            if not found:
                ret = False
                self.logger.warning('%s: unsupported attribute \'%s\'' \
                                 % (ifaceobj.name, attrname))
        return ret

    def read_iface_config(self, raw=False):
        """ Reads default network interface config /etc/network/interfaces. """
        ret = True
        nifaces = networkInterfaces(self.interfacesfile,
                        self.interfacesfileiobuf,
                        self.interfacesfileformat,
                        template_enable=self.config.get('template_enable', 0),
                        template_engine=self.config.get('template_engine'),
                template_lookuppath=self.config.get('template_lookuppath'),
                                    raw=raw)
        if self._ifaceobj_squash or self._ifaceobj_squash_internal:
            nifaces.subscribe('iface_found', self._save_iface_squash)
        else:
            nifaces.subscribe('iface_found', self._save_iface)
        if self.config.get('addon_syntax_check', '1') == '1':
            nifaces.subscribe('validateifaceattr',
                              self._iface_configattr_syntax_checker)
            nifaces.subscribe('validateifaceobj', self._ifaceobj_syntax_checker)
        nifaces.load()
        if nifaces.errors or nifaces.warns:
            ret = False

        self._schedule_addon_translate()
        return ret

    def read_old_iface_config(self):
        """ Reads the saved iface config instead of default iface config.
        And saved iface config is already read by the statemanager """
        self.ifaceobjdict = copy.deepcopy(self.statemanager.ifaceobjdict)

    def _load_addon_modules_config(self):
        """ Load addon modules config file """

        with open(self.addon_modules_configfile, 'r') as f:
            lines = f.readlines()
            for l in lines:
                try:
                    litems = l.strip(' \n\t\r').split(',')
                    if not litems or len(litems) < 2:
                        continue
                    operation = litems[0]
                    mname = litems[1]
                    self.module_ops[operation].append(mname)
                except Exception as e:
                    self.logger.warning('error reading line \'%s\' %s:' %(l, str(e)))
                    continue

    def load_addon_modules(self, modules_dir_list):
        """ load python modules from modules_dir

        Default modules_dir is /usr/share/ifupdownmodules

        """
        failed_import = list()

        self.logger.info('loading builtin modules from %s' % str(modules_dir_list))
        self._load_addon_modules_config()

        for modules_dir in modules_dir_list:
            if modules_dir not in sys.path:
                sys.path.insert(1, modules_dir)
            for op, mlist in list(self.module_ops.items()):
                for mname in mlist:
                    if self.modules.get(mname):
                        continue
                    mpath = modules_dir + '/' + mname + '.py'
                    if os.path.exists(mpath) and mpath not in failed_import:
                        try:
                            m = __import__(mname)
                            mclass = getattr(m, mname)
                        except Exception as e:
                            self.logger.warning('cannot load "%s" module: %s' % (mname, str(e)))
                            failed_import.append(mpath)
                            continue
                        try:
                            minstance = mclass()
                            script_override = minstance.get_overrides_ifupdown_scripts()
                            self.overridden_ifupdown_scripts.extend(script_override)
                        except moduleNotSupported as e:
                            self.logger.info('module %s not loaded (%s)'
                                             % (mname, str(e)))
                            continue
                        self.modules[mname] = minstance
                        try:
                            self.module_attrs[mname] = minstance.get_modinfo()
                        except Exception:
                            pass

        # Assign all modules to query operations
        self.module_ops['query-checkcurr'] = list(self.modules.keys())
        self.module_ops['query-running'] = list(self.modules.keys())
        self.module_ops['query-dependency'] = list(self.modules.keys())
        self.module_ops['query'] = list(self.modules.keys())
        self.module_ops['query-raw'] = list(self.modules.keys())

    def _keyword_number_comma_range_list(self, value, validrange=None):
        return self._keyword_number_range_list(value.replace(',', ' '), validrange=validrange)


    def _modules_help(self, fmt):
        """ Prints addon modules supported syntax """

        if fmt == 'json':
            modinfos = {}
            for key, value in list(self.modules.items()):
                if hasattr(value, '_modinfo'):
                    modinfos[key] = {
                        'mhelp': value._modinfo['mhelp'],
                        'attrs': value.merge_modinfo_with_policy_files()
                    }
            print(json.dumps(modinfos))
        else:
            indent = '  '
            for m, mdict in list(self.module_attrs.items()):
                if not mdict:
                    continue
                print(('%s: %s' %(m, mdict.get('mhelp'))))
                attrdict = self.modules[m].merge_modinfo_with_policy_files()
                if not attrdict:
                    continue
                try:
                    for attrname, attrvaldict in list(attrdict.items()):
                        if attrvaldict.get('compat', False):
                            continue
                        print(('%s%s' %(indent, attrname)))
                        print(('%shelp: %s' %(indent + '  ',
                              attrvaldict.get('help', ''))))
                        print(('%srequired: %s' %(indent + '  ',
                                attrvaldict.get('required', False))))
                        default = attrvaldict.get('default')
                        if default:
                            print(('%sdefault: %s' %(indent + '  ', default)))

                        validrange = attrvaldict.get('validrange')
                        if validrange:
                            print(('%svalidrange: %s-%s'
                                  %(indent + '  ', validrange[0], validrange[1])))

                        validvals = attrvaldict.get('validvals')
                        if validvals:
                            print(('%svalidvals: %s'
                                  %(indent + '  ', ','.join(validvals))))

                        examples = attrvaldict.get('example')
                        if not examples:
                            continue

                        print('%sexample:' %(indent + '  '))
                        for e in examples:
                            print('%s%s' %(indent + '    ', e))
                except Exception:
                    pass
                print('')

    def load_scripts(self, modules_dir):
        """ loading user modules from /etc/network/.

        Note that previously loaded python modules override modules found
        under /etc/network if any

        """

        self.logger.info('looking for user scripts under %s' %modules_dir)
        for op, mlist in list(self.script_ops.items()):
            msubdir = modules_dir + '/if-%s.d' %op
            self.logger.info('loading scripts under %s ...' %msubdir)
            try:
                module_list = os.listdir(msubdir)
                for module in module_list:
                    if self.modules.get(module) or module in self.overridden_ifupdown_scripts:
                        continue
                    self.script_ops[op].append(msubdir + '/' + module)
            except Exception:
                # continue reading
                pass


    def _schedule_addon_translate(self):
        merged_ifaceobjs = list(itertools.chain.from_iterable(self.ifaceobjdict.values()))

        for addon in self.modules.values():
            try:
                addon.translate(merged_ifaceobjs)
            except AttributeError:
                pass

    def _sched_ifaces(self, ifacenames, ops, skipupperifaces=False,
                      followdependents=True, sort=False, diff_mode=False):
        self.logger.debug('scheduling \'%s\' for %s'
                          %(str(ops), str(ifacenames)))
        self._pretty_print_ordered_dict('dependency graph',
                    self.dependency_graph)
        ifaceScheduler.sched_ifaces(self, ifacenames, ops,
                                    dependency_graph=self.dependency_graph,
                                    order=ifaceSchedulerFlags.INORDER
                            if 'down' in ops[0]
                                else ifaceSchedulerFlags.POSTORDER,
                                    followdependents=followdependents,
                                    skipupperifaces=skipupperifaces,
                                    sort=True if (sort or ifupdownflags.flags.CLASS) else False, diff_mode=diff_mode)
        return ifaceScheduler.get_sched_status()

    def _render_ifacename(self, ifacename):
        new_ifacenames = []
        vlan_match = re.match("^([\d]+)-([\d]+)", ifacename)
        if vlan_match:
            vlan_groups = vlan_match.groups()
            if vlan_groups[0] and vlan_groups[1]:
                [new_ifacenames.append('%d' %v)
                    for v in range(int(vlan_groups[0]),
                            int(vlan_groups[1])+1)]
        return new_ifacenames

    def _preprocess_ifacenames(self, ifacenames):
        """ validates interface list for config existance.

        returns -1 if one or more interface not found. else, returns 0

        """
        new_ifacenames = []
        err_iface = ''
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs:
                # if name not available, render interface name and check again
                rendered_ifacenames = utils.expand_iface_range(i)
                if rendered_ifacenames:
                    for ri in rendered_ifacenames:
                        ifaceobjs = self.get_ifaceobjs(ri)
                        if not ifaceobjs:
                            err_iface += ' ' + ri
                        else:
                            new_ifacenames.append(ri)
                else:
                    err_iface += ' ' + i
            else:
                new_ifacenames.append(i)
        if err_iface:
            raise MainException('cannot find interfaces:%s' %err_iface)
        return new_ifacenames

    def _iface_whitelisted(self, auto, allow_classes, excludepats, ifacename):
        """ Checks if interface is whitelisted depending on set of parameters.

        interfaces are checked against the allow_classes and auto lists.

        """

        ret = True

	    # Check if interface matches the exclude patter
        if excludepats:
            for e in excludepats:
                if re.search(e, ifacename):
                    ret = False
        ifaceobjs = self.get_ifaceobjs(ifacename)
        if not ifaceobjs:
            if ret:
                self.logger.debug('iface %s' %ifacename + ' not found')
            return ret
        # If matched exclude pattern, return false
        if not ret:
            for i in ifaceobjs:
                i.blacklisted = True
                self.blacklisted_ifaces_present = True
            return ret
        # Check if interface belongs to the class
        # the user is interested in, if not return false
        if allow_classes:
            ret = False
            for i in ifaceobjs:
                if i.classes:
                    common = set(allow_classes).intersection(set(i.classes))
                    if common:
                        ret = True
            if not ret:
                # If a class was requested and interface does not belong
                # to the class, only then mark the ifaceobjs as blacklisted
                self.blacklisted_ifaces_present = True
                for i in ifaceobjs:
                    i.blacklisted = True
            return ret
        # If the user has requested auto class, check if the interface
        # is marked auto
        if auto:
            ret = False
            for i in ifaceobjs:
                if i.auto:
                    ret = True
            if not ret:
                # If auto was requested and interface was not marked auto,
                # only then mark all of them as blacklisted
                self.blacklisted_ifaces_present = True
                for i in ifaceobjs:
                    i.blacklisted = True
        return ret

    def _compat_conv_op_to_mode(self, op):
        """ Returns old op name to work with existing scripts """
        if 'up' in op:
            return 'start'
        elif 'down' in op:
            return 'stop'
        else:
            return op

    def generate_running_env(self, ifaceobj, op):
        """ Generates a dictionary with env variables required for
        an interface. Used to support script execution for interfaces.
        """

        cenv = None
        iface_env = ifaceobj.get_env()
        if iface_env:
            cenv = dict(os.environ)
            if cenv:
                cenv.update(iface_env)
            else:
                cenv = iface_env
        else:
            cenv = {}
        cenv['MODE'] = self._compat_conv_op_to_mode(op)
        cenv['PHASE'] = op

        return cenv

    def _save_state(self):
        if (not self.flags.STATEMANAGER_ENABLE or
            not self.flags.STATEMANAGER_UPDATE):
            return
        try:
            # Update persistant iface states
            self.statemanager.save_state()
        except Exception as e:
            if self.logger.isEnabledFor(logging.DEBUG):
                t = sys.exc_info()[2]
                traceback.print_tb(t)
                self.logger.warning('error saving state (%s)' %str(e))

    def set_type(self, type):
        if type == 'iface':
            self.type = ifaceType.IFACE
        elif type == 'vlan':
            self.type = ifaceType.BRIDGE_VLAN
        else:
            self.type = ifaceType.UNKNOWN

    def _process_delay_admin_state_queue(self, op):
        if not self._delay_admin_state_iface_queue:
           return
        if op == 'up':
           func = self.netlink.link_up
        elif op == 'down':
           func = self.netlink.link_down
        else:
           return
        for i in self._delay_admin_state_iface_queue:
            try:
                if self.link_exists(i):
                   func(i)
            except Exception as e:
                self.logger.warning(str(e))

    def _get_iface_exclude_companion(self, ifacename):
        try:
            return ifupdown2.ifupdown.policymanager.policymanager_api.get_iface_default(
                                    module_name='main', ifname=ifacename,
                                    attr='exclude-companion')
        except Exception:
            return ifupdown.policymanager.policymanager_api.get_iface_default(
                                    module_name='main', ifname=ifacename,
                                    attr='exclude-companion')

    def _preprocess_excludepats(self, excludepats):
        new_excludepats = excludepats
        for e in excludepats:
            ifaceobjs = self.get_ifaceobjs(e)
            for iobj in ifaceobjs or []:
                ec = iobj.get_attr_value_first('exclude-companion')
                if not ec:
                    ec = self._get_iface_exclude_companion(e)
                    if not ec:
                        continue
                    else:
                        for ee in ec.split():
                            if ee in new_excludepats:
                                continue
                            if self.get_ifaceobjs(ee):
                                # if we know the object add it to the new
                                # excludepats list
                                new_excludepats.append(ee)
        self.logger.info('excludepats after processing companions [%s]' %' '.join(new_excludepats))
        return new_excludepats

    def up(self, ops, auto=False, allow_classes=None, ifacenames=None,
           excludepats=None, printdependency=None, syntaxcheck=False,
           type=None, skipupperifaces=False):
        """This brings the interface(s) up

        Args:
            ops (list): list of ops to perform on the interface(s).
            Eg: ['pre-up', 'up', 'post-up'

        Kwargs:
            auto (bool): act on interfaces marked auto
            allow_classes (list): act on interfaces belonging to classes in the list
            ifacenames (list): act on interfaces specified in this list
            excludepats (list): list of patterns of interfaces to exclude
            syntaxcheck (bool): only perform syntax check
        """

        self.set_type(type)

        if allow_classes:
            ifupdownflags.flags.CLASS = True
        if not self.flags.ADDONS_ENABLE:
            self.flags.STATEMANAGER_UPDATE = False
        if auto:
            ifupdownflags.flags.ALL = True
            ifupdownflags.flags.WITH_DEPENDS = True

        iface_read_ret = self.read_iface_config()

        if excludepats:
            excludepats = self._preprocess_excludepats(excludepats)

        filtered_ifacenames = None
        if ifacenames:
            ifacenames = self._preprocess_ifacenames(ifacenames)

            if allow_classes:
                filtered_ifacenames = self._get_filtered_ifacenames_with_classes(auto, allow_classes, excludepats, ifacenames)

        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = list(self.ifaceobjdict.keys())

        if not filtered_ifacenames:
            # filter interfaces based on auto and allow classes
            filtered_ifacenames = [i for i in ifacenames
                                    if self._iface_whitelisted(auto, allow_classes,
                                                excludepats, i)]

        if not filtered_ifacenames:
            raise MainException('no ifaces found matching given allow lists')

        if printdependency:
            self.populate_dependency_info(ops, filtered_ifacenames)
            self.print_dependency(printdependency)
            return
        else:
            self.populate_dependency_info(ops)

        # If only syntax check was requested, return here.
        # return here because we want to make sure most
        # errors above are caught and reported.
        if syntaxcheck:
            if not self._module_syntax_check(filtered_ifacenames):
                raise MainException()
            if not iface_read_ret:
                raise MainException()
            elif self._any_iface_errors(filtered_ifacenames):
                raise MainException()
            return

        ret = None
        try:
            ret = self._sched_ifaces(filtered_ifacenames, ops,
                                     skipupperifaces=skipupperifaces,
                                     followdependents=True
                                     if ifupdownflags.flags.WITH_DEPENDS
                                     else False)
        finally:
            self._process_delay_admin_state_queue('up')
            if not ifupdownflags.flags.DRYRUN and self.flags.ADDONS_ENABLE:
                self._save_state()

        if not iface_read_ret or not ret:
            raise MainException()

        self.check_running_configuration(filtered_ifacenames)

    def check_running_configuration(self, filtered_ifacenames, all=False):
        """
        Print warning and better info message when we don't recognize an interface
        AKA when the interface wasn't created.

        :param filtered_ifacenames:
        :param all:
        :return:
        """
        if not filtered_ifacenames:
            filtered_ifacenames = []

        for ifname, ifaceobj_list in self.ifaceobjdict.items():

            if not all and ifname not in filtered_ifacenames:
                continue

            auto = True

            for ifaceobj in ifaceobj_list:
                if not ifaceobj.auto:
                    auto = False
                    break

            if not ifupdownflags.flags.DRYRUN and auto and not os.path.exists("/sys/class/net/%s" % ifname) and not self._is_ifaceobj_bridge_vlan(ifaceobj_list):
                self.logger.warning("%s: interface not recognized - please check interface configuration" % ifname)

    def _is_ifaceobj_bridge_vlan(self, ifaceobj_list):
        for ifaceobj in ifaceobj_list:
            if ifaceobj.type == ifaceType.BRIDGE_VLAN:
                return True
        return False

    def _get_filtered_ifacenames_with_classes(self, auto, allow_classes, excludepats, ifacenames):
        # if user has specified ifacelist and allow_classes
        # append the allow_classes interfaces to user
        # ifacelist
        filtered_ifacenames = [i for i in list(self.ifaceobjdict.keys())
                               if self._iface_whitelisted(auto, allow_classes,
                                                          excludepats, i)]
        filtered_ifacenames += ifacenames

        for intf in ifacenames:
            for obj in self.get_ifaceobjs(intf) or []:
                obj.blacklisted = False

        return filtered_ifacenames

    def down(self, ops, auto=False, allow_classes=None, ifacenames=None,
             excludepats=None, printdependency=None, usecurrentconfig=False,
             type=None):
        """ down an interface """

        self.set_type(type)

        if allow_classes:
            ifupdownflags.flags.CLASS = True
        if not self.flags.ADDONS_ENABLE:
            self.flags.STATEMANAGER_UPDATE = False
        if auto:
            ifupdownflags.flags.ALL = True
            ifupdownflags.flags.WITH_DEPENDS = True
        # For down we need to look at old state, unless usecurrentconfig
        # is set
        if (not usecurrentconfig and self.flags.STATEMANAGER_ENABLE and
                    self.statemanager.ifaceobjdict):
            # Since we are using state manager objects,
            # skip the updating of state manager objects
            self.logger.debug('Looking at old state ..')
            self.read_old_iface_config()
        else:
            # If no old state available
            try:
                self.read_iface_config()
            except Exception as e:
                raise MainException('error reading iface config (%s)' %str(e))

        if excludepats:
            excludepats = self._preprocess_excludepats(excludepats)

        filtered_ifacenames = None
        if ifacenames:
            # If iface list is given by the caller, always check if iface
            # is present
            try:
               ifacenames = self._preprocess_ifacenames(ifacenames)

               if allow_classes:
                   filtered_ifacenames = self._get_filtered_ifacenames_with_classes(auto, allow_classes, excludepats, ifacenames)

            except Exception as e:
               raise MainException('%s' %str(e) +
                       ' (interface was probably never up ?)')


        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = list(self.ifaceobjdict.keys())

        if not filtered_ifacenames:
            # filter interfaces based on auto and allow classes
            filtered_ifacenames = [i for i in ifacenames
                                   if self._iface_whitelisted(auto, allow_classes,
                                                    excludepats, i)]

        if not filtered_ifacenames:
            raise MainException('no ifaces found matching given allow lists ' +
                    '(or interfaces were probably never up ?)')

        if printdependency:
            self.populate_dependency_info(ops, filtered_ifacenames)
            self.print_dependency(printdependency)
            return
        else:
            self.populate_dependency_info(ops)

        try:
            self._sched_ifaces(filtered_ifacenames, ops,
                               followdependents=True
                               if ifupdownflags.flags.WITH_DEPENDS else False)
        finally:
            self._process_delay_admin_state_queue('down')
            if not ifupdownflags.flags.DRYRUN and self.flags.ADDONS_ENABLE:
                self._save_state()

    def query(self, ops, auto=False, format_list=False, allow_classes=None,
              ifacenames=None,
              excludepats=None, printdependency=None,
              format='native', type=None):
        """ query an interface """

        self.set_type(type)

        # Let us forget internal squashing when it comes to
        # ifquery. It can surprise people relying of ifquery
        # output
        self._ifaceobj_squash_internal = False

        if allow_classes:
            ifupdownflags.flags.CLASS = True
        if self.flags.STATEMANAGER_ENABLE and ops[0] == 'query-savedstate':
            return self.statemanager.dump_pretty(ifacenames)
        self.flags.STATEMANAGER_UPDATE = False

        iface_read_ret = True

        if auto:
            self.logger.debug('setting flag ALL')
            ifupdownflags.flags.ALL = True
            ifupdownflags.flags.WITH_DEPENDS = True

        if ops[0] == 'query-syntax':
            self._modules_help(format)
            return
        elif ops[0] == 'query-running':
            # create fake devices to all dependents that dont have config
            for i in ifacenames:
                self.create_n_save_ifaceobj(i, ifacePrivFlags(False, True))
        else:
            iface_read_ret = self.read_iface_config(raw=ops[0] == "query-raw")

        if ifacenames and ops[0] != 'query-running':
            # If iface list is given, always check if iface is present
            ifacenames = self._preprocess_ifacenames(ifacenames)

        if allow_classes:
            filtered_ifacenames = self._get_filtered_ifacenames_with_classes(auto, allow_classes, excludepats, ifacenames)

        # if iface list not given by user, assume all from config file
        if not ifacenames: ifacenames = list(self.ifaceobjdict.keys())

        # filter interfaces based on auto and allow classes
        if ops[0] == 'query-running':
            filtered_ifacenames = ifacenames
        elif not allow_classes:
            filtered_ifacenames = [
                i for i in ifacenames
                if self._iface_whitelisted(
                    auto,
                    allow_classes,
                    excludepats, i
                )
            ]

        if not filtered_ifacenames:
                raise MainException('no ifaces found matching ' +
                        'given allow lists')

        self.populate_dependency_info(ops)
        if ops[0] == 'query-dependency' and printdependency:
            self.print_dependency(printdependency)
            return

        if format_list and (ops[0] == 'query' or ops[0] == 'query-raw'):
            return self.print_ifaceobjs_list(filtered_ifacenames)

        if ops[0] == 'query' and not ifupdownflags.flags.WITHDEFAULTS:
            return self.print_ifaceobjs_pretty(filtered_ifacenames, format)
        elif ops[0] == 'query-raw':
            return self.print_ifaceobjs_raw(filtered_ifacenames, format)

        ret = self._sched_ifaces(filtered_ifacenames, ops,
                                 followdependents=True
                           if ifupdownflags.flags.WITH_DEPENDS else False)

        if ops[0] == 'query' and ifupdownflags.flags.WITHDEFAULTS:
            return self.print_ifaceobjs_pretty(filtered_ifacenames, format)
        elif ops[0] == 'query-checkcurr':
            if self.print_ifaceobjscurr_pretty(filtered_ifacenames, format):
                # if any of the object has an error, signal that silently
                raise MainException('')
        elif ops[0] == 'query-running':
            self.print_ifaceobjsrunning_pretty(filtered_ifacenames, format)
            return

        if not iface_read_ret or not ret:
            raise MainException()

    def _reload_currentlyup(self, upops, downops, auto=False, allow=None,
            ifacenames=None, excludepats=None, usecurrentconfig=False,
            syntaxcheck=False, **extra_args):
        """ reload currently up interfaces """
        new_ifaceobjdict = {}

        self.logger.info('reloading interfaces that are currently up ..')

        iface_read_ret = self.read_iface_config()

        if not self.ifaceobjdict:
            self.logger.warning("nothing to reload ..exiting.")
            return
        already_up_ifacenames = []
        if not ifacenames: ifacenames = list(self.ifaceobjdict.keys())

        if (not usecurrentconfig and self.flags.STATEMANAGER_ENABLE
                and self.statemanager.ifaceobjdict):
            already_up_ifacenames = list(self.statemanager.ifaceobjdict.keys())

        # Get already up interfaces that still exist in the interfaces file
        already_up_ifacenames_not_present = set(
                        already_up_ifacenames).difference(ifacenames)
        already_up_ifacenames_still_present = set(
                        already_up_ifacenames).difference(
                        already_up_ifacenames_not_present)

        interfaces_to_up = already_up_ifacenames_still_present

        # generate dependency graph of interfaces
        self.populate_dependency_info(upops, interfaces_to_up)

        # If only syntax check was requested, return here.
        # return here because we want to make sure most
        # errors above are caught and reported.
        if syntaxcheck:
            if not self._module_syntax_check(interfaces_to_up):
                raise MainException()
            if not iface_read_ret:
                raise MainException()
            elif self._any_iface_errors(interfaces_to_up):
                raise MainException()
            return

        if (already_up_ifacenames_not_present and
                self.config.get('ifreload_currentlyup_down_notpresent') == '1'):
           self.logger.info('reload: schedule down on interfaces: %s'
                            %str(already_up_ifacenames_not_present))

           # Save a copy of new iface objects and dependency_graph
           new_ifaceobjdict = dict(self.ifaceobjdict)
           new_dependency_graph = dict(self.dependency_graph)

           # old interface config is read into self.ifaceobjdict
           self.read_old_iface_config()

           # reinitialize dependency graph
           self.dependency_graph = OrderedDict({})
           falready_up_ifacenames_not_present = [i for i in
                                    already_up_ifacenames_not_present
                                    if self._iface_whitelisted(auto, allow,
                                    excludepats, i)]
           self.populate_dependency_info(downops,
                                         falready_up_ifacenames_not_present)
           self._sched_ifaces(falready_up_ifacenames_not_present, downops,
                              followdependents=False, sort=True)
        else:
           self.logger.info('no interfaces to down ..')

        # Now, run 'up' with new config dict
        # reset statemanager update flag to default
        if auto:
            ifupdownflags.flags.ALL = True
            ifupdownflags.flags.WITH_DEPENDS = True
        if new_ifaceobjdict:
            # and now, ifaceobjdict is back to current config
            self.ifaceobjdict = new_ifaceobjdict
            self.dependency_graph = new_dependency_graph

        if not self.ifaceobjdict:
            self.logger.info('no interfaces to up')
            return
        self.logger.info('reload: scheduling up on interfaces: %s'
                         %str(interfaces_to_up))
        ret = self._sched_ifaces(interfaces_to_up, upops,
                                 followdependents=True
                                 if ifupdownflags.flags.WITH_DEPENDS else False)
        if ifupdownflags.flags.DRYRUN:
            return
        self._save_state()

        if not iface_read_ret or not ret:
            raise MainException()

    def _reload_default(self, upops, downops, auto=False, allow=None,
            ifacenames=None, excludepats=None, usecurrentconfig=False,
            syntaxcheck=False, diff=False, **extra_args):
        """ reload interface config """

        ifupdownConfig.diff_mode = self.diff_based = diff

        new_ifaceobjdict = {}
        ifacedownlist = []
        iface_read_ret = self.read_iface_config()

        if not self.ifaceobjdict:
            self.logger.warning("nothing to reload ..exiting.")
            return

        if not ifacenames: ifacenames = list(self.ifaceobjdict.keys())
        new_filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow,
                               excludepats, i)]
        # generate dependency graph of interfaces
        self.populate_dependency_info(upops)

        # If only syntax check was requested, return here.
        # return here because we want to make sure most
        # errors above are caught and reported.
        if syntaxcheck:
            if not self._module_syntax_check(new_filtered_ifacenames):
                raise MainException()
            if not iface_read_ret:
                raise MainException()
            elif self._any_iface_errors(new_filtered_ifacenames):
                raise MainException()
            return

        if (not usecurrentconfig and self.flags.STATEMANAGER_ENABLE
                and self.statemanager.ifaceobjdict):
            # Save a copy of new iface objects and dependency_graph
            new_ifaceobjdict = dict(self.ifaceobjdict)
            new_dependency_graph = dict(self.dependency_graph)

            self.ifaceobjdict = OrderedDict({})
            self.dependency_graph = OrderedDict({})

            # if old state is present, read old state and mark op for 'down'
            # followed by 'up' aka: reload
            # old interface config is read into self.ifaceobjdict
            self.read_old_iface_config()
            op = 'reload'
        else:
            # oldconfig not available, continue with 'up' with new config
            op = 'up'
            new_ifaceobjdict = self.ifaceobjdict
            new_dependency_graph = self.dependency_graph

        if excludepats:
            excludepats = self._preprocess_excludepats(excludepats)

        if op == 'reload' and ifacenames:
            ifacenames = list(self.ifaceobjdict.keys())
            old_filtered_ifacenames = [i for i in ifacenames
                               if self._iface_whitelisted(auto, allow,
                               excludepats, i)]

            # generate dependency graph of old interfaces,
            # This should make sure built in interfaces are
            # populated. disable check shared dependents as an optimization.
            # these are saved interfaces and dependency for these
            # have been checked before they became part of saved state.
            try:
                self.flags.CHECK_SHARED_DEPENDENTS = False
                self.populate_dependency_info(upops, old_ifaceobjs=True)
                self.flags.CHECK_SHARED_DEPENDENTS = True
            except Exception as e:
                self.logger.info("error generating dependency graph for "
                                 "saved interfaces (%s)" %str(e))

            # make sure we pick up built-in interfaces
            # if config file had 'ifreload_down_changed' variable
            # set, also look for interfaces that changed to down them
            down_changed = int(self.config.get('ifreload_down_changed', '1'))

            # Generate the interface down list
            # Interfaces that go into the down list:
            #   - interfaces that were present in last config and are not
            #     present in the new config
            #   - interfaces that were changed between the last and current
            #     config
            for ifname in list(self.ifaceobjdict.keys()):
                lastifaceobjlist = self.ifaceobjdict.get(ifname)
                if not self.is_ifaceobj_builtin(lastifaceobjlist[0]):
                    # if interface is not built-in and is not in
                    # old filtered ifacenames
                    if ifname not in old_filtered_ifacenames:
                        continue
                objidx = 0
                # If interface is not present in the new file
                # append it to the down list
                newifaceobjlist = new_ifaceobjdict.get(ifname)
                if not newifaceobjlist:
                    ifacedownlist.append(ifname)
                    continue
                # If ifaceobj was present in the old interfaces file,
                # and does not have a config in the new interfaces file
                # but has been picked up as a dependent of another
                # interface, catch it here. This catches a common error
                # for example: remove a bond section from the interfaces
                # file, but leave it around as a bridge port
                # XXX: Ideally its better to just add it to the
                # ifacedownlist. But we will be cautious here
                # and just print a warning
                if (self.is_ifaceobj_noconfig(newifaceobjlist[0]) and
                    not self.is_ifaceobj_builtin(newifaceobjlist[0]) and
                    lastifaceobjlist[0].is_config_present() and
                    lastifaceobjlist[0].link_kind):

                    # Check if interface is picked up by a regex in the upperifaces.
                    print_warning = True

                    for upper in newifaceobjlist[objidx].upperifaces or []:
                        slaves = []
                        for upper_ifaceobj in self.ifaceobjdict.get(upper):
                            slaves.extend(upper_ifaceobj.get_attr_value("bond-slaves") or [])
                            slaves.extend(upper_ifaceobj.get_attr_value("bridge-ports") or [])
                        slaves_string = " ".join(slaves)
                        if newifaceobjlist[objidx].name not in slaves_string:
                            print_warning = "regex" not in slaves_string
                            if not print_warning:
                                break
                    ###############################################################

                    warning_no_config_regex = (
                        "%s: misconfig ? removed but still exists as a dependency of %s.\n"
                        "Please remove the dependency manually `ifdown %s` if it is being "
                        "picked up as part of a regex" % (
                            newifaceobjlist[objidx].name,
                            str(newifaceobjlist[objidx].upperifaces),
                            newifaceobjlist[objidx].name
                        )
                    )

                    if print_warning:
                        self.logger.warning(warning_no_config_regex)
                    else:
                        # The warning shouldn't be printed because we've detected that this
                        # interface was pick up as part of a regex but the config doesn't
                        # exist anymore. It was most likely removed from the config file itself
                        # We should down this interface and remove it from the ifaceobjdict
                        # and dependency graph used for the following ifreload.
                        ifname_to_remove = newifaceobjlist[objidx].name
                        ifacedownlist.append(ifname_to_remove)

                        try:
                            if new_ifaceobjdict:
                                del new_ifaceobjdict[ifname_to_remove]

                            for k, v in new_dependency_graph.items():
                                if ifname_to_remove in v:
                                    v.remove(ifname_to_remove)
                            del new_dependency_graph[ifname_to_remove]
                        except Exception as e:
                            self.logger.warning(warning_no_config_regex)
                            self.logger.warning("while trying to fix this situation "
                                                "we ran into the following issues: %s" % str(e))

                elif (lastifaceobjlist[0].link_kind and
                    not newifaceobjlist[0].link_kind):
                    self.logger.warning('%s: moved from being a %s to a'
                                     ' physical interface (non-logical interface).'
                                     'This interface will be downed.\n'
                                     ' If this was not intentional, please restore the'
                                     ' original interface definition and execute ifreload'
                                     % (newifaceobjlist[objidx].name,
                                        ifaceLinkKind.to_str(lastifaceobjlist[0].link_kind)))
                    ifacedownlist.append(newifaceobjlist[objidx].name)
                if not down_changed:
                    continue
                if len(newifaceobjlist) != len(lastifaceobjlist):
                    ifacedownlist.append(ifname)
                    continue

                # If interface has changed between the current file
                # and the last installed append it to the down list
                # compare object list
                for objidx in range(0, len(lastifaceobjlist)):
                    oldobj = lastifaceobjlist[objidx]
                    newobj = newifaceobjlist[objidx]
                    if not newobj.compare(oldobj):
                        ifacedownlist.append(ifname)

            if ifacedownlist:
                self.logger.info('reload: scheduling down on interfaces: %s'
                                  %str(ifacedownlist))
                # reinitialize dependency graph
                self.dependency_graph = OrderedDict({})

                # Generate dependency info for old config
                self.flags.CHECK_SHARED_DEPENDENTS = False
                self.populate_dependency_info(downops, ifacedownlist)
                self.flags.CHECK_SHARED_DEPENDENTS = True

                try:
                    # XXX: Hack to skip checking upperifaces during down.
                    # the dependency list is not complete here
                    # and we dont want to down the upperiface.
                    # Hence during reload, set  this to true.
                    # This is being added to avoid a failure in
                    # scheduler._check_upperifaces when we are dowing
                    # a builtin bridge port
                    self.flags.SCHED_SKIP_CHECK_UPPERIFACES = True
                    self._sched_ifaces(ifacedownlist, downops,
                                       followdependents=False,
                                       sort=True)
                except Exception as e:
                    self.logger.error(str(e))
                finally:
                    self.flags.SCHED_SKIP_CHECK_UPPERIFACES = False
                    self._process_delay_admin_state_queue('down')
            else:
                self.logger.info('no interfaces to down ..')

        # Now, run 'up' with new config dict
        # reset statemanager update flag to default
        if not new_ifaceobjdict:
            self.logger.debug('no interfaces to up')
            return

        if auto:
            ifupdownflags.flags.ALL = True
            ifupdownflags.flags.WITH_DEPENDS = True
        # and now, we are back to the current config in ifaceobjdict

        if diff:
            new_filtered_ifacenames = list(
                self.get_diff_ifaceobjs(new_ifaceobjdict, ifacedownlist, self.dependency_graph)
            )

        self.ifaceobjdict = new_ifaceobjdict
        self.dependency_graph = new_dependency_graph

        if not new_filtered_ifacenames:
            self.logger.info(
                "nothing changed since the last reload, exiting."
                if self.diff_based else
                "nothing to reload - exiting."
            )
            self._save_state()
            return 0

        self.logger.info('reload: scheduling up on interfaces: %s'
                         %str(new_filtered_ifacenames))
        ifupdownflags.flags.CACHE = True
        try:
            ret = self._sched_ifaces(new_filtered_ifacenames, upops,
                                     followdependents=True
                                     if ifupdownflags.flags.WITH_DEPENDS
                                     else False, diff_mode=self.diff_based)
        except Exception as e:
            ret = None
            self.logger.error(str(e))
        finally:
            self._process_delay_admin_state_queue('up')
        if ifupdownflags.flags.DRYRUN:
            return
        self._save_state()

        if not iface_read_ret or not ret:
            raise MainException()

    def is_clag_interface(self, ifaceobjs):
        for ifaceobj in ifaceobjs or []:
            for attribute in ifaceobj.config.keys():
                if attribute.startswith("clagd-"):
                    return True
        return False

    def add_diff_interface_with_clag_check(self, diff_list: list, ifname: str, current_clag_interface: bool):
        diff_list.append(ifname)
        if current_clag_interface:
            self.clagd_change_detected = True

    def interface_should_be_up(self, ifname, ifaceobjs):
        # Return True if the link is down and should be up, check for link-down yes on any ifaceobjs
        return not any([ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN for ifaceobj in ifaceobjs]) and not self.netlink.cache.link_is_up(ifname)

    def get_diff_ifaceobjs(self, ifaceobj_dict, ifacedownlist, down_dependency_graph):
        diff_ifname = []

        # any changes in clagd attributes will result in all clagd interfaces
        # to be added to the run queue
        self.clagd_change_detected = False
        clag_interfaces = []

        for ifname, ifaceobjs in ifaceobj_dict.items():
            current_clagd_interface = False

            if ifname in diff_ifname:
                continue

            if self.is_clag_interface(ifaceobjs):
                clag_interfaces.append(ifname)
                current_clagd_interface = True

            old_ifaceobjs = statemanager_api.ifaceobjdict.get(ifname)

            if not old_ifaceobjs:
                self.add_diff_interface_with_clag_check(diff_ifname, ifname, current_clagd_interface)
            else:
                # If for some reason the statemanager has ifaceobjs but the device
                # doesn't exist in the system (is not cached), then we should no
                # matter what bring it back up
                # We also do a quick check to see if the interface is right admin state
                if not self.netlink.cache.link_exists(ifname) or self.interface_should_be_up(ifname, ifaceobjs):
                    self.add_diff_interface_with_clag_check(diff_ifname, ifname, current_clagd_interface)
                    continue

                for new, old in itertools.zip_longest(ifaceobjs, old_ifaceobjs):
                    if new != old and ifname not in diff_ifname:
                        self.add_diff_interface_with_clag_check(diff_ifname, ifname, current_clagd_interface)

        if self.clagd_change_detected:
            self.logger.info(f"diff-mode: clagd changes detected, updating run queue with: {clag_interfaces}")
            for ifname in clag_interfaces:
                if ifname not in diff_ifname:
                    diff_ifname.append(ifname)

        if ifacedownlist and down_dependency_graph:
            # If an interface is removed / downed we might need to reload lower_interfaces
            for down_ifname in ifacedownlist:
                for lower_ifname in down_dependency_graph.get(down_ifname, []):
                    if lower_ifname in ifaceobj_dict and lower_ifname not in diff_ifname:
                        diff_ifname.append(lower_ifname)

        return diff_ifname

    def reload(self, *args, **kargs):
        """ reload interface config """
        self.logger.debug('reloading interface config ..')
        if kargs.get('currentlyup', False):
            self._reload_currentlyup(*args, **kargs)
        else:
            self._reload_default(*args, **kargs)

        self.check_running_configuration([], all=True)

    def _any_iface_errors(self, ifacenames):
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            if not ifaceobjs: continue
            for ifaceobj in ifaceobjs:
                if (ifaceobj.status == ifaceStatus.NOTFOUND or
                    ifaceobj.status == ifaceStatus.ERROR):
                    return True
        return False

    def _pretty_print_ordered_dict(self, prefix, argdict):
        outbuf = prefix + ' {\n'
        for k, vlist in list(argdict.items()):
            outbuf += '\t%s : %s\n' %(k, str(vlist))
        self.logger.debug(outbuf + '}')

    def print_dependency(self, format):
        """ prints iface dependency information """
        if format == 'list':
            for k,v in list(self.dependency_graph.items()):
                print('%s : %s' %(k, str(v)))
        elif format == 'dot':
            indegrees = {}
            for i in list(self.dependency_graph.keys()):
                indegrees.update({i: self.get_iface_refcnt(i)})
            graph.generate_dots(self.dependency_graph, indegrees)

    def print_ifaceobjs_list(self, ifacenames):
        for i in ifacenames:
            print(i)

    def print_ifaceobjs_raw(self, ifacenames, format=None):
        """ prints raw lines for ifaces from config file """

        if format == "json":
            self.print_ifaceobjs_pretty(ifacenames, format)
            return

        for i in ifacenames:
            for ifaceobj in self.get_ifaceobjs(i):
                if self.is_ifaceobj_builtin(ifaceobj):
                    continue
                ifaceobj.dump_raw()
                if (ifupdownflags.flags.WITH_DEPENDS and
                    not ifupdownflags.flags.ALL):
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    self.print_ifaceobjs_raw(dlist)

    def _get_ifaceobjs_pretty(self, ifacenames, ifaceobjs, running=False):
        """ returns iface obj list """

        for i in ifacenames:
            for ifaceobj in self.get_ifaceobjs(i):
                if ((not running and self.is_ifaceobj_noconfig(ifaceobj)) or
                    (running and not ifaceobj.is_config_present() and
                     not self.is_iface_builtin_byname(i) and
                     not ifaceobj.upperifaces)):
                    continue
                ifaceobjs.append(ifaceobj)
                if (ifupdownflags.flags.WITH_DEPENDS and
                    not ifupdownflags.flags.ALL):
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    self._get_ifaceobjs_pretty(dlist, ifaceobjs, running)

    def print_ifaceobjs_pretty(self, ifacenames, format='native'):
        """ pretty prints iface in format given by keyword arg format """
        ifaceobjs = []
        self._get_ifaceobjs_pretty(ifacenames, ifaceobjs)
        if not ifaceobjs: return
        if format == 'json':
            print(json.dumps(ifaceobjs, cls=ifaceJsonEncoder,
                             indent=4, separators=(',', ': ')))
        else:
            expand = int(self.config.get('ifquery_ifacename_expand_range', '0'))
            for i in ifaceobjs:
                if not expand and (i.flags & iface.IFACERANGE_ENTRY):
                    # print only the first one
                    if i.flags & iface.IFACERANGE_START:
                       i.dump_pretty(use_realname=True)
                else:
                    i.dump_pretty()

    def _get_ifaceobjscurr_pretty(self, ifacenames, ifaceobjs):
        ret = 0
        for i in ifacenames:
            ifaceobjscurr = self.get_ifaceobjcurr(i)
            if not ifaceobjscurr: continue
            for ifaceobj in ifaceobjscurr:
                if (ifaceobj.status == ifaceStatus.NOTFOUND or
                    ifaceobj.status == ifaceStatus.ERROR):
                    ret = 1
                if self.is_ifaceobj_noconfig(ifaceobj):
                    continue
                ifaceobjs.append(ifaceobj)
                if (ifupdownflags.flags.WITH_DEPENDS and
                    not ifupdownflags.flags.ALL):
                    dlist = ifaceobj.lowerifaces
                    if not dlist: continue
                    dret = self._get_ifaceobjscurr_pretty(dlist, ifaceobjs)
                    if dret: ret = 1
        return ret

    def print_ifaceobjscurr_pretty(self, ifacenames, format='native'):
        """ pretty prints current running state of interfaces with status.

        returns 1 if any of the interface has an error,
        else returns 0
        """
        ifaceobjs = []
        ret = self._get_ifaceobjscurr_pretty(ifacenames, ifaceobjs)
        if not ifaceobjs: return

        # override ifaceStatusUserStrs
        ifaceStatusUserStrs.SUCCESS = self.config.get('ifquery_check_success_str', _success_sym)
        ifaceStatusUserStrs.ERROR = self.config.get('ifquery_check_error_str', _error_sym)
        ifaceStatusUserStrs.UNKNOWN = self.config.get('ifquery_check_unknown_str', '')
        if format == 'json':
            print(json.dumps(ifaceobjs, cls=ifaceJsonEncoderWithStatus,
                             indent=2, separators=(',', ': ')))
        else:
            for ifaceobj in ifaceobjs:
                ifaceobj.dump_pretty(with_status=True)
        return ret

    def print_ifaceobjsrunning_pretty(self, ifacenames, format='native'):
        """ pretty prints iface running state """

        ifaceobjs = []
        self._get_ifaceobjs_pretty(ifacenames, ifaceobjs, running=True)
        if not ifaceobjs: return
        if format == 'json':
            print(json.dumps(ifaceobjs, cls=ifaceJsonEncoder, indent=2,
                       separators=(',', ': ')))
        else:
            for i in ifaceobjs:
                i.dump_pretty()

    def _dump(self):
        print('ifupdown main object dump')
        print(self.pp.pprint(self.modules))
        print(self.pp.pprint(self.ifaceobjdict))

    def _dump_ifaceobjs(self, ifacenames):
        for i in ifacenames:
            ifaceobjs = self.get_ifaceobjs(i)
            for i in ifaceobjs:
                i.dump(self.logger)
                print('\n')
