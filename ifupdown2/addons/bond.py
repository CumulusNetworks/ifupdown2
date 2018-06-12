#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Roopa Prabhu, roopa@cumulusnetworks.com
#           Julien Fortin, julien@cumulusnetworks.com
#

import os

from sets import Set

try:
    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink
    from ifupdown2.ifupdown.statemanager import statemanager_api as statemanager

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink
    from ifupdown.statemanager import statemanager_api as statemanager

    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

class bond(moduleBase):
    """  ifupdown2 addon module to configure bond interfaces """

    overrides_ifupdown_scripts = ['ifenslave', ]

    _modinfo = { 'mhelp' : 'bond configuration module',
                    'attrs' : {
                    'bond-use-carrier':
                         {'help' : 'bond use carrier',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'yes',
                          'example': ['bond-use-carrier yes']},
                     'bond-num-grat-arp':
                         {'help' : 'bond use carrier',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bond-num-grat-arp 1']},
                     'bond-num-unsol-na' :
                         {'help' : 'bond slave devices',
                          'validrange' : ['0', '255'],
                          'default' : '1',
                          'example' : ['bond-num-unsol-na 1']},
                     'bond-xmit-hash-policy' :
                         {'help' : 'bond slave devices',
                          'validvals' : ['0', 'layer2',
                                         '1', 'layer3+4',
                                         '2', 'layer2+3',
                                         '3', 'encap2+3',
                                         '4', 'encap3+4'],
                          'default' : 'layer2',
                          'example' : ['bond-xmit-hash-policy layer2']},
                     'bond-miimon' :
                         {'help' : 'bond miimon',
                          'validrange' : ['0', '255'],
                          'default' : '0',
                          'example' : ['bond-miimon 0']},
                     'bond-mode' :
                         {'help': 'bond mode',
                          'validvals': ['0', 'balance-rr',
                                        '1', 'active-backup',
                                        '2', 'balance-xor',
                                        '3', 'broadcast',
                                        '4', '802.3ad',
                                        '5', 'balance-tlb',
                                        '6', 'balance-alb'],
                          'default': 'balance-rr',
                          'example': ['bond-mode 802.3ad']},
                     'bond-lacp-rate':
                         {'help' : 'bond lacp rate',
                          'validvals' : ['0', 'slow', '1', 'fast'],
                          'default' : '0',
                          'example' : ['bond-lacp-rate 0']},
                     'bond-min-links':
                         {'help' : 'bond min links',
                          'default' : '0',
                          'validrange' : ['0', '255'],
                          'example' : ['bond-min-links 0']},
                     'bond-ad-sys-priority':
                         {'help' : '802.3ad system priority',
                          'default' : '65535',
                          'validrange' : ['0', '65535'],
                          'example' : ['bond-ad-sys-priority 65535'],
                          'deprecated' : True,
                          'new-attribute' : 'bond-ad-actor-sys-prio'},
                     'bond-ad-actor-sys-prio':
                         {'help' : '802.3ad system priority',
                          'default' : '65535',
                          'validrange' : ['0', '65535'],
                          'example' : ['bond-ad-actor-sys-prio 65535']},
                     'bond-ad-sys-mac-addr':
                         {'help' : '802.3ad system mac address',
                          'validvals': ['<mac>', ],
                         'example' : ['bond-ad-sys-mac-addr 00:00:00:00:00:00'],
                         'deprecated' : True,
                         'new-attribute' : 'bond-ad-actor-system'},
                     'bond-ad-actor-system':
                         {'help' : '802.3ad system mac address',
                          'validvals': ['<mac>', ],
                         'example' : ['bond-ad-actor-system 00:00:00:00:00:00'],},
                     'bond-lacp-bypass-allow':
                         {'help' : 'allow lacp bypass',
                          'validvals' : ['yes', 'no', '0', '1'],
                          'default' : 'no',
                          'example' : ['bond-lacp-bypass-allow no']},
                     'bond-slaves' :
                        {'help' : 'bond slaves',
                         'required' : True,
                         'multivalue' : True,
                         'validvals': ['<interface-list>'],
                         'example' : ['bond-slaves swp1 swp2',
                                      'bond-slaves glob swp1-2',
                                      'bond-slaves regex (swp[1|2)'],
                         'aliases': ['bond-ports']},
                     'bond-updelay' :
                        {'help' : 'bond updelay',
                         'default' : '0',
                         'validrange' : ['0', '65535'],
                         'example' : ['bond-updelay 100']},
                     'bond-downdelay':
                        {'help' : 'bond downdelay',
                         'default' : '0',
                         'validrange' : ['0', '65535'],
                         'example' : ['bond-downdelay 100']}
                    }}

    _bond_attr_netlink_map = {
        'bond-mode': Link.IFLA_BOND_MODE,
        'bond-miimon': Link.IFLA_BOND_MIIMON,
        'bond-use-carrier': Link.IFLA_BOND_USE_CARRIER,
        'bond-lacp-rate': Link.IFLA_BOND_AD_LACP_RATE,
        'bond-xmit-hash-policy': Link.IFLA_BOND_XMIT_HASH_POLICY,
        'bond-min-links': Link.IFLA_BOND_MIN_LINKS,
        'bond-num-grat-arp': Link.IFLA_BOND_NUM_PEER_NOTIF,
        'bond-num-unsol-na': Link.IFLA_BOND_NUM_PEER_NOTIF,
        'bond-ad-sys-mac-addr': Link.IFLA_BOND_AD_ACTOR_SYSTEM,
        'bond-ad-actor-system': Link.IFLA_BOND_AD_ACTOR_SYSTEM,
        'bond-ad-sys-priority': Link.IFLA_BOND_AD_ACTOR_SYS_PRIO,
        'bond-ad-actor-sys-prio': Link.IFLA_BOND_AD_ACTOR_SYS_PRIO,
        'bond-lacp-bypass-allow': Link.IFLA_BOND_AD_LACP_BYPASS,
        'bond-updelay': Link.IFLA_BOND_UPDELAY,
        'bond-downdelay': Link.IFLA_BOND_DOWNDELAY
    }

    # ifquery-check attr dictionary with callable object to translate user data to netlink format
    _bond_attr_ifquery_check_translate_func = {
        Link.IFLA_BOND_MODE: lambda x: Link.ifla_bond_mode_tbl[x],
        Link.IFLA_BOND_MIIMON: int,
        Link.IFLA_BOND_USE_CARRIER: utils.get_boolean_from_string,
        Link.IFLA_BOND_AD_LACP_RATE: lambda x: int(utils.get_boolean_from_string(x)),
        Link.IFLA_BOND_XMIT_HASH_POLICY: lambda x: Link.ifla_bond_xmit_hash_policy_tbl[x],
        Link.IFLA_BOND_MIN_LINKS: int,
        Link.IFLA_BOND_NUM_PEER_NOTIF: int,
        Link.IFLA_BOND_AD_ACTOR_SYSTEM: str,
        Link.IFLA_BOND_AD_ACTOR_SYS_PRIO: int,
        Link.IFLA_BOND_AD_LACP_BYPASS: lambda x: int(utils.get_boolean_from_string(x)),
        Link.IFLA_BOND_UPDELAY: int,
        Link.IFLA_BOND_DOWNDELAY: int
    }

    # ifup attr list with callable object to translate user data to netlink format
    # in the future this can be moved to a dictionary, whenever we detect that some
    # netlink capabilities are missing we can dynamically remove them from the dict.
    _bond_attr_set_list = (
        ('bond-mode', Link.IFLA_BOND_MODE, lambda x: Link.ifla_bond_mode_tbl[x]),
        ('bond-xmit-hash-policy', Link.IFLA_BOND_XMIT_HASH_POLICY, lambda x: Link.ifla_bond_xmit_hash_policy_tbl[x]),
        ('bond-miimon', Link.IFLA_BOND_MIIMON, int),
        ('bond-min-links', Link.IFLA_BOND_MIN_LINKS, int),
        ('bond-num-grat-arp', Link.IFLA_BOND_NUM_PEER_NOTIF, int),
        ('bond-num-unsol-na', Link.IFLA_BOND_NUM_PEER_NOTIF, int),
        ('bond-ad-sys-priority', Link.IFLA_BOND_AD_ACTOR_SYS_PRIO, int),
        ('bond-ad-actor-sys-prio', Link.IFLA_BOND_AD_ACTOR_SYS_PRIO, int),
        ('bond-updelay', Link.IFLA_BOND_UPDELAY, int),
        ('bond-downdelay', Link.IFLA_BOND_DOWNDELAY, int),
        ('bond-use-carrier', Link.IFLA_BOND_USE_CARRIER, lambda x: int(utils.get_boolean_from_string(x))),
        ('bond-lacp-rate', Link.IFLA_BOND_AD_LACP_RATE, lambda x: int(utils.get_boolean_from_string(x))),
        ('bond-lacp-bypass-allow', Link.IFLA_BOND_AD_LACP_BYPASS, lambda x: int(utils.get_boolean_from_string(x))),
        ('bond-ad-sys-mac-addr', Link.IFLA_BOND_AD_ACTOR_SYSTEM, str),
        ('bond-ad-actor-system', Link.IFLA_BOND_AD_ACTOR_SYSTEM, str),
    )

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        self.bondcmd = None

        if not os.path.exists('/sys/class/net/bonding_masters'):
            utils.exec_command('modprobe -q bonding')

    @staticmethod
    def get_bond_slaves(ifaceobj):
        slaves = ifaceobj.get_attr_value_first('bond-slaves')
        if not slaves:
            slaves = ifaceobj.get_attr_value_first('bond-ports')
        return slaves

    def _is_bond(self, ifaceobj):
        # at first link_kind is not set but once ifupdownmain
        # calls get_dependent_ifacenames link_kind is set to BOND
        if ifaceobj.link_kind & ifaceLinkKind.BOND or self.get_bond_slaves(ifaceobj):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        """ Returns list of interfaces dependent on ifaceobj """

        if not self._is_bond(ifaceobj):
            return None
        slave_list = self.parse_port_list(ifaceobj.name,
                                          self.get_bond_slaves(ifaceobj),
                                          ifacenames_all)
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE
        # Also save a copy for future use
        ifaceobj.priv_data = list(slave_list)
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BOND
        ifaceobj.role |= ifaceRole.MASTER

        return slave_list

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        return self.syntax_check_updown_delay(ifaceobj)

    def get_dependent_ifacenames_running(self, ifaceobj):
        self._init_command_handlers()
        return self.bondcmd.bond_get_slaves(ifaceobj.name)

    def _get_slave_list(self, ifaceobj):
        """ Returns slave list present in ifaceobj config """

        # If priv data already has slave list use that first.
        if ifaceobj.priv_data:
            return ifaceobj.priv_data
        slaves = self.get_bond_slaves(ifaceobj)
        if slaves:
            return self.parse_port_list(ifaceobj.name, slaves)
        else:
            return None

    def _is_clag_bond(self, ifaceobj):
        if self.get_bond_slaves(ifaceobj):
            attrval = ifaceobj.get_attr_value_first('clag-id')
            if attrval and attrval != '0':
                return True
        return False

    def _add_slaves(self, ifaceobj, ifaceobj_getfunc=None):
        runningslaves = []

        slaves = self._get_slave_list(ifaceobj)
        if not slaves:
            self.logger.debug('%s: no slaves found' %ifaceobj.name)
            return

        if not ifupdownflags.flags.PERFMODE:
            runningslaves = self.bondcmd.bond_get_slaves(ifaceobj.name)

        clag_bond = self._is_clag_bond(ifaceobj)

        for slave in Set(slaves).difference(Set(runningslaves)):
            if (not ifupdownflags.flags.PERFMODE and
                not self.ipcmd.link_exists(slave)):
                    self.log_error('%s: skipping slave %s, does not exist'
                                   %(ifaceobj.name, slave), ifaceobj,
                                     raise_error=False)
                    continue
            link_up = False
            if self.ipcmd.is_link_up(slave):
                netlink.link_set_updown(slave, "down")
                link_up = True
            # If clag bond place the slave in a protodown state; clagd
            # will protoup it when it is ready
            if clag_bond:
                try:
                    netlink.link_set_protodown(slave, "on")
                except Exception, e:
                    self.logger.error('%s: %s' % (ifaceobj.name, str(e)))
            netlink.link_set_master(slave, ifaceobj.name)
            if link_up or ifaceobj.link_type != ifaceLinkType.LINK_NA:
               try:
                    if (ifaceobj_getfunc(slave)[0].link_privflags &
                        ifaceLinkPrivFlags.KEEP_LINK_DOWN):
                        netlink.link_set_updown(slave, "down")
                    else:
                        netlink.link_set_updown(slave, "up")
               except Exception, e:
                    self.logger.debug('%s: %s' % (ifaceobj.name, str(e)))
                    pass

        if runningslaves:
            for s in runningslaves:
                if s not in slaves:
                    self.bondcmd.bond_remove_slave(ifaceobj.name, s)
                    if clag_bond:
                        try:
                            netlink.link_set_protodown(s, "off")
                        except Exception, e:
                            self.logger.error('%s: %s' % (ifaceobj.name, str(e)))
                else:
                    # apply link-down config changes on running slaves
                    try:
                        link_up = self.ipcmd.is_link_up(s)
                        config_link_down = (ifaceobj_getfunc(s)[0].link_privflags &
                                            ifaceLinkPrivFlags.KEEP_LINK_DOWN)
                        if (config_link_down and link_up):
                            netlink.link_set_updown(s, "down")
                        elif (not config_link_down and not link_up):
                            netlink.link_set_updown(s, "up")
                    except Exception, e:
                        self.logger.warn('%s: %s' % (ifaceobj.name, str(e)))

    def _check_updown_delay_log(self, ifaceobj, attr_name, value):
        ifaceobj.status = ifaceStatus.ERROR
        self.logger.error('%s: unable to set %s %s as MII link monitoring is '
                          'disabled' % (ifaceobj.name, attr_name, value))
        # return False to notify syntax_check that an error has been logged
        return False

    def syntax_check_updown_delay(self, ifaceobj):
        result      = True
        updelay     = ifaceobj.get_attr_value_first('bond-updelay')
        downdelay   = ifaceobj.get_attr_value_first('bond-downdelay')

        if not updelay and not downdelay:
            return True

        try:
            miimon = int(ifaceobj.get_attr_value_first('bond-miimon'))
        except:
            try:
                miimon = int(policymanager.policymanager_api.get_iface_default(
                    module_name=self.__class__.__name__,
                    ifname=ifaceobj.name,
                    attr='bond-miimon'))
            except:
                miimon = 0

        if not miimon:
            # self._check_updown_delay_log returns False no matter what
            if updelay and int(updelay):
                result = self._check_updown_delay_log(ifaceobj, 'bond-updelay', updelay)
            if downdelay and int(downdelay):
                result = self._check_updown_delay_log(ifaceobj, 'bond-downdelay', downdelay)

        return result

    _bond_updown_delay_nl_list = (
        (Link.IFLA_BOND_UPDELAY, 'bond-updelay'),
        (Link.IFLA_BOND_DOWNDELAY, 'bond-downdelay')
    )

    def check_updown_delay_nl(self, link_exists, ifaceobj, ifla_info_data):
        """
            IFLA_BOND_MIIMON
            Specifies the time, in milliseconds, to wait before enabling a slave
            after a link recovery has been detected. This option is only valid
            for the miimon link monitor. The updelay value should be a multiple
            of the miimon value; if not, it will be rounded down to the nearest
            multiple. The default value is 0.

            This ifla_bond_miimon code should be move to get_ifla_bond_attr_from_user_config
            but we need to know if the operation was successful to update the cache accordingly
        """
        ifla_bond_miimon = ifla_info_data.get(Link.IFLA_BOND_MIIMON)
        if link_exists and ifla_bond_miimon is None:
            ifla_bond_miimon = self.bondcmd.link_cache_get([ifaceobj.name, 'linkinfo', Link.IFLA_BOND_MIIMON])

        if ifla_bond_miimon == 0:
            for nl_attr, attr_name in self._bond_updown_delay_nl_list:
                delay = ifla_info_data.get(nl_attr)
                # if up-down-delay exists we need to remove it, if non zero log error
                if delay is not None:
                    if delay > 0:
                        self._check_updown_delay_log(ifaceobj, attr_name, delay)
                    del ifla_info_data[nl_attr]
            return True
        return False

    _bond_lacp_attrs = (
        (Link.IFLA_BOND_AD_LACP_RATE, 'bond-lacp-rate'),
        (Link.IFLA_BOND_AD_LACP_BYPASS, 'bond-lacp-bypass')
    )

    def _check_bond_mode_user_config(self, ifname, link_exists, ifla_info_data):
        ifla_bond_mode = ifla_info_data.get(Link.IFLA_BOND_MODE)
        if ifla_bond_mode is None and link_exists:
            ifla_bond_mode = self.bondcmd.link_cache_get([ifname, 'linkinfo', Link.IFLA_BOND_MODE])
            # in this case the link already exists (we have a cached value):
            # if IFLA_BOND_MODE is not present in ifla_info_data it means:
            #   - that bond-mode was present in the user config and didn't change
            #   - never was in the user config so bond mode should be the system default value
            #   - was removed from the stanza so we might have to reset it to default value
            # nevertheless we need to add it back to the ifla_info_data dict to check
            # if we need to reset the mode to system default
            ifla_info_data[Link.IFLA_BOND_MODE] = ifla_bond_mode

        if ifla_bond_mode == 4:  # 802.3ad
            min_links = ifla_info_data.get(Link.IFLA_BOND_MIN_LINKS)
            if min_links is None:
                min_links = self.bondcmd.link_cache_get([ifname, 'linkinfo', Link.IFLA_BOND_MIN_LINKS])
            # get_min_links_nl may return None so we need to strictly check 0
            if min_links == 0:
                self.logger.warn('%s: attribute bond-min-links is set to \'0\'' % ifname)
        else:
            # IFLA_BOND_AD_LACP_RATE and IFLA_BOND_AD_LACP_BYPASS only for 802.3ad mode (4)
            for nl_attr, attr_name in self._bond_lacp_attrs:
                if nl_attr in ifla_info_data:
                    self.logger.info('%s: ignoring %s: only available for 802.3ad mode (4)' % (ifname, attr_name))
                    del ifla_info_data[nl_attr]

    @staticmethod
    def get_saved_ifaceobj(link_exists, ifname):
        if link_exists:
            old_config = statemanager.get_ifaceobjs(ifname)
            if old_config:
                return old_config[0]
        return None

    def get_ifla_bond_attr_from_user_config(self, ifaceobj, link_exists):
        """
            Potential issue: if a user load the bond driver with custom
            default values (say bond-mode 3), ifupdown2 has no knowledge
            of these default values.
            At bond creation everything should work, bonds will be created
            with mode 3 (even if not specified under the stanza).
            But, for example: if the user specifies a value under bond-mode
            and later on the user removes the bond-mode line from the stanza
            we will detect it and reset to MODINFO: BOND-MODE: DEFAULT aka 0
            which is not the real default value that the user may expect.
        """
        ifname          = ifaceobj.name
        ifla_info_data  = OrderedDict()
        old_config      = self.get_saved_ifaceobj(link_exists, ifname)

        # for each bond attribute we fetch the user configuration
        # if no configuration is provided we look for a config in policy files
        for attr_name, netlink_attr, func_ptr in self._bond_attr_set_list:
            cached_value        = None
            user_config         = ifaceobj.get_attr_value_first(attr_name)

            if not user_config:
                user_config = policymanager.policymanager_api.get_iface_default(
                    module_name=self.__class__.__name__,
                    ifname=ifname,
                    attr=attr_name)
                if user_config:
                    self.logger.debug('%s: %s %s: extracted from policy files'
                                      % (ifname, attr_name, user_config))

            # no policy override, do we need to reset an attr to default value?
            if not user_config and old_config and old_config.get_attr_value_first(attr_name):
                # if the link already exists but the value is set
                # (potentially removed from the stanza, we need to reset it to default)
                # might not work for specific cases, see explanation at the top of this function :)
                user_config = self.get_attr_default_value(attr_name)
                if user_config:
                    self.logger.debug('%s: %s: removed from stanza, resetting to default value: %s'
                                      % (ifname, attr_name, user_config))

            if user_config:
                try:
                    nl_value = func_ptr(user_config.lower())

                    if link_exists:
                        cached_value = self.bondcmd.link_cache_get([ifname, 'linkinfo', netlink_attr])

                    if link_exists and cached_value is None:
                        # the link already exists but we don't have any value
                        # cached for this attr, it probably means that the
                        # capability is not available on this system (i.e old kernel)
                        self.logger.debug('%s: ignoring %s %s: capability '
                                          'probably not supported on this system'
                                          % (ifname, attr_name, user_config))
                        continue
                    elif link_exists:
                        # there should be a cached value if the link already exists
                        if cached_value == nl_value:
                            # if the user value is already cached: continue
                            continue

                    # else: the link doesn't exist so we create the bond with
                    # all the user/policy defined values without extra checks
                    ifla_info_data[netlink_attr] = nl_value

                    if cached_value is not None:
                        self.logger.info('%s: set %s %s (cache %s)' % (ifname, attr_name, user_config, cached_value))
                    else:
                        self.logger.info('%s: set %s %s' % (ifname, attr_name, user_config))

                except KeyError:
                    self.logger.warning('%s: invalid %s value %s' % (ifname, attr_name, user_config))

        self._check_bond_mode_user_config(ifname, link_exists, ifla_info_data)
        return ifla_info_data

    _bond_down_nl_attributes_list = (
        Link.IFLA_BOND_MODE,
        Link.IFLA_BOND_XMIT_HASH_POLICY,
        Link.IFLA_BOND_AD_LACP_RATE,
        Link.IFLA_BOND_MIN_LINKS
    )

    def _should_down_bond(self, ifla_info_data):
        for nl_attr in self._bond_down_nl_attributes_list:
            if nl_attr in ifla_info_data:
                return True
        return False

    def should_update_bond_mode(self, ifaceobj, ifname, is_link_up, ifla_info_data):
        # if bond-mode was changed the bond needs to be brought
        # down and slaves un-slaved before bond mode is changed.
        cached_bond_mode = self.bondcmd.link_cache_get([ifname, 'linkinfo', Link.IFLA_BOND_MODE])
        ifla_bond_mode = ifla_info_data.get(Link.IFLA_BOND_MODE)

        # bond-mode was changed or is not specified
        if ifla_bond_mode is not None:
            if ifla_bond_mode != cached_bond_mode:
                self.logger.info('%s: bond mode changed to %s: running ops on bond and slaves'
                                 % (ifname, ifla_bond_mode))
                if is_link_up:
                    netlink.link_set_updown(ifname, 'down')
                    is_link_up = False

                for lower_dev in ifaceobj.lowerifaces:
                    netlink.link_set_nomaster(lower_dev)

                self.bondcmd.cache_delete([ifname, 'linkinfo', 'slaves'])
            else:
                # bond-mode user config value is the current running(cached) value
                # no need to reset it again we can ignore this attribute
                del ifla_info_data[Link.IFLA_BOND_MODE]

        return is_link_up

    def create_or_set_bond_config(self, ifaceobj):
        ifname          = ifaceobj.name
        link_exists     = self.ipcmd.link_exists(ifname)
        is_link_up      = self.ipcmd.is_link_up(ifname) if link_exists else False
        ifla_info_data  = self.get_ifla_bond_attr_from_user_config(ifaceobj, link_exists)

        remove_delay_from_cache = self.check_updown_delay_nl(link_exists, ifaceobj, ifla_info_data)

        # if link exists: down link if specific attributes are specified
        if link_exists:
            # did bond-mode changed?
            is_link_up = self.should_update_bond_mode(ifaceobj, ifname, is_link_up, ifla_info_data)

            # if specific attributes need to be set we need to down the bond first
            if ifla_info_data and is_link_up:
                if self._should_down_bond(ifla_info_data):
                    netlink.link_set_updown(ifname, 'down')
                    is_link_up = False

        if link_exists and not ifla_info_data:
            # if the bond already exists and no attrs need to be set
            # ignore the netlink call
            self.logger.info('%s: already exists, no change detected' % ifname)
        else:
            try:
                netlink.link_add_set(kind='bond', ifname=ifname, ifla_info_data=ifla_info_data)
            except Exception as e:
                # defensive code
                # if anything happens, we try to set up the bond with the sysfs api
                self.logger.debug('%s: bond setup: %s' % (ifname, str(e)))
                self.create_or_set_bond_config_sysfs(ifaceobj, ifla_info_data)

            if remove_delay_from_cache:
                # making sure up/down delay attributes are set to 0 before caching
                # this can be removed when moving to a nllistener/live cache
                ifla_info_data[Link.IFLA_BOND_UPDELAY] = 0
                ifla_info_data[Link.IFLA_BOND_DOWNDELAY] = 0

            # if link_add doesn't raise we can update the cache, the future
            # netlink listener will update the cache based on the kernel response
            for key, value in ifla_info_data.items():
                self.bondcmd.cache_update([ifname, 'linkinfo', key], value)

        if link_exists and ifla_info_data and not is_link_up:
            netlink.link_set_updown(ifname, 'up')

    def create_or_set_bond_config_sysfs(self, ifaceobj, ifla_info_data):
        if not self.ipcmd.link_exists(ifaceobj.name):
            self.bondcmd.create_bond(ifaceobj.name)
        self.bondcmd.bond_set_attrs_nl(ifaceobj.name, ifla_info_data)

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            self.create_or_set_bond_config(ifaceobj)
            self._add_slaves(ifaceobj, ifaceobj_getfunc)
        except Exception, e:
            self.log_error(str(e), ifaceobj)

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            netlink.link_del(ifaceobj.name)
            self.bondcmd.cache_delete([ifaceobj.name])
        except Exception as e:
            self.log_warn('%s: %s' % (ifaceobj.name, str(e)))

    def _query_check_bond_slaves(self, ifaceobjcurr, attr, user_bond_slaves, running_bond_slaves):
        query = 1

        if user_bond_slaves and running_bond_slaves:
            if not set(user_bond_slaves).symmetric_difference(running_bond_slaves):
                query = 0

        # we want to display the same bond-slaves list as provided
        # in the interfaces file but if this list contains regexes or
        # globs, for now, we won't try to change it.
        if 'regex' in user_bond_slaves or 'glob' in user_bond_slaves:
            user_bond_slaves = running_bond_slaves
        else:
            ordered = []
            for slave in user_bond_slaves:
                if slave in running_bond_slaves:
                    ordered.append(slave)
            user_bond_slaves = ordered
        ifaceobjcurr.update_config_with_status(attr, ' '.join(user_bond_slaves) if user_bond_slaves else 'None', query)

    def _query_check(self, ifaceobj, ifaceobjcurr, ifaceobj_getfunc=None):
        if not self.bondcmd.bond_exists(ifaceobj.name):
            self.logger.debug('bond iface %s does not exist' % ifaceobj.name)
            return

        iface_attrs = self.dict_key_subset(ifaceobj.config, self.get_mod_attrs())
        if not iface_attrs:
            return

        # remove bond-slaves and bond-ports from the list,
        # because there aren't any ifla_info_data netlink attr for slaves
        # an exception is raised when index is not found, so query_slaves will stay False
        query_slaves = False

        user_bond_slaves    = None
        running_bond_slaves = None
        try:
            del iface_attrs[iface_attrs.index('bond-slaves')]

            # if user specified bond-slaves we need to display it
            query_slaves = True
            if not user_bond_slaves:
                user_bond_slaves = self._get_slave_list(ifaceobj)
                running_bond_slaves = self.bondcmd.bond_get_slaves(ifaceobj.name)

            self._query_check_bond_slaves(ifaceobjcurr, 'bond-slaves', user_bond_slaves, running_bond_slaves)
        except:
            pass
        try:
            del iface_attrs[iface_attrs.index('bond-ports')]

            # if user specified bond-ports we need to display it
            if not query_slaves and not user_bond_slaves: # if get_slave_list was already called for slaves
                user_bond_slaves = self._get_slave_list(ifaceobj)
                running_bond_slaves = self.bondcmd.bond_get_slaves(ifaceobj.name)

            self._query_check_bond_slaves(ifaceobjcurr, 'bond-ports', user_bond_slaves, running_bond_slaves)
        except:
            pass

        for attr in iface_attrs:
            nl_attr         = self._bond_attr_netlink_map[attr]
            translate_func  = self._bond_attr_ifquery_check_translate_func[nl_attr]
            current_config  = self.bondcmd.link_cache_get([ifaceobj.name, 'linkinfo', nl_attr])
            user_config     = ifaceobj.get_attr_value_first(attr)

            if current_config == translate_func(user_config):
                ifaceobjcurr.update_config_with_status(attr, user_config, 0)
            else:
                ifaceobjcurr.update_config_with_status(attr, str(current_config), 1)

    @staticmethod
    def translate_nl_value_yesno(value):
        return 'yes' if value else 'no'

    @staticmethod
    def translate_nl_value_slowfast(value):
        return 'fast' if value else 'slow'

    def _query_running_attrs(self, bondname):
        bond_attrs = {
            'bond-mode': Link.ifla_bond_mode_pretty_tbl.get(self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MODE])),
            'bond-miimon': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MIIMON]),
            'bond-use-carrier': self.translate_nl_value_yesno(self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_USE_CARRIER])),
            'bond-lacp-rate': self.translate_nl_value_slowfast(self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_RATE])),
            'bond-min-links': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MIN_LINKS]),
            'bond-ad-actor-system': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYSTEM]),
            'bond-ad-actor-sys-prio': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYS_PRIO]),
            'bond-xmit-hash-policy': Link.ifla_bond_xmit_hash_policy_pretty_tbl.get(self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_XMIT_HASH_POLICY])),
            'bond-lacp-bypass-allow': self.translate_nl_value_yesno(self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_BYPASS])),
            'bond-num-unsol-na': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF]),
            'bond-num-grat-arp': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF]),
            'bond-updelay': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_UPDELAY]),
            'bond-downdelay': self.bondcmd.link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_DOWNDELAY])
        }
        slaves = self.bondcmd.bond_get_slaves(bondname)
        if slaves:
            bond_attrs['bond-slaves'] = slaves
        return bond_attrs

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.bondcmd.bond_exists(ifaceobjrunning.name):
            return
        bond_attrs = self._query_running_attrs(ifaceobjrunning.name)
        if bond_attrs.get('bond-slaves'):
            bond_attrs['bond-slaves'] = ' '.join(bond_attrs.get('bond-slaves'))

        [ifaceobjrunning.update_config(k, str(v))
         for k, v in bond_attrs.items()
         if v is not None]

    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-running': _query_running,
        'query-checkcurr': _query_check
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = self.bondcmd = LinkUtils()

    def run(self, ifaceobj, operation, query_ifaceobj=None,
            ifaceobj_getfunc=None):
        """ run bond configuration on the interface object passed as argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'pre-up', 'post-down', 'query-checkcurr',
                'query-running'

        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if operation != 'query-running' and not self._is_bond(ifaceobj):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
