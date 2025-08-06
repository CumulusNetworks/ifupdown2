#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Authors:
#           Roopa Prabhu, roopa@cumulusnetworks.com
#           Julien Fortin, julien@cumulusnetworks.com
#

import re
import os

from collections import OrderedDict
from contextlib import suppress

try:
    from ifupdown2.nlmanager.ipnetwork import IPv4Address
    from ifupdown2.lib.addon import Addon
    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.statemanager import statemanager_api as statemanager

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from nlmanager.ipnetwork import IPv4Address
    from lib.addon import Addon
    from nlmanager.nlmanager import Link

    from ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags, ifaceLinkType, ifaceDependencyType, ifaceStatus
    from ifupdown.utils import utils
    from ifupdown.statemanager import statemanager_api as statemanager

    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

class bond(Addon, moduleBase):
    """  ifupdown2 addon module to configure bond interfaces """

    overrides_ifupdown_scripts = ['ifenslave', ]

    _modinfo = {
        "mhelp": "bond configuration module",
        "attrs": {
            "bond-use-carrier": {
                "help": "bond use carrier",
                "validvals": ["yes", "no", "0", "1"],
                "default": "yes",
                "example": ["bond-use-carrier yes"]},
            "bond-num-grat-arp": {
                "help": "bond use carrier",
                "validrange": ["0", "255"],
                "default": "1",
                "example": ["bond-num-grat-arp 1"]
            },
            "bond-num-unsol-na": {
                "help": "bond slave devices",
                "validrange": ["0", "255"],
                "default": "1",
                "example": ["bond-num-unsol-na 1"]
            },
            "bond-xmit-hash-policy": {
                "help": "bond slave devices",
                "validvals": [
                    "0", "layer2",
                    "1", "layer3+4",
                    "2", "layer2+3",
                    "3", "encap2+3",
                    "4", "encap3+4",
                    "5", "vlan+srcmac"
                ],
                "default": "layer2",
                "example": ["bond-xmit-hash-policy layer2"]
            },
            "bond-miimon": {
                "help": "bond miimon",
                "validrange": ["0", "255"],
                "default": "0",
                "example": ["bond-miimon 0"]
            },
            "bond-arp-interval": {
                "help": "bond arp interval (only mode 0 and 2)",
                "default": "0",
                "example": ["bond-arp_interval 0"]
            },
            "bond-arp-ip-target": {
                "help": "ipv4 addresses maximum 16",
                "validvals": ["<ipv4>"],
                "multiline": True,
                "example": ["bond-arp-ip-target 10.0.12.3"]
            },
            "bond-mode": {
                "help": "bond mode",
                "validvals": [
                    "0", "balance-rr",
                    "1", "active-backup",
                    "2", "balance-xor",
                    "3", "broadcast",
                    "4", "802.3ad",
                    "5", "balance-tlb",
                    "6", "balance-alb"
                ],
                "default": "balance-rr",
                "example": ["bond-mode 802.3ad"]
            },
            "bond-lacp-rate": {
                "help": "bond lacp rate",
                "validvals": ["0", "slow", "1", "fast"],
                "default": "0",
                "example": ["bond-lacp-rate 0"]
            },
            "bond-min-links": {
                "help": "bond min links",
                "default": "0",
                "validrange": ["0", "255"],
                "example": ["bond-min-links 0"]
            },
            "bond-ad-sys-priority": {
                "help": "802.3ad system priority",
                "default": "65535",
                "validrange": ["0", "65535"],
                "example": ["bond-ad-sys-priority 65535"],
                "deprecated": True,
                "new-attribute": "bond-ad-actor-sys-prio"
            },
            "bond-ad-actor-sys-prio": {
                "help": "802.3ad system priority",
                "default": "65535",
                "validrange": ["0", "65535"],
                "example": ["bond-ad-actor-sys-prio 65535"]
            },
            "bond-ad-sys-mac-addr": {
                "help": "802.3ad system mac address",
                "validvals": ["<mac>", ],
                "example": ["bond-ad-sys-mac-addr 00:00:00:00:00:00"],
                "deprecated": True,
                "new-attribute": "bond-ad-actor-system"
            },
            "bond-ad-actor-system": {
                "help": "802.3ad system mac address",
                "validvals": ["<mac>", ],
                "example": ["bond-ad-actor-system 00:00:00:00:00:00"],
            },
            "bond-lacp-bypass-allow": {
                "help": "allow lacp bypass",
                "validvals": ["yes", "no", "0", "1"],
                "default": "no",
                "example": ["bond-lacp-bypass-allow no"]
            },
            "bond-slaves": {
                "help": "bond slaves",
                "required": True,
                "multivalue": True,
                "validvals": ["<interface-list>"],
                "example": [
                    "bond-slaves swp1 swp2",
                    "bond-slaves glob swp1-2",
                    "bond-slaves regex (swp[1|2])"
                ],
                "aliases": ["bond-ports"]
            },
            "bond-updelay": {
                "help": "bond updelay",
                "default": "0",
                "validrange": ["0", "65535"],
                "example": ["bond-updelay 100"]
            },
            "bond-downdelay": {
                "help": "bond downdelay",
                "default": "0",
                "validrange": ["0", "65535"],
                "example": ["bond-downdelay 100"]
            },
            "bond-primary": {
                "help": "Control which slave interface is "
                        "preferred active member",
                "example": ["bond-primary swp1"]
            },
            "bond-primary-reselect": {
                "help": "bond primary reselect",
                "validvals": [
                    "0", "always",
                    "1", "better",
                    "2", "failure",
                ],
                "example": ["bond-primary-reselect failure"]
            },
            "es-sys-mac": {
                "help": "evpn-mh: system mac address",
                "validvals": ["<mac>", ],
                "example": ["es-sys-mac 00:00:00:00:00:42"],
            }
        }
    }

    _bond_attr_netlink_map = {
        'bond-mode': Link.IFLA_BOND_MODE,
        'bond-miimon': Link.IFLA_BOND_MIIMON,
        'bond-arp-interval': Link.IFLA_BOND_ARP_INTERVAL,
        'bond-arp-ip-target': Link.IFLA_BOND_ARP_IP_TARGET,
        'bond-use-carrier': Link.IFLA_BOND_USE_CARRIER,
        'bond-lacp-rate': Link.IFLA_BOND_AD_LACP_RATE,
        'bond-xmit-hash-policy': Link.IFLA_BOND_XMIT_HASH_POLICY,
        'bond-min-links': Link.IFLA_BOND_MIN_LINKS,
        'bond-num-grat-arp': Link.IFLA_BOND_NUM_PEER_NOTIF,
        'bond-num-unsol-na': Link.IFLA_BOND_NUM_PEER_NOTIF,
        'es-sys-mac': Link.IFLA_BOND_AD_ACTOR_SYSTEM,
        'bond-ad-sys-mac-addr': Link.IFLA_BOND_AD_ACTOR_SYSTEM,
        'bond-ad-actor-system': Link.IFLA_BOND_AD_ACTOR_SYSTEM,
        'bond-ad-sys-priority': Link.IFLA_BOND_AD_ACTOR_SYS_PRIO,
        'bond-ad-actor-sys-prio': Link.IFLA_BOND_AD_ACTOR_SYS_PRIO,
        'bond-lacp-bypass-allow': Link.IFLA_BOND_AD_LACP_BYPASS,
        'bond-updelay': Link.IFLA_BOND_UPDELAY,
        'bond-downdelay': Link.IFLA_BOND_DOWNDELAY,
        'bond-primary': Link.IFLA_BOND_PRIMARY,
        'bond-primary-reselect': Link.IFLA_BOND_PRIMARY_RESELECT

    }

    # ifquery-check attr dictionary with callable object to translate user data to netlink format
    _bond_attr_ifquery_check_translate_func = {
        Link.IFLA_BOND_MODE: lambda x: Link.ifla_bond_mode_tbl[x],
        Link.IFLA_BOND_MIIMON: int,
        Link.IFLA_BOND_ARP_INTERVAL: int,
        Link.IFLA_BOND_ARP_IP_TARGET: lambda x: [IPv4Address(ip) for ip in x],
        Link.IFLA_BOND_USE_CARRIER: utils.get_boolean_from_string,
        Link.IFLA_BOND_AD_LACP_RATE: lambda x: int(utils.get_boolean_from_string(x)),
        Link.IFLA_BOND_XMIT_HASH_POLICY: lambda x: Link.ifla_bond_xmit_hash_policy_tbl[x],
        Link.IFLA_BOND_MIN_LINKS: int,
        Link.IFLA_BOND_NUM_PEER_NOTIF: int,
        Link.IFLA_BOND_AD_ACTOR_SYSTEM: str,
        Link.IFLA_BOND_AD_ACTOR_SYS_PRIO: int,
        Link.IFLA_BOND_AD_LACP_BYPASS: lambda x: int(utils.get_boolean_from_string(x)),
        Link.IFLA_BOND_UPDELAY: int,
        Link.IFLA_BOND_DOWNDELAY: int,
        Link.IFLA_BOND_PRIMARY_RESELECT: lambda x: Link.ifla_bond_primary_reselect_tbl[x],
        # Link.IFLA_BOND_PRIMARY: self.netlink.get_ifname is added in __init__()
    }

    # ifup attr list with callable object to translate user data to netlink format
    # in the future this can be moved to a dictionary, whenever we detect that some
    # netlink capabilities are missing we can dynamically remove them from the dict.
    _bond_attr_set_list = (
        ('bond-mode', Link.IFLA_BOND_MODE, lambda x: Link.ifla_bond_mode_tbl[x]),
        ('bond-xmit-hash-policy', Link.IFLA_BOND_XMIT_HASH_POLICY, lambda x: Link.ifla_bond_xmit_hash_policy_tbl[x]),
        ('bond-miimon', Link.IFLA_BOND_MIIMON, int),
        ('bond-arp-interval', Link.IFLA_BOND_ARP_INTERVAL, int),
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
        ('es-sys-mac', Link.IFLA_BOND_AD_ACTOR_SYSTEM, str),
        ('bond-ad-sys-mac-addr', Link.IFLA_BOND_AD_ACTOR_SYSTEM, str),
        ('bond-ad-actor-system', Link.IFLA_BOND_AD_ACTOR_SYSTEM, str),
        ('bond-primary-reselect', Link.IFLA_BOND_PRIMARY_RESELECT, lambda x: Link.ifla_bond_primary_reselect_tbl[x])
        # ('bond-primary', Link.IFLA_BOND_PRIMARY, self.cache.get_ifindex) added in __init__()
    )

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

        if not os.path.exists('/sys/class/net/bonding_masters'):
            try:
                utils.exec_command('modprobe -q bonding')
            except Exception as e:
                self.logger.info("bond: error while loading bonding module: %s" % str(e))

        self._bond_attr_ifquery_check_translate_func[Link.IFLA_BOND_PRIMARY] = self.cache.get_ifindex
        self._bond_attr_set_list = self._bond_attr_set_list + (('bond-primary', Link.IFLA_BOND_PRIMARY, self.cache.get_ifindex),)

        self.bond_mac_mgmt = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="bond_mac_mgmt"),
            True
        )

        self.current_bond_speed = -1
        self.speed_pattern = re.compile(r"Speed: (\d+)")

    def get_bond_slaves(self, ifaceobj):
        # bond-ports aliases should be translated to bond-slaves
        return ifaceobj.get_attr_value_first('bond-slaves')

    def _is_bond(self, ifaceobj):
        # at first link_kind is not set but once ifupdownmain
        # calls get_dependent_ifacenames link_kind is set to BOND
        return ifaceobj.link_kind & ifaceLinkKind.BOND \
               or ifaceobj.get_attr_value_first("bond-mode") \
               or self.get_bond_slaves(ifaceobj)

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None, old_ifaceobjs=False):
        """ Returns list of interfaces dependent on ifaceobj """

        if not self._is_bond(ifaceobj):
            return None
        slave_list = self.parse_port_list(ifaceobj.name,
                                          self.get_bond_slaves(ifaceobj),
                                          ifacenames_all)
        ifaceobj.dependency_type = ifaceDependencyType.MASTER_SLAVE
        # Also save a copy for future use
        ifaceobj.priv_data = list(slave_list) if slave_list else []
        if ifaceobj.link_type != ifaceLinkType.LINK_NA:
           ifaceobj.link_type = ifaceLinkType.LINK_MASTER
        ifaceobj.link_kind |= ifaceLinkKind.BOND
        ifaceobj.role |= ifaceRole.MASTER

        if ifaceobj.get_attr_value("es-sys-mac"):
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.ES_BOND

        return slave_list

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        return self.syntax_check_updown_delay(ifaceobj)

    def get_dependent_ifacenames_running(self, ifaceobj):
        return self.cache.get_slaves(ifaceobj.name)

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

    def enable_ipv6_if_prev_brport(self, ifname):
        """
        If the intf was previously enslaved to a bridge it is possible ipv6 is still disabled.
        """
        try:
            for ifaceobj in statemanager.get_ifaceobjs(ifname) or []:
                if ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT:
                    self.write_file("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % ifname, "0")
                    return
        except Exception as e:
            self.logger.info(str(e))

    def _is_clag_bond(self, ifaceobj):
        if self.get_bond_slaves(ifaceobj):
            attrval = ifaceobj.get_attr_value_first('clag-id')
            if attrval and attrval != '0':
                return True
        return False

    def compare_bond_and_slave_speed(self, bond_ifaceobj, slave_ifname, slave_speed):
        if self.current_bond_speed != slave_speed:
            self.log_error(
                "%s: ignoring device due to device's speed (%s) mismatching bond (%s) speed (%s)"
                % (slave_ifname, slave_speed, bond_ifaceobj.name, self.current_bond_speed)
            )

    def valid_slave_speed(self, ifaceobj, bond_slaves, slave, ifaceobj_getfunc):
        if not slave.startswith("swp"):
            # lazy optimization: only check "swp" interfaces
            return True

        try:
            if ifaceobj_getfunc(slave)[0].link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
                return True
        except:
            pass

        if not self.sysfs.link_is_up(slave):
            self.logger.debug(f"{slave}: bond-slave is down - skipping speed validation")
            return True

        if self.current_bond_speed < 0:
            self.current_bond_speed = self.get_bond_speed(bond_slaves)

        if self.current_bond_speed < 0:
            # if we can't get the speed of the bond there's probably no ports enslaved
            return True

        try:
            self.compare_bond_and_slave_speed(ifaceobj, slave, int(self.read_file_oneline(f"/sys/class/net/{slave}/speed")))
        except Exception:
            try:
                match = self.speed_pattern.search(utils.exec_commandl(["/usr/sbin/ethtool", f"{slave}"]))
                if match:
                    self.compare_bond_and_slave_speed(ifaceobj, slave, int(match.group(1)))
            except ValueError:
                # if we can't manage to extract the speed, it's not a big deal lets continue
                pass
        # validate if we are unable to get a speed (logical interface?)
        return True

    def get_bond_speed(self, runningslaves):
        # check bond slave speed
        bond_speed = -1
        for slave in runningslaves:
            if not slave.startswith("swp"):
                continue
            try:
                slave_speed = int(self.read_file_oneline(f"/sys/class/net/{slave}/speed"))
            except Exception:
                slave_speed = -1

            if bond_speed < 0:
                bond_speed = slave_speed
        return bond_speed

    def get_bond_slave_upper_dev_ifaceobj(self, ifname, ifaceobj_getfunc):
        for ifaceobj in ifaceobj_getfunc(ifname):
            yield from ifaceobj.upperifaces or []

    def slave_has_no_subinterface(self, bond_ifaceobj, slave, ifaceobj_getfunc):
        for upper_ifname in self.get_bond_slave_upper_dev_ifaceobj(slave, ifaceobj_getfunc):
            if upper_ifname != bond_ifaceobj.name:
                self.log_error(
                    f"{bond_ifaceobj.name}: sub interfaces are not allowed on bond slave: {slave} ({upper_ifname})",
                    bond_ifaceobj
                )
        return True

    def _add_slaves(self, ifaceobj, runningslaves, ifaceobj_getfunc=None):
        # reset the current_bond_speed
        self.current_bond_speed = -1

        slaves = self._get_slave_list(ifaceobj)
        if not slaves:
            self.logger.debug('%s: no slaves found' %ifaceobj.name)
            return

        clag_bond = self._is_clag_bond(ifaceobj)

        # remove duplicates and devices that are already enslaved
        devices_to_enslave = []
        for s in slaves:
            if s not in runningslaves and s not in devices_to_enslave:
                devices_to_enslave.append(s)

        for slave in devices_to_enslave:
            if (not ifupdownflags.flags.PERFMODE and
                not self.cache.link_exists(slave)):
                    self.log_error('%s: skipping slave %s, does not exist'
                                   %(ifaceobj.name, slave), ifaceobj,
                                     raise_error=False)
                    continue

            if not self.slave_has_no_subinterface(ifaceobj, slave, ifaceobj_getfunc):
                continue

            link_up = False
            if self.cache.link_is_up(slave):
                self.netlink.link_down_force(slave)
                link_up = True

            # if clag or ES bond: place the slave in a protodown state;
            # (clagd will proto-up it when it is ready)
            if clag_bond or ifaceobj.link_privflags & ifaceLinkPrivFlags.ES_BOND:
                try:
                    self.netlink.link_set_protodown_on(slave)
                    if clag_bond:
                        self.iproute2.link_set_protodown_reason_clag_on(slave)
                    else:
                        self.iproute2.link_set_protodown_reason_frr_on(slave)
                except Exception as e:
                    self.logger.error('%s: %s' % (ifaceobj.name, str(e)))

            self.enable_ipv6_if_prev_brport(slave)
            self.netlink.link_set_master(slave, ifaceobj.name)
            runningslaves.append(slave)
            # TODO: if this fail we should switch to iproute2
            # start a batch: down - set master - up
            if link_up or ifaceobj.link_type != ifaceLinkType.LINK_NA:
               try:
                    if (ifaceobj_getfunc(slave)[0].link_privflags &
                        ifaceLinkPrivFlags.KEEP_LINK_DOWN):
                        self.netlink.link_down_force(slave)
                    else:
                        self.netlink.link_up_force(slave)
               except Exception as e:
                    self.logger.debug('%s: %s' % (ifaceobj.name, str(e)))

        if runningslaves:
            removed_slave = []

            for s in runningslaves:
                # make sure that slaves are not in protodown since we are not in the clag-bond or es-bond case
                if not clag_bond and not ifaceobj.link_privflags & ifaceLinkPrivFlags.ES_BOND and self.cache.get_link_protodown(s):
                    self.iproute2.link_set_protodown_reason_clag_off(s)
                    self.netlink.link_set_protodown_off(s)
                if s not in slaves:
                    self.sysfs.bond_remove_slave(ifaceobj.name, s)
                    removed_slave.append(s)
                    if clag_bond:
                        try:
                            self.iproute2.link_set_protodown_reason_clag_off(s)
                            self.netlink.link_set_protodown_off(s)
                        except Exception as e:
                            self.logger.error('%s: %s' % (ifaceobj.name, str(e)))
                    elif ifaceobj.link_privflags & ifaceLinkPrivFlags.ES_BOND:
                        self.netlink.link_set_protodown_off(s)

                    # ip link set $slave nomaster will set the slave admin down
                    # if the slave has an auto stanza, we should keep it admin up
                    # unless link-down yes is set
                    slave_class_auto = False
                    slave_link_down = False
                    for obj in ifaceobj_getfunc(s) or []:
                        if obj.auto:
                            slave_class_auto = True
                        if obj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
                            slave_link_down = True
                    if slave_class_auto and not slave_link_down:
                        self.netlink.link_up_force(s)
                else:
                    # apply link-down config changes on running slaves
                    try:
                        link_up = self.cache.link_is_up(s)
                        config_link_down = (ifaceobj_getfunc(s)[0].link_privflags &
                                            ifaceLinkPrivFlags.KEEP_LINK_DOWN)
                        if (config_link_down and link_up):
                            self.netlink.link_down_force(s)
                        elif (not config_link_down and not link_up):
                            self.netlink.link_up_force(s)
                    except Exception as e:
                        self.logger.warning('%s: %s' % (ifaceobj.name, str(e)))

            for s in removed_slave:
                try:
                    runningslaves.remove(s)
                except Exception:
                    pass

        return  runningslaves

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
        except Exception:
            try:
                miimon = int(policymanager.policymanager_api.get_iface_default(
                    module_name=self.__class__.__name__,
                    ifname=ifaceobj.name,
                    attr='bond-miimon'))
            except Exception:
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
            ifla_bond_miimon = self.cache.get_link_info_data_attribute(ifaceobj.name, Link.IFLA_BOND_MIIMON)

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
            ifla_bond_mode = self.cache.get_link_info_data_attribute(ifname, Link.IFLA_BOND_MODE)
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
                min_links = self.cache.get_link_info_data_attribute(ifname, Link.IFLA_BOND_MIN_LINKS)
            # get_min_links_nl may return None so we need to strictly check 0
            if min_links == 0:
                self.logger.warning('%s: attribute bond-min-links is set to \'0\'' % ifname)
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
                        cached_value = self.cache.get_link_info_data_attribute(ifname, netlink_attr)

                    if link_exists and cached_value is None:
                        # the link already exists but we don't have any value
                        # cached for this attr, it probably means that the
                        # capability is not available on this system (i.e old kernel)
                        self.logger.debug('%s: ignoring %s %s: capability '
                                          'probably not supported on this system'
                                          % (ifname, attr_name, user_config))
                        continue
                    elif link_exists and cached_value == nl_value:
                        # there should be a cached value if the link already exists
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

    def check_miimon_arp(self, link_exists, ifaceobj, ifla_info_data):
        """
            Check bond checks either miimon or arp ip check
        """
        # miimon
        ifla_bond_miimon = ifla_info_data.get(Link.IFLA_BOND_MIIMON)
        if link_exists and ifla_bond_miimon is None:
            ifla_bond_miimon = self.cache.get_link_info_data_attribute(ifaceobj.name, Link.IFLA_BOND_MIIMON)

        if ifla_bond_miimon:
            ifla_bond_miimon = str(ifla_bond_miimon)

        # bond mode
        ifla_bond_mode = ifla_info_data.get(Link.IFLA_BOND_MODE)
        if link_exists and ifla_bond_mode is None:
            ifla_bond_mode = self.cache.get_link_info_data_attribute(ifaceobj.name, Link.IFLA_BOND_MODE)

        ifla_bond_mode = str(ifla_bond_mode)

        # arp interval
        ifla_arp_interval = ifla_info_data.get(Link.IFLA_BOND_ARP_INTERVAL)
        if link_exists and ifla_arp_interval is None:
            ifla_arp_interval = self.cache.get_link_info_data_attribute(ifaceobj.name, Link.IFLA_BOND_ARP_INTERVAL)

        if ifla_arp_interval:
            ifla_arp_interval = str(ifla_arp_interval)

        # arp ip target
        ifla_arp_ip_target = ifaceobj.get_attr_value('bond-arp-ip-target')
        if ifla_arp_ip_target:
            ifla_arp_ip_target = [IPv4Address(ip) for ip in ifla_arp_ip_target]

        if ifla_arp_ip_target:
            ifla_info_data[Link.IFLA_BOND_ARP_IP_TARGET] = ifla_arp_ip_target

        # Only works in mode 0 and 2
        if ifla_bond_mode not in ['0', '2', 'balance-rr', 'balance-xor']:
            if Link.IFLA_BOND_ARP_INTERVAL in ifla_info_data:
                self.logger.info('%s: bond arp interval/ip only works in balance-rr and balance-xor mode. Option bond-arp-interval is ignored' % ifaceobj.name)
                del ifla_info_data[Link.IFLA_BOND_ARP_INTERVAL]
            if Link.IFLA_BOND_ARP_IP_TARGET in ifla_info_data:
                self.logger.info('%s: bond arp interval/ip only works in balance-rr and balance-xor mode. Option bond-arp-ip-target is ignored' % ifaceobj.name)
                del ifla_info_data[Link.IFLA_BOND_ARP_IP_TARGET]

        if ifla_bond_miimon and ifla_bond_miimon != '0' and Link.IFLA_BOND_ARP_INTERVAL in ifla_info_data:
            self.logger.info('%s: bond arp interval and bond miimon are set. The options are mutually exclusive and bond-arp-interval is ignored' % ifaceobj.name)
            del ifla_info_data[Link.IFLA_BOND_ARP_INTERVAL]

        if ifla_arp_interval and ifla_arp_interval != '0' and Link.IFLA_BOND_MIIMON in ifla_info_data:
            self.logger.info('%s: bond arp interval and bond miimon are set. The options are mutually exclusive and bond-miimon is ignored' % ifaceobj.name)
            del ifla_info_data[Link.IFLA_BOND_MIIMON]

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

    def should_update_bond_mode(self, ifaceobj, ifname, is_link_up, ifla_info_data, bond_slaves):
        # if bond-mode was changed the bond needs to be brought
        # down and slaves un-slaved before bond mode is changed.
        cached_bond_mode = self.cache.get_link_info_data_attribute(ifname, Link.IFLA_BOND_MODE)
        ifla_bond_mode = ifla_info_data.get(Link.IFLA_BOND_MODE)

        # bond-mode was changed or is not specified
        if ifla_bond_mode is not None:
            if ifla_bond_mode != cached_bond_mode:
                self.logger.info('%s: bond mode changed to %s: running ops on bond and slaves'
                                 % (ifname, ifla_bond_mode))
                if is_link_up:
                    self.netlink.link_down(ifname)
                    is_link_up = False

                for lower_dev in ifaceobj.lowerifaces:
                    self.netlink.link_set_nomaster(lower_dev)

                    # when unslaving a device from an ES bond we need to set
                    # protodown off
                    if ifaceobj.link_privflags & ifaceLinkPrivFlags.ES_BOND:
                        self.netlink.link_set_protodown_off(lower_dev)

                    try:
                        bond_slaves.remove(lower_dev)
                    except Exception:
                        pass

            else:
                # bond-mode user config value is the current running(cached) value
                # no need to reset it again we can ignore this attribute
                del ifla_info_data[Link.IFLA_BOND_MODE]

        return is_link_up, bond_slaves

    def create_or_set_bond_config(self, ifaceobj):
        ifname          = ifaceobj.name
        link_exists, is_link_up = self.cache.link_exists_and_up(ifname)
        ifla_info_data  = self.get_ifla_bond_attr_from_user_config(ifaceobj, link_exists)
        ifla_info_data = self.check_miimon_arp(link_exists, ifaceobj, ifla_info_data)
        ifla_master = None

        remove_delay_from_cache = self.check_updown_delay_nl(link_exists, ifaceobj, ifla_info_data)

        # if link exists: down link if specific attributes are specified
        if link_exists:
            # if bond already exists we need to set IFLA_MASTER to the cached value otherwise
            # we might loose some information in the cache due to some optimization.
            ifla_master = self.cache.get_link_attribute(ifname, Link.IFLA_MASTER)

            # did bond-mode changed?
            is_link_up, bond_slaves = self.should_update_bond_mode(
                ifaceobj,
                ifname,
                is_link_up,
                ifla_info_data,
                self.cache.get_slaves(ifname)
            )

            # if specific attributes need to be set we need to down the bond first
            if ifla_info_data and is_link_up and self._should_down_bond(ifla_info_data):
                self.netlink.link_down_force(ifname)
                is_link_up = False
        else:
            bond_slaves = []

        if link_exists and not ifla_info_data:
            # if the bond already exists and no attrs need to be set
            # ignore the netlink call
            self.logger.info('%s: already exists, no change detected' % ifname)
        else:
            try:
                self.netlink.link_add_bond_with_info_data(ifname, ifla_master, ifla_info_data)
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

        if link_exists and ifla_info_data and not is_link_up:
            self.netlink.link_up_force(ifname)

        return link_exists, bond_slaves

    def create_or_set_bond_config_sysfs(self, ifaceobj, ifla_info_data):
        if len(ifaceobj.name) > 15:
            self.log_error("%s: cannot create bond: interface name exceeds max length of 15" % ifaceobj.name, ifaceobj)
            return

        if not self.cache.link_exists(ifaceobj.name):
            self.sysfs.bond_create(ifaceobj.name)
        self.sysfs.bond_set_attrs_nl(ifaceobj.name, ifla_info_data)

    def _up(self, ifaceobj, ifaceobj_getfunc=None):
        try:
            link_exists, bond_slaves = self.create_or_set_bond_config(ifaceobj)
            bond_slaves = self._add_slaves(
                ifaceobj,
                bond_slaves,
                ifaceobj_getfunc,
            )
            self.set_bond_mac(link_exists, ifaceobj, bond_slaves)
        except Exception as e:
            self.log_error(str(e), ifaceobj)

    def set_bond_mac(self, link_exists, ifaceobj, bond_slaves):
        if not self.bond_mac_mgmt or not link_exists or ifaceobj.get_attr_value_first("hwaddress"):
            return

        # check if the bond mac address is correctly inherited from it's
        # first slave. There's a case where that might not be happening:
        # $ ip link show swp1 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $ ip link show swp2 | grep ether
        #    link/ether 08:00:27:04:d8:02 brd ff:ff:ff:ff:ff:ff
        # $ ip link add dev bond0 type bond
        # $ ip link set dev swp1 master bond0
        # $ ip link set dev swp2 master bond0
        # $ ip link show bond0 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $ ip link add dev bond1 type bond
        # $ ip link set dev swp1 master bond1
        # $ ip link show swp1 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $ ip link show swp2 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $ ip link show bond0 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $ ip link show bond1 | grep ether
        #    link/ether 08:00:27:04:d8:01 brd ff:ff:ff:ff:ff:ff
        # $
        # ifupdown2 will automatically correct and fix this unexpected behavior
        # Although if the bond's mac belongs to any of its slave we won't update it
        bond_mac = self.cache.get_link_address(ifaceobj.name)

        # Get the list of slave macs
        bond_slave_macs = list(map(
            lambda slave_ifname: self.cache.get_link_info_slave_data_attribute(
                slave_ifname,
                Link.IFLA_BOND_SLAVE_PERM_HWADDR,
                default=list()
            ),
            bond_slaves
        ))

        if bond_slaves and bond_slave_macs and bond_mac not in bond_slave_macs:
            first_slave_ifname = bond_slaves[0]
            first_slave_mac = bond_slave_macs[0]

            if first_slave_mac and bond_mac != first_slave_mac:
                self.logger.info(
                    "%s: invalid bond mac detected - resetting to %s's mac (%s)"
                    % (ifaceobj.name, first_slave_ifname, first_slave_mac)
                )
                self.netlink.link_set_address(ifaceobj.name, first_slave_mac, utils.mac_str_to_int(first_slave_mac))

    def _down(self, ifaceobj, ifaceobj_getfunc=None):
        bond_slaves = self.cache.get_slaves(ifaceobj.name)

        try:
            self.netlink.link_del(ifaceobj.name)
        except Exception as e:
            self.log_warn('%s: %s' % (ifaceobj.name, str(e)))

        # set protodown (and reason) off bond slaves
        for slave in bond_slaves:
            with suppress(Exception):
                self.iproute2.link_set_protodown_reason_clag_off(slave)
            with suppress(Exception):
                self.iproute2.link_set_protodown_reason_frr_off(slave)
            with suppress(Exception):
                self.netlink.link_set_protodown_off(slave)

    def _query_check_bond_slaves(self, ifaceobjcurr, attr, user_bond_slaves, running_bond_slaves):
        query = 1

        if user_bond_slaves and running_bond_slaves and not set(user_bond_slaves).symmetric_difference(running_bond_slaves):
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
        if not self.cache.bond_exists(ifaceobj.name):
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
                running_bond_slaves = self.cache.get_slaves(ifaceobj.name)

            self._query_check_bond_slaves(ifaceobjcurr, 'bond-slaves', user_bond_slaves, running_bond_slaves)
        except Exception:
            pass
        try:
            del iface_attrs[iface_attrs.index('bond-ports')]

            # if user specified bond-ports we need to display it
            if not query_slaves and not user_bond_slaves: # if get_slave_list was already called for slaves
                user_bond_slaves = self._get_slave_list(ifaceobj)
                running_bond_slaves = self.cache.get_slaves(ifaceobj.name)

            self._query_check_bond_slaves(ifaceobjcurr, 'bond-ports', user_bond_slaves, running_bond_slaves)
        except Exception:
            pass
        try:
            attr = 'bond-arp-ip-target'
            nl_attr         = self._bond_attr_netlink_map[attr]
            translate_func  = self._bond_attr_ifquery_check_translate_func[nl_attr]
            current_config  = self.cache.get_link_info_data_attribute(ifaceobj.name, nl_attr)
            user_config     = ifaceobj.get_attr_value(attr)

            del iface_attrs[iface_attrs.index('bond-arp-ip-target')]

            current_config = [str(c.ip) for c in current_config]
            user_config = [str(u) for u in user_config]

            difference = list(set(current_config).symmetric_difference(user_config))
            intersection = list(set(current_config).intersection(user_config))

            for ip in difference:
                ifaceobjcurr.update_config_with_status(attr, ip, 1)

            for ip in intersection:
                ifaceobjcurr.update_config_with_status(attr, ip, 0)
        except Exception:
            pass

        user_config_translate_func = {
            "es-sys-mac": lambda x: str(x).lower()
        }

        if "es-sys-mac" in iface_attrs and os.geteuid() != 0:
            # for some reason es-sys-mac (IFLA_BOND_AD_ACTOR_SYSTEM) is not part
            # of the netlink dump if requested by non-root user
            try:
                iface_attrs.remove("es-sys-mac")
                self.logger.info("%s: non-root user can't check attribute \"es-sys-mac\" value" % ifaceobj.name)
            except Exception:
                pass

        for attr in iface_attrs:
            nl_attr         = self._bond_attr_netlink_map[attr]
            translate_func  = self._bond_attr_ifquery_check_translate_func[nl_attr]
            current_config  = self.cache.get_link_info_data_attribute(ifaceobj.name, nl_attr)
            user_config_f   = user_config_translate_func.get(attr)

            if user_config_f:
                user_config = user_config_f(ifaceobj.get_attr_value_first(attr))
            else:
                user_config = ifaceobj.get_attr_value_first(attr)

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
        cached_vxlan_ifla_info_data = self.cache.get_link_info_data(bondname)

        bond_attrs = {
            'bond-mode': Link.ifla_bond_mode_pretty_tbl.get(cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_MODE)),
            'bond-miimon': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_MIIMON),
            'bond-arp-interval': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_ARP_INTERVAL),
            'bond-arp-ip-target': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_ARP_IP_TARGET),
            'bond-use-carrier': self.translate_nl_value_yesno(cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_USE_CARRIER)),
            'bond-lacp-rate': self.translate_nl_value_slowfast(cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_AD_LACP_RATE)),
            'bond-min-links': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_MIN_LINKS),
            'bond-ad-actor-system': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_AD_ACTOR_SYSTEM),
            'es-sys-mac': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_AD_ACTOR_SYSTEM),
            'bond-ad-actor-sys-prio': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_AD_ACTOR_SYS_PRIO),
            'bond-xmit-hash-policy': Link.ifla_bond_xmit_hash_policy_pretty_tbl.get(cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_XMIT_HASH_POLICY)),
            'bond-lacp-bypass-allow': self.translate_nl_value_yesno(cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_AD_LACP_BYPASS)),
            'bond-num-unsol-na': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_NUM_PEER_NOTIF),
            'bond-num-grat-arp': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_NUM_PEER_NOTIF),
            'bond-updelay': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_UPDELAY),
            'bond-downdelay': cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_DOWNDELAY)
        }

        cached_bond_primary = cached_vxlan_ifla_info_data.get(Link.IFLA_BOND_PRIMARY)
        if cached_bond_primary:
            bond_attrs['bond-primary'] = self.cache.get_ifname(cached_bond_primary)

        slaves = self.cache.get_slaves(bondname)
        if slaves:
            bond_attrs['bond-slaves'] = slaves
        return bond_attrs

    def _query_running(self, ifaceobjrunning, ifaceobj_getfunc=None):
        if not self.cache.bond_exists(ifaceobjrunning.name):
            return
        bond_attrs = self._query_running_attrs(ifaceobjrunning.name)
        if bond_attrs.get('bond-slaves'):
            bond_attrs['bond-slaves'] = ' '.join(bond_attrs.get('bond-slaves'))
        if bond_attrs.get('bond-arp-ip-target'):
            for ip in bond_attrs.get('bond-arp-ip-target'):
                ifaceobjrunning.update_config('bond-arp-ip-target', str(ip.ip))
            del bond_attrs['bond-arp-ip-target']

        [ifaceobjrunning.update_config(k, str(v))
         for k, v in list(bond_attrs.items())
         if v is not None]

    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-running': _query_running,
        'query-checkcurr': _query_check
    }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

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
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj,
                       ifaceobj_getfunc=ifaceobj_getfunc)
        else:
            op_handler(self, ifaceobj, ifaceobj_getfunc=ifaceobj_getfunc)
