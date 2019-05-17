#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#         Julien Fortin, julien@cumulusnetworks.com
#

import os
import re
import glob
import shlex
import signal
import socket
import subprocess

from ipaddr import IPNetwork, IPv6Network

try:
    import ifupdown2.ifupdown.statemanager as statemanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.nlmanager.nlmanager import Link, Route

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.utilsbase import utilsBase
    from ifupdown2.ifupdownaddons.cache import linkCache, MSTPAttrsCache
except ImportError:
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.statemanager as statemanager

    from nlmanager.nlmanager import Link, Route

    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.utilsbase import utilsBase
    from ifupdownaddons.cache import linkCache, MSTPAttrsCache


class LinkUtils(utilsBase):
    """
    This class contains helper methods to cache and manipulate interfaces through
    non-netlink APIs (sysfs, iproute2, brctl...)
    """
    _CACHE_FILL_DONE = False

    ipbatchbuf = ''
    ipbatch = False
    ipbatch_pause = False

    bridge_utils_is_installed = os.path.exists(utils.brctl_cmd)
    bridge_utils_missing_warning = True

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)

        self.supported_command = {
            '%s -c -json vlan show' % utils.bridge_cmd: True,
            'showmcqv4src': True
        }
        self.bridge_vlan_cache = {}
        self.bridge_vlan_cache_fill_done = False

        if not ifupdownflags.flags.PERFMODE and not LinkUtils._CACHE_FILL_DONE:
            self._fill_cache()

    @classmethod
    def reset(cls):
        LinkUtils._CACHE_FILL_DONE = False
        LinkUtils.ipbatchbuf = ''
        LinkUtils.ipbatch = False
        LinkUtils.ipbatch_pause = False

    def _fill_cache(self):
        if not LinkUtils._CACHE_FILL_DONE:
            self._link_fill()
            self._addr_fill()
            LinkUtils._CACHE_FILL_DONE = True
            return True
        return False

    @staticmethod
    def _get_vland_id(citems, i, warn):
        try:
            sub = citems[i:]
            index = sub.index('id')
            int(sub[index + 1])
            return sub[index + 1]
        except:
            if warn:
                raise Exception('invalid use of \'vlan\' keyword')
            return None

    def _link_fill(self, ifacename=None, refresh=False):
        """ fills cache with link information

        if ifacename argument given, fill cache for ifacename, else
        fill cache for all interfaces in the system
        """

        if LinkUtils._CACHE_FILL_DONE and not refresh:
            return
        try:
            # if ifacename already present, return
            if (ifacename and not refresh and
                    linkCache.get_attr([ifacename, 'ifflag'])):
                return
        except:
            pass

        if True:
            try:
                pass
                #[linkCache.update_attrdict([ifname], linkattrs)
                # for ifname, linkattrs in netlink.link_dump(ifacename).items()]
            except Exception as e:
                self.logger.info('%s' % str(e))
                # this netlink call replaces the call to _link_fill_iproute2_cmd()
                # We shouldn't have netlink calls in the iproute2 module, this will
                # be removed in the future. We plan to release, a flexible backend
                # (netlink+iproute2) by default we will use netlink backend but with
                # a CLI arg we can switch to iproute2 backend.
                # Until we decide to create this "backend" switch capability,
                # we have to put the netlink call inside the iproute2 module.
        else:
            self._link_fill_iproute2_cmd(ifacename, refresh)

        self._fill_bond_info(ifacename)
        self._fill_bridge_info(ifacename)

    def _fill_bridge_info(self, ifacename):

        if True:  # netlink
            brports = {}

            if ifacename:
                cache_dict = {ifacename: linkCache.links.get(ifacename, {})}
            else:
                cache_dict = linkCache.links

            for ifname, obj in cache_dict.items():
                slave_kind = obj.get('slave_kind')
                if not slave_kind and slave_kind != 'bridge':
                    continue

                info_slave_data = obj.get('info_slave_data')
                if not info_slave_data:
                    continue

                ifla_master = obj.get('master')
                if not ifla_master:
                    raise Exception('No master associated with bridge port %s' % ifname)

                for nl_attr in [
                    Link.IFLA_BRPORT_STATE,
                    Link.IFLA_BRPORT_COST,
                    Link.IFLA_BRPORT_PRIORITY,
                ]:
                    if nl_attr not in info_slave_data and LinkUtils.bridge_utils_is_installed:
                        self._fill_bridge_info_brctl()
                        return

                brport_attrs = {
                    'pathcost': str(info_slave_data.get(Link.IFLA_BRPORT_COST, 0)),
                    'fdelay': format(float(info_slave_data.get(Link.IFLA_BRPORT_FORWARD_DELAY_TIMER, 0) / 100), '.2f'),
                    'portmcrouter': str(info_slave_data.get(Link.IFLA_BRPORT_MULTICAST_ROUTER, 0)),
                    'portmcfl': str(info_slave_data.get(Link.IFLA_BRPORT_FAST_LEAVE, 0)),
                    'portprio': str(info_slave_data.get(Link.IFLA_BRPORT_PRIORITY, 0)),
                    'unicast-flood': str(info_slave_data.get(Link.IFLA_BRPORT_UNICAST_FLOOD, 0)),
                    'multicast-flood': str(info_slave_data.get(Link.IFLA_BRPORT_MCAST_FLOOD, 0)),
                    'learning': str(info_slave_data.get(Link.IFLA_BRPORT_LEARNING, 0)),
                    'arp-nd-suppress': str(info_slave_data.get(Link.IFLA_BRPORT_NEIGH_SUPPRESS, 0))
                }

                if ifla_master in brports:
                    brports[ifla_master][ifname] = brport_attrs
                else:
                    brports[ifla_master] = {ifname: brport_attrs}

                linkCache.update_attrdict([ifla_master, 'linkinfo', 'ports'], brports[ifla_master])
        else:
            if LinkUtils.bridge_utils_is_installed:
                self._fill_bridge_info_brctl()

    def _fill_bridge_info_brctl(self):
        brctlout = utils.exec_command('%s show' % utils.brctl_cmd)
        if not brctlout:
            return

        for bline in brctlout.splitlines()[1:]:
            bitems = bline.split()
            if len(bitems) < 2:
                continue
            try:
                linkCache.update_attrdict([bitems[0], 'linkinfo'],
                                          {'stp': bitems[2]})
            except KeyError:
                linkCache.update_attrdict([bitems[0]],
                                          {'linkinfo': {'stp': bitems[2]}})
            self._bridge_attrs_fill(bitems[0])

    def _bridge_attrs_fill(self, bridgename):
        battrs = {}
        bports = {}

        brout = utils.exec_command('%s showstp %s' % (utils.brctl_cmd, bridgename))
        chunks = re.split(r'\n\n', brout, maxsplit=0, flags=re.MULTILINE)

        try:
            # Get all bridge attributes
            broutlines = chunks[0].splitlines()
            # battrs['pathcost'] = broutlines[3].split('path cost')[1].strip()

            try:
                battrs['maxage'] = broutlines[4].split('bridge max age')[
                    1].strip().replace('.00', '')
            except:
                pass

            try:
                battrs['hello'] = broutlines[5].split('bridge hello time')[
                    1].strip().replace('.00', '')
            except:
                pass

            try:
                battrs['fd'] = broutlines[6].split('bridge forward delay')[
                    1].strip().replace('.00', '')
            except:
                pass

            try:
                battrs['ageing'] = broutlines[7].split('ageing time')[
                    1].strip().replace('.00', '')
            except:
                pass

            try:
                battrs['mcrouter'] = broutlines[12].split('mc router')[
                    1].strip().split('\t\t\t')[0]
            except:
                pass

            try:
                battrs['bridgeprio'] = self.read_file_oneline(
                    '/sys/class/net/%s/bridge/priority' % bridgename)
            except:
                pass

            try:
                battrs['vlan-protocol'] = VlanProtocols.ID_TO_ETHERTYPES[
                    self.read_file_oneline(
                        '/sys/class/net/%s/bridge/vlan_protocol' % bridgename)]
            except:
                pass

            try:
                battrs.update(self._bridge_get_mcattrs_from_sysfs(bridgename))
            except:
                pass

                # XXX: comment this out until mc attributes become available
                # with brctl again
                # battrs['hashel'] = broutlines[10].split('hash elasticity')[1].split()[0].strip()
                # battrs['hashmax'] = broutlines[10].split('hash max')[1].strip()
                # battrs['mclmc'] = broutlines[11].split('mc last member count')[1].split()[0].strip()
                # battrs['mciqc'] = broutlines[11].split('mc init query count')[1].strip()
                # battrs['mcrouter'] = broutlines[12].split('mc router')[1].split()[0].strip()
                ##battrs['mcsnoop'] = broutlines[12].split('mc snooping')[1].strip()
                # battrs['mclmt'] = broutlines[13].split('mc last member timer')[1].split()[0].strip()
        except Exception, e:
            self.logger.warn('%s: error while processing bridge attributes: %s' % (bridgename, str(e)))
            pass

        linkCache.update_attrdict([bridgename, 'linkinfo'], battrs)
        for cidx in range(1, len(chunks)):
            bpout = chunks[cidx].lstrip('\n')
            if not bpout or bpout[0] == ' ':
                continue
            bplines = bpout.splitlines()
            pname = bplines[0].split()[0]
            bportattrs = {}
            try:
                bportattrs['pathcost'] = bplines[2].split(
                    'path cost')[1].strip()
                bportattrs['fdelay'] = bplines[4].split(
                    'forward delay timer')[1].strip()
                bportattrs['portmcrouter'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/multicast_router' % pname)
                bportattrs['portmcfl'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/multicast_fast_leave' % pname)
                bportattrs['portprio'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/priority' % pname)
                bportattrs['unicast-flood'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/unicast_flood' % pname)
                bportattrs['multicast-flood'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/multicast_flood' % pname)
                bportattrs['learning'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/learning' % pname)
                bportattrs['arp-nd-suppress'] = self.read_file_oneline(
                    '/sys/class/net/%s/brport/neigh_suppress' % pname)
                # bportattrs['mcrouters'] = bplines[6].split('mc router')[1].split()[0].strip()
                # bportattrs['mc fast leave'] = bplines[6].split('mc fast leave')[1].strip()
            except Exception, e:
                self.logger.warn('%s: error while processing bridge attributes: %s' % (bridgename, str(e)))
            bports[pname] = bportattrs
            linkCache.update_attrdict([bridgename, 'linkinfo', 'ports'], bports)

    _bridge_sysfs_mcattrs = {
        'mclmc': 'multicast_last_member_count',
        'mcrouter': 'multicast_router',
        'mcsnoop': 'multicast_snooping',
        'mcsqc': 'multicast_startup_query_count',
        'mcqifaddr': 'multicast_query_use_ifaddr',
        'mcquerier': 'multicast_querier',
        'hashel': 'hash_elasticity',
        'hashmax': 'hash_max',
        'mclmi': 'multicast_last_member_interval',
        'mcmi': 'multicast_membership_interval',
        'mcqpi': 'multicast_querier_interval',
        'mcqi': 'multicast_query_interval',
        'mcqri': 'multicast_query_response_interval',
        'mcsqi': 'multicast_startup_query_interval',
        'igmp-version': 'multicast_igmp_version',
        'mld-version': 'multicast_mld_version',
        'vlan-stats': 'vlan_stats_enabled',
        'mcstats': 'multicast_stats_enabled',
    }

    def _bridge_get_mcattrs_from_sysfs(self, bridgename):
        mcattrsdivby100 = ['mclmi', 'mcmi', 'mcqpi', 'mcqi', 'mcqri', 'mcsqi']
        mcattrs = {}

        for m, s in self._bridge_sysfs_mcattrs.items():
            n = self.read_file_oneline('/sys/class/net/%s/bridge/%s' % (bridgename, s))
            if m in mcattrsdivby100:
                try:
                    v = int(n) / 100
                    mcattrs[m] = str(v)
                except Exception, e:
                    self.logger.warn('error getting mc attr %s (%s)' % (m, str(e)))
                    pass
            else:
                mcattrs[m] = n
        return mcattrs

    def _fill_bond_info(self, ifacename):
        bonding_masters = self.read_file_oneline('/sys/class/net/bonding_masters')
        if not bonding_masters:
            return

        bond_masters_list = bonding_masters.split()

        if ifacename:
            if ifacename in bond_masters_list:
                bond_masters_list = [ifacename]
            else:
                # we want to refresh this interface only if it's a bond master
                return

        for bondname in bond_masters_list:
            try:
                if bondname not in linkCache.links:
                    linkCache.set_attr([bondname], {'linkinfo': {}})
                linkCache.set_attr([bondname, 'linkinfo', 'slaves'],
                                   self.read_file_oneline('/sys/class/net/%s/bonding/slaves'
                                                          % bondname).split())
                try:
                    # if some attribute are missing we try to get the bond attributes via sysfs
                    bond_linkinfo = linkCache.links[bondname]['linkinfo']
                    for attr in [Link.IFLA_BOND_MODE, Link.IFLA_BOND_XMIT_HASH_POLICY, Link.IFLA_BOND_MIN_LINKS]:
                        if attr not in bond_linkinfo:
                            self._fill_bond_info_sysfs(bondname)
                            # after we fill in the cache we can continue to the next bond
                            break
                except:
                    self._fill_bond_info_sysfs(bondname)

            except Exception as e:
                self.logger.debug('LinkUtils: bond cache error: %s' % str(e))

    def _fill_bond_info_sysfs(self, bondname):
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_MIN_LINKS],
                               self.read_file_oneline(
                                   '/sys/class/net/%s/bonding/min_links'
                                   % bondname))
        except Exception as e:
            self.logger.debug(str(e))

        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_MODE],
                               self.read_file_oneline('/sys/class/net/%s/bonding/mode'
                                                      % bondname).split()[0])
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_XMIT_HASH_POLICY],
                               self.read_file_oneline(
                                   '/sys/class/net/%s/bonding/xmit_hash_policy'
                                   % bondname).split()[0])
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_RATE],
                               self.read_file_oneline('/sys/class/net/%s/bonding/lacp_rate'
                                                      % bondname).split()[1])
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYS_PRIO],
                               self.read_file_oneline('/sys/class/net/%s/bonding/ad_actor_sys_prio'
                                                      % bondname))
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYSTEM],
                               self.read_file_oneline('/sys/class/net/%s/bonding/ad_actor_system'
                                                      % bondname))
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_BYPASS],
                               self.read_file_oneline('/sys/class/net/%s/bonding/lacp_bypass'
                                                      % bondname).split()[1])
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_UPDELAY],
                               self.read_file_oneline('/sys/class/net/%s/bonding/updelay'
                                                      % bondname))
        except Exception as e:
            self.logger.debug(str(e))
        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_DOWNDELAY],
                               self.read_file_oneline('/sys/class/net/%s/bonding/downdelay'
                                                      % bondname))
        except Exception as e:
            self.logger.debug(str(e))

        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_USE_CARRIER],
                               self.read_file_oneline('/sys/class/net/%s/bonding/use_carrier' % bondname))
        except Exception as e:
            self.logger.debug(str(e))

        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_MIIMON],
                               self.read_file_oneline('/sys/class/net/%s/bonding/miimon' % bondname))
        except Exception as e:
            self.logger.debug(str(e))

        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF],
                               self.read_file_oneline('/sys/class/net/%s/bonding/num_unsol_na' % bondname))
        except Exception as e:
            self.logger.debug(str(e))

        try:
            linkCache.set_attr([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF],
                               self.read_file_oneline('/sys/class/net/%s/bonding/num_grat_arp' % bondname))
        except Exception as e:
            self.logger.debug(str(e))


    def _link_fill_iproute2_cmd(self, ifacename=None, refresh=False):
        warn = True
        linkout = {}
        if LinkUtils._CACHE_FILL_DONE and not refresh:
            return
        try:
            # if ifacename already present, return
            if (ifacename and not refresh and
                    linkCache.get_attr([ifacename, 'ifflag'])):
                return
        except:
            pass
        cmdout = self.link_show(ifacename=ifacename)
        if not cmdout:
            return
        for c in cmdout.splitlines():
            citems = c.split()
            ifnamenlink = citems[1].split('@')
            if len(ifnamenlink) > 1:
                ifname = ifnamenlink[0]
                iflink = ifnamenlink[1].strip(':')
            else:
                ifname = ifnamenlink[0].strip(':')
                iflink = None
            linkattrs = dict()
            linkattrs['link'] = iflink
            linkattrs['ifindex'] = citems[0].strip(':')
            flags = citems[2].strip('<>').split(',')
            linkattrs['flags'] = flags
            linkattrs['ifflag'] = 'UP' if 'UP' in flags else 'DOWN'
            for i in range(0, len(citems)):
                try:
                    if citems[i] == 'mtu':
                        linkattrs['mtu'] = citems[i + 1]
                    elif citems[i] == 'state':
                        linkattrs['state'] = citems[i + 1]
                    elif citems[i] == 'link/ether':
                        linkattrs['hwaddress'] = citems[i + 1]
                    elif citems[i] == 'vlan':
                        vlanid = self._get_vland_id(citems, i, warn)
                        if vlanid:
                            linkattrs['linkinfo'] = {'vlanid': vlanid}
                            linkattrs['kind'] = 'vlan'
                    elif citems[i] == 'dummy':
                        linkattrs['kind'] = 'dummy'
                    elif citems[i] == 'vxlan' and citems[i + 1] == 'id':
                        linkattrs['kind'] = 'vxlan'
                        vattrs = {'vxlanid': citems[i + 2],
                                  'svcnode': None,
                                  'remote': [],
                                  'ageing': citems[i + 2],
                                  'learning': 'on'}
                        for j in range(i + 2, len(citems)):
                            if citems[j] == 'local':
                                vattrs['local'] = citems[j + 1]
                            elif citems[j] == 'remote':
                                vattrs['svcnode'] = citems[j + 1]
                            elif citems[j] == 'ageing':
                                vattrs['ageing'] = citems[j + 1]
                            elif citems[j] == 'nolearning':
                                vattrs['learning'] = 'off'
                            elif citems[j] == 'dev':
                                vattrs['physdev'] = citems[j + 1]
                        linkattrs['linkinfo'] = vattrs
                        break
                    elif citems[i] == 'vrf' and citems[i + 1] == 'table':
                        vattrs = {'table': citems[i + 2]}
                        linkattrs['linkinfo'] = vattrs
                        linkattrs['kind'] = 'vrf'
                        linkCache.vrfs[ifname] = vattrs
                        break
                    elif citems[i] == 'veth':
                        linkattrs['kind'] = 'veth'
                    elif citems[i] == 'vrf_slave':
                        linkattrs['slave_kind'] = 'vrf_slave'
                        break
                    elif citems[i] == 'macvlan' and citems[i + 1] == 'mode':
                        linkattrs['kind'] = 'macvlan'
                except Exception as e:
                    if warn:
                        self.logger.debug('%s: parsing error: id, mtu, state, '
                                          'link/ether, vlan, dummy, vxlan, local, '
                                          'remote, ageing, nolearning, vrf, table, '
                                          'vrf_slave are reserved keywords: %s' %
                                          (ifname, str(e)))
                        warn = False
            # linkattrs['alias'] = self.read_file_oneline(
            #            '/sys/class/net/%s/ifalias' %ifname)
            linkout[ifname] = linkattrs
        [linkCache.update_attrdict([ifname], linkattrs)
         for ifname, linkattrs in linkout.items()]

    @staticmethod
    def _addr_filter(ifname, addr, scope=None):
        default_addrs = ['127.0.0.1/8', '::1/128', '0.0.0.0']
        if ifname == 'lo' and addr in default_addrs:
            return True
        if scope and scope == 'link':
            return True
        return False

    def _addr_fill(self, ifacename=None, refresh=False):
        """ fills cache with address information

        if ifacename argument given, fill cache for ifacename, else
        fill cache for all interfaces in the system
        """
        if LinkUtils._CACHE_FILL_DONE and not refresh:
            return
        try:
            # Check if ifacename is already full, in which case, return
            if ifacename and not refresh:
                linkCache.get_attr([ifacename, 'addrs'])
                return
        except:
            pass

        if True:
            try:
                pass
                #[linkCache.update_attrdict([ifname], linkattrs)
                # for ifname, linkattrs in netlink.addr_dump(ifname=ifacename).items()]
            except Exception as e:
                self.logger.info(str(e))

                # this netlink call replaces the call to _addr_fill_iproute2_cmd()
                # We shouldn't have netlink calls in the iproute2 module, this will
                # be removed in the future. We plan to release, a flexible backend
                # (netlink+iproute2) by default we will use netlink backend but with
                # a CLI arg we can switch to iproute2 backend.
                # Until we decide to create this "backend" switch capability,
                # we have to put the netlink call inside the iproute2 module.

        else:
            self._addr_fill_iproute2_cmd(ifacename, refresh)

    def _addr_fill_iproute2_cmd(self, ifacename=None, refresh=False):
        """ fills cache with address information

        if ifacename argument given, fill cache for ifacename, else
        fill cache for all interfaces in the system
        """
        linkout = {}
        if LinkUtils._CACHE_FILL_DONE and not refresh:
            return
        try:
            # Check if ifacename is already full, in which case, return
            if ifacename and not refresh:
                linkCache.get_attr([ifacename, 'addrs'])
                return
        except:
            pass
        cmdout = self.addr_show(ifacename=ifacename)
        if not cmdout:
            return
        for c in cmdout.splitlines():
            citems = c.split()
            ifnamenlink = citems[1].split('@')
            if len(ifnamenlink) > 1:
                ifname = ifnamenlink[0]
            else:
                ifname = ifnamenlink[0].strip(':')
            if not linkout.get(ifname):
                linkattrs = dict()
                linkattrs['addrs'] = OrderedDict({})
                try:
                    linkout[ifname].update(linkattrs)
                except KeyError:
                    linkout[ifname] = linkattrs
            if citems[2] == 'inet':
                if self._addr_filter(ifname, citems[3], scope=citems[5]):
                    continue
                addrattrs = dict()
                addrattrs['scope'] = citems[5]
                addrattrs['type'] = 'inet'
                linkout[ifname]['addrs'][citems[3]] = addrattrs
            elif citems[2] == 'inet6':
                if self._addr_filter(ifname, citems[3], scope=citems[5]):
                    continue
                if citems[5] == 'link':
                    continue  # skip 'link' addresses
                addrattrs = dict()
                addrattrs['scope'] = citems[5]
                addrattrs['type'] = 'inet6'
                linkout[ifname]['addrs'][citems[3]] = addrattrs
        [linkCache.update_attrdict([ifname], linkattrs)
         for ifname, linkattrs in linkout.items()]

    def del_cache_entry(self, ifname):
        try:
            del linkCache.links[ifname]
        except:
            pass

    def cache_get(self, t, attrlist, refresh=False):
        return self._cache_get(t, attrlist, refresh)

    def _cache_get(self, t, attrlist, refresh=False):
        try:
            if ifupdownflags.flags.DRYRUN:
                return False
            if ifupdownflags.flags.CACHE:
                if self._fill_cache():
                    # if we filled the cache, return new data
                    return linkCache.get_attr(attrlist)
                if not refresh:
                    return linkCache.get_attr(attrlist)
            if t == 'link':
                self._link_fill(attrlist[0], refresh)
            elif t == 'addr':
                self._addr_fill(attrlist[0], refresh)
            else:
                self._link_fill(attrlist[0], refresh)
                self._addr_fill(attrlist[0], refresh)
            return linkCache.get_attr(attrlist)
        except Exception, e:
            self.logger.debug('_cache_get(%s) : [%s]' % (str(attrlist), str(e)))
        return None

    def cache_check(self, attrlist, value, refresh=False):
        return self._cache_check('link', attrlist, value, refresh=refresh)

    def _cache_check(self, t, attrlist, value, refresh=False):
        try:
            return self._cache_get(t, attrlist, refresh) == value
        except Exception, e:
            self.logger.debug('_cache_check(%s) : [%s]'
                              % (str(attrlist), str(e)))
        return False

    def cache_update(self, attrlist, value):
        return self._cache_update(attrlist, value)

    @staticmethod
    def _cache_update(attrlist, value):
        if ifupdownflags.flags.DRYRUN:
            return
        try:
            if attrlist[-1] == 'slaves':
                linkCache.append_to_attrlist(attrlist, value)
                return
            linkCache.set_attr(attrlist, value)
        except:
            pass

    @staticmethod
    def _cache_delete(attrlist, value=None):
        if ifupdownflags.flags.DRYRUN:
            return
        try:
            if value:
                linkCache.remove_from_attrlist(attrlist, value)
            else:
                linkCache.del_attr(attrlist)
        except:
            pass

    @staticmethod
    def _cache_invalidate():
        linkCache.invalidate()
        LinkUtils._CACHE_FILL_DONE = False

    @staticmethod
    def batch_start():
        LinkUtils.ipbatcbuf = ''
        LinkUtils.ipbatch = True
        LinkUtils.ipbatch_pause = False

    @staticmethod
    def add_to_batch(cmd):
        LinkUtils.ipbatchbuf += cmd + '\n'

    @staticmethod
    def batch_pause():
        LinkUtils.ipbatch_pause = True

    @staticmethod
    def batch_resume():
        LinkUtils.ipbatch_pause = False

    def batch_commit(self):
        if not LinkUtils.ipbatchbuf:
            LinkUtils.ipbatchbuf = ''
            LinkUtils.ipbatch = False
            LinkUtils.ipbatch_pause = False
            return
        try:
            utils.exec_command('%s -force -batch -' % utils.ip_cmd,
                               stdin=self.ipbatchbuf)
        except:
            raise
        finally:
            LinkUtils.ipbatchbuf = ''
            LinkUtils.ipbatch = False
            LinkUtils.ipbatch_pause = False

    def bridge_batch_commit(self):
        if not LinkUtils.ipbatchbuf:
            LinkUtils.ipbatchbuf = ''
            LinkUtils.ipbatch = False
            LinkUtils.ipbatch_pause = False
            return
        try:
            utils.exec_command('%s -force -batch -'
                               % utils.bridge_cmd, stdin=self.ipbatchbuf)
        except:
            raise
        finally:
            LinkUtils.ipbatchbuf = ''
            LinkUtils.ipbatch = False
            LinkUtils.ipbatch_pause = False

    def addr_show(self, ifacename=None):
        if ifacename:
            if not self.link_exists(ifacename):
                return
            return utils.exec_commandl([utils.ip_cmd,
                                        '-o', 'addr', 'show', 'dev', ifacename])
        else:
            return utils.exec_commandl([utils.ip_cmd,
                                        '-o', 'addr', 'show'])

    @staticmethod
    def link_show(ifacename=None):
        if ifacename:
            return utils.exec_commandl([utils.ip_cmd,
                                        '-o', '-d', 'link', 'show', 'dev', ifacename])
        else:
            return utils.exec_commandl([utils.ip_cmd,
                                        '-o', '-d', 'link', 'show'])

    def addr_add(self, ifacename, address, broadcast=None,
                 peer=None, scope=None, preferred_lifetime=None, metric=None):
        if not address:
            return
        cmd = 'addr add %s' % address
        if broadcast:
            cmd += ' broadcast %s' % broadcast
        if peer:
            cmd += ' peer %s' % peer
        if scope:
            cmd += ' scope %s' % scope
        if preferred_lifetime:
            cmd += ' preferred_lft %s' % preferred_lifetime
        cmd += ' dev %s' % ifacename

        if metric:
            cmd += ' metric %s' % metric

        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
            attrs = {}
            try:
                addr_obj = IPNetwork(address)
                if isinstance(addr_obj, IPv6Network):
                    attrs['family'] = 'inet6'
                else:
                    attrs['family'] = 'inet'
            except:
                attrs['family'] = 'inet'

            self._cache_update([ifacename, 'addrs', address], attrs)

    def addr_del(self, ifacename, address, broadcast=None,
                 peer=None, scope=None):
        """ Delete ipv4 address """
        if not address:
            return
        if not self._cache_get('addr', [ifacename, 'addrs', address]):
            return
        cmd = 'addr del %s' % address
        if broadcast:
            cmd += 'broadcast %s' % broadcast
        if peer:
            cmd += 'peer %s' % peer
        if scope:
            cmd += 'scope %s' % scope
        cmd += ' dev %s' % ifacename
        utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_delete([ifacename, 'addrs', address])

    def addr_flush(self, ifacename):
        cmd = 'addr flush dev %s' % ifacename
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_delete([ifacename, 'addrs'])

    def _link_set_ifflag(self, ifacename, value):
        # Dont look at the cache, the cache may have stale value
        # because link status can be changed by external
        # entity (One such entity is ifupdown main program)
        cmd = 'link set dev %s %s' % (ifacename, value.lower())
        if LinkUtils.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))

    def link_up(self, ifacename):
        self._link_set_ifflag(ifacename, 'UP')

    def link_down(self, ifacename):
        self._link_set_ifflag(ifacename, 'DOWN')

    def link_set(self, ifacename, key, value=None,
                 force=False, t=None, state=None):
        if not force:
            if (key not in ['master', 'nomaster'] and
                    self._cache_check('link', [ifacename, key], value)):
                return
        cmd = 'link set dev %s' % ifacename
        if t:
            cmd += ' type %s' % t
        cmd += ' %s' % key
        if value:
            cmd += ' %s' % value
        if state:
            cmd += ' %s' % state
        if LinkUtils.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        if key not in ['master', 'nomaster']:
            self._cache_update([ifacename, key], value)

    def link_set_hwaddress(self, ifacename, hwaddress, force=False):
        if not force:
            if self._cache_check('link', [ifacename, 'hwaddress'], hwaddress):
                return
        self.link_down(ifacename)
        cmd = 'link set dev %s address %s' % (ifacename, hwaddress)
        if LinkUtils.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self.link_up(ifacename)
        self._cache_update([ifacename, 'hwaddress'], hwaddress)

    def link_isloopback(self, ifacename):
        flags = self._cache_get('link', [ifacename, 'flags'])
        if not flags:
            return
        if 'LOOPBACK' in flags:
            return True
        return False

    def link_get_status(self, ifacename):
        return self._cache_get('link', [ifacename, 'ifflag'], refresh=True)

    def link_create_vlan(self, vlan_device_name, vlan_raw_device, vlanid):
        if self.link_exists(vlan_device_name):
            return
        utils.exec_command('%s link add link %s name %s type vlan id %d' %
                           (utils.ip_cmd,
                            vlan_raw_device, vlan_device_name, vlanid))
        self._cache_update([vlan_device_name], {})

    def link_create_vlan_from_name(self, vlan_device_name):
        v = vlan_device_name.split('.')
        if len(v) != 2:
            self.logger.warn('invalid vlan device name %s' % vlan_device_name)
            return
        self.link_create_vlan(vlan_device_name, v[0], v[1])

    def link_create_macvlan(self, name, linkdev, mode='private'):
        if self.link_exists(name):
            return
        cmd = ('link add link %s' % linkdev +
               ' name %s' % name +
               ' type macvlan mode %s' % mode)
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_update([name], {})

    @staticmethod
    def link_exists(ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return os.path.exists('/sys/class/net/%s' % ifacename)

    @staticmethod
    def link_exists_nodryrun(ifname):
        return os.path.exists('/sys/class/net/%s' % ifname)

    def link_get_ifindex(self, ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return self.read_file_oneline('/sys/class/net/%s/ifindex' % ifacename)

    def is_vlan_device_by_name(self, ifacename):
        if re.search(r'\.', ifacename):
            return True
        return False

    @staticmethod
    def route_add(route):
        utils.exec_command('%s route add %s' % (utils.ip_cmd,
                                                route))

    @staticmethod
    def route6_add(route):
        utils.exec_command('%s -6 route add %s' % (utils.ip_cmd,
                                                   route))

    def get_vlandev_attrs(self, ifacename):
        return (self._cache_get('link', [ifacename, 'link']),
                self._cache_get('link', [ifacename, 'linkinfo', 'vlanid']),
                self._cache_get('link', [ifacename, 'linkinfo', 'vlan_protocol']))

    def get_vlan_protocol(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo', 'vlan_protocol'])

    def get_vxlandev_attrs(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo'])

    def get_vxlandev_learning(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo', Link.IFLA_VXLAN_LEARNING])

    def set_vxlandev_learning(self, ifacename, learn):
        if learn == 'on':
            utils.exec_command('%s link set dev %s type vxlan learning' %
                               (utils.ip_cmd, ifacename))
            self._cache_update([ifacename, 'linkinfo', 'learning'], 'on')
        else:
            utils.exec_command('%s link set dev %s type vxlan nolearning' %
                               (utils.ip_cmd, ifacename))
            self._cache_update([ifacename, 'linkinfo', 'learning'], 'off')

    def link_get_linkinfo_attrs(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo'])

    def link_get_mtu(self, ifacename, refresh=False):
        return self._cache_get('link', [ifacename, 'mtu'], refresh=refresh)

    def link_get_mtu_sysfs(self, ifacename):
        return self.read_file_oneline('/sys/class/net/%s/mtu'
                                      % ifacename)

    def link_get_kind(self, ifacename):
        return self._cache_get('link', [ifacename, 'kind'])

    def link_get_slave_kind(self, ifacename):
        return self._cache_get('link', [ifacename, 'slave_kind'])

    def link_get_hwaddress(self, ifacename):
        address = self._cache_get('link', [ifacename, 'hwaddress'])
        # newly created logical interface addresses dont end up in the cache
        # read hwaddress from sysfs file for these interfaces
        if not address:
            address = self.read_file_oneline('/sys/class/net/%s/address'
                                             % ifacename)
        return address

    def link_create(self, ifacename, t, attrs={}):
        """ generic link_create function """
        if self.link_exists(ifacename):
            return
        cmd = 'link add'
        cmd += ' name %s type %s' % (ifacename, t)
        if attrs:
            for k, v in attrs.iteritems():
                cmd += ' %s' % k
                if v:
                    cmd += ' %s' % v
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_update([ifacename], {})

    def link_delete(self, ifacename):
        if not self.link_exists(ifacename):
            return
        cmd = 'link del %s' % ifacename
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_invalidate()

    def link_get_master(self, ifacename):
        sysfs_master_path = '/sys/class/net/%s/master' % ifacename
        if os.path.exists(sysfs_master_path):
            link_path = os.readlink(sysfs_master_path)
            if link_path:
                return os.path.basename(link_path)
            else:
                return None
        else:
            return self._cache_get('link', [ifacename, 'master'])

    def get_brport_peer_link(self, bridgename):
        try:
            return self._cache_get('link', [bridgename, 'info_slave_data', Link.IFLA_BRPORT_PEER_LINK])
        except:
            return None

    @staticmethod
    def bridge_port_vids_flush(bridgeportname, vid):
        utils.exec_command('%s vlan del vid %s dev %s' %
                           (utils.bridge_cmd,
                            vid, bridgeportname))

    def bridge_is_vlan_aware(self, bridgename):
        filename = '/sys/class/net/%s/bridge/vlan_filtering' % bridgename
        if os.path.exists(filename) and self.read_file_oneline(filename) == '1':
            return True
        return False

    @staticmethod
    def bridge_port_get_bridge_name(bridgeport):
        filename = '/sys/class/net/%s/brport/bridge' % bridgeport
        try:
            return os.path.basename(os.readlink(filename))
        except:
            return None

    @staticmethod
    def bridge_port_exists(bridge, bridgeportname):
        try:
            return os.path.exists('/sys/class/net/%s/brif/%s'
                                  % (bridge, bridgeportname))
        except Exception:
            return False

    @staticmethod
    def is_bridge(bridge):
        return os.path.exists('/sys/class/net/%s/bridge' % bridge)

    def is_link_up(self, ifacename):
        ret = False
        try:
            flags = self.read_file_oneline('/sys/class/net/%s/flags' % ifacename)
            iflags = int(flags, 16)
            if iflags & 0x0001:
                ret = True
        except:
            ret = False
        return ret

    def link_get_vrfs(self):
        if not LinkUtils._CACHE_FILL_DONE:
            self._fill_cache()
        return linkCache.vrfs

    @staticmethod
    def cache_get_info_slave(attrlist):
        try:
            return linkCache.get_attr(attrlist)
        except:
            return None

    def get_brport_learning(self, ifacename):
        learn = self.read_file_oneline('/sys/class/net/%s/brport/learning'
                                       % ifacename)
        if learn and learn == '1':
            return 'on'
        else:
            return 'off'

    def get_brport_learning_bool(self, ifacename):
        return utils.get_boolean_from_string(self.read_file_oneline('/sys/class/net/%s/brport/learning' % ifacename))

    def set_brport_learning(self, ifacename, learn):
        if learn == 'off':
            return self.write_file('/sys/class/net/%s/brport/learning'
                                   % ifacename, '0')
        else:
            return self.write_file('/sys/class/net/%s/brport/learning'
                                   % ifacename, '1')

    #################################################################################
    ################################### BOND UTILS ##################################
    #################################################################################

    def _link_cache_get(self, attrlist, refresh=False):
        return self._cache_get('link', attrlist, refresh)

    def cache_delete(self, attrlist, value=None):
        return self._cache_delete(attrlist, value)

    def link_cache_get(self, attrlist, refresh=False):
        return self._link_cache_get(attrlist, refresh)

    def link_cache_check(self, attrlist, value, refresh=False):
        return self._link_cache_check(attrlist, value, refresh)

    def _link_cache_check(self, attrlist, value, refresh=False):
        try:
            return self._link_cache_get(attrlist, refresh) == value
        except Exception, e:
            self.logger.debug('_cache_check(%s) : [%s]'
                              % (str(attrlist), str(e)))
            pass
        return False

    #################################################################################
    ################################## BRIDGE UTILS #################################
    #################################################################################

    def create_bridge(self, bridgename):
        if not LinkUtils.bridge_utils_is_installed:
            return
        if self.bridge_exists(bridgename):
            return
        utils.exec_command('%s addbr %s' % (utils.brctl_cmd, bridgename))
        self._cache_update([bridgename], {})

    def delete_bridge(self, bridgename):
        if not LinkUtils.bridge_utils_is_installed:
            return
        if not self.bridge_exists(bridgename):
            return
        utils.exec_command('%s delbr %s' % (utils.brctl_cmd, bridgename))
        self._cache_invalidate()

    def add_bridge_port(self, bridgename, bridgeportname):
        """ Add port to bridge """
        if not LinkUtils.bridge_utils_is_installed:
            return
        ports = self._link_cache_get([bridgename, 'linkinfo', 'ports'])
        if ports and ports.get(bridgeportname):
            return
        utils.exec_command('%s addif %s %s' % (utils.brctl_cmd, bridgename, bridgeportname))
        self._cache_update([bridgename, 'linkinfo', 'ports', bridgeportname], {})

    def delete_bridge_port(self, bridgename, bridgeportname):
        """ Delete port from bridge """
        if not LinkUtils.bridge_utils_is_installed:
            return
        ports = self._link_cache_get([bridgename, 'linkinfo', 'ports'])
        if not ports or not ports.get(bridgeportname):
            return
        utils.exec_command('%s delif %s %s' % (utils.brctl_cmd, bridgename, bridgeportname))
        self._cache_delete([bridgename, 'linkinfo', 'ports', 'bridgeportname'])

    def set_bridgeport_attrs(self, bridgename, bridgeportname, attrdict):
        portattrs = self._link_cache_get([bridgename, 'linkinfo', 'ports', bridgeportname])
        if portattrs == None:
            portattrs = {}
        for k, v in attrdict.iteritems():
            if ifupdownflags.flags.CACHE:
                curval = portattrs.get(k)
                if curval and curval == v:
                    continue
            if k == 'unicast-flood':
                self.write_file('/sys/class/net/%s/brport/unicast_flood' % bridgeportname, v)
            elif k == 'multicast-flood':
                self.write_file('/sys/class/net/%s/brport/multicast_flood' % bridgeportname, v)
            elif k == 'learning':
                self.write_file('/sys/class/net/%s/brport/learning' % bridgeportname, v)
            elif k == 'arp-nd-suppress':
                self.write_file('/sys/class/net/%s/brport/neigh_suppress' % bridgeportname, v)
            else:
                if not LinkUtils.bridge_utils_is_installed:
                    continue
                utils.exec_command('%s set%s %s %s %s' % (utils.brctl_cmd, k, bridgename, bridgeportname, v))

    def set_bridgeport_attr(self, bridgename, bridgeportname,
                            attrname, attrval):
        if not LinkUtils.bridge_utils_is_installed:
            return
        if self._link_cache_check([bridgename, 'linkinfo', 'ports', bridgeportname, attrname], attrval):
            return
        utils.exec_command('%s set%s %s %s %s' %
                           (utils.brctl_cmd,
                            attrname,
                            bridgename,
                            bridgeportname,
                            attrval))

    def set_bridge_attrs(self, bridgename, attrdict):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            if self._link_cache_check([bridgename, 'linkinfo', k], v):
                continue
            try:
                if k == 'igmp-version':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_igmp_version' % bridgename, v)
                elif k == 'mld-version':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_mld_version' % bridgename, v)
                elif k == 'vlan-protocol':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'vlan_protocol' % bridgename,
                                    VlanProtocols.ETHERTYPES_TO_ID.get(v.upper(),
                                                                       None))
                elif k == 'vlan-stats':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'vlan_stats_enabled' % bridgename, v)
                elif k == 'mcstats':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_stats_enabled' % bridgename, v)
                else:
                    if not LinkUtils.bridge_utils_is_installed:
                        continue
                    cmd = ('%s set%s %s %s' %
                           (utils.brctl_cmd, k, bridgename, v))
                    utils.exec_command(cmd)
            except Exception, e:
                self.logger.warn('%s: %s' % (bridgename, str(e)))
                pass

    def set_bridge_attr(self, bridgename, attrname, attrval):
        if self._link_cache_check([bridgename, 'linkinfo', attrname], attrval):
            return
        if attrname == 'igmp-version':
            self.write_file('/sys/class/net/%s/bridge/multicast_igmp_version'
                            % bridgename, attrval)
        elif attrname == 'mld-version':
            self.write_file('/sys/class/net/%s/bridge/multicast_mld_version'
                            % bridgename, attrval)
        elif attrname == 'vlan-protocol':
            self.write_file('/sys/class/net/%s/bridge/vlan_protocol'
                            % bridgename, VlanProtocols.ETHERTYPES_TO_ID[attrval.upper()])
        elif attrname == 'vlan-stats':
            self.write_file('/sys/class/net/%s/bridge/vlan_stats_enabled'
                            % bridgename, attrval)
        elif attrname == 'mcstats':
            self.write_file('/sys/class/net/%s/bridge/multicast_stats_enabled'
                            % bridgename, attrval)
        else:
            if not LinkUtils.bridge_utils_is_installed:
                return
            cmd = '%s set%s %s %s' % (utils.brctl_cmd,
                                      attrname, bridgename, attrval)
            utils.exec_command(cmd)

    def get_bridge_attrs(self, bridgename):
        attrs = self._link_cache_get([bridgename, 'linkinfo'])
        no_ints_attrs = {}
        for key, value in attrs.items():
            if type(key) == str:
                no_ints_attrs[key] = value
        return no_ints_attrs

    def get_bridgeport_attrs(self, bridgename, bridgeportname):
        return self._link_cache_get([bridgename, 'linkinfo', 'ports',
                                     bridgeportname])

    def get_bridgeport_attr(self, bridgename, bridgeportname, attrname):
        return self._link_cache_get([bridgename, 'linkinfo', 'ports',
                                     bridgeportname, attrname])

    @staticmethod
    def _conv_value_to_user(s):
        try:
            ret = int(s) / 100
            return '%d' % ret
        except:
            return None

    def read_value_from_sysfs(self, filename, preprocess_func):
        value = self.read_file_oneline(filename)
        if not value:
            return None
        return preprocess_func(value)

    @staticmethod
    def bridge_set_ageing(bridge, ageing):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setageing %s %s' % (utils.brctl_cmd, bridge, ageing))

    def bridge_get_ageing(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/ageing_time'
                                          % bridge, self._conv_value_to_user)

    @staticmethod
    def set_bridgeprio(bridge, prio):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setbridgeprio %s %s' % (utils.brctl_cmd, bridge, prio))

    def get_bridgeprio(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/priority' % bridge)

    @staticmethod
    def bridge_set_fd(bridge, fd):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setfd %s %s' % (utils.brctl_cmd, bridge, fd))

    def bridge_get_fd(self, bridge):
        return self.read_value_from_sysfs(
            '/sys/class/net/%s/bridge/forward_delay'
            % bridge, self._conv_value_to_user)

    def bridge_set_gcint(self, bridge, gcint):
        raise Exception('set_gcint not implemented')

    @staticmethod
    def bridge_set_hello(bridge, hello):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s sethello %s %s' % (utils.brctl_cmd, bridge, hello))

    def bridge_get_hello(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/hello_time'
                                          % bridge, self._conv_value_to_user)

    @staticmethod
    def bridge_set_maxage(bridge, maxage):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmaxage %s %s' % (utils.brctl_cmd, bridge, maxage))

    def bridge_get_maxage(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/max_age'
                                          % bridge, self._conv_value_to_user)

    @staticmethod
    def bridge_set_pathcost(bridge, port, pathcost):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setpathcost %s %s %s' % (utils.brctl_cmd, bridge, port, pathcost))

    @staticmethod
    def bridge_set_portprio(bridge, port, prio):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setportprio %s %s %s' % (utils.brctl_cmd, bridge, port, prio))

    @staticmethod
    def bridge_set_hashmax(bridge, hashmax):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s sethashmax %s %s' % (utils.brctl_cmd, bridge, hashmax))

    def bridge_get_hashmax(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_max'
                                      % bridge)

    @staticmethod
    def bridge_set_hashel(bridge, hashel):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s sethashel %s %s' % (utils.brctl_cmd, bridge, hashel))

    def bridge_get_hashel(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_elasticity'
                                      % bridge)

    @staticmethod
    def bridge_set_mclmc(bridge, mclmc):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmclmc %s %s' % (utils.brctl_cmd, bridge, mclmc))

    def bridge_get_mclmc(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_last_member_count'
            % bridge)

    @staticmethod
    def bridge_set_mcrouter(bridge, mcrouter):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcrouter %s %s' % (utils.brctl_cmd, bridge, mcrouter))

    def bridge_get_mcrouter(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_router' % bridge)

    @staticmethod
    def bridge_set_mcsnoop(bridge, mcsnoop):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcsnoop %s %s' % (utils.brctl_cmd, bridge, mcsnoop))

    def bridge_get_mcsnoop(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_snooping' % bridge)

    @staticmethod
    def bridge_set_mcsqc(bridge, mcsqc):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcsqc %s %s' % (utils.brctl_cmd, bridge, mcsqc))

    def bridge_get_mcsqc(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_startup_query_count'
            % bridge)

    @staticmethod
    def bridge_set_mcqifaddr(bridge, mcqifaddr):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcqifaddr %s %s' % (utils.brctl_cmd, bridge, mcqifaddr))

    def bridge_get_mcqifaddr(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_startup_query_use_ifaddr'
            % bridge)

    @staticmethod
    def bridge_set_mcquerier(bridge, mcquerier):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcquerier %s %s' % (utils.brctl_cmd, bridge, mcquerier))

    def bridge_get_mcquerier(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_querier' % bridge)

    @staticmethod
    def bridge_set_mclmi(bridge, mclmi):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmclmi %s %s' % (utils.brctl_cmd, bridge, mclmi))

    def bridge_get_mclmi(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_last_member_interval'
            % bridge)

    @staticmethod
    def bridge_set_mcmi(bridge, mcmi):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setmcmi %s %s' % (utils.brctl_cmd, bridge, mcmi))

    def bridge_get_mcmi(self, bridge):
        return self.read_file_oneline(
            '/sys/class/net/%s/bridge/multicast_membership_interval'
            % bridge)

    @staticmethod
    def bridge_exists(bridge):
        return os.path.exists('/sys/class/net/%s/bridge' % bridge)

    @staticmethod
    def is_bridge_port(ifacename):
        return os.path.exists('/sys/class/net/%s/brport' % ifacename)

    @staticmethod
    def bridge_port_exists(bridge, bridgeportname):
        try:
            return os.path.exists('/sys/class/net/%s/brif/%s' % (bridge, bridgeportname))
        except:
            return False

    @staticmethod
    def get_bridge_ports(bridgename):
        try:
            return os.listdir('/sys/class/net/%s/brif/' % bridgename)
        except:
            return []
