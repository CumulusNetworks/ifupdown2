#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#         Julien Fortin, julien@cumulusnetworks.com
#

try:
    import os
    import re
    import json
    import glob
    import shlex
    import signal
    import subprocess

    from ipaddr import IPNetwork, IPv6Network

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.statemanager as statemanager

    from ifupdownaddons.utilsbase import utilsBase
    from ifupdownaddons.cache import linkCache, MSTPAttrsCache
    from ifupdown.netlink import netlink
    from ifupdown.utils import utils
    from ifupdown.iface import *

    from collections import OrderedDict

    from nlmanager.nlmanager import Link, Route
except ImportError, e:
    raise ImportError('%s - required module not found' % str(e))


class LinkUtils(utilsBase):
    """
    This class contains helper methods to cache and manipulate interfaces through
    non-netlink APIs (sysfs, iproute2, brctl...)
    """
    _CACHE_FILL_DONE = False
    VXLAN_UDP_PORT = 4789

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
                [linkCache.update_attrdict([ifname], linkattrs)
                 for ifname, linkattrs in netlink.link_dump(ifacename).items()]
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
                    'arp-nd-suppress': str(info_slave_data.get(Link.IFLA_BRPORT_ARP_SUPPRESS, 0))
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
                        linkattrs['linkinfo'] = vattrs
                        break
                    elif citems[i] == 'vrf' and citems[i + 1] == 'table':
                        vattrs = {'table': citems[i + 2]}
                        linkattrs['linkinfo'] = vattrs
                        linkattrs['kind'] = 'vrf'
                        linkCache.vrfs[ifname] = vattrs
                        break
                    elif citems[i] == 'vrf_slave':
                        linkattrs['kind'] = 'vrf_slave'
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
                [linkCache.update_attrdict([ifname], linkattrs)
                 for ifname, linkattrs in netlink.addr_dump(ifname=ifacename).items()]
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
                 peer=None, scope=None, preferred_lifetime=None):
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
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))
        self._cache_update([ifacename, 'addrs', address], {})

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

    def del_addr_all(self, ifacename, skip_addrs=[]):
        if not skip_addrs:
            skip_addrs = []
        runningaddrsdict = self.get_running_addrs(ifname=ifacename)
        try:
            # XXX: ignore errors. Fix this to delete secondary addresses
            # first
            [self.addr_del(ifacename, a) for a in
             set(runningaddrsdict.keys()).difference(skip_addrs)]
        except:
            # ignore errors
            pass

    def addr_get(self, ifacename, details=True, refresh=False):
        addrs = self._cache_get('addr', [ifacename, 'addrs'], refresh=refresh)
        if not addrs:
            return None
        if details:
            return addrs
        return addrs.keys()

    def get_running_addrs(self, ifaceobj=None, ifname=None, details=True):
        """
            We now support addr with link scope. Since the kernel may add it's
            own link address to some interfaces we need to filter them out and
            make sure we only deal with the addresses set by ifupdown2.

            To do so we look at the previous configuration made by ifupdown2
            (with the help of the statemanager) together with the addresses
            specified by the user in /etc/network/interfaces, these addresses
            are then compared to the running state of the intf (ip addr show)
            made via a netlink addr dump.
            For each configured addresses of scope link, we check if it was
            previously configured by ifupdown2 to create a final set of the
            addresses watched by ifupdown2
        """
        if not ifaceobj and not ifname:
            return None

        config_addrs = set()

        if ifaceobj:
            for addr in ifaceobj.get_attr_value('address') or []:
                config_addrs.add(addr)

            interface_name = ifaceobj.name
        else:
            interface_name = ifname

        saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(interface_name)
        for saved_ifaceobj in saved_ifaceobjs or []:
            for addr in saved_ifaceobj.get_attr_value('address') or []:
                config_addrs.add(addr)

        running_addrs = OrderedDict()
        cached_addrs = self.addr_get(interface_name)
        if cached_addrs:
            for addr, addr_details in cached_addrs.items():
                try:
                    scope = int(addr_details['scope'])
                except Exception:
                    try:
                        details = {}
                        addr_obj = IPNetwork(addr)
                        if isinstance(addr_obj, IPv6Network):
                            details['family'] = 'inet6'
                        else:
                            details['family'] = 'inet'
                        running_addrs[addr] = details
                    except:
                        running_addrs[addr] = {}
                    continue
                if (scope & Route.RT_SCOPE_LINK and addr in config_addrs) or not scope & Route.RT_SCOPE_LINK:
                    running_addrs[addr] = addr_details
        else:
            return None

        if details:
            return running_addrs
        return running_addrs.keys()

    def addr_add_multiple(self, ifacename, addrs, purge_existing=False):
        # purges address
        if purge_existing:
            # if perfmode is not set and also if iface has no sibling
            # objects, purge addresses that are not present in the new
            # config
            runningaddrs = self.get_running_addrs(ifname=ifacename, details=False)
            addrs = utils.get_normalized_ip_addr(ifacename, addrs)

            if addrs == runningaddrs:
                return
            try:
                # if primary address is not same, there is no need to keep any.
                # reset all addresses
                if (addrs and runningaddrs and
                        (addrs[0] != runningaddrs[0])):
                    self.del_addr_all(ifacename)
                else:
                    self.del_addr_all(ifacename, addrs)
            except Exception, e:
                self.logger.warning('%s: %s' % (ifacename, str(e)))
        for a in addrs:
            try:
                self.addr_add(ifacename, a)
            except Exception, e:
                self.logger.error(str(e))

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

    def link_set_mtu(self, ifacename, mtu):
        if ifupdownflags.flags.DRYRUN:
            return True
        if not mtu or not ifacename: return
        self.write_file('/sys/class/net/%s/mtu' % ifacename, mtu)
        self._cache_update([ifacename, 'mtu'], mtu)

    def link_set_alias(self, ifacename, alias):
        self.write_file('/sys/class/net/%s/ifalias' % ifacename,
                        '\n' if not alias else alias)

    def link_get_alias(self, ifacename):
        return self.read_file_oneline('/sys/class/net/%s/ifalias'
                                      % ifacename)

    def link_isloopback(self, ifacename):
        flags = self._cache_get('link', [ifacename, 'flags'])
        if not flags:
            return
        if 'LOOPBACK' in flags:
            return True
        return False

    def link_get_status(self, ifacename):
        return self._cache_get('link', [ifacename, 'ifflag'], refresh=True)

    @staticmethod
    def route_add_gateway(ifacename, gateway, vrf=None, metric=None):
        if not gateway:
            return
        if not vrf:
            cmd = '%s route add default via %s' % (utils.ip_cmd,
                                                   gateway)
        else:
            cmd = ('%s route add table %s default via %s' %
                   (utils.ip_cmd, vrf, gateway))
        # Add metric
        if metric:
            cmd += 'metric %s' % metric
        cmd += ' dev %s' % ifacename
        utils.exec_command(cmd)

    @staticmethod
    def route_del_gateway(ifacename, gateway, vrf=None, metric=None):
        # delete default gw
        if not gateway:
            return
        if not vrf:
            cmd = ('%s route del default via %s' %
                   (utils.ip_cmd, gateway))
        else:
            cmd = ('%s route del table %s default via %s' %
                   (utils.ip_cmd, vrf, gateway))
        if metric:
            cmd += ' metric %s' % metric
        cmd += ' dev %s' % ifacename
        utils.exec_command(cmd)

    @staticmethod
    def route6_add_gateway(ifacename, gateway):
        if not gateway:
            return
        return utils.exec_command('%s -6 route add default via %s dev %s' %
                                  (utils.ip_cmd, gateway, ifacename))

    @staticmethod
    def route6_del_gateway(ifacename, gateway):
        if not gateway:
            return
        return utils.exec_command('%s -6 route del default via %s dev %s' %
                                  (utils.ip_cmd, gateway, ifacename))

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

    def get_vxlan_peers(self, dev, svcnodeip):
        cmd = '%s fdb show brport %s' % (utils.bridge_cmd,
                                         dev)
        cur_peers = []
        try:
            ps = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, close_fds=False)
            utils.enable_subprocess_signal_forwarding(ps, signal.SIGINT)
            output = subprocess.check_output(('grep', '00:00:00:00:00:00'), stdin=ps.stdout)
            ps.wait()
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
            try:
                ppat = re.compile('\s+dst\s+(\d+.\d+.\d+.\d+)\s+')
                for l in output.split('\n'):
                    m = ppat.search(l)
                    if m and m.group(1) != svcnodeip:
                        cur_peers.append(m.group(1))
            except:
                self.logger.warn('error parsing ip link output')
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                self.logger.error(str(e))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)

        return cur_peers

    def link_create_vxlan(self, name, vxlanid,
                          localtunnelip=None,
                          svcnodeip=None,
                          remoteips=None,
                          learning='on',
                          ageing=None,
                          anycastip=None):
        if svcnodeip and remoteips:
            raise Exception("svcnodeip and remoteip is mutually exclusive")
        args = ''
        if svcnodeip:
            args += ' remote %s' % svcnodeip
        if ageing:
            args += ' ageing %s' % ageing
        if learning == 'off':
            args += ' nolearning'

        if self.link_exists(name):
            cmd = 'link set dev %s type vxlan dstport %d' % (name, LinkUtils.VXLAN_UDP_PORT)
            vxlanattrs = self.get_vxlandev_attrs(name)
            # on ifreload do not overwrite anycast_ip to individual ip if clagd
            # has modified
            if vxlanattrs:
                running_localtunnelip = vxlanattrs.get('local')
                if anycastip and running_localtunnelip and anycastip == running_localtunnelip:
                    localtunnelip = running_localtunnelip
                running_svcnode = vxlanattrs.get('svcnode')
                if running_svcnode and not svcnodeip:
                    args += ' noremote'
        else:
            cmd = 'link add dev %s type vxlan id %s dstport %d' % (name, vxlanid, LinkUtils.VXLAN_UDP_PORT)

        if localtunnelip:
            args += ' local %s' % localtunnelip
        cmd += args

        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('%s %s' % (utils.ip_cmd, cmd))

        # XXX: update linkinfo correctly
        #self._cache_update([name], {})

    @staticmethod
    def link_exists(ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return os.path.exists('/sys/class/net/%s' % ifacename)

    def link_get_ifindex(self, ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return self.read_file_oneline('/sys/class/net/%s/ifindex' % ifacename)

    def is_vlan_device_by_name(self, ifacename):
        if re.search(r'\.', ifacename):
            return True
        return False

    @staticmethod
    def link_add_macvlan(ifname, macvlan_ifacename):
        utils.exec_commandl(['ip', 'link', 'add',  'link', ifname, 'name', macvlan_ifacename, 'type', 'macvlan', 'mode', 'private'])

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
    def bridge_port_vids_add(bridgeportname, vids):
        [utils.exec_command('%s vlan add vid %s dev %s' %
                            (utils.bridge_cmd,
                             v, bridgeportname)) for v in vids]

    @staticmethod
    def bridge_port_vids_del(bridgeportname, vids):
        if not vids:
            return
        [utils.exec_command('%s vlan del vid %s dev %s' %
                            (utils.bridge_cmd,
                             v, bridgeportname)) for v in vids]

    @staticmethod
    def bridge_port_vids_flush(bridgeportname, vid):
        utils.exec_command('%s vlan del vid %s dev %s' %
                           (utils.bridge_cmd,
                            vid, bridgeportname))

    @staticmethod
    def bridge_port_vids_get(bridgeportname):
        bridgeout = utils.exec_command('%s vlan show dev %s' %
                                       (utils.bridge_cmd,
                                        bridgeportname))
        if not bridgeout:
            return []
        brvlanlines = bridgeout.readlines()[2:]
        vids = [l.strip() for l in brvlanlines]
        return [v for v in vids if v]

    @staticmethod
    def bridge_port_vids_get_all():
        brvlaninfo = {}
        bridgeout = utils.exec_command('%s -c vlan show'
                                       % utils.bridge_cmd)
        if not bridgeout:
            return brvlaninfo
        brvlanlines = bridgeout.splitlines()
        brportname = None
        for l in brvlanlines[1:]:
            if l and not l.startswith(' ') and not l.startswith('\t'):
                attrs = l.split()
                brportname = attrs[0].strip()
                brvlaninfo[brportname] = {'pvid': None, 'vlan': []}
                l = ' '.join(attrs[1:])
            if not brportname or not l:
                continue
            l = l.strip()
            if 'PVID' in l:
                brvlaninfo[brportname]['pvid'] = l.split()[0]
            elif 'Egress Untagged' not in l:
                brvlaninfo[brportname]['vlan'].append(l)
        return brvlaninfo

    def bridge_port_vids_get_all_json(self):
        if not self.supported_command['%s -c -json vlan show'
                % utils.bridge_cmd]:
            return {}
        brvlaninfo = {}
        try:
            bridgeout = utils.exec_command('%s -c -json vlan show'
                                           % utils.bridge_cmd)
        except:
            self.supported_command['%s -c -json vlan show'
                                   % utils.bridge_cmd] = False
            self.logger.info('%s -c -json vlan show: skipping unsupported command'
                             % utils.bridge_cmd)
            try:
                return self.get_bridge_vlan_nojson()
            except Exception as e:
                self.logger.info('bridge: get_bridge_vlan_nojson: %s' % str(e))
                return {}

        if not bridgeout: return brvlaninfo
        try:
            vlan_json_dict = json.loads(bridgeout, encoding="utf-8")
        except Exception, e:
            self.logger.info('json loads failed with (%s)' % str(e))
            return {}
        return vlan_json_dict

    @staticmethod
    def get_bridge_vlan_nojson():
        vlan_json = {}
        bridgeout = utils.exec_commandl([utils.bridge_cmd, '-c', 'vlan', 'show'])
        if bridgeout:
            output = [line.split('\n') for line in bridgeout.split('\n\n')]
            output[0] = output[0][1:]
            for line in output:
                current_swp = None
                if not line:
                    continue
                for entry in line:
                    if not entry:
                        continue
                    prefix, vlan = entry.split('\t')
                    if prefix:
                        current_swp = prefix
                        vlan_json[prefix] = []
                    v = {}
                    vlan = vlan[1:]
                    try:
                        v['vlan'] = int(vlan)
                    except:
                        try:
                            if '-' in vlan:
                                start, end = vlan.split('-')
                                if ' ' in end:
                                    end = end[0:end.index(' ')]
                                v['vlan'] = int(start)
                                v['vlanEnd'] = int(end)
                            else:
                                v['vlan'] = int(vlan[0:vlan.index(' ')])
                            flags = []
                            if 'PVID' in vlan:
                                flags.append('PVID')
                            if 'Egress Untagged' in vlan:
                                flags.append('Egress Untagged')
                            v['flags'] = flags
                        except:
                            continue
                    vlan_json[current_swp].append(v)
        return vlan_json

    def bridge_vlan_cache_get(self, ifacename, refresh=False):
        if not self.bridge_vlan_cache_fill_done or refresh:
            self.bridge_vlan_cache = self.bridge_port_vids_get_all_json()
            self.bridge_vlan_cache_fill_done = True
        return self.bridge_vlan_cache.get(ifacename, {})

    def bridge_vlan_get_pvid(self, ifacename, refresh=False):
        pvid = 0

        for vinfo in self.bridge_vlan_cache_get(ifacename, refresh):
            v = vinfo.get('vlan')
            pvid = v if 'PVID' in vinfo.get('flags', []) else 0
            if pvid:
                return pvid
        return pvid

    def bridge_vlan_get_vids(self, ifacename, refresh=False):
        vids = []

        for vinfo in self.bridge_vlan_cache_get(ifacename, refresh):
            v = vinfo.get('vlan')
            ispvid = True if 'PVID' in vinfo.get('flags', []) else False
            if ispvid:
                pvid = v if 'PVID' in vinfo.get('flags', []) else 0
                if pvid == 1:
                    continue
            vEnd = vinfo.get('vlanEnd')
            if vEnd:
                vids.extend(range(v, vEnd + 1))
            else:
                vids.append(v)
        return vids

    def bridge_vlan_get_vids_n_pvid(self, ifacename, refresh=False):
        vids = []
        pvid = 0

        for vinfo in self.bridge_vlan_cache_get(ifacename, refresh):
            v = vinfo.get('vlan')
            ispvid = True if 'PVID' in vinfo.get('flags', []) else False
            if ispvid:
                pvid = v if 'PVID' in vinfo.get('flags', []) else 0
            vEnd = vinfo.get('vlanEnd')
            if vEnd:
                vids.extend(range(v, vEnd + 1))
            else:
                vids.append(v)
        return vids, pvid

    def bridge_port_pvid_add(self, bridgeportname, pvid):
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch('vlan add vid %s untagged pvid dev %s' %
                              (pvid, bridgeportname))
        else:
            utils.exec_command('%s vlan add vid %s untagged pvid dev %s' %
                               (utils.bridge_cmd,
                                pvid, bridgeportname))

    def bridge_port_pvid_del(self, bridgeportname, pvid):
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            self.add_to_batch('vlan del vid %s untagged pvid dev %s' %
                              (pvid, bridgeportname))
        else:
            utils.exec_command('%s vlan del vid %s untagged pvid dev %s' %
                               (utils.bridge_cmd,
                                pvid, bridgeportname))

    def bridge_port_pvids_get(self, bridgeportname):
        return self.read_file_oneline('/sys/class/net/%s/brport/pvid'
                                      % bridgeportname)

    def bridge_vids_add(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            [self.add_to_batch('vlan add vid %s dev %s %s' %
                               (v, bridgeportname, target)) for v in vids]
        else:
            [utils.exec_command('%s vlan add vid %s dev %s %s' %
                                (utils.bridge_cmd,
                                 v, bridgeportname, target)) for v in vids]

    def bridge_vids_del(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        if LinkUtils.ipbatch and not LinkUtils.ipbatch_pause:
            [self.add_to_batch('vlan del vid %s dev %s %s' %
                               (v, bridgeportname, target)) for v in vids]
        else:
            [utils.exec_command('%s vlan del vid %s dev %s %s' %
                                (utils.bridge_cmd,
                                 v, bridgeportname, target)) for v in vids]

    @staticmethod
    def bridge_fdb_add(dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        utils.exec_command('%s fdb replace %s dev %s %s %s %s' %
                           (utils.bridge_cmd,
                            address, dev, vlan_str, target, dst_str))

    @staticmethod
    def bridge_fdb_append(dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        utils.exec_command('%s fdb append %s dev %s %s %s %s' %
                           (utils.bridge_cmd,
                            address, dev, vlan_str, target, dst_str))

    @staticmethod
    def bridge_fdb_del(dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote
        utils.exec_command('%s fdb del %s dev %s %s %s %s' %
                           (utils.bridge_cmd,
                            address, dev, vlan_str, target, dst_str))

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

    def bridge_fdb_show_dev(self, dev):
        try:
            fdbs = {}
            output = utils.exec_command('%s fdb show dev %s'
                                        % (utils.bridge_cmd, dev))
            if output:
                for fdb_entry in output.splitlines():
                    try:
                        entries = fdb_entry.split()
                        fdbs.setdefault(entries[2], []).append(entries[0])
                    except:
                        self.logger.debug('%s: invalid fdb line \'%s\''
                                          % (dev, fdb_entry))
            return fdbs
        except Exception:
            return None

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

    def ip_route_get_dev(self, prefix):
        try:
            output = utils.exec_command('%s route get %s' %
                                        (utils.ip_cmd, prefix))
            if output:
                rline = output.splitlines()[0]
                if rline:
                    rattrs = rline.split()
                    return rattrs[rattrs.index('dev') + 1]
        except Exception, e:
            self.logger.debug('ip_route_get_dev: failed .. %s' % str(e))
        return None

    @staticmethod
    def link_get_lowers(ifacename):
        try:
            lowers = glob.glob("/sys/class/net/%s/lower_*" % ifacename)
            if not lowers:
                return []
            return [os.path.basename(l)[6:] for l in lowers]
        except:
            return []

    @staticmethod
    def link_get_uppers(ifacename):
        try:
            uppers = glob.glob("/sys/class/net/%s/upper_*" % ifacename)
            if not uppers:
                return None
            return [os.path.basename(u)[6:] for u in uppers]
        except Exception:
            return None

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

    bondcmd_attrmap = {
        Link.IFLA_BOND_MODE: 'mode',
        Link.IFLA_BOND_MIIMON: 'miimon',
        Link.IFLA_BOND_USE_CARRIER: 'use_carrier',
        Link.IFLA_BOND_AD_LACP_RATE: 'lacp_rate',
        Link.IFLA_BOND_XMIT_HASH_POLICY: 'xmit_hash_policy',
        Link.IFLA_BOND_MIN_LINKS: 'min_links',
        Link.IFLA_BOND_NUM_PEER_NOTIF: 'num_grat_arp',
        Link.IFLA_BOND_AD_ACTOR_SYSTEM: 'ad_actor_system',
        Link.IFLA_BOND_AD_ACTOR_SYS_PRIO: 'ad_actor_sys_prio',
        Link.IFLA_BOND_AD_LACP_BYPASS: 'lacp_bypass',
        Link.IFLA_BOND_UPDELAY: 'updelay',
        Link.IFLA_BOND_DOWNDELAY: 'downdelay',
    }

    def bond_set_attrs_nl(self, bondname, ifla_info_data):
        bond_attr_name = 'None'  # for log purpose (in case an exception raised)
        for nl_attr, value in ifla_info_data.items():
            try:
                bond_attr_name = self.bondcmd_attrmap[nl_attr]
                file_path = '/sys/class/net/%s/bonding/%s' % (bondname, bond_attr_name)
                if os.path.exists(file_path):
                    self.write_file(file_path, str(value))
            except Exception as e:
                exception_str = '%s: %s %s: %s' % (bondname, bond_attr_name, value, str(e))
                if ifupdownflags.flags.FORCE:
                    self.logger.warning(exception_str)
                else:
                    self.logger.debug(exception_str)

    def bond_set_attrs(self, bondname, attrdict, prehook):
        for attrname, attrval in attrdict.items():
            if (self._link_cache_check([bondname, 'linkinfo',
                                        attrname], attrval)):
                continue
            if (attrname == 'mode'
                or attrname == 'xmit_hash_policy'
                or attrname == 'lacp_rate' or attrname == 'min_links'):
                if prehook:
                    prehook(bondname)
            try:
                if ((attrname not in ['lacp_rate',
                                      'lacp_bypass']) or
                        self._link_cache_check([bondname, 'linkinfo', 'mode'], '802.3ad',
                                               True)):
                    self.write_file('/sys/class/net/%s/bonding/%s'
                                    % (bondname, attrname), attrval)
            except Exception, e:
                if ifupdownflags.flags.FORCE:
                    self.logger.warn(str(e))
                    pass
                else:
                    raise

    def bond_set_use_carrier(self, bondname, use_carrier):
        if not use_carrier or (use_carrier != '0' and use_carrier != '1'):
            return
        if (self._link_cache_check([bondname, 'linkinfo', 'use_carrier'],
                                   use_carrier)):
            return
        self.write_file('/sys/class/net/%s' % bondname +
                        '/bonding/use_carrier', use_carrier)
        self._cache_update([bondname, 'linkinfo',
                            'use_carrier'], use_carrier)

    def bond_get_use_carrier(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'use_carrier'])

    def bond_get_use_carrier_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_USE_CARRIER])

    def bond_set_xmit_hash_policy(self, bondname, hash_policy, prehook=None):
        valid_values = ['layer2', 'layer3+4', 'layer2+3']
        if not hash_policy:
            return
        if hash_policy not in valid_values:
            raise Exception('invalid hash policy value %s' % hash_policy)
        if (self._link_cache_check([bondname, 'linkinfo', 'xmit_hash_policy'],
                                   hash_policy)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s' % bondname +
                        '/bonding/xmit_hash_policy', hash_policy)
        self._cache_update([bondname, 'linkinfo', 'xmit_hash_policy'],
                           hash_policy)

    def bond_get_xmit_hash_policy(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'xmit_hash_policy'])

    def bond_get_xmit_hash_policy_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_XMIT_HASH_POLICY])

    def bond_set_miimon(self, bondname, miimon):
        if (self._link_cache_check([bondname, 'linkinfo', 'miimon'],
                                   miimon)):
            return
        self.write_file('/sys/class/net/%s' % bondname +
                        '/bonding/miimon', miimon)
        self._cache_update([bondname, 'linkinfo', 'miimon'], miimon)

    def bond_get_miimon(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'miimon'])

    def bond_get_miimon_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MIIMON])

    def bond_set_mode(self, bondname, mode, prehook=None):
        valid_modes = ['balance-rr', 'active-backup', 'balance-xor',
                       'broadcast', '802.3ad', 'balance-tlb', 'balance-alb']
        if not mode:
            return
        if mode not in valid_modes:
            raise Exception('invalid mode %s' % mode)
        if (self._link_cache_check([bondname, 'linkinfo', 'mode'],
                                   mode)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s' % bondname + '/bonding/mode', mode)
        self._cache_update([bondname, 'linkinfo', 'mode'], mode)

    def bond_get_mode(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'mode'])

    def bond_get_mode_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MODE])

    def bond_set_lacp_rate(self, bondname, lacp_rate, prehook=None, posthook=None):
        if not lacp_rate or (lacp_rate != '0' and lacp_rate != '1'):
            return
        if (self._link_cache_check([bondname, 'linkinfo', 'lacp_rate'],
                                   lacp_rate)):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' % bondname +
                            '/bonding/lacp_rate', lacp_rate)
        except:
            raise
        finally:
            if posthook:
                prehook(bondname)
            self._cache_update([bondname, 'linkinfo',
                                'lacp_rate'], lacp_rate)

    def bond_get_lacp_rate(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'lacp_rate'])

    def bond_get_lacp_rate_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_RATE])

    def bond_set_lacp_bypass_allow(self, bondname, allow, prehook=None, posthook=None):
        if self._link_cache_check([bondname, 'linkinfo', 'lacp_bypass'], allow):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' % bondname +
                            '/bonding/lacp_bypass', allow)
        except:
            raise
        finally:
            if posthook:
                posthook(bondname)
            self._cache_update([bondname, 'linkinfo',
                                'lacp_bypass'], allow)

    def bond_get_lacp_bypass_allow(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'lacp_bypass'])

    def bond_get_lacp_bypass_allow_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_LACP_BYPASS])

    def bond_set_min_links(self, bondname, min_links, prehook=None):
        if (self._link_cache_check([bondname, 'linkinfo', 'min_links'],
                                   min_links)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s/bonding/min_links' % bondname,
                        min_links)
        self._cache_update([bondname, 'linkinfo', 'min_links'], min_links)

    def bond_get_min_links(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'min_links'])

    def get_min_links_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_MIN_LINKS])

    def bond_get_ad_actor_system(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'ad_actor_system'])

    def bond_get_ad_actor_system_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYSTEM])

    def bond_get_ad_actor_sys_prio(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'ad_actor_sys_prio'])

    def bond_get_ad_actor_sys_prio_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_AD_ACTOR_SYS_PRIO])

    def bond_get_num_unsol_na(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'num_unsol_na'])

    def bond_get_num_unsol_na_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF])

    def bond_get_num_grat_arp(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'num_grat_arp'])

    def bond_get_num_grat_arp_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_NUM_PEER_NOTIF])

    def bond_get_updelay(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'updelay'])

    def bond_get_updelay_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_UPDELAY])

    def bond_get_downdelay(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', 'downdelay'])

    def bond_get_downdelay_nl(self, bondname):
        return self._link_cache_get([bondname, 'linkinfo', Link.IFLA_BOND_DOWNDELAY])

    def bond_enslave_slave(self, bondname, slave, prehook=None, posthook=None):
        slaves = self._link_cache_get([bondname, 'linkinfo', 'slaves'])
        if slaves and slave in slaves:
            return
        if prehook:
            prehook(slave)
        self.write_file('/sys/class/net/%s' % bondname +
                        '/bonding/slaves', '+' + slave)
        if posthook:
            posthook(slave)
        self._cache_update([bondname, 'linkinfo', 'slaves'], slave)

    def bond_remove_slave(self, bondname, slave):
        slaves = self._link_cache_get([bondname, 'linkinfo', 'slaves'])
        if slave not in slaves:
            return
        sysfs_bond_path = ('/sys/class/net/%s' % bondname +
                           '/bonding/slaves')
        if not os.path.exists(sysfs_bond_path):
            return
        self.write_file(sysfs_bond_path, '-' + slave)
        self._cache_delete([bondname, 'linkinfo', 'slaves'], slave)

    def bond_remove_slaves_all(self, bondname):
        if not self._link_cache_get([bondname, 'linkinfo', 'slaves']):
            return
        slaves = None
        sysfs_bond_path = ('/sys/class/net/%s' % bondname +
                           '/bonding/slaves')
        try:
            with open(sysfs_bond_path, 'r') as f:
                slaves = f.readline().strip().split()
        except IOError, e:
            raise Exception('error reading slaves of bond %s (%s)' % (bondname, str(e)))
        for slave in slaves:
            self.link_down(slave)
            try:
                self.bond_remove_slave(bondname, slave)
            except Exception, e:
                if not ifupdownflags.flags.FORCE:
                    raise Exception('error removing slave %s from bond %s (%s)' % (slave, bondname, str(e)))
                else:
                    pass
        self._cache_delete([bondname, 'linkinfo', 'slaves'])

    @staticmethod
    def bond_load_bonding_module():
        return utils.exec_command('%s -q bonding' % utils.modprobe_cmd)

    def create_bond(self, bondname):
        if self.bond_exists(bondname):
            return
        # load_bonding_module() has already been run
        self.write_file('/sys/class/net/bonding_masters', '+' + bondname)
        self._cache_update([bondname], {})

    def delete_bond(self, bondname):
        if not os.path.exists('/sys/class/net/%s' % bondname):
            return
        self.write_file('/sys/class/net/bonding_masters', '-' + bondname)
        self._cache_delete([bondname])

    def bond_get_slaves(self, bondname):
        slaves = self._link_cache_get([bondname, 'linkinfo', 'slaves'])
        if slaves:
            return list(slaves)
        slavefile = '/sys/class/net/%s/bonding/slaves' % bondname
        if os.path.exists(slavefile):
            buf = self.read_file_oneline(slavefile)
            if buf:
                slaves = buf.split()
        if not slaves:
            return []
        self._cache_update([bondname, 'linkinfo', 'slaves'], slaves)
        return list(slaves)

    def bond_slave_exists(self, bond, slave):
        slaves = self.bond_get_slaves(bond)
        if not slaves:
            return False
        return slave in slaves

    @staticmethod
    def bond_exists(bondname):
        return os.path.exists('/sys/class/net/%s/bonding' % bondname)

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
    def bridge_set_stp(bridge, stp_state):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s stp %s %s' % (utils.brctl_cmd, bridge, stp_state))

    def bridge_get_stp(self, bridge):
        sysfs_stpstate = '/sys/class/net/%s/bridge/stp_state' % bridge
        if not os.path.exists(sysfs_stpstate):
            return 'error'
        stpstate = self.read_file_oneline(sysfs_stpstate)
        if not stpstate:
            return 'error'
        try:
            if int(stpstate) > 0:
                return 'yes'
            elif int(stpstate) == 0:
                return 'no'
        except:
            return 'unknown'

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

    def bridge_get_pathcost(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/path_cost'
                                      % port)

    @staticmethod
    def bridge_set_portprio(bridge, port, prio):
        if not LinkUtils.bridge_utils_is_installed:
            return
        utils.exec_command('%s setportprio %s %s %s' % (utils.brctl_cmd, bridge, port, prio))

    def bridge_get_portprio(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/priority'
                                      % port)

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

    def bridge_set_mcqv4src(self, bridge, vlan, mcquerier):
        try:
            vlan = int(vlan)
        except:
            self.logger.info('%s: set mcqv4src vlan: invalid parameter %s: %s' %(bridge, vlan, str(e)))
            return
        if vlan == 0 or vlan > 4095:
            self.logger.warn('mcqv4src vlan \'%d\' invalid range' % vlan)
            return

        ip = mcquerier.split('.')
        if len(ip) != 4:
            self.logger.warn('mcqv4src \'%s\' invalid IPv4 address' % mcquerier)
            return
        for k in ip:
            if not k.isdigit() or int(k, 10) < 0 or int(k, 10) > 255:
                self.logger.warn('mcqv4src \'%s\' invalid IPv4 address' % mcquerier)
                return

        if not LinkUtils.bridge_utils_is_installed:
            return

        utils.exec_command('%s setmcqv4src %s %d %s' %
                           (utils.brctl_cmd, bridge, vlan, mcquerier))

    def bridge_del_mcqv4src(self, bridge, vlan):
        if not LinkUtils.bridge_utils_is_installed:
            return
        try:
            vlan = int(vlan)
        except:
            self.logger.info('%s: del mcqv4src vlan: invalid parameter %s: %s' %(bridge, vlan, str(e)))
            return
        utils.exec_command('%s delmcqv4src %s %d' % (utils.brctl_cmd, bridge, vlan))

    def bridge_get_mcqv4src(self, bridge, vlan=None):
        if not LinkUtils.bridge_utils_is_installed:
            return {}
        if not self.supported_command['showmcqv4src']:
            return {}
        mcqv4src = {}
        try:
            mcqout = utils.exec_command('%s showmcqv4src %s' %
                                        (utils.brctl_cmd, bridge))
        except Exception as e:
            s = str(e).lower()
            if 'never heard' in s:
                msg = ('%s showmcqv4src: skipping unsupported command'
                       % utils.brctl_cmd)
                self.logger.info(msg)
                self.supported_command['showmcqv4src'] = False
                return {}
            raise
        if not mcqout:
            return {}
        mcqlines = mcqout.splitlines()
        for l in mcqlines[1:]:
            l = l.strip()
            k, d, v = l.split('\t')
            if not k or not v:
                continue
            mcqv4src[k] = v
        if vlan:
            return mcqv4src.get(vlan)
        return mcqv4src

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
