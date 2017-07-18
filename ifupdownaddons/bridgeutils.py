#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    import os
    import re

    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    from ifupdownaddons.cache import *
    from ifupdownaddons.utilsbase import *

    import ifupdown.ifupdownflags as ifupdownflags
except ImportError, e:
    raise ImportError('%s - required module not found' % str(e))


class brctl(utilsBase):
    """ This class contains helper functions to interact with the bridgeutils
    commands """

    _cache_fill_done = False

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        if ifupdownflags.flags.CACHE and not brctl._cache_fill_done:
            if os.path.exists('/sbin/brctl'):
                self._bridge_fill()
            brctl._cache_fill_done = True
        self.supported_command = {'showmcqv4src': True}

    @classmethod
    def reset(cls):
        brctl._cache_fill_done = False

    def _bridge_get_mcattrs_from_sysfs(self, bridgename):
        mcattrs = {}
        mcattrmap = {'mclmc': 'multicast_last_member_count',
                     'mcrouter': 'multicast_router',
                     'mcsnoop' : 'multicast_snooping',
                     'mcsqc' : 'multicast_startup_query_count',
                     'mcqifaddr' : 'multicast_query_use_ifaddr',
                     'mcquerier' : 'multicast_querier',
                     'hashel' : 'hash_elasticity',
                     'hashmax' : 'hash_max',
                     'mclmi' : 'multicast_last_member_interval',
                     'mcmi' : 'multicast_membership_interval',
                     'mcqpi' : 'multicast_querier_interval',
                     'mcqi' : 'multicast_query_interval',
                     'mcqri' : 'multicast_query_response_interval',
                     'mcsqi' : 'multicast_startup_query_interval',
                     'igmp-version': 'multicast_igmp_version',
                     'mld-version': 'multicast_mld_version',
                     'vlan-stats' : 'vlan_stats_enabled',
                     'mcstats' : 'multicast_stats_enabled',
                    }

        mcattrsdivby100 = ['mclmi', 'mcmi', 'mcqpi', 'mcqi', 'mcqri', 'mcsqi']

        for m, s in mcattrmap.items():
            n = self.read_file_oneline('/sys/class/net/%s/bridge/%s'
                                    %(bridgename, s))
            if m in mcattrsdivby100:
                try:
                    v = int(n) / 100
                    mcattrs[m] = str(v)
                except Exception, e:
                    self.logger.warn('error getting mc attr %s (%s)'
                                     %(m, str(e)))
                    pass
            else:
                mcattrs[m] = n
        return mcattrs

    def _bridge_attrs_fill(self, bridgename):
        battrs = {}
        bports = {}

        brout = utils.exec_command('/sbin/brctl showstp %s' % bridgename)
        chunks = re.split(r'\n\n', brout, maxsplit=0, flags=re.MULTILINE)

        try:
            # Get all bridge attributes
            broutlines = chunks[0].splitlines()
            #battrs['pathcost'] = broutlines[3].split('path cost')[1].strip()

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
            #battrs['hashel'] = broutlines[10].split('hash elasticity')[1].split()[0].strip()
            #battrs['hashmax'] = broutlines[10].split('hash max')[1].strip()
            #battrs['mclmc'] = broutlines[11].split('mc last member count')[1].split()[0].strip()
            #battrs['mciqc'] = broutlines[11].split('mc init query count')[1].strip()
            #battrs['mcrouter'] = broutlines[12].split('mc router')[1].split()[0].strip()
            ##battrs['mcsnoop'] = broutlines[12].split('mc snooping')[1].strip()
            #battrs['mclmt'] = broutlines[13].split('mc last member timer')[1].split()[0].strip()
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
                         '/sys/class/net/%s/brport/multicast_router' %pname)
                bportattrs['portmcfl'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/multicast_fast_leave' %pname)
                bportattrs['portprio'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/priority' %pname)
                bportattrs['unicast-flood'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/unicast_flood' %pname)
                bportattrs['multicast-flood'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/multicast_flood' %pname)
                bportattrs['learning'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/learning' %pname)
                bportattrs['arp-nd-suppress'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/neigh_suppress' %pname)
                #bportattrs['mcrouters'] = bplines[6].split('mc router')[1].split()[0].strip()
                #bportattrs['mc fast leave'] = bplines[6].split('mc fast leave')[1].strip()
            except Exception, e:
                self.logger.warn('%s: error while processing bridge attributes: %s' % (bridgename, str(e)))
            bports[pname] = bportattrs
            linkCache.update_attrdict([bridgename, 'linkinfo', 'ports'], bports)

    def _bridge_fill(self, bridgename=None):
        try:
            # if cache is already filled, return
            linkCache.get_attr([bridgename, 'linkinfo', 'fd'])
            return
        except:
            pass
        if True:  # netlink
            try:
                [linkCache.update_attrdict([ifname], linkattrs)
                 for ifname, linkattrs in netlink.link_dump().items()]

                brports = {}

                for ifname, obj in linkCache.links.items():
                    slave_kind = obj.get('slave_kind')
                    if not slave_kind and slave_kind != 'bridge':
                        continue

                    info_slave_data = obj.get('info_slave_data')
                    if not info_slave_data:
                        continue

                    ifla_master = obj.get('master')
                    if not ifla_master:
                        raise Exception('No master associated with bridge port %s' % ifname)

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
                    brctl._cache_fill_done = True
            except Exception as e:
                self.logger.warning('%s: %s' % (bridgename if bridgename else 'bridge dump', str(e)))

        else:
            if not bridgename:
                brctlout = utils.exec_command('/sbin/brctl show')
            else:
                brctlout = utils.exec_command('/sbin/brctl show %s' % bridgename)
            if not brctlout:
                return

            for bline in brctlout.splitlines()[1:]:
                bitems = bline.split()
                if len(bitems) < 2:
                    continue
                try:
                    linkCache.update_attrdict([bitems[0], 'linkinfo'],
                                          {'stp' : bitems[2]})
                except KeyError:
                    linkCache.update_attrdict([bitems[0]],
                                    {'linkinfo' : {'stp' : bitems[2]}})
                self._bridge_attrs_fill(bitems[0])

    def cache_get(self, attr_list, refresh=False):
        return self._cache_get(attr_list, refresh)

    def cache_get_info_slave(self, attrlist):
        try:
            if attrlist[0] not in linkCache.links:
                self._bridge_fill(attrlist[0])
            return linkCache.get_attr(attrlist)
        except:
            return self._cache_get(attrlist, refresh=True)

    def _cache_get(self, attrlist, refresh=False):
        try:
            if ifupdownflags.flags.DRYRUN:
                return None
            if ifupdownflags.flags.CACHE:
                if not brctl._cache_fill_done:
                    self._bridge_fill()
                    brctl._cache_fill_done = True
                    return linkCache.get_attr(attrlist)
                if not refresh:
                    return linkCache.get_attr(attrlist)
            self._bridge_fill(attrlist[0])
            return linkCache.get_attr(attrlist)
        except Exception, e:
            self.logger.debug('_cache_get(%s) : [%s]'
                    %(str(attrlist), str(e)))
            pass
        return None

    def _cache_check(self, attrlist, value, refresh=False):
        try:
            attrvalue = self._cache_get(attrlist, refresh)
            if attrvalue and attrvalue.upper() == value.upper():
                return True
        except Exception, e:
            self.logger.debug('_cache_check(%s) : [%s]'
                    %(str(attrlist), str(e)))
            pass
        return False

    def _cache_update(self, attrlist, value):
        if ifupdownflags.flags.DRYRUN: return
        try:
            linkCache.set_attr(attrlist, value)
        except:
            pass

    def _cache_delete(self, attrlist):
        if ifupdownflags.flags.DRYRUN: return
        try:
            linkCache.del_attr(attrlist)
        except:
            pass

    def _cache_invalidate(self):
        if ifupdownflags.flags.DRYRUN: return
        linkCache.invalidate()

    def create_bridge(self, bridgename):
        if self.bridge_exists(bridgename):
            return
        utils.exec_command('/sbin/brctl addbr %s' % bridgename)
        self._cache_update([bridgename], {})

    def delete_bridge(self, bridgename):
        if not self.bridge_exists(bridgename):
            return
        utils.exec_command('/sbin/brctl delbr %s' % bridgename)
        self._cache_invalidate()

    def add_bridge_port(self, bridgename, bridgeportname):
        """ Add port to bridge """
        ports = self._cache_get([bridgename, 'linkinfo', 'ports'])
        if ports and ports.get(bridgeportname):
            return
        utils.exec_command('/sbin/brctl addif %s %s' %
                           (bridgename, bridgeportname))
        self._cache_update([bridgename, 'linkinfo', 'ports',
                            bridgeportname], {})

    def delete_bridge_port(self, bridgename, bridgeportname):
        """ Delete port from bridge """
        ports = self._cache_get([bridgename, 'linkinfo', 'ports'])
        if not ports or not ports.get(bridgeportname):
            return
        utils.exec_command('/sbin/brctl delif %s %s' %
                           (bridgename, bridgeportname))
        self._cache_delete([bridgename, 'linkinfo', 'ports',
                           'bridgeportname'])

    def set_bridgeport_attrs(self, bridgename, bridgeportname, attrdict):
        portattrs = self._cache_get([bridgename, 'linkinfo',
                                       'ports', bridgeportname])
        if portattrs == None: portattrs = {}
        for k, v in attrdict.iteritems():
            if ifupdownflags.flags.CACHE:
                curval = portattrs.get(k)
                if curval and curval == v:
                    continue
            if k == 'unicast-flood':
                self.write_file('/sys/class/net/%s/brport/'
                                'unicast_flood' %bridgeportname, v)
            elif k == 'multicast-flood':
                self.write_file('/sys/class/net/%s/brport/'
                                'multicast_flood' %bridgeportname, v)
            elif k == 'learning':
                self.write_file('/sys/class/net/%s/brport/'
                                'learning' %bridgeportname, v)
            elif k == 'arp-nd-suppress':
                self.write_file('/sys/class/net/%s/brport/'
                                'neigh_suppress' %bridgeportname, v)
            else:
                utils.exec_command('/sbin/brctl set%s %s %s %s' %
                                   (k, bridgename, bridgeportname, v))

    def set_bridgeport_attr(self, bridgename, bridgeportname,
                            attrname, attrval):
        if self._cache_check([bridgename, 'linkinfo', 'ports',
                        bridgeportname, attrname], attrval):
            return
        utils.exec_command('/sbin/brctl set%s %s %s %s' %
                           (attrname,
                            bridgename,
                            bridgeportname,
                            attrval))

    def set_bridge_attrs(self, bridgename, attrdict):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            if self._cache_check([bridgename, 'linkinfo', k], v):
                continue
            try:
                if k == 'igmp-version':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_igmp_version' %bridgename, v)
                elif k == 'mld-version':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_mld_version' %bridgename, v)
                elif k == 'vlan-protocol':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'vlan_protocol' %bridgename,
                                    VlanProtocols.ETHERTYPES_TO_ID.get(v.upper(),
                                                                       None))
                elif k == 'vlan-stats':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'vlan_stats_enabled' %bridgename, v)
                elif k == 'mcstats':
                    self.write_file('/sys/class/net/%s/bridge/'
                                    'multicast_stats_enabled' %bridgename, v)
                else:
                    cmd = '/sbin/brctl set%s %s %s' % (k, bridgename, v)
                    utils.exec_command(cmd)
            except Exception, e:
                self.logger.warn('%s: %s' %(bridgename, str(e)))
                pass

    def set_bridge_attr(self, bridgename, attrname, attrval):
        if self._cache_check([bridgename, 'linkinfo', attrname], attrval):
            return
        if attrname == 'igmp-version':
            self.write_file('/sys/class/net/%s/bridge/multicast_igmp_version'
                            %bridgename, attrval)
        elif attrname == 'mld-version':
            self.write_file('/sys/class/net/%s/bridge/multicast_mld_version'
                            %bridgename, attrval)
        elif attrname == 'vlan-protocol':
            self.write_file('/sys/class/net/%s/bridge/vlan_protocol'
                            %bridgename, VlanProtocols.ETHERTYPES_TO_ID[attrval.upper()])
        elif attrname == 'vlan-stats':
            self.write_file('/sys/class/net/%s/bridge/vlan_stats_enabled'
                            %bridgename, attrval)
        elif attrname == 'mcstats':
            self.write_file('/sys/class/net/%s/bridge/multicast_stats_enabled'
                            %bridgename, attrval)
        else:
            cmd = '/sbin/brctl set%s %s %s' %(attrname, bridgename, attrval)
            utils.exec_command(cmd)

    def get_bridge_attrs(self, bridgename):
        attrs = self._cache_get([bridgename, 'linkinfo'])
        no_ints_attrs = {}
        for key, value in attrs.items():
            if type(key) == str:
                no_ints_attrs[key] = value
        return no_ints_attrs

    def get_bridgeport_attrs(self, bridgename, bridgeportname):
        return self._cache_get([bridgename, 'linkinfo', 'ports',
                                      bridgeportname])

    def get_brport_peer_link(self, bridgename):
        return self._cache_get([bridgename, 'info_slave_data', Link.IFLA_BRPORT_PEER_LINK])

    def get_bridgeport_attr(self, bridgename, bridgeportname, attrname):
        return self._cache_get([bridgename, 'linkinfo', 'ports',
                                      bridgeportname, attrname])

    def set_stp(self, bridge, stp_state):
        utils.exec_command('/sbin/brctl stp %s %s' % (bridge, stp_state))

    def get_stp(self, bridge):
        sysfs_stpstate = '/sys/class/net/%s/bridge/stp_state' %bridge
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

    def conv_value_to_user(self, str):
        try:
            ret = int(str) / 100
        except:
            return None
        finally:
            return '%d' %ret

    def read_value_from_sysfs(self, filename, preprocess_func):
        value = self.read_file_oneline(filename)
        if not value:
            return None
        return preprocess_func(value)

    def set_ageing(self, bridge, ageing):
        utils.exec_command('/sbin/brctl setageing %s %s' % (bridge, ageing))

    def get_ageing(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/ageing_time'
                                     %bridge, self.conv_value_to_user)

    def set_bridgeprio(self, bridge, prio):
        utils.exec_command('/sbin/brctl setbridgeprio %s %s' % (bridge, prio))

    def get_bridgeprio(self, bridge):
        return self.read_file_oneline(
                       '/sys/class/net/%s/bridge/priority' %bridge)

    def set_fd(self, bridge, fd):
        utils.exec_command('/sbin/brctl setfd %s %s' % (bridge, fd))

    def get_fd(self, bridge):
        return self.read_value_from_sysfs(
                            '/sys/class/net/%s/bridge/forward_delay'
                            %bridge, self.conv_value_to_user)

    def set_gcint(self, bridge, gcint):
        #cmd = '/sbin/brctl setgcint ' + bridge + ' ' + gcint
        raise Exception('set_gcint not implemented')

    def set_hello(self, bridge, hello):
        utils.exec_command('/sbin/brctl sethello %s %s' % (bridge, hello))

    def get_hello(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/hello_time'
                                          %bridge, self.conv_value_to_user)

    def set_maxage(self, bridge, maxage):
        utils.exec_command('/sbin/brctl setmaxage %s %s' % (bridge, maxage))

    def get_maxage(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/max_age'
                                          %bridge, self.conv_value_to_user)

    def set_pathcost(self, bridge, port, pathcost):
        utils.exec_command('/sbin/brctl setpathcost %s %s %s' %
                           (bridge, port, pathcost))

    def get_pathcost(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/path_cost'
                                        %port)

    def set_portprio(self, bridge, port, prio):
        utils.exec_command('/sbin/brctl setportprio %s %s %s' %
                           (bridge, port, prio))

    def get_portprio(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/priority'
                                        %port)

    def set_hashmax(self, bridge, hashmax):
        utils.exec_command('/sbin/brctl sethashmax %s %s' % (bridge, hashmax))

    def get_hashmax(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_max'
                                        %bridge)

    def set_hashel(self, bridge, hashel):
        utils.exec_command('/sbin/brctl sethashel %s %s' % (bridge, hashel))

    def get_hashel(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_elasticity'
                                        %bridge)

    def set_mclmc(self, bridge, mclmc):
        utils.exec_command('/sbin/brctl setmclmc %s %s' % (bridge, mclmc))

    def get_mclmc(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_last_member_count'
                    %bridge)

    def set_mcrouter(self, bridge, mcrouter):
        utils.exec_command('/sbin/brctl setmcrouter %s %s' % (bridge, mcrouter))

    def get_mcrouter(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_router' %bridge)

    def set_mcsnoop(self, bridge, mcsnoop):
        utils.exec_command('/sbin/brctl setmcsnoop %s %s' % (bridge, mcsnoop))

    def get_mcsnoop(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_snooping' %bridge)

    def set_mcsqc(self, bridge, mcsqc):
        utils.exec_command('/sbin/brctl setmcsqc %s %s' % (bridge, mcsqc))

    def get_mcsqc(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_startup_query_count'
                    %bridge)

    def set_mcqifaddr(self, bridge, mcqifaddr):
        utils.exec_command('/sbin/brctl setmcqifaddr %s %s' %
                           (bridge, mcqifaddr))

    def get_mcqifaddr(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_startup_query_use_ifaddr'
                 %bridge)

    def set_mcquerier(self, bridge, mcquerier):
        utils.exec_command('/sbin/brctl setmcquerier %s %s' %
                           (bridge, mcquerier))

    def get_mcquerier(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_querier' %bridge)

    def set_mcqv4src(self, bridge, vlan, mcquerier):
        if vlan == 0 or vlan > 4095:
            self.logger.warn('mcqv4src vlan \'%d\' invalid range' %vlan)
            return

        ip = mcquerier.split('.')
        if len(ip) != 4:
            self.logger.warn('mcqv4src \'%s\' invalid IPv4 address' %mcquerier)
            return
        for k in ip:
            if not k.isdigit() or int(k, 10) < 0 or int(k, 10) > 255:
                self.logger.warn('mcqv4src \'%s\' invalid IPv4 address' %mcquerier)
                return

        utils.exec_command('/sbin/brctl setmcqv4src %s %d %s' %
                           (bridge, vlan, mcquerier))

    def del_mcqv4src(self, bridge, vlan):
        utils.exec_command('/sbin/brctl delmcqv4src %s %d' % (bridge, vlan))

    def get_mcqv4src(self, bridge, vlan=None):
        if not self.supported_command['showmcqv4src']:
            return {}
        mcqv4src = {}
        try:
            mcqout = utils.exec_command('/sbin/brctl showmcqv4src %s' % bridge)
        except Exception as e:
            s = str(e).lower()
            if 'never heard' in s:
                self.logger.info('/sbin/brctl showmcqv4src: '
                                 'skipping unsupported command')
                self.supported_command['showmcqv4src'] = False
                return {}
            raise
        if not mcqout: return {}
        mcqlines = mcqout.splitlines()
        for l in mcqlines[1:]:
            l=l.strip()
            k, d, v = l.split('\t')
            if not k or not v:
                continue
            mcqv4src[k] = v
        if vlan:
            return mcqv4src.get(vlan)
        return mcqv4src

    def set_mclmi(self, bridge, mclmi):
        utils.exec_command('/sbin/brctl setmclmi %s %s' % (bridge, mclmi))

    def get_mclmi(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_last_member_interval'
                 %bridge)

    def set_mcmi(self, bridge, mcmi):
        utils.exec_command('/sbin/brctl setmcmi %s %s' % (bridge, mcmi))

    def get_mcmi(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_membership_interval'
                 %bridge)

    def bridge_exists(self, bridge):
        return os.path.exists('/sys/class/net/%s/bridge' %bridge)

    def is_bridge_port(self, ifacename):
        return os.path.exists('/sys/class/net/%s/brport' %ifacename)

    def bridge_port_exists(self, bridge, bridgeportname):
        try:
            return os.path.exists('/sys/class/net/%s/brif/%s'
                                  %(bridge, bridgeportname))
        except Exception:
            return False
   
    def get_bridge_ports(self, bridgename):
        try:
            return os.listdir('/sys/class/net/%s/brif/' %bridgename)
        except:
            return []
