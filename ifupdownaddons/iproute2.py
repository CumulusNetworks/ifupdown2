#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import glob
import shlex
import signal
import subprocess

from ifupdown.utils import utils
from collections import OrderedDict
from utilsbase import *
from systemutils import *
from cache import *
import ifupdown.ifupdownflags as ifupdownflags

VXLAN_UDP_PORT = 4789

class iproute2(utilsBase):
    """ This class contains helper methods to cache and interact with the
    commands in the iproute2 package """

    _cache_fill_done = False
    ipbatchbuf = ''
    ipbatch = False
    ipbatch_pause = False

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        if ifupdownflags.flags.CACHE:
            self._fill_cache()
        self.supported_command = {
            '/sbin/bridge -c -json vlan show': True
        }

    def _fill_cache(self):
        if not iproute2._cache_fill_done:
            self._link_fill()
            self._addr_fill()
            iproute2._cache_fill_done = True
            return True
        return False

    def _get_vland_id(self, citems, i, warn):
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

        warn = True
        linkout = {}
        vxrd_running = False
        if iproute2._cache_fill_done and not refresh: return
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
        # read vxrd.pid and cache the running state before going through
        # every interface in the system
        if systemUtils.is_service_running(None, '/var/run/vxrd.pid'):
            vxrd_running = True
        for c in cmdout.splitlines():
            citems = c.split()
            ifnamenlink = citems[1].split('@')
            if len(ifnamenlink) > 1:
                ifname = ifnamenlink[0]
                iflink = ifnamenlink[1].strip(':')
            else:
                ifname = ifnamenlink[0].strip(':')
                iflink = None
            linkattrs = {}
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
                        # get vxlan peer nodes if provisioned by user and not by vxrd
                        if not vxrd_running:
                            peers = self.get_vxlan_peers(ifname, vattrs['svcnode'])
                            if peers:
                                vattrs['remote'] = peers
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
                        self.logger.debug('%s: parsing error: id, mtu, state, link/ether, vlan, dummy, vxlan, local, remote, ageing, nolearning, vrf, table, vrf_slave are reserved keywords: %s' % (ifname, str(e)))
                        warn = False
            #linkattrs['alias'] = self.read_file_oneline(
            #            '/sys/class/net/%s/ifalias' %ifname)
            linkout[ifname] = linkattrs
        [linkCache.update_attrdict([ifname], linkattrs)
                    for ifname, linkattrs in linkout.items()]

    def _addr_filter(self, ifname, addr, scope=None):
        default_addrs = ['127.0.0.1/8', '::1/128' , '0.0.0.0']
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
        linkout = {}
        if iproute2._cache_fill_done and not refresh: return

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
                linkattrs = {}
                linkattrs['addrs'] = OrderedDict({})
                try:
                    linkout[ifname].update(linkattrs)
                except KeyError:
                    linkout[ifname] = linkattrs
            if citems[2] == 'inet':
                if self._addr_filter(ifname, citems[3], scope=citems[5]):
                    continue
                addrattrs = {}
                addrattrs['scope'] = citems[5]
                addrattrs['type'] = 'inet'
                linkout[ifname]['addrs'][citems[3]] = addrattrs
            elif citems[2] == 'inet6':
                if self._addr_filter(ifname, citems[3], scope=citems[5]):
                    continue
                if citems[5] == 'link': continue #skip 'link' addresses
                addrattrs = {}
                addrattrs['scope'] = citems[5]
                addrattrs['type'] = 'inet6'
                linkout[ifname]['addrs'][citems[3]] = addrattrs
        [linkCache.update_attrdict([ifname], linkattrs)
                    for ifname, linkattrs in linkout.items()]

    def _cache_get(self, type, attrlist, refresh=False):
        try:
            if ifupdownflags.flags.DRYRUN:
                return False
            if ifupdownflags.flags.CACHE:
                if self._fill_cache():
                    # if we filled the cache, return new data
                    return linkCache.get_attr(attrlist)
                if not refresh:
                    return linkCache.get_attr(attrlist)
            if type == 'link':
                self._link_fill(attrlist[0], refresh)
            elif type == 'addr':
                self._addr_fill(attrlist[0], refresh)
            else:
                self._link_fill(attrlist[0], refresh)
                self._addr_fill(attrlist[0], refresh)
            return linkCache.get_attr(attrlist)
        except Exception, e:
            self.logger.debug('_cache_get(%s) : [%s]'
                    %(str(attrlist), str(e)))
            pass
        return None

    def _cache_check(self, type, attrlist, value, refresh=False):
        try:
            attrvalue = self._cache_get(type, attrlist, refresh)
            if attrvalue and attrvalue == value:
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
        linkCache.invalidate()
        iproute2._cache_fill_done = False

    def batch_start(self):
        self.ipbatcbuf = ''
        self.ipbatch = True
        self.ipbatch_pause = False

    def add_to_batch(self, cmd):
        self.ipbatchbuf += cmd + '\n'

    def batch_pause(self):
        self.ipbatch_pause = True

    def batch_resume(self):
        self.ipbatch_pause = False

    def batch_commit(self):
        if not self.ipbatchbuf:
            self.ipbatchbuf = ''
            self.ipbatch = False
            self.ipbatch_pause = False
            return
        try:
            utils.exec_command('ip -force -batch -', stdin=self.ipbatchbuf)
        except:
            raise
        finally:
            self.ipbatchbuf = ''
            self.ipbatch = False
            self.ipbatch_pause = False

    def bridge_batch_commit(self):
        if not self.ipbatchbuf:
            self.ipbatchbuf = ''
            self.ipbatch = False
            self.ipbatch_pause = False
            return
        try:
            utils.exec_command('bridge -force -batch -', stdin=self.ipbatchbuf)
        except:
            raise
        finally:
            self.ipbatchbuf = ''
            self.ipbatch = False
            self.ipbatch_pause = False

    def addr_show(self, ifacename=None):
        if ifacename:
            if not self.link_exists(ifacename):
                return
            return utils.exec_commandl(['ip', '-o', 'addr', 'show', 'dev',
                                        ifacename])
        else:
            return utils.exec_commandl(['ip', '-o', 'addr', 'show'])

    def link_show(self, ifacename=None):
        if ifacename:
            return utils.exec_commandl(['ip', '-o', '-d', 'link', 'show', 'dev',
                                        ifacename])
        else:
            return utils.exec_commandl(['ip', '-o', '-d', 'link', 'show'])

    def addr_add(self, ifacename, address, broadcast='+',
                    peer=None, scope=None, preferred_lifetime=None):
        if not address:
            return
        cmd = 'addr add %s' %address
        if broadcast:
            cmd += ' broadcast %s' %broadcast
        if peer:
            cmd += ' peer %s' %peer
        if scope:
            cmd += ' scope %s' %scope
        if preferred_lifetime:
            cmd += ' preferred_lft %s' %preferred_lifetime
        cmd += ' dev %s' %ifacename
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self._cache_update([ifacename, 'addrs', address], {})

    def addr_del(self, ifacename, address, broadcast=None,
                    peer=None, scope=None):
        """ Delete ipv4 address """
        if not address:
            return
        if not self._cache_get('addr', [ifacename, 'addrs', address]):
            return
        cmd = 'addr del %s' %address
        if broadcast:
            cmd += 'broadcast %s' %broadcast
        if peer:
            cmd += 'peer %s' %peer
        if scope:
            cmd += 'scope %s' %scope
        cmd += ' dev %s' %ifacename
        utils.exec_command('ip %s' % cmd)
        self._cache_delete([ifacename, 'addrs', address])

    def addr_flush(self, ifacename):
        cmd = 'addr flush dev %s' %ifacename
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self._cache_delete([ifacename, 'addrs'])

    def del_addr_all(self, ifacename, skip_addrs=[]):
        if not skip_addrs: skip_addrs = []
        runningaddrsdict = self.addr_get(ifacename)
        try:
            # XXX: ignore errors. Fix this to delete secondary addresses
            # first
            [self.addr_del(ifacename, a) for a in
                set(runningaddrsdict.keys()).difference(skip_addrs)]
        except:
            # ignore errors
            pass

    def addr_get(self, ifacename, details=True, refresh=False):
        addrs = self._cache_get('addr', [ifacename, 'addrs'],
                                refresh=refresh)
        if not addrs:
            return None
        if details:
            return addrs
        return addrs.keys()

    def addr_add_multiple(self, ifacename, addrs, purge_existing=False):
        # purges address
        if purge_existing:
            # if perfmode is not set and also if iface has no sibling
            # objects, purge addresses that are not present in the new
            # config
            runningaddrs = self.addr_get(ifacename, details=False)
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
                self.log_warn(str(e))
        for a in addrs:
            try:
                self.addr_add(ifacename, a)
            except Exception, e:
                self.logger.error(str(e))

    def _link_set_ifflag(self, ifacename, value):
        # Dont look at the cache, the cache may have stale value
        # because link status can be changed by external
        # entity (One such entity is ifupdown main program)
        cmd = 'link set dev %s %s' %(ifacename, value.lower())
        if self.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)

    def link_up(self, ifacename):
        self._link_set_ifflag(ifacename, 'UP')

    def link_down(self, ifacename):
        self._link_set_ifflag(ifacename, 'DOWN')

    def link_set(self, ifacename, key, value=None,
                 force=False, type=None, state=None):
        if not force:
            if (key not in ['master', 'nomaster'] and
                self._cache_check('link', [ifacename, key], value)):
                return
        cmd = 'link set dev %s' %ifacename
        if type:
            cmd += ' type %s' %type
        cmd += ' %s' %key
        if value:
            cmd += ' %s' %value
        if state:
            cmd += ' %s' %state
        if self.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        if key not in ['master', 'nomaster']:
            self._cache_update([ifacename, key], value)

    def link_set_hwaddress(self, ifacename, hwaddress, force=False):
        if not force:
            if self._cache_check('link', [ifacename, 'hwaddress'], hwaddress):
               return
        self.link_down(ifacename)
        cmd = 'link set dev %s address %s' %(ifacename, hwaddress)
        if self.ipbatch:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self.link_up(ifacename)
        self._cache_update([ifacename, 'hwaddress'], hwaddress)

    def link_set_mtu(self, ifacename, mtu):
        if ifupdownflags.flags.DRYRUN:
            return True
        if not mtu or not ifacename: return
        with open('/sys/class/net/%s/mtu' % ifacename, 'w') as f:
            f.write(mtu)
        self._cache_update([ifacename, 'mtu'], mtu)

    def link_set_alias(self, ifacename, alias):
        if not alias:
            utils.exec_user_command('echo "" > /sys/class/net/%s/ifalias'
                                    % ifacename)
        else:
            self.write_file('/sys/class/net/%s/ifalias' % ifacename, alias)

    def link_get_alias(self, ifacename):
        return self.read_file_oneline('/sys/class/net/%s/ifalias'
                    %ifacename)

    def link_isloopback(self, ifacename):
        flags = self._cache_get('link', [ifacename, 'flags'])
        if not flags:
            return
        if 'LOOPBACK' in flags:
            return True
        return False

    def link_get_status(self, ifacename):
        return self._cache_get('link', [ifacename, 'ifflag'], refresh=True)

    def route_add_gateway(self, ifacename, gateway, vrf=None, metric=None):
        if not gateway:
           return
        if not vrf:
            cmd = 'ip route add default via %s' %gateway
        else:
            cmd = 'ip route add table %s default via %s' %(vrf, gateway)
        # Add metric
        if metric:
            cmd += 'metric %s' %metric
        cmd += ' dev %s' %ifacename
        utils.exec_command(cmd)

    def route_del_gateway(self, ifacename, gateway, vrf=None, metric=None):
        # delete default gw
        if not gateway:
            return
        if not vrf:
            cmd = 'ip route del default via %s' %gateway
        else:
            cmd = 'ip route del table %s default via %s' %(vrf, gateway)
        if metric:
            cmd += ' metric %s' %metric
        cmd += ' dev %s' %ifacename
        utils.exec_command(cmd)

    def route6_add_gateway(self, ifacename, gateway):
        if not gateway:
            return
        return utils.exec_command('ip -6 route add default via %s dev %s' %
                                  (gateway, ifacename))

    def route6_del_gateway(self, ifacename, gateway):
        if not gateway:
            return
        return utils.exec_command('ip -6 route del default via %s dev %s' %
                                  (gateway, ifacename))

    def link_create_vlan(self, vlan_device_name, vlan_raw_device, vlanid):
        if self.link_exists(vlan_device_name):
            return
        utils.exec_command('ip link add link %s name %s type vlan id %d' %
                           (vlan_raw_device, vlan_device_name, vlanid))
        self._cache_update([vlan_device_name], {})

    def link_create_vlan_from_name(self, vlan_device_name):
        v = vlan_device_name.split('.')
        if len(v) != 2:
            self.logger.warn('invalid vlan device name %s' %vlan_device_name)
            return
        self.link_create_vlan(vlan_device_name, v[0], v[1])

    def link_create_macvlan(self, name, linkdev, mode='private'):
        if self.link_exists(name):
            return
        cmd = ('link add link %s' %linkdev +
                          ' name %s' %name +
                          ' type macvlan mode %s' %mode)
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self._cache_update([name], {})

    def get_vxlan_peers(self, dev, svcnodeip):
        cmd = 'bridge fdb show brport %s' % dev
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
                pass
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
            args += ' remote %s' %svcnodeip
        if ageing:
            args += ' ageing %s' %ageing
        if learning == 'off':
            args += ' nolearning'

        if self.link_exists(name):
            cmd = 'link set dev %s type vxlan dstport %d' %(name, VXLAN_UDP_PORT)
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
            cmd = 'link add dev %s type vxlan id %s dstport %d' %(name, vxlanid, VXLAN_UDP_PORT)

        if localtunnelip:
            args += ' local %s' %localtunnelip
        cmd += args

        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)

        # XXX: update linkinfo correctly
        self._cache_update([name], {})

    def link_exists(self, ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return os.path.exists('/sys/class/net/%s' %ifacename)

    def link_get_ifindex(self, ifacename):
        if ifupdownflags.flags.DRYRUN:
            return True
        return self.read_file_oneline('/sys/class/net/%s/ifindex' %ifacename)

    def is_vlan_device_by_name(self, ifacename):
        if re.search(r'\.', ifacename):
            return True
        return False

    def route_add(self, route):
        utils.exec_command('ip route add %s' % route)

    def route6_add(self, route):
        utils.exec_command('ip -6 route add %s' % route)

    def get_vlandev_attrs(self, ifacename):
        return (self._cache_get('link', [ifacename, 'link']),
                self._cache_get('link', [ifacename, 'linkinfo', 'vlanid']))

    def get_vxlandev_attrs(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo'])

    def get_vxlandev_learning(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo', 'learning'])

    def set_vxlandev_learning(self, ifacename, learn):
        if learn == 'on':
            utils.exec_command('ip link set dev %s type vxlan learning' %ifacename)
            self._cache_update([ifacename, 'linkinfo', 'learning'], 'on')
        else:
            utils.exec_command('ip link set dev %s type vxlan nolearning' %ifacename)
            self._cache_update([ifacename, 'linkinfo', 'learning'], 'off')

    def link_get_linkinfo_attrs(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo'])

    def link_get_mtu(self, ifacename, refresh=False):
        return self._cache_get('link', [ifacename, 'mtu'], refresh=refresh)

    def link_get_mtu_sysfs(self, ifacename):
        return self.read_file_oneline('/sys/class/net/%s/mtu'
                                      %ifacename)

    def link_get_kind(self, ifacename):
        return self._cache_get('link', [ifacename, 'kind'])

    def link_get_hwaddress(self, ifacename):
        address = self._cache_get('link', [ifacename, 'hwaddress'])
        # newly created logical interface addresses dont end up in the cache
        # read hwaddress from sysfs file for these interfaces
        if not address:
            address = self.read_file_oneline('/sys/class/net/%s/address'
                                             %ifacename)
        return address

    def link_create(self, ifacename, type, attrs={}):
        """ generic link_create function """
        if self.link_exists(ifacename):
            return
        cmd = 'link add'
        cmd += ' name %s type %s' %(ifacename, type)
        if attrs:
            for k, v in attrs.iteritems():
                cmd += ' %s' %k
                if v:
                    cmd += ' %s' %v
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self._cache_update([ifacename], {})

    def link_delete(self, ifacename):
        if not self.link_exists(ifacename):
            return
        cmd = 'link del %s' %ifacename
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            utils.exec_command('ip %s' % cmd)
        self._cache_invalidate()

    def link_get_master(self, ifacename):
        sysfs_master_path = '/sys/class/net/%s/master' %ifacename
        if os.path.exists(sysfs_master_path):
            link_path = os.readlink(sysfs_master_path)
            if link_path:
                return os.path.basename(link_path)
            else:
                return None
        else:
            return self._cache_get('link', [ifacename, 'master'])

    def bridge_port_vids_add(self, bridgeportname, vids):
        [utils.exec_command('bridge vlan add vid %s dev %s' %
                            (v, bridgeportname)) for v in vids]

    def bridge_port_vids_del(self, bridgeportname, vids):
        if not vids:
            return
        [utils.exec_command('bridge vlan del vid %s dev %s' %
                            (v, bridgeportname)) for v in vids]

    def bridge_port_vids_flush(self, bridgeportname, vid):
        utils.exec_command('bridge vlan del vid %s dev %s' %
                           (vid, bridgeportname))

    def bridge_port_vids_get(self, bridgeportname):
        utils.exec_command('/sbin/bridge vlan show %s' % bridgeportname)
        bridgeout = utils.exec_command('/sbin/bridge vlan show dev %s' %
                                       bridgeportname)
        if not bridgeout: return []
        brvlanlines = bridgeout.readlines()[2:]
        vids = [l.strip() for l in brvlanlines]
        return [v for v in vids if v]

    def bridge_port_vids_get_all(self):
        brvlaninfo = {}
        bridgeout = utils.exec_command('/sbin/bridge -c vlan show')
        if not bridgeout: return brvlaninfo
        brvlanlines = bridgeout.splitlines()
        brportname=None
        for l in brvlanlines[1:]:
            if l and not l.startswith(' ') and not l.startswith('\t'):
                attrs = l.split()
                brportname = attrs[0].strip()
                brvlaninfo[brportname] = {'pvid' : None, 'vlan' : []}
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
        if not self.supported_command['/sbin/bridge -c -json vlan show']:
            return {}
        brvlaninfo = {}
        try:
            bridgeout = utils.exec_command('/sbin/bridge -c -json vlan show')
        except:
            self.supported_command['/sbin/bridge -c -json vlan show'] = False
            self.logger.info('/sbin/bridge -c -json vlan show: skipping unsupported command')
            return {}
        if not bridgeout: return brvlaninfo
        try:
            vlan_json_dict = json.loads(bridgeout, encoding="utf-8")
        except Exception, e:
            self.logger.info('json loads failed with (%s)' %str(e))
            return {}
        return vlan_json_dict

    def bridge_port_pvid_add(self, bridgeportname, pvid):
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch('vlan add vid %s untagged pvid dev %s' %
                              (pvid, bridgeportname))
        else:
            utils.exec_command('bridge vlan add vid %s untagged pvid dev %s' %
                               (pvid, bridgeportname))

    def bridge_port_pvid_del(self, bridgeportname, pvid):
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch('vlan del vid %s untagged pvid dev %s' %
                              (pvid, bridgeportname))
        else:
            utils.exec_command('bridge vlan del vid %s untagged pvid dev %s' %
                               (pvid, bridgeportname))

    def bridge_port_pvids_get(self, bridgeportname):
        return self.read_file_oneline('/sys/class/net/%s/brport/pvid'
                                      %bridgeportname)

    def bridge_vids_add(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        if self.ipbatch and not self.ipbatch_pause:
            [self.add_to_batch('vlan add vid %s dev %s %s' %
                               (v, bridgeportname, target)) for v in vids]
        else:
            [utils.exec_command('bridge vlan add vid %s dev %s %s' %
                                (v, bridgeportname, target)) for v in vids]

    def bridge_vids_del(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        if self.ipbatch and not self.ipbatch_pause:
            [self.add_to_batch('vlan del vid %s dev %s %s' %
                               (v, bridgeportname, target)) for v in vids]
        else:
            [utils.exec_command('bridge vlan del vid %s dev %s %s' %
                                (v, bridgeportname, target)) for v in vids]

    def bridge_fdb_add(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        utils.exec_command('bridge fdb replace %s dev %s %s %s %s' %
                           (address, dev, vlan_str, target, dst_str))

    def bridge_fdb_append(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        utils.exec_command('bridge fdb append %s dev %s %s %s %s' %
                           (address, dev, vlan_str, target, dst_str))

    def bridge_fdb_del(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote
        utils.exec_command('bridge fdb del %s dev %s %s %s %s' %
                           (address, dev, vlan_str, target, dst_str))

    def bridge_is_vlan_aware(self, bridgename):
        filename = '/sys/class/net/%s/bridge/vlan_filtering' %bridgename
        if os.path.exists(filename) and self.read_file_oneline(filename) == '1':
            return True
        return False

    def bridge_port_get_bridge_name(self, bridgeport):
        filename = '/sys/class/net/%s/brport/bridge' %bridgeport
        try:
            return os.path.basename(os.readlink(filename))
        except:
            return None

    def bridge_port_exists(self, bridge, bridgeportname):
        try:
            return os.path.exists('/sys/class/net/%s/brif/%s'
                                  %(bridge, bridgeportname))
        except Exception:
            return False

    def bridge_fdb_show_dev(self, dev):
        try:
            fdbs = {}
            output = utils.exec_command('bridge fdb show dev %s' % dev)
            if output:
                for fdb_entry in output.splitlines():
                    try:
                        entries = fdb_entry.split()
                        fdbs.setdefault(entries[2], []).append(entries[0])
                    except:
                        self.logger.debug('%s: invalid fdb line \'%s\''
                                %(dev, fdb_entry))
                        pass
            return fdbs
        except Exception:
            return None

    def is_bridge(self, bridge):
        return os.path.exists('/sys/class/net/%s/bridge' %bridge)

    def is_link_up(self, ifacename):
        ret = False
        try:
            flags = self.read_file_oneline('/sys/class/net/%s/flags' %ifacename)
            iflags = int(flags, 16)
            if (iflags & 0x0001):
                ret = True
        except:
            ret = False
            pass
        return ret

    def ip_route_get_dev(self, prefix):
        try:
            output = utils.exec_command('ip route get %s' % prefix)
            if output:
               rline = output.splitlines()[0]
               if rline:
                    rattrs = rline.split()
                    return rattrs[rattrs.index('dev') + 1]
        except Exception, e:
            self.logger.debug('ip_route_get_dev: failed .. %s' %str(e))
            pass
        return None

    def link_get_lowers(self, ifacename):
        try:
            lowers = glob.glob("/sys/class/net/%s/lower_*" %ifacename)
            if not lowers:
                return []
            return [os.path.basename(l)[6:] for l in lowers]
        except:
            return []

    def link_get_uppers(self, ifacename):
        try:
            uppers = glob.glob("/sys/class/net/%s/upper_*" %ifacename)
            if not uppers:
                return None
            return [ os.path.basename(u)[6:] for u in uppers ]
        except:
            return None

    def link_get_vrfs(self):
        self._fill_cache()
        return linkCache.vrfs

    def get_brport_learning(self, ifacename):
        learn = self.read_file_oneline('/sys/class/net/%s/brport/learning'
                                       %ifacename)
        if learn and learn == '1':
            return 'on'
        else:
            return 'off'

    def set_brport_learning(self, ifacename, learn):
        if learn == 'off':
            return self.write_file('/sys/class/net/%s/brport/learning'
                                    %ifacename, '0')
        else:
            return self.write_file('/sys/class/net/%s/brport/learning'
                                    %ifacename, '1')
