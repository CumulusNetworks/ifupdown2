#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
from collections import OrderedDict
from utilsbase import *
from cache import *

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
        if self.CACHE and not iproute2._cache_fill_done:
            self._link_fill()
            self._addr_fill()
            iproute2._cache_fill_done = True
        
    def _link_fill(self, ifacename=None, refresh=False):
        """ fills cache with link information
       
        if ifacename argument given, fill cache for ifacename, else
        fill cache for all interfaces in the system
        """

        linkout = {}
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
                if citems[i] == 'mtu': linkattrs['mtu'] = citems[i+1]
                elif citems[i] == 'state': linkattrs['state'] = citems[i+1]
                elif citems[i] == 'link/ether': linkattrs['hwaddress'] = citems[i+1]
                elif citems[i] == 'vlan' and citems[i+1] == 'id':
                    linkattrs['linkinfo'] = {'vlanid' : citems[i+2]}
                elif citems[i] == 'vxlan' and citems[i+1] == 'id':
                    vattrs = {'vxlanid' : citems[i+2],
                              'svcnode' : [],
                              'remote'  : [],
                              'ageing' : citems[i+2],
                              'learning': 'on'}
                    for j in range(i+2, len(citems)):
                        if citems[j] == 'local':
                            vattrs['local'] = citems[j+1]
                        elif citems[j] == 'svcnode':
                            vattrs['svcnode'].append(citems[j+1])
                        elif citems[j] == 'ageing':
                            vattrs['ageing'] = citems[j+1]
                        elif citems[j] == 'nolearning':
                            vattrs['learning'] = 'off'
                    # get vxlan peer nodes
                    peers = self.get_vxlan_peers(ifname)
                    if peers:
                        vattrs['remote'] = peers
                    linkattrs['linkinfo'] = vattrs
                    break
            #linkattrs['alias'] = self.read_file_oneline(
            #            '/sys/class/net/%s/ifalias' %ifname)
            linkout[ifname] = linkattrs
        [linkCache.update_attrdict([ifname], linkattrs)
                    for ifname, linkattrs in linkout.items()]

    def _addr_filter(self, addr, scope=None):
        default_addrs = ['127.0.0.1/8', '::1/128' , '0.0.0.0']
        if addr in default_addrs:
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
        if iproute2._cache_fill_done: return
        try:
            # Check if ifacename is already full, in which case, return
            if ifacename:
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
                if self._addr_filter(citems[3], scope=citems[5]):
                    continue
                addrattrs = {}
                addrattrs['scope'] = citems[5]
                addrattrs['type'] = 'inet'
                linkout[ifname]['addrs'][citems[3]] = addrattrs
            elif citems[2] == 'inet6':
                if self._addr_filter(citems[3], scope=citems[5]):
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
            if self.DRYRUN:
                return False
            if self.CACHE:
                if not iproute2._cache_fill_done: 
                    self._link_fill()
                    self._addr_fill()
                    iproute2._cache_fill_done = True
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
        if self.DRYRUN: return
        try:
            linkCache.add_attr(attrlist, value)
        except:
            pass

    def _cache_delete(self, attrlist):
        if self.DRYRUN: return
        try:
            linkCache.del_attr(attrlist)
        except:
            pass

    def _cache_invalidate(self):
        linkCache.invalidate()

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
            return
        try:
            self.exec_command_talk_stdin('ip -force -batch -',
                    stdinbuf=self.ipbatchbuf)
        except Exception:
            raise
        finally:
            self.ipbatchbuf = ''
            self.ipbatch = False
            self.ipbatch_pause = False

    def addr_show(self, ifacename=None):
        if ifacename:
            if not self.link_exists(ifacename):
                return
            return self.exec_commandl(['ip','-o', 'addr', 'show', 'dev',
                    '%s' %ifacename])
        else:
            return self.exec_commandl(['ip', '-o', 'addr', 'show'])

    def link_show(self, ifacename=None):
        if ifacename:
            return self.exec_commandl(['ip', '-o', '-d', 'link',
                    'show', 'dev', '%s' %ifacename])
        else:
            return self.exec_commandl(['ip', '-o', '-d', 'link', 'show'])

    def addr_add(self, ifacename, address, broadcast=None,
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
            self.exec_command('ip ' + cmd)
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
        self.exec_command('ip ' + cmd)
        self._cache_delete([ifacename, 'addrs', address])

    def addr_flush(self, ifacename):
        cmd = 'addr flush dev %s' %ifacename
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            self.exec_command('ip ' + cmd)
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

    def addr_get(self, ifacename, details=True):
        addrs = self._cache_get('addr', [ifacename, 'addrs'])
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
            self.exec_command('ip ' + cmd)

    def link_up(self, ifacename):
        self._link_set_ifflag(ifacename, 'UP')

    def link_down(self, ifacename):
        self._link_set_ifflag(ifacename, 'DOWN')

    def link_set(self, ifacename, key, value=None, force=False):
        if not force:
            if (key not in ['master', 'nomaster'] and
                self._cache_check('link', [ifacename, key], value)):
                return
        cmd = 'link set dev %s %s' %(ifacename, key)
        if value:
            cmd += ' %s' %value
        if self.ipbatch:
            self.add_to_batch(cmd)
        else:
            self.exec_command('ip ' + cmd)
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
            self.exec_command('ip ' + cmd)
        self.link_up(ifacename)
        self._cache_update([ifacename, 'hwaddress'], hwaddress)

    def link_set_alias(self, ifacename, alias):
        self.exec_commandl(['ip', 'link', 'set', 'dev',
                    ifacename, 'alias', alias])

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

    def route_add_gateway(self, ifacename, gateway, metric=None):
        if not gateway:
           return
        cmd = 'ip route add default via %s' %gateway
        # Add metric
        if metric:
            cmd += 'metric %s' %metric
        cmd += ' dev %s' %ifacename
        self.exec_command(cmd)

    def route_del_gateway(self, ifacename, gateway, metric=None):
        # delete default gw
        if not gateway:
            return
        cmd = 'ip route del default via %s' %gateway
        if metric:
            cmd += ' metric %s' %metric
        cmd += ' dev %s' %ifacename
        self.exec_command(cmd)

    def route6_add_gateway(self, ifacename, gateway):
        if not gateway:
            return
        return self.exec_command('ip -6 route add default via %s' %gateway +
                                 ' dev %s' %ifacename)

    def route6_del_gateway(self, ifacename, gateway):
        if not gateway:
            return
        return self.exec_command('ip -6 route del default via %s' %gateway +
                                 'dev %s' %ifacename)

    def link_create_vlan(self, vlan_device_name, vlan_raw_device, vlanid):
        if self.link_exists(vlan_device_name):
            return
        self.exec_command('ip link add link %s' %vlan_raw_device +
                          ' name %s' %vlan_device_name +
                          ' type vlan id %d' %vlanid)
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
            self.exec_command('ip %s' %cmd)
        self._cache_update([name], {})

    def get_vxlan_peers(self, dev):
        cmd = 'bridge fdb show brport %s' % dev
        cur_peers = []
        try:
            ps = subprocess.Popen((cmd).split(), stdout=subprocess.PIPE, close_fds=True)
            output = subprocess.check_output(('grep', '00:00:00:00:00:00'), stdin=ps.stdout)
            ps.wait()
            try:
                ppat = re.compile('\s+dst\s+(\d+.\d+.\d+.\d+)\s+')
                for l in output.split('\n'):
                    m = ppat.search(l)
                    if m:
                        cur_peers.append(m.group(1))
            except:
                self.logger.warn('error parsing ip link output')
                pass
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                self.logger.error(str(e))

        return cur_peers

    def link_create_vxlan(self, name, vxlanid,
                          localtunnelip=None,
                          svcnodeips=None,
                          remoteips=None,
                          learning='on',
                          ageing=None):
        if svcnodeips and remoteips:
            raise Exception("svcnodeip and remoteip is mutually exclusive")
        args = ''
        if localtunnelip:
            args += ' local %s' %localtunnelip
        if svcnodeips:
            for s in svcnodeips:
                args += ' svcnode %s' %s
        if ageing:
            args += ' ageing %s' %ageing
        if learning == 'off':
            args += ' nolearning'

        if self.link_exists(name):
            if not svcnodeips:
                args += ' svcnode 0.0.0.0'
            cmd = 'link set dev %s type vxlan dstport %d' %(name, VXLAN_UDP_PORT)
        else:
            cmd = 'link add dev %s type vxlan id %s dstport %d' %(name, vxlanid, VXLAN_UDP_PORT)
        cmd += args

        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            self.exec_command('ip %s' %cmd)

        # figure out the diff for remotes and do the bridge fdb updates
        cur_peers = set(self.get_vxlan_peers(name))
        if remoteips:
            new_peers = set(remoteips)
            del_list = cur_peers.difference(new_peers)
            add_list = new_peers.difference(cur_peers)
        else:
            del_list = cur_peers
            add_list = []

        try:
            for addr in del_list:
                self.bridge_fdb_del(name, '00:00:00:00:00:00', None, True, addr)
        except:
            pass

        try:
            for addr in add_list:
                self.bridge_fdb_append(name, '00:00:00:00:00:00', None, True, addr)
        except:
            pass

        # XXX: update linkinfo correctly
        self._cache_update([name], {})

    def link_exists(self, ifacename):
        if self.DRYRUN:
            return True
        return os.path.exists('/sys/class/net/%s' %ifacename)

    def is_vlan_device_by_name(self, ifacename):
        if re.search(r'\.', ifacename):
            return True
        return False

    def route_add(self, route):
        self.exec_command('ip route add ' + route)

    def route6_add(self, route):
        self.exec_command('ip -6 route add ' + route)

    def get_vlandev_attrs(self, ifacename):
        return (self._cache_get('link', [ifacename, 'linkinfo', 'link']),
                self._cache_get('link', [ifacename, 'linkinfo', 'vlanid']))

    def get_vxlandev_attrs(self, ifacename):
        return self._cache_get('link', [ifacename, 'linkinfo'])

    def link_get_mtu(self, ifacename):
        return self._cache_get('link', [ifacename, 'mtu'])

    def link_get_hwaddress(self, ifacename):
        address = self._cache_get('link', [ifacename, 'hwaddress'])
        # newly created logical interface addresses dont end up in the cache
        # read hwaddress from sysfs file for these interfaces
        if not address:
            address = self.read_file_oneline('/sys/class/net/%s/address'
                                             %ifacename)
        return address

    def link_create(self, ifacename, type, link=None):
        if self.link_exists(ifacename):
            return
        cmd = 'link add'
        if link:
            cmd += ' link %s' %link
        cmd += ' name %s type %s' %(ifacename, type)
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            self.exec_command('ip %s' %cmd)
        self._cache_update([ifacename], {})

    def link_delete(self, ifacename):
        if not self.link_exists(ifacename):
            return
        cmd = 'link del %s' %ifacename
        if self.ipbatch and not self.ipbatch_pause:
            self.add_to_batch(cmd)
        else:
            self.exec_command('ip %s' %cmd)
        self._cache_invalidate()

    def bridge_port_vids_add(self, bridgeportname, vids):
        [self.exec_command('bridge vlan add vid %s dev %s'
                          %(v, bridgeportname)) for v in vids]

    def bridge_port_vids_del(self, bridgeportname, vids):
        if not vids:
            return
        [self.exec_command('bridge vlan del vid %s dev %s'
                          %(v, bridgeportname)) for v in vids]

    def bridge_port_vids_flush(self, bridgeportname):
        self.exec_command('bridge vlan del vid %s dev %s'
                          %(vid, bridgeportname))

    def bridge_port_vids_get(self, bridgeportname):
        self.exec_command('/bin/bridge vlan show %s' %bridgeportname)
        bridgeout = self.exec_command('/bin/bridge vlan show dev %s'
                                      %bridgeportname)
        if not bridgeout: return []
        brvlanlines = bridgeout.readlines()[2:]
        vids = [l.strip() for l in brvlanlines]
        return [vid for v in vids if vid]

    def bridge_port_vids_get_all(self):
        brvlaninfo = {}
        bridgeout = self.exec_command('/bin/bridge vlan show')
        if not bridgeout: return brvlaninfo
        brvlanlines = bridgeout.splitlines()
        brportname=None
        for l in brvlanlines[1:]:
            if l and l[0] not in [' ', '\t']:
                brportname = None
            l=l.strip()
            if not l:
                brportname=None
                continue
            if 'PVID' in l:
		        attrs = l.split()
		        brportname = attrs[0]
		        brvlaninfo[brportname] = {'pvid' : attrs[1],
					                      'vlan' : []}
            elif brportname:
                if 'Egress Untagged' not in l:
		            brvlaninfo[brportname]['vlan'].append(l)
            elif not brportname:
                attrs = l.split()
                if attrs[1] == 'None' or 'Egress Untagged' in attrs[1]:
                    continue
                brportname = attrs[0]
                brvlaninfo[brportname] = {'vlan' : [attrs[1]]}
        return brvlaninfo

    def bridge_port_pvid_add(self, bridgeportname, pvid):
        self.exec_command('bridge vlan add vid %s untagged pvid dev %s'
                          %(pvid, bridgeportname))

    def bridge_port_pvid_del(self, bridgeportname, pvid):
        self.exec_command('bridge vlan del vid %s untagged pvid dev %s'
                          %(pvid, bridgeportname))

    def bridge_port_pvids_get(self, bridgeportname):
        return self.read_file_oneline('/sys/class/net/%s/brport/pvid'
                                      %bridgeportname)

    def bridge_vids_add(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        [self.exec_command('bridge vlan add vid %s dev %s %s'
                          %(v, bridgeportname, target)) for v in vids]

    def bridge_vids_del(self, bridgeportname, vids, bridge=True):
        target = 'self' if bridge else ''
        [self.exec_command('bridge vlan del vid %s dev %s %s'
                          %(v, bridgeportname, target)) for v in vids]

    def bridge_fdb_add(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        self.exec_command('bridge fdb replace %s dev %s %s %s %s'
                          %(address, dev, vlan_str, target, dst_str))

    def bridge_fdb_append(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan
 
        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote

        self.exec_command('bridge fdb append %s dev %s %s %s %s'
                          %(address, dev, vlan_str, target, dst_str))

    def bridge_fdb_del(self, dev, address, vlan=None, bridge=True, remote=None):
        target = 'self' if bridge else ''
        vlan_str = ''
        if vlan:
            vlan_str = 'vlan %s ' % vlan

        dst_str = ''
        if remote:
            dst_str = 'dst %s ' % remote
        self.exec_command('bridge fdb del %s dev %s %s %s %s'
                          %(address, dev, vlan_str, target, dst_str))

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
            output = self.exec_command('bridge fdb show dev %s' %dev)
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
            output = self.exec_command('ip route get %s' %prefix)
            if output:
               rline = output.splitlines()[0]
               if rline:
                    rattrs = rline.split()
                    return rattrs[rattrs.index('dev') + 1]
        except Exception, e:
            self.logger.debug('ip_route_get_dev: failed .. %s' %str(e))
            pass
        return None
