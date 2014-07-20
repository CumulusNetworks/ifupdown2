#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
from collections import OrderedDict
from utilsbase import *
from cache import *

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
            else:
                linkattrs = {}
                linkattrs['addrs'] = OrderedDict({})
                try:
                    linkout[ifname].update(linkattrs)
                except KeyError:
                    linkout[ifname] = linkattrs

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

    def link_set(self, ifacename, key, value=None):
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

    def link_exists(self, ifacename):
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

    def link_get_mtu(self, ifacename):
        return self._cache_get('link', [ifacename, 'mtu'])

    def link_get_hwaddress(self, ifacename):
        return self._cache_get('link', [ifacename, 'hwaddress'])

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
