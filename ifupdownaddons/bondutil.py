#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import re
from ifupdown.iface import *
from utilsbase import *
from iproute2 import *
from cache import *

class bondutil(utilsBase):
    """ This class contains methods to interact with linux kernel bond
    related interfaces """

    _cache_fill_done = False

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        if self.CACHE and not self._cache_fill_done:
            self._bond_linkinfo_fill_all()
            self._cache_fill_done = True

    def _bond_linkinfo_fill_attrs(self, bondname):
        try:
            linkCache.links[bondname]['linkinfo'] = {}
        except:
            linkCache.links[bondname] = {'linkinfo': {}}

        try:
            linkCache.set_attr([bondname, 'linkinfo', 'slaves'],
                self.read_file_oneline('/sys/class/net/%s/bonding/slaves'
                %bondname).split())
            linkCache.set_attr([bondname, 'linkinfo', 'mode'],
                self.read_file_oneline('/sys/class/net/%s/bonding/mode'
                %bondname).split()[0])
            linkCache.set_attr([bondname, 'linkinfo', 'xmit_hash_policy'],
                self.read_file_oneline(
                    '/sys/class/net/%s/bonding/xmit_hash_policy'
                    %bondname).split()[0])
            linkCache.set_attr([bondname, 'linkinfo', 'lacp_rate'],
                self.read_file_oneline('/sys/class/net/%s/bonding/lacp_rate'
                                       %bondname).split()[1])
            linkCache.set_attr([bondname, 'linkinfo', 'ad_sys_priority'],
                self.read_file_oneline('/sys/class/net/%s/bonding/ad_sys_priority'
                                       %bondname))
            linkCache.set_attr([bondname, 'linkinfo', 'ad_sys_mac_addr'],
                self.read_file_oneline('/sys/class/net/%s/bonding/ad_sys_mac_addr'
                                       %bondname))
            map(lambda x: linkCache.set_attr([bondname, 'linkinfo', x],
                   self.read_file_oneline('/sys/class/net/%s/bonding/%s'
                        %(bondname, x))),
                       ['use_carrier', 'miimon', 'min_links', 'num_unsol_na',
                        'num_grat_arp', 'lacp_bypass_allow', 'lacp_bypass_period', 
                        'lacp_bypass_all_active'])
        except Exception, e:
            pass

    def _bond_linkinfo_fill_all(self):
        bondstr = self.read_file_oneline('/sys/class/net/bonding_masters')
        if not bondstr:
            return
        [self._bond_linkinfo_fill_attrs(b) for b in bondstr.split()]

    def _bond_linkinfo_fill(self, bondname, refresh=False):
        try:
            linkCache.get_attr([bondname, 'linkinfo', 'slaves'])
            return
        except:
            pass
        bondstr = self.read_file_oneline('/sys/class/net/bonding_masters')
        if (not bondstr or bondname not in bondstr.split()):
            raise Exception('bond %s not found' %bondname)
        self._bond_linkinfo_fill_attrs(bondname)

    def _cache_get(self, attrlist, refresh=False):
        try:
            if self.DRYRUN:
                return None
            if self.CACHE:
                if not bondutil._cache_fill_done: 
                    self._bond_linkinfo_fill_all()
                    bondutil._cache_fill_done = True
                    return linkCache.get_attr(attrlist)
                if not refresh:
                    return linkCache.get_attr(attrlist)
            self._bond_linkinfo_fill(attrlist[0], refresh)
            return linkCache.get_attr(attrlist)
        except Exception, e:
            self.logger.debug('_cache_get(%s) : [%s]'
                    %(str(attrlist), str(e)))
            pass
        return None

    def _cache_check(self, attrlist, value, refresh=False):
        try:
            attrvalue = self._cache_get(attrlist, refresh)
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
            if attrlist[-1] == 'slaves':
                linkCache.add_to_attrlist(attrlist, value)
                return
            linkCache.add_attr(attrlist, value)
        except:
            pass

    def _cache_delete(self, attrlist, value=None):
        if self.DRYRUN: return
        try:
            if attrlist[-1] == 'slaves':
                linkCache.remove_from_attrlist(attrlist, value)
                return
            linkCache.del_attr(attrlist)
        except:
            pass

    def _cache_invalidate(self):
        if self.DRYRUN: return
        linkCache.invalidate()

    def set_attrs(self, bondname, attrdict, prehook):
        for attrname, attrval in attrdict.items():
            if (self._cache_check([bondname, 'linkinfo',
                attrname], attrval)):
                continue
            if (attrname == 'mode' or attrname == 'xmit_hash_policy' or
                    attrname == 'lacp_rate' or attrname == 'min_links'):
                if prehook:
                    prehook(bondname)
            try:
                if ((attrname not in ['lacp_rate',
                                      'lacp_bypass_allow',
                                      'lacp_bypass_period',
                                      'lacp_bypass_all_active']) or
                    ('mode', '802.3ad') in attrdict.items()):
                    self.write_file('/sys/class/net/%s/bonding/%s'
                                    %(bondname, attrname), attrval)
            except Exception, e:
                if self.FORCE:
                    self.logger.warn(str(e))
                    pass
                else:
                    raise

    def set_use_carrier(self, bondname, use_carrier):
        if not use_carrier or (use_carrier != '0' and use_carrier != '1'):
            return
        if (self._cache_check([bondname, 'linkinfo', 'use_carrier'],
                use_carrier)):
                return
        self.write_file('/sys/class/net/%s' %bondname +
                         '/bonding/use_carrier', use_carrier)
        self._cache_update([bondname, 'linkinfo',
                            'use_carrier'], use_carrier)

    def get_use_carrier(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'use_carrier'])

    def set_xmit_hash_policy(self, bondname, hash_policy, prehook=None):
        valid_values = ['layer2', 'layer3+4', 'layer2+3']
        if not hash_policy:
            return
        if hash_policy not in valid_values:
            raise Exception('invalid hash policy value %s' %hash_policy)
        if (self._cache_check([bondname, 'linkinfo', 'xmit_hash_policy'],
                hash_policy)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s' %bondname +
                         '/bonding/xmit_hash_policy', hash_policy)
        self._cache_update([bondname, 'linkinfo', 'xmit_hash_policy'],
                hash_policy)

    def get_xmit_hash_policy(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'xmit_hash_policy'])

    def set_miimon(self, bondname, miimon):
        if (self._cache_check([bondname, 'linkinfo', 'miimon'],
                miimon)):
            return
        self.write_file('/sys/class/net/%s' %bondname +
                '/bonding/miimon', miimon)
        self._cache_update([bondname, 'linkinfo', 'miimon'], miimon)

    def get_miimon(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'miimon'])

    def set_mode(self, bondname, mode, prehook=None):
        valid_modes = ['balance-rr', 'active-backup', 'balance-xor',
                       'broadcast', '802.3ad', 'balance-tlb', 'balance-alb']
        if not mode:
            return
        if mode not in valid_modes:
            raise Exception('invalid mode %s' %mode)
        if (self._cache_check([bondname, 'linkinfo', 'mode'],
                mode)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s' %bondname + '/bonding/mode', mode)
        self._cache_update([bondname, 'linkinfo', 'mode'], mode)

    def get_mode(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'mode'])

    def set_lacp_rate(self, bondname, lacp_rate, prehook=None, posthook=None):
        if not lacp_rate or (lacp_rate != '0' and lacp_rate != '1'):
            return
        if (self._cache_check([bondname, 'linkinfo', 'lacp_rate'],
                lacp_rate)):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' %bondname +
                            '/bonding/lacp_rate', lacp_rate)
        except:
            raise
        finally:
            if posthook:
                prehook(bondname)
            self._cache_update([bondname, 'linkinfo',
                                'lacp_rate'], lacp_rate)

    def get_lacp_rate(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'lacp_rate'])

    def set_lacp_fallback_allow(self, bondname, allow, prehook=None, posthook=None):
        if (self._cache_check([bondname, 'linkinfo', 'lacp_bypass_allow'],
                lacp_bypass_allow)):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' %bondname +
                            '/bonding/lacp_bypass_allow', allow)
        except:
            raise
        finally:
            if posthook:
                posthook(bondname)
            self._cache_update([bondname, 'linkinfo',
                               'lacp_bypass_allow'], allow)

    def get_lacp_fallback_allow(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'lacp_bypass_allow'])

    def set_lacp_fallback_period(self, bondname, period, prehook=None, posthook=None):
        if (self._cache_check([bondname, 'linkinfo', 'lacp_bypass_period'],
                lacp_bypass_period)):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' %bondname + 
                            '/bonding/lacp_bypass_period', period)
        except:
            raise
        finally:
            if posthook:
                posthook(bondname)
            self._cache_update([bondname, 'linkinfo',
                               'lacp_bypass_period'], period)

    def get_lacp_fallback_period(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'lacp_bypass_period']) 

    def set_min_links(self, bondname, min_links, prehook=None):
        if (self._cache_check([bondname, 'linkinfo', 'min_links'],
                min_links)):
            return
        if prehook:
            prehook(bondname)
        self.write_file('/sys/class/net/%s/bonding/min_links' %bondname,
                         min_links)
        self._cache_update([bondname, 'linkinfo', 'min_links'], min_links)

    def get_min_links(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'min_links'])

    def set_lacp_fallback_priority(self, bondname, port, val):
        slavefile = '/sys/class/net/%s/bonding_slave/lacp_bypass_priority' %port
        if os.path.exists(slavefile):
            self.write_file(slavefile, val)

    def get_lacp_fallback_priority(self, bondname):
        slaves = self.get_slaves(bondname)
        if not slaves:
            return slaves
        prios = []
        for slave in slaves:
            priofile = '/sys/class/net/%s/bonding_slave/lacp_bypass_priority' %slave
            if os.path.exists(priofile):
                val = self.read_file_oneline(priofile)
                if val and val != '0':
                    prio = slave + '=' + val
                    prios.append(prio)
        prios.sort()
        prio_str = ' '.join(prios)
        return prio_str

    def set_lacp_fallback_all_active(self, bondname, useprio, prehook=None, posthook=None):
        if (self._cache_check([bondname, 'linkinfo', 'lacp_bypass_all_active'], 
                              lacp_bypass_all_active)):
            return
        if prehook:
            prehook(bondname)
        try:
            self.write_file('/sys/class/net/%s' %bondname +
                            '/bonding/lacp_bypass_all_active', useprio)
        except:
            raise
        finally:
            if posthook:
                posthook(bondname)
            self._cache_update([bondname, 'linkinfo',
                               'lacp_bypass_all_active'], useprio)

    def get_lacp_fallback_all_active(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'lacp_bypass_all_active'])

    def get_ad_sys_mac_addr(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'ad_sys_mac_addr'])

    def get_ad_sys_priority(self, bondname):
        return self._cache_get([bondname, 'linkinfo', 'ad_sys_priority'])

    def enslave_slave(self, bondname, slave, prehook=None, posthook=None):
        slaves = self._cache_get([bondname, 'linkinfo', 'slaves'])
        if slaves and slave in slaves: return
        if prehook:
            prehook(slave)
        self.write_file('/sys/class/net/%s' %bondname +
                         '/bonding/slaves', '+' + slave)
        if posthook:
            posthook(slave)
        self._cache_update([bondname, 'linkinfo', 'slaves'], slave) 

    def remove_slave(self, bondname, slave):
        slaves = self._cache_get([bondname, 'linkinfo', 'slaves'])
        if slave not in slaves:
            return
        sysfs_bond_path = ('/sys/class/net/%s' %bondname +
                           '/bonding/slaves')
        if not os.path.exists(sysfs_bond_path):
           return
        self.write_file(sysfs_bond_path, '-' + slave)
        self._cache_delete([bondname, 'linkinfo', 'slaves'], slave) 

    def remove_slaves_all(self, bondname):
        if not _self._cache_get([bondname, 'linkinfo', 'slaves']):
            return
        slaves = None
        sysfs_bond_path = ('/sys/class/net/%s' %bondname +
                           '/bonding/slaves')
        ipcmd = iproute2()
        try:
            f = open(sysfs_bond_path, 'r')
            slaves = f.readline().strip().split()
            f.close()
        except IOError, e:
            raise Exception('error reading slaves of bond %s' %bondname
                + '(' + str(e) + ')')
        for slave in slaves:
            ipcmd.ip_link_down(slave)
            try:
                self.remove_slave(bondname, slave)
            except Exception, e:
                if not self.FORCE:
                    raise Exception('error removing slave %s'
                        %slave + ' from bond %s' %bondname +
                        '(%s)' %str(e))
                else:
                    pass
        self._cache_del([bondname, 'linkinfo', 'slaves'])

    def load_bonding_module(self):
        return self.exec_command('modprobe -q bonding')

    def create_bond(self, bondname):
        if self.bond_exists(bondname):
            return
        sysfs_net = '/sys/class/net/'
        sysfs_bonding_masters = sysfs_net + 'bonding_masters'
        if not os.path.exists(sysfs_bonding_masters):
            self.logger.debug('loading bonding driver')
            self.load_bonding_module()
        self.write_file(sysfs_bonding_masters, '+' + bondname)
        self._cache_update([bondname], {})

    def delete_bond(self, bondname):
        if not os.path.exists('/sys/class/net/%s' %bondname):
            return
        self.write_file('/sys/class/net/bonding_masters', '-' + bondname)
        self._cache_delete([bondname])

    def unset_master(self, bondname):
        print 'Do nothing yet'
        return 0

    def get_slaves(self, bondname):
        slaves = self._cache_get([bondname, 'linkinfo', 'slaves'])
        if slaves:
            return list(slaves)
        slavefile = '/sys/class/net/%s/bonding/slaves' %bondname
        if os.path.exists(slavefile):
            buf = self.read_file_oneline(slavefile)
            if buf:
                slaves = buf.split()
        if not slaves:
            return slaves
        self._cache_update([bondname, 'linkinfo', 'slaves'], slaves)
        return list(slaves)

    def bond_slave_exists(self, bond, slave):
        slaves = self.get_slaves(bond)
        if not slaves: return False
        return slave in slaves

    def bond_exists(self, bondname):
        return os.path.exists('/sys/class/net/%s/bonding' %bondname)
