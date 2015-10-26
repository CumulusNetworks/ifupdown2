#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from ifupdown.iface import *
from utilsbase import *
import os
import re
import logging
from cache import *

class brctl(utilsBase):
    """ This class contains helper functions to interact with the bridgeutils
    commands """

    _cache_fill_done = False

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)
        if self.CACHE and not brctl._cache_fill_done:
            if os.path.exists('/sbin/brctl'):
                self._bridge_fill()
            self._cache_fill_done = True

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
                     'mcsqi' : 'multicast_startup_query_interval'}

        mcattrsdivby100 = ['mclmi', 'mcmi', 'mcqpi', 'mcqi', 'mcqri', 'mcsqi']

        for m, s in mcattrmap.items():
            n = self.read_file_oneline('/sys/class/net/%s/bridge/%s'
                                    %(bridgename, s))
            if m in mcattrsdivby100:
                try:
                    v = int(n) / 100
                    mcattrs[m] = str(v)
                except Exception as e:
                    self.logger.warn('error getting mc attr %s (%s)'
                                     %(m, str(e)))
                    pass
            else:
                mcattrs[m] = n
        return mcattrs

    def _bridge_attrs_fill(self, bridgename):
        battrs = {}
        bports = {}

        brout = self.exec_command('/sbin/brctl showstp %s' %bridgename)
        chunks = re.split(r'\n\n', brout, maxsplit=0, flags=re.MULTILINE)

        try:
            # Get all bridge attributes
            broutlines = chunks[0].splitlines()
            #battrs['pathcost'] = broutlines[3].split('path cost')[1].strip()
            battrs['maxage'] = broutlines[4].split(
                                'bridge max age')[1].strip().replace('.00', '')
            battrs['hello'] = broutlines[5].split(
                                'bridge hello time')[1].strip().replace('.00',
                                                                        '')
            battrs['fd'] = broutlines[6].split(
                                    'bridge forward delay')[1].strip(
                                            ).replace('.00', '')
            battrs.update(self._bridge_get_mcattrs_from_sysfs(bridgename))

            # XXX: comment this out until mc attributes become available
            # with brctl again
            #battrs['hashel'] = broutlines[10].split('hash elasticity')[1].split()[0].strip()
            #battrs['hashmax'] = broutlines[10].split('hash max')[1].strip()
            #battrs['mclmc'] = broutlines[11].split('mc last member count')[1].split()[0].strip()
            #battrs['mciqc'] = broutlines[11].split('mc init query count')[1].strip()
            #battrs['mcrouter'] = broutlines[12].split('mc router')[1].split()[0].strip()
            ##battrs['mcsnoop'] = broutlines[12].split('mc snooping')[1].strip()
            #battrs['mclmt'] = broutlines[13].split('mc last member timer')[1].split()[0].strip()
        except Exception as e:
            self.logger.warn(str(e))
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
                bportattrs['mcrouter'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/multicast_router' %pname)
                bportattrs['mcfl'] = self.read_file_oneline(
                         '/sys/class/net/%s/brport/multicast_fast_leave' %pname)

                #bportattrs['mcrouters'] = bplines[6].split('mc router')[1].split()[0].strip()
                #bportattrs['mc fast leave'] = bplines[6].split('mc fast leave')[1].strip()
            except Exception as e:
                self.logger.warn(str(e))
                pass
            bports[pname] = bportattrs
            linkCache.update_attrdict([bridgename, 'linkinfo', 'ports'], bports)

    def _bridge_fill(self, bridgename=None, refresh=False):
        try:
            # if cache is already filled, return
            linkCache.get_attr([bridgename, 'linkinfo', 'fd'])
            return
        except:
            pass
        if not bridgename:
            brctlout = self.exec_command('/sbin/brctl show')
        else:
            brctlout = self.exec_command('/sbin/brctl show ' + bridgename)
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

    def _cache_get(self, attrlist, refresh=False):
        try:
            if self.DRYRUN:
                return None
            if self.CACHE:
                if not self._cache_fill_done: 
                    self._bridge_fill()
                    self._cache_fill_done = True
                    return linkCache.get_attr(attrlist)
                if not refresh:
                    return linkCache.get_attr(attrlist)
            self._bridge_fill(attrlist[0], refresh)
            return linkCache.get_attr(attrlist)
        except Exception as e:
            self.logger.debug('_cache_get(%s) : [%s]'
                    %(str(attrlist), str(e)))
            pass
        return None

    def _cache_check(self, attrlist, value, refresh=False):
        try:
            attrvalue = self._cache_get(attrlist, refresh)
            if attrvalue and attrvalue == value:
                return True
        except Exception as e:
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
        if self.DRYRUN: return
        linkCache.invalidate()

    def create_bridge(self, bridgename):
        if self.bridge_exists(bridgename):
            return
        self.exec_command('/sbin/brctl addbr %s' %bridgename)
        self._cache_update([bridgename], {})

    def delete_bridge(self, bridgename):
        if not self.bridge_exists(bridgename):
            return
        self.exec_command('/sbin/brctl delbr %s' %bridgename)
        self._cache_invalidate()

    def add_bridge_port(self, bridgename, bridgeportname):
        """ Add port to bridge """
        ports = self._cache_get([bridgename, 'linkinfo', 'ports'])
        if ports and ports.get(bridgeportname):
            return
        self.exec_command('/sbin/brctl addif ' + bridgename + ' ' +
                          bridgeportname)
        self._cache_update([bridgename, 'linkinfo', 'ports',
                            bridgeportname], {})

    def delete_bridge_port(self, bridgename, bridgeportname):
        """ Delete port from bridge """
        ports = self._cache_get([bridgename, 'linkinfo', 'ports'])
        if not ports or not ports.get(bridgeportname):
            return
        self.exec_command('/sbin/brctl delif ' + bridgename + ' ' +
                          bridgeportname)
        self._cache_delete([bridgename, 'linkinfo', 'ports',
                           'bridgeportname'])

    def set_bridgeport_attrs(self, bridgename, bridgeportname, attrdict):
        portattrs = self._cache_get([bridgename, 'linkinfo',
                                       'ports', bridgeportname])
        if portattrs == None: portattrs = {}
        for k, v in attrdict.iteritems():
            if self.CACHE:
                curval = portattrs.get(k)
                if curval and curval == v:
                    continue
            self.exec_command('/sbin/brctl set%s %s %s %s'
                              %(k, bridgename, bridgeportname, v))

    def set_bridgeport_attr(self, bridgename, bridgeportname,
                            attrname, attrval):
        if self._cache_check([bridgename, 'linkinfo', 'ports',
                        bridgeportname, attrname], attrval):
            return
        self.exec_command('/sbin/brctl set%s %s %s %s' %(attrname, bridgename,
                          bridgeportname, attrval))

    def set_bridge_attrs(self, bridgename, attrdict):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            if self._cache_check([bridgename, 'linkinfo', k], v):
                continue
            try:
                self.exec_command('/sbin/brctl set%s %s %s'
                                  %(k, bridgename, v))
            except Exception as e:
                self.logger.warn('%s: %s' %(bridgename, str(e)))
                pass

    def set_bridge_attr(self, bridgename, attrname, attrval):
        if self._cache_check([bridgename, 'linkinfo', attrname], attrval):
            return
        self.exec_command('/sbin/brctl set%s %s %s'
                          %(attrname, bridgename, attrval))

    def get_bridge_attrs(self, bridgename):
        return self._cache_get([bridgename, 'linkinfo'])

    def get_bridgeport_attrs(self, bridgename, bridgeportname):
        return self._cache_get([bridgename, 'linkinfo', 'ports',
                                      bridgeportname])

    def get_bridgeport_attr(self, bridgename, bridgeportname, attrname):
        return self._cache_get([bridgename, 'linkinfo', 'ports',
                                      bridgeportname, attrname])

    def set_stp(self, bridge, stp_state):
        self.exec_command('/sbin/brctl stp ' + bridge + ' ' + stp_state)

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
        self.exec_command('/sbin/brctl setageing ' + bridge + ' ' + ageing)

    def get_ageing(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/ageing_time'
                                     %bridge, self.conv_value_to_user)

    def set_bridgeprio(self, bridge, bridgeprio):
        self.exec_command('/sbin/brctl setbridgeprio ' + bridge + ' ' +
                            bridgeprio)

    def get_bridgeprio(self, bridge):
        return self.read_file_oneline(
                       '/sys/class/net/%s/bridge/priority' %bridge)

    def set_fd(self, bridge, fd):
        self.exec_command('/sbin/brctl setfd ' + bridge + ' ' + fd)

    def get_fd(self, bridge):
        return self.read_value_from_sysfs(
                            '/sys/class/net/%s/bridge/forward_delay'
                            %bridge, self.conv_value_to_user)

    def set_gcint(self, bridge, gcint):
        #cmd = '/sbin/brctl setgcint ' + bridge + ' ' + gcint
        raise Exception('set_gcint not implemented')

    def set_hello(self, bridge, hello):
        self.exec_command('/sbin/brctl sethello ' + bridge + ' ' + hello)

    def get_hello(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/hello_time'
                                          %bridge, self.conv_value_to_user)

    def set_maxage(self, bridge, maxage):
        self.exec_command('/sbin/brctl setmaxage ' + bridge + ' ' + maxage)

    def get_maxage(self, bridge):
        return self.read_value_from_sysfs('/sys/class/net/%s/bridge/max_age'
                                          %bridge, self.conv_value_to_user)

    def set_pathcost(self, bridge, port, pathcost):
        self.exec_command('/sbin/brctl setpathcost %s' %bridge + ' %s' %port +
                            ' %s' %pathcost)

    def get_pathcost(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/path_cost'
                                        %port)

    def set_portprio(self, bridge, port, prio):
        self.exec_command('/sbin/brctl setportprio %s' %bridge + ' %s' %port +
                          ' %s' %prio)

    def get_portprio(self, bridge, port):
        return self.read_file_oneline('/sys/class/net/%s/brport/priority'
                                        %port)

    def set_hashmax(self, bridge, hashmax):
        self.exec_command('/sbin/brctl sethashmax %s' %bridge + ' %s' %hashmax)

    def get_hashmax(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_max'
                                        %bridge)

    def set_hashel(self, bridge, hashel):
        self.exec_command('/sbin/brctl sethashel %s' %bridge + ' %s' %hashel)

    def get_hashel(self, bridge):
        return self.read_file_oneline('/sys/class/net/%s/bridge/hash_elasticity'
                                        %bridge)

    def set_mclmc(self, bridge, mclmc):
        self.exec_command('/sbin/brctl setmclmc %s' %bridge + ' %s' %mclmc)

    def get_mclmc(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_last_member_count'
                    %bridge)

    def set_mcrouter(self, bridge, mcrouter):
        self.exec_command('/sbin/brctl setmcrouter %s' %bridge +
                          ' %s' %mcrouter)

    def get_mcrouter(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_router' %bridge)

    def set_mcsnoop(self, bridge, mcsnoop):
        self.exec_command('/sbin/brctl setmcsnoop %s' %bridge +
                          ' %s' %mcsnoop)

    def get_mcsnoop(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_snooping' %bridge)

    def set_mcsqc(self, bridge, mcsqc):
        self.exec_command('/sbin/brctl setmcsqc %s' %bridge +
                          ' %s' %mcsqc)

    def get_mcsqc(self, bridge):
        return self.read_file_oneline(
                    '/sys/class/net/%s/bridge/multicast_startup_query_count'
                    %bridge)

    def set_mcqifaddr(self, bridge, mcqifaddr):
        self.exec_command('/sbin/brctl setmcqifaddr %s' %bridge +
                          ' %s' %mcqifaddr)

    def get_mcqifaddr(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_startup_query_use_ifaddr'
                 %bridge)

    def set_mcquerier(self, bridge, mcquerier):
        self.exec_command('/sbin/brctl setmcquerier %s' %bridge +
                          ' %s' %mcquerier)

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

        self.exec_command('/sbin/brctl setmcqv4src %s' %bridge +
                          ' %d %s' %(vlan, mcquerier)) 

    def del_mcqv4src(self, bridge, vlan):
        self.exec_command('/sbin/brctl delmcqv4src %s %d' %(bridge, vlan))

    def get_mcqv4src(self, bridge, vlan=None):
        mcqv4src = {}
        mcqout = self.exec_command('/sbin/brctl showmcqv4src %s' %bridge)
        if not mcqout: return None
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
        self.exec_command('/sbin/brctl setmclmi %s' %bridge +
                          ' %s' %mclmi)

    def get_mclmi(self, bridge):
        return self.read_file_oneline(
                 '/sys/class/net/%s/bridge/multicast_last_member_interval'
                 %bridge)

    def set_mcmi(self, bridge, mcmi):
        self.exec_command('/sbin/brctl setmcmi %s' %bridge +
                          ' %s' %mcmi)

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
