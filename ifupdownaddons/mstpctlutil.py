#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from utilsbase import *
from ifupdown.iface import *
from cache import *
import re
import json

class mstpctlutil(utilsBase):
    """ This class contains helper methods to interact with mstpd using
    mstputils commands """

    _cache_fill_done = False

    _bridgeattrmap = {'bridgeid' : 'bridge-id',
                     'maxage' : 'max-age',
                     'fdelay' : 'forward-delay',
                     'txholdcount' : 'tx-hold-count',
                     'maxhops' : 'max-hops',
                     'ageing' : 'ageing-time',
                     'hello' : 'hello-time',
                     'forcevers' : 'force-protocol-version'}

    _bridgeportattrmap = {'portadminedge' : 'admin-edge-port',
                     'portp2p' : 'admin-point-to-point',
                     'portrestrrole' : 'restricted-role',
                     'portrestrtcn' : 'restricted-TCN',
                     'bpduguard' : 'bpdu-guard-port',
                     'portautoedge' : 'auto-edge-port',
                     'portnetwork' : 'network-port',
                     'portbpdufilter' : 'bpdufilter-port'}

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)

    def is_mstpd_running(self):
        try:
            self.exec_command('/bin/pidof mstpd')
        except:
            return False
        else:
            return True

    def get_bridgeport_attr(self, bridgename, portname, attrname):
        try:
            return self.subprocess_check_output(['/sbin/mstpctl',
                       'showportdetail', '%s' %bridgename, '%s' %portname,
                       self._bridgeportattrmap[attrname]]).strip('\n')
        except Exception, e:
            pass
        return None

    def get_bridgeport_attrs(self, bridgename, portname):
        bridgeattrs = {}
        try:
            bridgeattrs = dict((k, self.get_bridgeport_attr(bridgename, v))
                                 for k, v in self._bridgeattrmap.items())
            bridgeattrs['treeprio'] = int(bridgeattrs.get('bridgeid',
                                     '').split('.')[0], base=16) * 4096
        except Exception, e:
            self.logger.warn(str(e))
            pass
        return bridgeattrs

    def cache_bridgeport_attrs(self,bridgename):
        '''
        This method grab output of a mstpctl showportdetail json and caches
        it this should save on the overhead of checking each attribute
        for every port in the bridge.
        '''
        self.mstpctl_bridgeport_attrs_dict = {}
        self.mstpctl_bridgeport_attrs_dict[bridgename] = {}
        try:
            showall_output = self.subprocess_check_output(['/sbin/mstpctl',
                         'showportdetail', bridgename, 'json'])
        except:
            pass
        if not showall_output or showall_output == '':
            return
        showall_output = showall_output.strip('\n')
        mstpctl_bridge_cache = json.loads(showall_output)
        for portname in mstpctl_bridge_cache.keys():
            # we will ignore the portid for now and just index
            # by bridgename, portname, and json attribute
            for portid in mstpctl_bridge_cache[portname].keys():
                self.mstpctl_bridgeport_attrs_dict[bridgename][portname] = {}
                for jsonAttr in mstpctl_bridge_cache[portname][portid].keys():
                    jsonVal = mstpctl_bridge_cache[portname][portid][jsonAttr]
                    self.mstpctl_bridgeport_attrs_dict[bridgename][portname]\
                                               [jsonAttr] = str(jsonVal)

    def get_mstpctl_bridgeport_attr(self,bridgename=None, portname=None,
                                    jsonAttr=None):
        '''
        Just return the JSON attribute we cached earlier making
        sure to convert integers to strings for later comparison.
        '''
        if not bridgename or not portname or not jsonAttr:
            return
        # just return the value or None if there is no JSON attr defined the
        # output will not show anything if the value is no so we default to no
        val = self.mstpctl_bridgeport_attrs_dict.get(bridgename,{}).get(portname,{}).\
              get(jsonAttr,'no')
        if val == 'True':
            val = 'yes'
         # some values are integers so we need to return only strings
        return str(val)

    def set_bridgeport_attrs(self, bridgename, bridgeportname, attrdict,
                             check=True):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            try:
                self.set_bridgeport_attr(self, bridgename, bridgeportname,
                        k, v, check)
            except Exception, e:
                self.logger.warn(str(e))

    def set_bridgeport_attr(self, bridgename, bridgeportname, attrname,
                            attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridgeport_attr(bridgename,
                                    bridgeportname, attrname)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        if attrname == 'treeportcost' or attrname == 'treeportprio':
            self.subprocess_check_output(['/sbin/mstpctl', 'set%s' %attrname,
                  '%s' %bridgename, '%s' %bridgeportname, '0', '%s' %attrvalue])
        else:
            self.subprocess_check_output(['/sbin/mstpctl', 'set%s' %attrname,
                  '%s' %bridgename, '%s' %bridgeportname, '%s' %attrvalue])

    def get_bridge_attrs(self, bridgename):
        bridgeattrs = {}
        try:
            bridgeattrs = dict((k, self.get_bridge_attr(bridgename, k))
                                 for k in self._bridgeattrmap.keys())
            bridgeattrs['treeprio'] = '%d' %(int(bridgeattrs.get('bridgeid',
                                     '').split('.')[0], base=16) * 4096)
            del bridgeattrs['bridgeid']
        except Exception, e:
            self.logger.debug(bridgeattrs)
            self.logger.debug(str(e))
            pass
        return bridgeattrs

    def get_bridge_attr(self, bridgename, attrname):
        try:
            return self.subprocess_check_output(['/sbin/mstpctl',
                       'showbridge', '%s' %bridgename,
                       self._bridgeattrmap[attrname]]).strip('\n')
        except Exception, e:
            pass
        return None

    def set_bridge_attr(self, bridgename, attrname, attrvalue, check=True):

        if check:
            attrvalue_curr = self.get_bridge_attr(bridgename, attrname)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        if attrname == 'treeprio':
            self.subprocess_check_call(['/sbin/mstpctl', 'set%s' %attrname,
                        '%s' %bridgename, '0',  '%s' %attrvalue])
        else:
            self.subprocess_check_call(['/sbin/mstpctl', 'set%s' %attrname,
                        '%s' %bridgename, '%s' %attrvalue])

    def set_bridge_attrs(self, bridgename, attrdict, check=True):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            try:
                self.set_bridge_attr(bridgename, k, v, check)
            except Exception, e:
                self.logger.warn('%s: %s' %(bridgename, str(e)))
                pass

    def get_bridge_treeprio(self, bridgename):
        try:
            bridgeid = subprocess.check_output(['/sbin/mstpctl',
                       'showbridge', '%s' %bridgename,
                       self._bridgeattrmap['bridgeid']]).strip('\n')
            return '%d' %(int(bridgeid.split('.')[0], base=16) * 4096)
        except:
            pass
        return None

    def set_bridge_treeprio(self, bridgename, attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridge_treeprio(bridgename)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        self.subprocess_check_output(['/sbin/mstpctl', 'settreeprio',
                        '%s' %bridgename, '0',  '%s' %attrvalue])

    def showbridge(self, bridgename=None):
        if bridgename:
            return self.exec_command('/sbin/mstpctl showbridge %s' %bridgename)
        else:
            return self.exec_command('/sbin/mstpctl showbridge')

    def showportdetail(self, bridgename):
        return self.exec_command('/sbin/mstpctl showportdetail %s' %bridgename)

    def mstpbridge_exists(self, bridgename):
        try:
            subprocess.check_call('mstpctl showbridge %s' %bridgename)
            return True
        except:
            return False
