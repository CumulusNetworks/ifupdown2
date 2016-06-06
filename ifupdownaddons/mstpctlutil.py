#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

from cache import MSTPAttrsCache
from utilsbase import *
from ifupdown.iface import *
from ifupdown.utils import utils
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
            utils.exec_command('/bin/pidof mstpd')
        except:
            return False
        else:
            return True

    def get_bridgeport_attr(self, bridgename, portname, attrname):
        try:
            cmdl = ['/sbin/mstpctl', 'showportdetail', bridgename, portname,
                    self._bridgeportattrmap[attrname]]
            return utils.exec_commandl(cmdl).strip('\n')
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

    def _get_mstpctl_bridgeport_attr_from_cache(self, bridgename):
        attrs = MSTPAttrsCache.get(bridgename)
        if not attrs:
            try:
                cmd = ['/sbin/mstpctl', 'showportdetail', bridgename, 'json']
                output = utils.exec_commandl(cmd)
                if not output:
                    return None
            except Exception as e:
                self.logger.info(str(e))
                return None
            mstpctl_bridgeport_attrs_dict = {}
            try:
                mstpctl_bridge_cache = json.loads(output.strip('\n'))
                for portname in mstpctl_bridge_cache.keys():
                    # we will ignore the portid for now and just index
                    # by bridgename, portname, and json attribute
                    for portid in mstpctl_bridge_cache[portname].keys():
                        mstpctl_bridgeport_attrs_dict[portname] = {}
                        for jsonAttr in mstpctl_bridge_cache[portname][portid].keys():
                            jsonVal = mstpctl_bridge_cache[portname][portid][jsonAttr]
                            mstpctl_bridgeport_attrs_dict[portname][jsonAttr] = str(jsonVal)
                MSTPAttrsCache.set(bridgename, mstpctl_bridgeport_attrs_dict)
                return mstpctl_bridgeport_attrs_dict
            except Exception as e:
                self.logger.info('%s: cannot fetch mstpctl bridge port attributes: %s', str(e))
        return attrs

    def get_mstpctl_bridgeport_attr(self, bridgename, portname, attr):
        attrs = self._get_mstpctl_bridgeport_attr_from_cache(bridgename)
        if not attrs:
            return 'no'
        else:
            val = attrs.get(portname,{}).get(attr, 'no')
            if val == 'True':
                val = 'yes'
            return str(val)

    def set_bridgeport_attrs(self, bridgename, bridgeportname, attrdict,
                             check=True):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            try:
                self.set_bridgeport_attr(bridgename, bridgeportname,
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
            utils.exec_commandl(['/sbin/mstpctl', 'set%s' % attrname,
                                 '%s' % bridgename, '%s' % bridgeportname, '0',
                                 '%s' % attrvalue])
        else:
            utils.exec_commandl(['/sbin/mstpctl', 'set%s' % attrname,
                                 '%s' % bridgename, '%s' % bridgeportname,
                                 '%s' % attrvalue])

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
            cmdl = ['/sbin/mstpctl', 'showbridge', bridgename,
                    self._bridgeattrmap[attrname]]
            return utils.exec_commandl(cmdl).strip('\n')
        except Exception, e:
            pass
        return None

    def set_bridge_attr(self, bridgename, attrname, attrvalue, check=True):

        if check:
            attrvalue_curr = self.get_bridge_attr(bridgename, attrname)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        if attrname == 'treeprio':
            utils.exec_commandl(['/sbin/mstpctl', 'set%s' % attrname,
                                 '%s' % bridgename, '0', '%s' % attrvalue],
                                stdout=False, stderr=None)
        else:
            utils.exec_commandl(['/sbin/mstpctl', 'set%s' % attrname,
                                 '%s' % bridgename, '%s' % attrvalue],
                                stdout=False, stderr=None)

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
            cmdl = ['/sbin/mstpctl',
                    'showbridge',
                    bridgename,
                    self._bridgeattrmap['bridgeid']]

            bridgeid = utils.exec_commandl(cmdl).strip('\n')
            return '%d' %(int(bridgeid.split('.')[0], base=16) * 4096)
        except:
            pass
        return None

    def set_bridge_treeprio(self, bridgename, attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridge_treeprio(bridgename)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        utils.exec_commandl(['/sbin/mstpctl', 'settreeprio', bridgename, '0',
                             str(attrvalue)])

    def showbridge(self, bridgename=None):
        if bridgename:
            return utils.exec_command('/sbin/mstpctl showbridge %s' % bridgename)
        else:
            return utils.exec_command('/sbin/mstpctl showbridge')

    def showportdetail(self, bridgename):
        return utils.exec_command('/sbin/mstpctl showportdetail %s' % bridgename)

    def mstpbridge_exists(self, bridgename):
        try:
            utils.exec_command('mstpctl showbridge %s' % bridgename, stdout=False)
            return True
        except:
            return False
