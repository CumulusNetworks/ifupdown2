#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.cache import *
    from ifupdown2.ifupdownaddons.utilsbase import *
except ImportError:
    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.cache import *
    from ifupdownaddons.utilsbase import *


class mstpctlutil(utilsBase):
    """ This class contains helper methods to interact with mstpd using
    mstputils commands """

    _DEFAULT_PORT_PRIO = '128'

    _cache_fill_done = False

    _bridgeattrmap = {'bridgeid' : 'bridge-id',
                     'maxage' : 'max-age',
                     'fdelay' : 'forward-delay',
                     'txholdcount' : 'tx-hold-count',
                     'maxhops' : 'max-hops',
                     'ageing' : 'ageing-time',
                     'hello' : 'hello-time',
                     'forcevers' : 'force-protocol-version'}

    _bridge_jsonAttr_map = {
                            'treeprio': 'bridgeId',
                            'maxage': 'maxAge',
                            'fdelay': 'fwdDelay',
                            'txholdcount': 'txHoldCounter',
                            'maxhops': 'maxHops',
                            'ageing': 'ageingTime',
                            'hello': 'helloTime',
                            'forcevers': 'forceProtocolVersion',
                            }

    _bridgeportattrmap = {'portadminedge' : 'admin-edge-port',
                     'portp2p' : 'admin-point-to-point',
                     'portrestrrole' : 'restricted-role',
                     'portrestrtcn' : 'restricted-TCN',
                     'bpduguard' : 'bpdu-guard-port',
                     'portautoedge' : 'auto-edge-port',
                     'portnetwork' : 'network-port',
                     'portbpdufilter' : 'bpdufilter-port',
                     'portpathcost' : 'external-port-cost',
                     'treeportcost' : 'internal-port-cost'}

    def __init__(self, *args, **kargs):
        utilsBase.__init__(self, *args, **kargs)

    @classmethod
    def reset(cls):
        cls._cache_fill_done = False

    def is_mstpd_running(self):
        try:
            utils.exec_command('%s mstpd'%utils.pidof_cmd)
        except:
            return False
        else:
            return True

    def _extract_bridge_port_prio(self, portid):
        try:
            return str(int(portid[0], 16) * 16)
        except:
            return mstpctlutil._DEFAULT_PORT_PRIO

    def _get_bridge_and_port_attrs_from_cache(self, bridgename):
        attrs = MSTPAttrsCache.get(bridgename, None)
        if attrs is not None:
            return attrs
        mstpctl_bridgeport_attrs_dict = {}
        try:
            cmd = [utils.mstpctl_cmd,
                   'showportdetail', bridgename, 'json']
            output = utils.exec_commandl(cmd)
            if not output:
                MSTPAttrsCache.set(bridgename, mstpctl_bridgeport_attrs_dict)
                return mstpctl_bridgeport_attrs_dict
        except Exception as e:
            self.logger.info(str(e))
            return mstpctl_bridgeport_attrs_dict
        try:
            mstpctl_bridge_cache = json.loads(output.strip('\n'))
            for portname in mstpctl_bridge_cache.keys():
                for portid in mstpctl_bridge_cache[portname].keys():
                    mstpctl_bridgeport_attrs_dict[portname] = {}
                    mstpctl_bridgeport_attrs_dict[portname]['treeportprio'] = self._extract_bridge_port_prio(portid)
                    for jsonAttr in mstpctl_bridge_cache[portname][portid].keys():
                        jsonVal = mstpctl_bridge_cache[portname][portid][jsonAttr]
                        mstpctl_bridgeport_attrs_dict[portname][jsonAttr] = str(jsonVal)
            MSTPAttrsCache.set(bridgename, mstpctl_bridgeport_attrs_dict)
        except Exception as e:
            self.logger.info('%s: cannot fetch mstpctl bridge port attributes: %s' % str(e))

        mstpctl_bridge_attrs_dict = {}
        try:
            cmd = [utils.mstpctl_cmd,
                   'showbridge', 'json', bridgename]
            output = utils.exec_commandl(cmd)
            if not output:
                return mstpctl_bridge_attrs_dict
        except Exception as e:
            self.logger.info(str(e))
            return mstpctl_bridge_attrs_dict
        try:
            mstpctl_bridge_cache = json.loads(output.strip('\n'))
            for jsonAttr in mstpctl_bridge_cache[bridgename].keys():
                mstpctl_bridge_attrs_dict[jsonAttr] = (
                    str(mstpctl_bridge_cache[bridgename][jsonAttr]))
            mstpctl_bridge_attrs_dict['treeprio'] = '%d' %(
                                   int(mstpctl_bridge_attrs_dict.get('bridgeId',
                                   '').split('.')[0], base=16) * 4096)
            del mstpctl_bridge_attrs_dict['bridgeId']
            MSTPAttrsCache.bridges[bridgename].update(mstpctl_bridge_attrs_dict)
        except Exception as e:
            self.logger.info('%s: cannot fetch mstpctl bridge attributes: %s' % str(e))
        return MSTPAttrsCache.get(bridgename)

    def get_bridge_ports_attrs(self, bridgename):
        return self._get_bridge_and_port_attrs_from_cache(bridgename)

    def get_bridge_port_attr(self, bridgename, portname, attrname):
        attrs = self._get_bridge_and_port_attrs_from_cache(bridgename)
        value = attrs.get(portname, {}).get(attrname, 'no')
        if value == 'True' or value == 'true':
            return 'yes'
        return str(value)

    def update_bridge_port_cache(self, bridgename, portname, attrname, value):
        attrs = self.get_bridge_ports_attrs(bridgename)
        if not attrs:
            attrs = {}
        if not portname in attrs:
            attrs[portname] = {}
        attrs[portname][attrname] = value
        MSTPAttrsCache.set(bridgename, attrs)

    def update_bridge_cache(self, bridgename, attrname, value):
        attrs = self.get_bridge_ports_attrs(bridgename)
        if not attrs:
            attrs = {}
        attrs[attrname] = value
        MSTPAttrsCache.set(bridgename, attrs)

    def set_bridge_port_attr(self, bridgename, portname, attrname, value, json_attr=None):
        cache_value = self.get_bridge_port_attr(bridgename, portname, json_attr)
        if cache_value and cache_value == value:
            return
        if attrname == 'treeportcost' or attrname == 'treeportprio':
            utils.exec_commandl([utils.mstpctl_cmd, 'set%s' % attrname,
                                 bridgename, portname, '0', value])
        else:
            utils.exec_commandl([utils.mstpctl_cmd, 'set%s' % attrname,
                                 bridgename, portname, value])
        if json_attr:
            self.update_bridge_port_cache(bridgename, portname, json_attr, value)

    def get_bridge_attrs(self, bridgename):
        bridgeattrs = {}
        try:
            bridgeattrs = dict((k, self.get_bridge_attr(bridgename, v))
                                 for k,v in self._bridge_jsonAttr_map.items())
        except Exception, e:
            self.logger.debug(bridgeattrs)
            self.logger.debug(str(e))
            pass
        return bridgeattrs

    def get_bridge_attr(self, bridgename, attrname):
        if attrname == 'bridgeId':
            attrname = 'treeprio'
        return self._get_bridge_and_port_attrs_from_cache(bridgename).get(attrname)

    def set_bridge_attr(self, bridgename, attrname, attrvalue, check=True):

        if check:
            if attrname == 'treeprio':
                attrvalue_curr = self.get_bridge_attr(bridgename, attrname)
            else:
                attrvalue_curr = self.get_bridge_attr(bridgename,
                                        self._bridge_jsonAttr_map[attrname])
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        if attrname == 'treeprio':
            utils.exec_commandl([utils.mstpctl_cmd, 'set%s' % attrname,
                                 '%s' % bridgename, '0', '%s' % attrvalue], stderr=None)
            self.update_bridge_cache(bridgename, attrname, str(attrvalue))
        else:
            utils.exec_commandl([utils.mstpctl_cmd, 'set%s' % attrname,
                                 '%s' % bridgename, '%s' % attrvalue], stderr=None)
            self.update_bridge_cache(bridgename,
                                     self._bridge_jsonAttr_map[attrname],
                                     str(attrvalue))

    def set_bridge_attrs(self, bridgename, attrdict, check=True):
        for k, v in attrdict.iteritems():
            if not v:
                continue
            try:
                self.set_bridge_attr(bridgename, k, v, check)
            except Exception, e:
                self.logger.warn('%s: %s' %(bridgename, str(e)))

    def get_bridge_treeprio(self, bridgename):
        return self.get_bridge_attr(bridgename, 'treeprio')

    def set_bridge_treeprio(self, bridgename, attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridge_treeprio(bridgename)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        utils.exec_commandl([utils.mstpctl_cmd,
                             'settreeprio', bridgename, '0',
                             str(attrvalue)])
        self.update_bridge_cache(bridgename, 'treeprio', str(attrvalue))

    def showbridge(self, bridgename=None):
        if bridgename:
            return utils.exec_command('%s showbridge %s' %
                                       (utils.mstpctl_cmd, bridgename))
        else:
            return utils.exec_command('%s showbridge' %utils.mstpctl_cmd)

    def showportdetail(self, bridgename):
        return utils.exec_command('%s showportdetail %s' %
                                  (utils.mstpctl_cmd, bridgename))

    def mstpbridge_exists(self, bridgename):
        try:
            utils.exec_command('%s showbridge %s' %
                               (utils.mstpctl_cmd, bridgename))
            return True
        except:
            return False
