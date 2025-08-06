#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import operator
from functools import reduce

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.utilsbase import *
except ImportError:
    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.utilsbase import *


class mstpctlutil(utilsBase):
    """ This class contains helper methods to interact with mstpd using
    mstputils commands """

    _DEFAULT_PORT_PRIO      = "128"
    _DEFAULT_PORT_PRIO_INT  = 128

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

        self.__batch = []
        self.__batch_mode = False

        self.pvrst_mode = None
        self.cache = {}

    def __add_to_batch(self, cmd):
        self.__batch.append(cmd)

    def __execute_or_batch(self, cmd):
        if self.__batch_mode:
            self.__add_to_batch(cmd)
        else:
            utils.exec_command("%s %s" % (utils.mstpctl_cmd, cmd))

    def __execute_or_batch_dry_run(self, cmd):
        """
        The batch function has it's own dryrun handler so we only handle
        dryrun for non-batch mode. Which will be removed once the "utils"
        module has it's own dryrun handlers
        """
        if self.__batch_mode:
            self.__add_to_batch(cmd)
        else:
            self.logger.info("DRY-RUN: executing: %s %s" % (utils.mstpctl_cmd, cmd))

    def batch_start(self):
        if not self.__batch_mode:
            self.__batch_mode = True
            self.__batch = []

    def batch_commit(self):
        if not self.__batch_mode or not self.__batch:
            return
        try:
            utils.exec_command(
                "%s batch -" % utils.mstpctl_cmd,
                stdin="\n".join(self.__batch)
            )
        finally:
            self.__batch_mode = False
            del self.__batch
            self.__batch = None

    ###############################################################################
    ###############################################################################
    ###############################################################################

    @classmethod
    def reset(cls):
        cls._cache_fill_done = False

    def is_mstpd_running(self):
        try:
            utils.exec_command('%s mstpd'%utils.pidof_cmd)
        except Exception:
            return False
        else:
            return True

    def _extract_bridge_port_prio(self, portid, pvrst=False):
        try:
            if pvrst:
                return int(portid[0], 16) * 16
            else:
                return str(int(portid[0], 16) * 16)
        except Exception:
            if pvrst:
                return mstpctlutil._DEFAULT_PORT_PRIO_INT
            else:
                return mstpctlutil._DEFAULT_PORT_PRIO

    def set_bridge_port_attr(self, bridgename, portname, attrname, value, json_attr=None):
        cache_value = self.get_bridge_port_attribute_value(bridgename, portname, json_attr)

        if cache_value and cache_value == value:
            return

        if value in ("yes", "no", "on", "off"):
            if utils.get_boolean_from_string(value) == utils.get_boolean_from_string(cache_value):
                return

        if attrname == 'treeportcost' or attrname == 'treeportprio':
            self.__execute_or_batch("set%s %s %s 0 %s" % (attrname, bridgename, portname, value))
        else:
            self.__execute_or_batch("set%s %s %s %s" % (attrname, bridgename, portname, value))
        if json_attr:
            self.update_cached_bridge_port_attribute(bridgename, portname, json_attr, value)

    def get_bridge_attrs(self, bridgename):
        bridgeattrs = {}
        try:
            bridgeattrs = dict((k, self.get_bridge_attribute_value(bridgename, v))
                                 for k,v in list(self._bridge_jsonAttr_map.items()))
        except Exception as e:
            self.logger.debug(bridgeattrs)
            self.logger.debug(str(e))
        return bridgeattrs

    def set_bridge_attr(self, bridgename, attrname, attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridge_attribute_value(bridgename, self._bridge_jsonAttr_map[attrname])

            if attrvalue_curr and attrvalue_curr == attrvalue:
                return

        if attrname == 'treeprio':
            self.__execute_or_batch("set%s %s 0 %s" % (attrname, bridgename, attrvalue))
            self.update_cached_bridge_attribute(bridgename, attrname, str(attrvalue))
        else:
            self.__execute_or_batch("set%s %s %s" % (attrname, bridgename, attrvalue))
            self.update_cached_bridge_attribute(bridgename,
                                     self._bridge_jsonAttr_map[attrname],
                                     str(attrvalue))

    def set_bridge_attrs(self, bridgename, attrdict, check=True):
        for k, v in attrdict.items():
            if not v:
                continue
            try:
                self.set_bridge_attr(bridgename, k, v, check)
            except Exception as e:
                self.logger.warning('%s: %s' %(bridgename, str(e)))

    def get_bridge_treeprio(self, bridgename):
        return self.get_bridge_attribute_value(bridgename, 'treeprio')

    def set_bridge_treeprio(self, bridgename, attrvalue, check=True):
        if check:
            attrvalue_curr = self.get_bridge_treeprio(bridgename)
            if attrvalue_curr and attrvalue_curr == attrvalue:
                return
        self.__execute_or_batch("settreeprio %s 0 %s" % (bridgename, str(attrvalue)))

        self.update_cached_bridge_attribute(bridgename, 'treeprio', str(attrvalue))

    def set_pvrst_attribute(self, attr, bridge_name, vlan_range, value):
        self.__execute_or_batch(
            f"set{attr} {bridge_name} {vlan_range} {value}"
        )

    def set_pvrst_port_attribute(self, attr, bridge_name, port_name, vlan_range, value):
        self.__execute_or_batch(
            f"set{attr} {bridge_name} {port_name} {vlan_range} {value}"
        )

    def mstpbridge_exists(self, bridgename):
        try:
            utils.exec_command('%s showstpbridge %s' %
                               (utils.mstpctl_cmd, bridgename))
            return True
        except Exception:
            return False

    def pvrst_on(self):
        if not self.pvrst_mode:
            utils.exec_command("mstpctl setmodepvrst")
            self.pvrst_mode = True
        else:
            self.logger.debug("pvrst mode already enabled")

    def pvrst_off(self):
        # if pvrst_mode == None we should still run clearmodepvrst
        if self.pvrst_mode != False:
            utils.exec_command("mstpctl clearmodepvrst")
            self.pvrst_mode = False
        else:
            self.logger.debug("pvrst mode already disabled")


    #############################################################################################
    #############################################################################################
    #############################################################################################

    @staticmethod
    def __get_showstpportdetail_json(bridge_name):
        try:
            return json.loads(
                utils.exec_commandl([utils.mstpctl_cmd, "showstpportdetail", bridge_name, "json"])
            )
        except:
            return {}

    @staticmethod
    def __get_showstpbridge_json(bridge_name):
        try:
            return json.loads(
                utils.exec_commandl([utils.mstpctl_cmd, "showstpbridge", "json", bridge_name])
            )
        except:
            return {}

    def _invalid_mstpctl_output(self, bridge_name, bridge_data, bridge_port_details):
        self.logger.info("%s: mstpctl output is incomplete" % bridge_name)
        self.logger.debug("bridge_data=%s" % bridge_data)
        self.logger.debug("bridge_port_details=%s" % bridge_port_details)
        self.cache[bridge_name] = {"ports": bridge_port_details}

    def __get_bridge_data(self, bridge_name):
        bridge_data = self.cache.get(bridge_name)

        if not bridge_data:
            bridge_data = self.__get_showstpbridge_json(bridge_name)
            bridge_port_details = self.__get_showstpportdetail_json(bridge_name)

            protocol = bridge_data.get("protocol")

            if not protocol:
                self._invalid_mstpctl_output(bridge_name, bridge_data, bridge_port_details)
                return

            try:
                pvrst = protocol == "rapid-pvst"

                if not pvrst:
                    # Convert bridgeId into treeprio for backward compatibility
                    bridge_id = bridge_data["BridgeInfo"]["trees"]["cist"]["bridgeId"]
                    bridge_data["BridgeInfo"]["trees"]["cist"][
                        "treeprio"] = f'{(int(bridge_id.split(".")[0], base=16) * 4096)}'


                # Convert portId into treeportprio for backward compatibility
                for port_objects in bridge_port_details.values():
                    treeportprio = None

                    for port_data in port_objects.values():
                        port_id = port_data.get("portId")
                        if port_id:
                            port_data["treeportprio"] = treeportprio = self._extract_bridge_port_prio(port_id, pvrst)

                    try:
                        prio = port_objects.get("1", {}).get("treeportprio", treeportprio)
                        if not prio:
                           prio = mstpctlutil._DEFAULT_PORT_PRIO_INT

                        port_objects["commonPortInfo"]["treeportprio"] = prio
                    except:
                        port_objects["commonPortInfo"]["treeportprio"] = mstpctlutil._DEFAULT_PORT_PRIO_INT

                bridge_data["ports"] = bridge_port_details
                self.cache[bridge_name] = bridge_data

            except KeyError:
                self._invalid_mstpctl_output(bridge_name, bridge_data, bridge_port_details)
                return

        return bridge_data

    def reset_cache(self, ifname):
        try:
            del self.cache[ifname]
        except:
            pass

    # The current patch will only update the backend/cache mechanism
    # To be safe we want to support both mstpctl attribute names but also
    # JSON keys, just in case they are still in use in the mstpctl addon.
    bridge_attribute_to_json_key = {
        "maxhops": ["BridgeInfo", "maxHops"],
        "maxHops": ["BridgeInfo", "maxHops"],

        "ageing": ["BridgeInfo", "ageingTime"],
        "ageingTime": ["BridgeInfo", "ageingTime"],

        "hello": ["BridgeInfo", "helloTime"],
        "helloTime": ["BridgeInfo", "helloTime"],

        "maxage": ["BridgeInfo", "bridgeMaxAge"],
        "maxAge": ["BridgeInfo", "bridgeMaxAge"],
        "bridgeMaxAge": ["BridgeInfo", "bridgeMaxAge"],

        "fdelay": ["BridgeInfo", "bridgeFwdDelay"],
        "fwdDelay": ["BridgeInfo", "bridgeFwdDelay"],
        "bridgeFwdDelay": ["BridgeInfo", "bridgeFwdDelay"],

        "txholdcount": ["BridgeInfo", "txHoldCounter"],
        "txHoldCounter": ["BridgeInfo", "txHoldCounter"],

        "forcevers": ["BridgeInfo", "forceProtocolVersion"],
        "forceProtocolVersion": ["BridgeInfo", "forceProtocolVersion"],

        "treeprio": ["BridgeInfo", "trees", "cist", "treeprio"],
        "bridgeId": ["BridgeInfo", "trees", "cist", "treeprio"],

        # PVRST attributes have special handling in mstpctl.py
        "mstpctl-vlan-hello": ["BridgeInfo", "trees"],
        "mstpctl-vlan-fdelay": ["BridgeInfo", "trees"],
        "mstpctl-vlan-maxage": ["BridgeInfo", "trees"],
        "mstpctl-vlan-priority": ["BridgeInfo", "trees"],
    }

    def reduce_cache_get(self, bridge_name, path_list):
        try:
            return reduce(operator.getitem, path_list, self.__get_bridge_data(bridge_name))
        except (TypeError, KeyError):
            return None

    def get_bridge_attribute_value(self, bridge_name, bridge_attr_name, as_string=True):
        path = self.bridge_attribute_to_json_key[bridge_attr_name]
        attr_value = self.reduce_cache_get(bridge_name, path)

        return str(attr_value) if as_string else attr_value

    bridge_port_attribute_to_json_key = {
        "treeportprio": ["commonPortInfo", "treeportprio"],

        "extPortCost": ["commonPortInfo", "PortCost"],
        "treeportcost": ["commonPortInfo", "PortCost"],

        "networkPort": ["commonPortInfo", "networkPort"],
        "portnetwork": ["commonPortInfo", "networkPort"],

        "autoEdgePort": ["commonPortInfo", "autoEdgePort"],

        "bpduguard": ["commonPortInfo", "bpduGuardPort"],
        "bpduGuardPort": ["commonPortInfo", "bpduGuardPort"],

        "portrestrtcn": ["commonPortInfo", "restrictedTCN"],
        "restrictedTcn": ["commonPortInfo", "restrictedTCN"],

        "adminEdgePort": ["commonPortInfo", "adminEdgePort"],
        "portadminedge": ["commonPortInfo", "adminEdgePort"],

        "portrestrrole": ["commonPortInfo", "restrictedRole"],
        "restrictedRole": ["commonPortInfo", "restrictedRole"],

        "portbpdufilter": ["commonPortInfo", "bpduFilterPort"],
        "bpduFilterPort": ["commonPortInfo", "bpduFilterPort"],

        "adminExtPortCost": ["commonPortInfo", "adminExtPortCost"],
        "adminPointToPoint": ["commonPortInfo", "adminPointToPoint"],

        # [] will return the entire dict
        "mstpctl-port-vlan-path-cost": [],
        "mstpctl-port-vlan-priority": [],
    }

    def get_bridge_port_attribute_value(self, bridge_name, port_name, attr_name, as_string=True):
        path = self.bridge_port_attribute_to_json_key[attr_name]
        attr_value = self.reduce_cache_get(bridge_name, ["ports", port_name, *path])

        if not as_string:
            return attr_value

        attr_value_str = str(attr_value)

        if attr_value_str.lower() == "true":
            attr_value_str = "yes"

        return attr_value_str

    def reduce_cache_set(self, bridge_name, map_list, value):
        try:
            reduce(operator.getitem, map_list[:-1], self.__get_bridge_data(bridge_name))[map_list[-1]] = value
        except KeyError:
            pass

    def update_cached_bridge_port_attribute(self, bridge_name, port_name, attr_name, value):
        path = self.bridge_port_attribute_to_json_key[attr_name]
        self.reduce_cache_set(bridge_name, ["ports", port_name, *path], value)

    def update_cached_bridge_attribute(self, bridge_name, attr_name, value):
        self.reduce_cache_set(bridge_name, self.bridge_attribute_to_json_key[attr_name], value)

    def cache_port(self, bridge_name, ifname):
        if ifname not in self.cache.get(bridge_name, {}).get("ports", {}).keys():
            self.reset_cache(bridge_name)
