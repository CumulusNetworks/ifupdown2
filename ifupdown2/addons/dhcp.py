#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import re
import time
import socket
import logging

try:
    from ifupdown2.lib.addon import Addon
    from ifupdown2.lib.log import LogManager

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdown.iface import ifaceLinkPrivFlags, ifaceStatus
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.dhclient import dhclient
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from lib.addon import Addon
    from lib.log import LogManager

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

    from ifupdown.iface import ifaceLinkPrivFlags, ifaceStatus
    from ifupdown.utils import utils

    from ifupdownaddons.dhclient import dhclient
    from ifupdownaddons.modulebase import moduleBase


class dhcp(Addon, moduleBase):
    """ ifupdown2 addon module to configure dhcp on interface """

    # by default we won't perform any dhcp retry
    # this can be changed by setting the module global
    # policy: dhclient_retry_on_failure
    DHCLIENT_DEFAULT_RETRY_ON_FAILURE = 0

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.dhclientcmd = dhclient(**kargs)
        vrf_id = self._get_vrf_context()
        if vrf_id and vrf_id == 'mgmt':
            self.mgmt_vrf_context = True
        else:
            self.mgmt_vrf_context = False
        self.logger.info('mgmt vrf_context = %s' %self.mgmt_vrf_context)

        try:
            self.dhclient_retry_on_failure = int(
                policymanager.policymanager_api.get_module_globals(
                    module_name=self.__class__.__name__,
                    attr="dhclient_retry_on_failure"
                )
            )
        except Exception:
            self.dhclient_retry_on_failure = self.DHCLIENT_DEFAULT_RETRY_ON_FAILURE

        if self.dhclient_retry_on_failure < 0:
            self.dhclient_retry_on_failure = 0

        self.logger.debug("dhclient: dhclient_retry_on_failure set to %s" % self.dhclient_retry_on_failure)

        self.dhclient_no_wait_on_reload = utils.get_boolean_from_string(
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="dhclient_no_wait_on_reload"
            ),
        )

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        return self.is_dhcp_allowed_on(ifaceobj, syntax_check=True)

    def is_dhcp_allowed_on(self, ifaceobj, syntax_check):
        if ifaceobj.addr_method and 'dhcp' in ifaceobj.addr_method:
            return utils.is_addr_ip_allowed_on(ifaceobj, syntax_check=True)
        return True

    def get_current_ip_configured(self, ifname, family):
        ips = set()
        try:
            a = utils.exec_commandl(["ip", "-o", "addr", "show", ifname]).split("\n")

            for entry in a:
                family_index = entry.find(family)

                if family_index < 0:
                    continue

                tmp = entry[entry.find(family) + len(family) + 1:]
                ip = tmp[:tmp.find(" ")]

                if ip:
                    ips.add(ip)
        except Exception:
            pass
        return ips

    def dhclient_start_and_check(self, ifname, family, handler, wait=True, **handler_kwargs):
        ip_config_before = self.get_current_ip_configured(ifname, family)
        retry = self.dhclient_retry_on_failure

        while retry >= 0:
            handler(ifname, wait=wait, **handler_kwargs)
            if not wait:
                # In most case, the client won't have the time to find anything
                # with the wait=False param.
                return
            retry = self.dhclient_check(ifname, family, ip_config_before, retry, handler_kwargs.get("cmd_prefix"))

    def dhclient_check(self, ifname, family, ip_config_before, retry, dhclient_cmd_prefix):
        diff = self.get_current_ip_configured(ifname, family).difference(ip_config_before)

        if diff:
            self.logger.info(
                "%s: dhclient: new address%s detected: %s"
                % (ifname, "es" if len(diff) > 1 else "", ", ".join(diff))
            )
            return -1
        else:
                if retry > 0:
                    self.logger.error(
                        "%s: dhclient: couldn't detect new ip address, retrying %s more times..."
                        % (ifname, retry)
                    )
                    self.dhclientcmd.stop(ifname)
                else:
                    self.logger.error("%s: dhclient: timeout failed to detect new ip addresses" % ifname)
                    return -1
        retry -= 1
        return retry

    def _up(self, ifaceobj):
        # if dhclient is already running do not stop and start it
        dhclient4_running = self.dhclientcmd.is_running(ifaceobj.name)
        dhclient6_running = self.dhclientcmd.is_running6(ifaceobj.name)

        # today if we have an interface with both inet and inet6, if we
        # remove the inet or inet6 or both then execute ifreload, we need
        # to release/kill the appropriate dhclient(4/6) if they are running
        self._down_stale_dhcp_config(ifaceobj, 'inet', dhclient4_running)
        self._down_stale_dhcp_config(ifaceobj, 'inet6', dhclient6_running)

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
            self.logger.info("%s: bringing dhcp configuration down due to: link-down yes" % ifaceobj.name)
            self._dhcp_down(ifaceobj)
            return

        try:
            dhclient_cmd_prefix = None
            dhcp_wait = policymanager.policymanager_api.get_attr_default(
                module_name=self.__class__.__name__, attr='dhcp-wait')
            wait = str(dhcp_wait).lower() != "no"
            dhcp6_ll_wait = policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, \
                ifname=ifaceobj.name, attr='dhcp6-ll-wait')
            try:
                timeout = int(dhcp6_ll_wait)+1
            except Exception:
                timeout = 10
            dhcp6_duid = policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, \
                ifname=ifaceobj.name, attr='dhcp6-duid')
            vrf = ifaceobj.get_attr_value_first('vrf')
            if (vrf and self.vrf_exec_cmd_prefix and
                self.cache.link_exists(vrf)):
                dhclient_cmd_prefix = '%s %s' %(self.vrf_exec_cmd_prefix, vrf)
            elif self.mgmt_vrf_context:
                dhclient_cmd_prefix = '%s %s' %(self.vrf_exec_cmd_prefix, 'default')
                self.logger.info('detected mgmt vrf context starting dhclient in default vrf context')

            if not ifupdownflags.flags.PERFMODE and self.dhclient_no_wait_on_reload:
                self.logger.info("%s: dhclient won't wait (-nw): policy dhclient_no_wait_on_reload=true" % (ifaceobj.name))
                wait = False

            if 'inet' in ifaceobj.addr_family:
                if dhclient4_running:
                    self.logger.info('dhclient4 already running on %s. '
                                     'Not restarting.' % ifaceobj.name)
                else:
                    # First release any existing dhclient processes
                    try:
                        if not ifupdownflags.flags.PERFMODE:
                            self.dhclientcmd.stop(ifaceobj.name)
                    except Exception:
                        pass

                    self.dhclient_start_and_check(
                        ifaceobj.name,
                        "inet",
                        self.dhclientcmd.start,
                        wait=wait,
                        cmd_prefix=dhclient_cmd_prefix
                    )

            if 'inet6' in ifaceobj.addr_family:
                if dhclient6_running:
                    self.logger.info('dhclient6 already running on %s. '
                                     'Not restarting.' % ifaceobj.name)
                else:
                    accept_ra = ifaceobj.get_attr_value_first('accept_ra')
                    if accept_ra:
                        # XXX: Validate value
                        self.sysctl_set('net.ipv6.conf.%s' %ifaceobj.name +
                                '.accept_ra', accept_ra)
                    autoconf = ifaceobj.get_attr_value_first('autoconf')
                    if autoconf:
                        # XXX: Validate value
                        self.sysctl_set('net.ipv6.conf.%s' %ifaceobj.name +
                                '.autoconf', autoconf)
                        try:
                            self.dhclientcmd.stop6(ifaceobj.name, duid=dhcp6_duid)
                        except Exception:
                            pass
                    #add delay before starting IPv6 dhclient to
                    #make sure the configured interface/link is up.
                    if timeout > 1:
                        time.sleep(1)
                    while timeout:
                        addr_output = utils.exec_command('%s -6 addr show %s'
                                                         %(utils.ip_cmd, ifaceobj.name))
                        r = re.search('inet6 .* scope link', addr_output)
                        if r:
                            self.dhclientcmd.start6(ifaceobj.name,
                                                    wait=wait,
                                                    cmd_prefix=dhclient_cmd_prefix, duid=dhcp6_duid)
                            return
                        timeout -= 1
                        if timeout:
                            time.sleep(1)
        except Exception as e:
            self.logger.error("%s: %s" % (ifaceobj.name, str(e)))
            ifaceobj.set_status(ifaceStatus.ERROR)

    def _down_stale_dhcp_config(self, ifaceobj, family, dhclient_running):
        addr_family = ifaceobj.addr_family
        try:
            if family not in ifaceobj.addr_family and dhclient_running:
                ifaceobj.addr_family = [family]
                self._dhcp_down(ifaceobj)
        except Exception:
            pass
        finally:
            ifaceobj.addr_family = addr_family

    def _dhcp_down(self, ifaceobj):
        dhclient_cmd_prefix = None
        vrf = ifaceobj.get_attr_value_first('vrf')
        if (vrf and self.vrf_exec_cmd_prefix and
            self.cache.link_exists(vrf)):
            dhclient_cmd_prefix = '%s %s' %(self.vrf_exec_cmd_prefix, vrf)
        dhcp6_duid = policymanager.policymanager_api.get_iface_default(module_name=self.__class__.__name__, \
                                                                       ifname=ifaceobj.name, attr='dhcp6-duid')
        if 'inet6' in ifaceobj.addr_family:
            self.dhclientcmd.release6(ifaceobj.name, dhclient_cmd_prefix, duid=dhcp6_duid)
            self.cache.force_address_flush_family(ifaceobj.name, socket.AF_INET6)
        if 'inet' in ifaceobj.addr_family:
            self.dhclientcmd.release(ifaceobj.name, dhclient_cmd_prefix)
            self.cache.force_address_flush_family(ifaceobj.name, socket.AF_INET)

    def _down(self, ifaceobj):
        self._dhcp_down(ifaceobj)
        self.netlink.link_down(ifaceobj.name)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        status = ifaceStatus.SUCCESS
        dhcp_running = False

        dhcp_v4 = self.dhclientcmd.is_running(ifaceobjcurr.name)
        dhcp_v6 = self.dhclientcmd.is_running6(ifaceobjcurr.name)

        if dhcp_v4:
            dhcp_running = True
            if 'inet' not in ifaceobj.addr_family and not dhcp_v6:
                status = ifaceStatus.ERROR
            ifaceobjcurr.addr_method = 'dhcp'
        if dhcp_v6:
            dhcp_running = True
            if 'inet6' not in ifaceobj.addr_family and not dhcp_v4:
                status = ifaceStatus.ERROR
            ifaceobjcurr.addr_method = 'dhcp'
        ifaceobjcurr.addr_family = ifaceobj.addr_family
        if not dhcp_running:
            ifaceobjcurr.addr_family = []
            status = ifaceStatus.ERROR
        ifaceobjcurr.status = status

    def _query_running(self, ifaceobjrunning):
        if not self.cache.link_exists(ifaceobjrunning.name):
            return
        if self.dhclientcmd.is_running(ifaceobjrunning.name):
            ifaceobjrunning.addr_family.append('inet')
            ifaceobjrunning.addr_method = 'dhcp'
        if self.dhclientcmd.is_running6(ifaceobjrunning.name):
            ifaceobjrunning.addr_family.append('inet6')
            ifaceobjrunning.addr_method = 'dhcp6'

    _run_ops = {'up' : _up,
               'down' : _down,
               'pre-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running }

    def get_ops(self):
        """ returns list of ops supported by this module """
        return list(self._run_ops.keys())

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        """ run dhcp configuration on the interface object passed as argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'up', 'down', 'query-checkcurr',
                                 'query-running'

        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        try:
            if (operation != 'query-running' and
                   (ifaceobj.addr_method != 'dhcp' and
                       ifaceobj.addr_method != 'dhcp6')):
                return
        except Exception:
            return
        if not self.is_dhcp_allowed_on(ifaceobj, syntax_check=False):
            return

        log_manager = LogManager.get_instance()

        syslog_log_level = logging.INFO
        disable_syslog_on_exit = None

        if operation in ["up", "down"]:
            # if syslog is already enabled we shouldn't disable it
            if log_manager.is_syslog_enabled():
                # save current syslog level
                syslog_log_level = log_manager.get_syslog_log_level()
                # prevent syslog from being disabled on exit
                disable_syslog_on_exit = False
            else:
                # enabling syslog
                log_manager.enable_syslog()
                # syslog will be disabled once we are done
                disable_syslog_on_exit = True

            # update the current syslog handler log level if higher than INFO
            if syslog_log_level >= logging.INFO:
                log_manager.set_level_syslog(logging.INFO)

            self.logger.info("%s: enabling syslog for dhcp configuration" % ifaceobj.name)

        try:
            if operation == 'query-checkcurr':
                op_handler(self, ifaceobj, query_ifaceobj)
            else:
                op_handler(self, ifaceobj)
        finally:
            # disable syslog handler or re-set the proper log-level
            if disable_syslog_on_exit is True:
                log_manager.get_instance().disable_syslog()
            elif disable_syslog_on_exit is False:
                log_manager.set_level_syslog(syslog_log_level)
