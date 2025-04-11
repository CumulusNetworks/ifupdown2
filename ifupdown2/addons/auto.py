#!/usr/bin/env python3
#

import socket

try:
    from ifupdown2.lib.addon import Addon
    from ifupdown2.lib.log import LogManager

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except (ImportError, ModuleNotFoundError):
    from lib.addon import Addon
    from lib.log import LogManager

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags

    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.modulebase import moduleBase


class auto(Addon, moduleBase):
    """ ifupdown2 addon module to configure slaac on inet6 interface """

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        return self.is_auto_allowed_on(ifaceobj, syntax_check=True)

    def is_auto_allowed_on(self, ifaceobj, syntax_check):
        if ifaceobj.addr_method and 'auto' in ifaceobj.addr_method:
            return utils.is_addr_ip_allowed_on(ifaceobj, syntax_check=True)
        return True

    def _up(self, ifaceobj):

        if ifaceobj.link_privflags & ifaceLinkPrivFlags.KEEP_LINK_DOWN:
            self.logger.info("%s: skipping auto configuration: link-down yes" % ifaceobj.name)
            return

        try:
            if 'inet6' in ifaceobj.addr_family:
                running_accept_ra = self.cache.get_link_inet6_accept_ra(ifaceobj)
                if running_accept_ra != '2':
                    accept_ra = '2'
                    self.sysctl_set('net.ipv6.conf.%s.accept_ra'
                                    %('/'.join(ifaceobj.name.split("."))),
                                    accept_ra)
                    self.cache.update_link_inet6_accept_ra(ifaceobj.name, accept_ra)

                running_autoconf = self.cache.get_link_inet6_autoconf(ifaceobj)
                if running_autoconf != '1':
                    autoconf = '1'
                    self.sysctl_set('net.ipv6.conf.%s.autoconf'
                                    %('/'.join(ifaceobj.name.split("."))),
                                    autoconf)
                    self.cache.update_link_inet6_autoconf(ifaceobj.name, autoconf)

        except Exception as e:
            self.logger.error("%s: %s" % (ifaceobj.name, str(e)))
            ifaceobj.set_status(ifaceStatus.ERROR)

    def _down(self, ifaceobj):
        if 'inet6' in ifaceobj.addr_family:
            self.cache.force_address_flush_family(ifaceobj.name, socket.AF_INET6)
        self.netlink.link_down(ifaceobj.name)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.cache.link_exists(ifaceobj.name):
            return
        ifaceobjcurr.addr_family = ifaceobj.addr_family
        ifaceobjcurr.addr_method = 'auto'

        inet6conf = self.cache.get_link_inet6_conf(ifaceobj.name)
        if inet6conf['accept_ra'] == 2 and inet6conf['autoconf'] == 1:
            ifaceobjcurr.status = ifaceStatus.SUCCESS
        else:
            ifaceobjcurr.status = ifaceStatus.ERROR

    def _query_running(self, ifaceobjrunning):
        pass

    _run_ops = {'pre-up' : _up,
               'up' : _up,
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
            if (operation != 'query-running' and ifaceobj.addr_method != 'auto'):
                return
        except Exception:
            return
        if not self.is_auto_allowed_on(ifaceobj, syntax_check=False):
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

            self.logger.info("%s: enabling syslog for auto configuration" % ifaceobj.name)

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
