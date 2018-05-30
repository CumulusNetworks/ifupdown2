#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# This should be pretty simple and might not really even need to exist.
# The key is that we need to call link_create with a type of "dummy"
# since that will translate to 'ip link add loopbackX type dummy'
# The config file should probably just indicate that the type is
# loopback or dummy.

try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils

    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager
except ImportError:
    from ifupdown.iface import *
    from ifupdown.utils import utils

    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager


class link(moduleBase):
    _modinfo = {'mhelp' : 'create/configure link types. similar to ip-link',
                'attrs' : {
                   'link-type' :
                        {'help' : 'type of link as in \'ip link\' command.',
                         'validvals' : ['dummy', 'veth'],
                         'example' : ['link-type <dummy|veth>']},
                   'link-down' :
                        {'help': 'keep link down',
                         'example' : ['link-down yes/no'],
                         'default' : 'no',
                         'validvals' : ['yes', 'no']}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

        self.check_physical_port_existance = utils.get_boolean_from_string(policymanager.policymanager_api.get_module_globals(
            self.__class__.__name__,
            'warn_on_physdev_not_present'
        ))

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self.check_physical_port_existance:
            if not ifaceobj.link_kind and not LinkUtils.link_exists(ifaceobj.name):
                self.logger.warning('%s: interface does not exist' % ifaceobj.name)
                return False
        return True

    def _is_my_interface(self, ifaceobj):
        if (ifaceobj.get_attr_value_first('link-type')
                or ifaceobj.get_attr_value_first('link-down')):
            return True
        return False

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if ifaceobj.get_attr_value_first('link-down') == 'yes':
            ifaceobj.link_privflags |= ifaceLinkPrivFlags.KEEP_LINK_DOWN
        if ifaceobj.get_attr_value_first('link-type'):
            ifaceobj.link_kind = ifaceLinkKind.OTHER

    def _up(self, ifaceobj):
        link_type = ifaceobj.get_attr_value_first('link-type')
        if link_type:
            self.ipcmd.link_create(ifaceobj.name,
                                   ifaceobj.get_attr_value_first('link-type'))

    def _down(self, ifaceobj):
        if not ifaceobj.get_attr_value_first('link-type'):
            return
        if (not ifupdownflags.flags.PERFMODE and
            not self.ipcmd.link_exists(ifaceobj.name)):
           return
        try:
            self.ipcmd.link_delete(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if ifaceobj.get_attr_value('link-type'):
            if not self.ipcmd.link_exists(ifaceobj.name):
                ifaceobjcurr.update_config_with_status('link-type', 'None', 1)
            else:
                link_type = ifaceobj.get_attr_value_first('link-type')
                if self.ipcmd.link_get_kind(ifaceobj.name) == link_type:
                    ifaceobjcurr.update_config_with_status('link-type',
                                                            link_type, 0)
                else:
                    ifaceobjcurr.update_config_with_status('link-type',
                                                            link_type, 1)

        link_down = ifaceobj.get_attr_value_first('link-down')
        if link_down:
            link_up = self.ipcmd.is_link_up(ifaceobj.name)
            link_should_be_down = utils.get_boolean_from_string(link_down)

            if link_should_be_down and link_up:
                status = 1
                link_down = 'no'
            elif link_should_be_down and not link_up:
                status = 0
            elif not link_should_be_down and link_up:
                status = 0
            else:
                status = 1

            ifaceobjcurr.update_config_with_status('link-down', link_down, status)

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check}

    def get_ops(self):
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = LinkUtils()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        if (operation != 'query-running' and
                not self._is_my_interface(ifaceobj)):
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
