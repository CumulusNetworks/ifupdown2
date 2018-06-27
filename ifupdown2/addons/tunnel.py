#!/usr/bin/python
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Mon 10 Oct 2016 10:53:13 PM CEST
#
try:
    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.netlink import netlink

    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from ifupdown.iface import *
    from ifupdown.netlink import netlink

    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase

    import ifupdown.ifupdownflags as ifupdownflags


#
# TODO: Add checks for ipip tunnels.
#
class tunnel(moduleBase):
    """
    ifupdown2 addon module to configure tunnels
    """
    _modinfo = {
        'mhelp': 'create/configure GRE/IPIP/SIT and GRETAP tunnel interfaces',
        'attrs': {
            'mode': {
                'help': 'type of tunnel as in \'ip link\' command.',
                'validvals': ['gre', 'gretap', 'ipip', 'sit', 'vti', 'ip6gre', 'ipip6', 'ip6ip6', 'vti6'],
                'required': True,
                'example': ['mode gre']
            },
            'local': {
                'help': 'IP of local tunnel endpoint',
                'validvals': ['<ipv4>', '<ipv6>'],
                'required': True,
                'example': ['local 192.2.0.42']
            },
            'endpoint': {
                'help': 'IP of remote tunnel endpoint',
                'validvals': ['<ipv4>', '<ipv6>'],
                'required': True,
                'example': ['endpoint 192.2.0.23']
            },
            'ttl': {
                'help': 'TTL for tunnel packets',
                'validvals': ['<number>'],
                'required': False,
                'example': ['ttl 64']
            },
            'tunnel-physdev': {
                'help': 'Physical underlay device to use for tunnel packets',
                'validvals': ['<interface>'],
                'required': False,
                'example': ['tunnel-physdev eth1']
            },
        }
    }

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None

    @staticmethod
    def _is_my_interface(ifaceobj):
        return ifaceobj.addr_method == "tunnel" and ifaceobj.get_attr_value_first('mode')

    def _check_settings(self, ifaceobj, attrs):
        linkup = self.ipcmd.is_link_up(ifaceobj.name)
        try:
            if attrs:
                self.ipcmd.tunnel_change(ifaceobj.name, attrs)
        except:
            raise
        finally:
            if attrs and linkup:
                netlink.link_set_updown(ifaceobj.name, 'up')

    def _up(self, ifaceobj):
        attr_map = {
            # attr_name -> ip route param name
            'local': 'local',
            'endpoint': 'remote',
            'ttl': 'ttl',
            'tunnel-physdev': 'dev',
        }

        mode = ifaceobj.get_attr_value_first('mode')
        attrs = {}

        # Only include attributes which have been set and map ifupdown2 names
        # to attribute names expected by iproute
        for attr, iproute_attr in attr_map.items():
            attr_val = ifaceobj.get_attr_value_first(attr)
            if attr_val != None:
                attrs[iproute_attr] = attr_val

        current_mode = self.ipcmd.link_cache_get([ifaceobj.name, 'kind'])

        try:
            if not self.ipcmd.link_exists(ifaceobj.name):
                self.ipcmd.tunnel_create(ifaceobj.name, mode, attrs)
            elif current_mode and current_mode != mode and (('6' in mode and '6' not in current_mode) or ('6' not in mode and '6' in current_mode)):
                # Mode changes between ipv4 and ipv6 are not possible without recreating the interface
                self.ipcmd.link_delete(ifaceobj.name)
                self.ipcmd.tunnel_create(ifaceobj.name, mode, attrs)
            else:
                attrs['mode'] = mode
                self._check_settings(ifaceobj, attrs)
        except Exception, e:
            self.log_warn(str(e))

    def _down(self, ifaceobj):
        if not ifupdownflags.flags.PERFMODE and not self.ipcmd.link_exists(ifaceobj.name):
            return
        try:
            self.ipcmd.link_delete(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def get_dependent_ifacenames(self, ifaceobj, ifacenames_all=None):
        if not self._is_my_interface(ifaceobj):
            return None

        device = ifaceobj.get_attr_value_first('tunnel-physdev')
        if device:
            return [device]

        return None

    @staticmethod
    def _query_check_n_update(ifaceobj, ifaceobjcurr, attrname, attrval, running_attrval):
        if not ifaceobj.get_attr_value_first(attrname):
            return
        if running_attrval and attrval == running_attrval:
            ifaceobjcurr.update_config_with_status(attrname, attrval, 0)
        else:
            ifaceobjcurr.update_config_with_status(attrname, running_attrval, 1)

    def _query_check(self, ifaceobj, ifaceobjcurr):
        if not self.ipcmd.link_exists(ifaceobj.name):
            return

        tunattrs = self.ipcmd.link_get_linkinfo_attrs(ifaceobj.name)
        if not tunattrs:
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj, self.get_mod_attrs(), -1)
            return

        for attr in self.get_mod_attrs():
            if not ifaceobj.get_attr_value_first(attr):
                continue

            # Validate all interface attributes set in the config.
            # Remote any leading 'tunnel-' prefix in front of the attr name
            # when accessing tunattrs parsed from 'ip -d link'.
            self._query_check_n_update(ifaceobj, ifaceobjcurr, attr,
                                       ifaceobj.get_attr_value_first(attr),
                                       tunattrs.get(attr.replace("tunnel-", "")))

    # Operations supported by this addon (yet).
    _run_ops = {
        'pre-up': _up,
        'post-down': _down,
        'query-checkcurr': _query_check
    }

    def get_ops(self):
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = LinkUtils()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return

        if operation != 'query-running' and not self._is_my_interface(ifaceobj):
            return

        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
