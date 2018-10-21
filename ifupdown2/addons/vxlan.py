#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#


from sets import Set
from ipaddr import IPNetwork, IPv4Address, IPv4Network, AddressValueError

try:
    import ifupdown2.ifupdown.policymanager as policymanager

    from ifupdown2.lib.addon import Addon
    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink
    from ifupdown2.ifupdownaddons.cache import *
    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    import ifupdown.policymanager as policymanager

    from lib.addon import Addon
    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    from ifupdownaddons.cache import *
    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase


class vxlan(Addon, moduleBase):
    _modinfo = {'mhelp' : 'vxlan module configures vxlan interfaces.',
                'attrs' : {
                        'vxlan-id' :
                            {'help' : 'vxlan id',
                             'validrange' : ['1', '16777214'],
                             'required' : True,
                             'example': ['vxlan-id 100']},
                        'vxlan-local-tunnelip' :
                            {'help' : 'vxlan local tunnel ip',
                             'validvals' : ['<ipv4>'],
                             'example': ['vxlan-local-tunnelip 172.16.20.103']},
                        'vxlan-svcnodeip' :
                            {'help' : 'vxlan id',
                             'validvals' : ['<ipv4>'],
                             'example': ['vxlan-svcnodeip 172.16.22.125']},
                        'vxlan-remoteip' :
                            {'help' : 'vxlan remote ip',
                             'validvals' : ['<ipv4>'],
                             'example': ['vxlan-remoteip 172.16.22.127'],
                             'multiline': True},
                        'vxlan-learning' :
                            {'help' : 'vxlan learning yes/no',
                             'validvals' : ['yes', 'no', 'on', 'off'],
                             'example': ['vxlan-learning no'],
                             'default': 'yes'},
                        'vxlan-ageing' :
                            {'help' : 'vxlan aging timer',
                             'validrange' : ['0', '4096'],
                             'example': ['vxlan-ageing 300'],
                             'default': '300'},
                        'vxlan-purge-remotes' :
                            {'help' : 'vxlan purge existing remote entries',
                             'validvals' : ['yes', 'no'],
                             'example': ['vxlan-purge-remotes yes'],},
                    'vxlan-port': {
                        'help': 'vxlan UDP port (transmitted to vxlan driver)',
                        'validvals': ['<number>'],
                        'example': ['vxlan-port 4789'],
                        'validrange': ['1', '65536'],
                        'default': '4789',
                    },
                    'vxlan-physdev':
                        {'help': 'vxlan physical device',
                         'example': ['vxlan-physdev eth1']},

                }}

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        purge_remotes = policymanager.policymanager_api.get_module_globals(module_name=self.__class__.__name__, attr='vxlan-purge-remotes')
        if purge_remotes:
            self._purge_remotes = utils.get_boolean_from_string(purge_remotes)
        else:
            self._purge_remotes = False
        self._vxlan_local_tunnelip = None
        self._clagd_vxlan_anycast_ip = ""

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self._is_vxlan_device(ifaceobj):
            if not ifaceobj.get_attr_value_first('vxlan-local-tunnelip') and not self._vxlan_local_tunnelip:
                self.logger.warning('%s: missing vxlan-local-tunnelip' % ifaceobj.name)
                return False
            return self.syntax_check_localip_anycastip_equal(
                ifaceobj.name,
                ifaceobj.get_attr_value_first('vxlan-local-tunnelip') or self._vxlan_local_tunnelip,
                self._clagd_vxlan_anycast_ip
            )
        return True

    def syntax_check_localip_anycastip_equal(self, ifname, local_ip, anycast_ip):
        try:
            if local_ip and anycast_ip and IPNetwork(local_ip) == IPNetwork(anycast_ip):
                self.logger.warning('%s: vxlan-local-tunnelip and clagd-vxlan-anycast-ip are identical (%s)'
                                    % (ifname, local_ip))
                return False
        except:
            pass
        return True

    def get_dependent_ifacenames(self, ifaceobj, ifaceobjs_all=None):
        if self._is_vxlan_device(ifaceobj):
            ifaceobj.link_kind |= ifaceLinkKind.VXLAN
            self._set_global_local_ip(ifaceobj)
        elif ifaceobj.name == 'lo':
            clagd_vxlan_list = ifaceobj.get_attr_value('clagd-vxlan-anycast-ip')
            if clagd_vxlan_list:
                if len(clagd_vxlan_list) != 1:
                    self.log_warn('%s: multiple clagd-vxlan-anycast-ip lines, using first one'
                                  % (ifaceobj.name,))
                self._clagd_vxlan_anycast_ip = clagd_vxlan_list[0]

            self._set_global_local_ip(ifaceobj)

        # If we should use a specific underlay device for the VXLAN
        # tunnel make sure this device is set up before the VXLAN iface.
        physdev = ifaceobj.get_attr_value_first('vxlan-physdev')

        if physdev:
            return [physdev]

        return None

    def _set_global_local_ip(self, ifaceobj):
        vxlan_local_tunnel_ip = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if vxlan_local_tunnel_ip and not self._vxlan_local_tunnelip:
            self._vxlan_local_tunnelip = vxlan_local_tunnel_ip

    def _is_vxlan_device(self, ifaceobj):
        if ifaceobj.get_attr_value_first('vxlan-id'):
            return True
        return False

    def _get_purge_remotes(self, ifaceobj):
        if not ifaceobj:
            return self._purge_remotes
        purge_remotes = ifaceobj.get_attr_value_first('vxlan-purge-remotes')
        if purge_remotes:
            purge_remotes = utils.get_boolean_from_string(purge_remotes)
        else:
            purge_remotes = self._purge_remotes
        return purge_remotes

    def should_create_set_vxlan(self, link_exists, ifname, vxlan_id, local, learning, ageing, group, cached_vxlan_ifla_info_data):
        """
            should we issue a netlink: ip link add dev %ifname type vxlan ...?
            checking each attribute against the cache
        """
        if not link_exists:
            return True

        try:
            if ageing:
                ageing = int(ageing)
        except:
            pass

        for nl_attr, nl_value in (
                (Link.IFLA_VXLAN_ID, vxlan_id),
                (Link.IFLA_VXLAN_AGEING, ageing),
                (Link.IFLA_VXLAN_LOCAL, local),
                (Link.IFLA_VXLAN_LEARNING, learning),
                (Link.IFLA_VXLAN_GROUP, group),
        ):
            if nl_value != cached_vxlan_ifla_info_data.get(nl_attr):
                return True
        return False

    def _vxlan_create(self, ifaceobj):
        vxlanid = ifaceobj.get_attr_value_first('vxlan-id')
        if vxlanid:
            ifname = ifaceobj.name
            anycastip = self._clagd_vxlan_anycast_ip
            # TODO: vxlan._clagd_vxlan_anycast_ip should be a IPNetwork obj
            group = ifaceobj.get_attr_value_first('vxlan-svcnodeip')

            local = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
            if not local and self._vxlan_local_tunnelip:
                local = self._vxlan_local_tunnelip

            self.syntax_check_localip_anycastip_equal(ifname, local, anycastip)
            # if both local-ip and anycast-ip are identical the function prints a warning

            ageing = ifaceobj.get_attr_value_first('vxlan-ageing')
            vxlan_port = ifaceobj.get_attr_value_first('vxlan-port')
            physdev = ifaceobj.get_attr_value_first('vxlan-physdev')
            purge_remotes = self._get_purge_remotes(ifaceobj)

            link_exists = netlink.cache.link_exists(ifname)

            try:
                vxlanid = int(vxlanid)
            except:
                self.log_error('%s: invalid vxlan-id \'%s\'' % (ifname, vxlanid), ifaceobj)

            if link_exists:
                cached_vxlan_ifla_info_data = netlink.cache.get_link_info_data(ifname)

                # on ifreload do not overwrite anycast_ip to individual ip
                # if clagd has modified
                running_localtunnelip = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL)

                if (anycastip and running_localtunnelip and anycastip == running_localtunnelip):
                    local = running_localtunnelip

                if cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_ID) != vxlanid:
                    self.log_error('%s: Cannot change running vxlan id: '
                                   'Operation not supported' % ifname, ifaceobj)
            else:
                cached_vxlan_ifla_info_data = {}

            if (not link_exists or
                not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
                vxlan_learning = ifaceobj.get_attr_value_first('vxlan-learning')
                if not vxlan_learning:
                    vxlan_learning = self.get_attr_default_value('vxlan-learning')
                learning = utils.get_boolean_from_string(vxlan_learning)
            else:
                learning = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LEARNING)

            if not group:
                group = policymanager.policymanager_api.get_attr_default(
                    module_name=self.__class__.__name__,
                    attr='vxlan-svcnodeip'
                )

            if group:
                try:
                    group = IPv4Address(group)
                except AddressValueError:
                    try:
                        group_ip = IPv4Network(group).ip
                        self.logger.warning('%s: vxlan-svcnodeip %s: netmask ignored' % (ifname, group))
                        group = group_ip
                    except:
                        raise Exception('%s: invalid vxlan-svcnodeip %s: must be in ipv4 format' % (ifname, group))

            if not local:
                local = policymanager.policymanager_api.get_attr_default(
                    module_name=self.__class__.__name__,
                    attr='vxlan-local-tunnelip'
                )

            if local:
                try:
                    local = IPv4Address(local)
                except AddressValueError:
                    try:
                        local_ip = IPv4Network(local).ip
                        self.logger.warning('%s: vxlan-local-tunnelip %s: netmask ignored' % (ifname, local))
                        local = local_ip
                    except:
                        raise Exception('%s: invalid vxlan-local-tunnelip %s: must be in ipv4 format' % (ifname, local))

            if not ageing:
                ageing = policymanager.policymanager_api.get_attr_default(
                    module_name=self.__class__.__name__,
                    attr='vxlan-ageing'
                )

                if not ageing and link_exists:
                    # if link doesn't exist we let the kernel define ageing
                    ageing = self.get_attr_default_value('vxlan-ageing')

            if not vxlan_port:
                vxlan_port = policymanager.policymanager_api.get_attr_default(
                    module_name=self.__class__.__name__,
                    attr='vxlan-port'
                )

            try:
                vxlan_port = int(vxlan_port)
            except TypeError:
                # TypeError means vxlan_port was None
                # ie: not provided by the user or the policy
                vxlan_port = netlink.VXLAN_UDP_PORT
            except ValueError as e:
                self.logger.warning('%s: vxlan-port: using default %s: invalid configured value %s' % (ifname, netlink.VXLAN_UDP_PORT, str(e)))
                vxlan_port = netlink.VXLAN_UDP_PORT

            if link_exists:
                cache_port = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_PORT)
                if vxlan_port != cache_port:
                    self.logger.warning('%s: vxlan-port (%s) cannot be changed - to apply the desired change please run: ifdown %s && ifup %s'
                                        % (ifname, cache_port, ifname, ifname))
                    vxlan_port = cache_port

            if self.should_create_set_vxlan(link_exists, ifname, vxlanid, local, learning, ageing, group, cached_vxlan_ifla_info_data):
                try:
                    netlink.link_add_vxlan(ifname, vxlanid,
                                           local=local,
                                           learning=learning,
                                           ageing=ageing,
                                           group=group,
                                           dstport=vxlan_port,
                                           physdev=physdev)
                except Exception as e_netlink:
                    self.logger.debug('%s: vxlan netlink: %s' % (ifname, str(e_netlink)))
                    try:
                        self.ipcmd.link_create_vxlan(ifname, vxlanid,
                                                     localtunnelip=local,
                                                     svcnodeip=group,
                                                     remoteips=ifaceobj.get_attr_value('vxlan-remoteip'),
                                                     learning='on' if learning else 'off',
                                                     ageing=ageing)
                    except Exception as e_iproute2:
                        self.logger.warning('%s: vxlan add/set failed: %s' % (ifname, str(e_iproute2)))
                        return

                try:
                    # manually adding an entry to the caching after creating/updating the vxlan
                    if not ifname in linkCache.links:
                        linkCache.links[ifname] = {'linkinfo': {}}
                    linkCache.links[ifname]['linkinfo'].update({
                        'learning': learning,
                        Link.IFLA_VXLAN_LEARNING: learning,
                        'vxlanid': str(vxlanid),
                        Link.IFLA_VXLAN_ID: vxlanid
                    })
                    if ageing:
                        linkCache.links[ifname]['linkinfo'].update({
                            'ageing': ageing,
                            Link.IFLA_VXLAN_AGEING: int(ageing)
                        })
                except:
                    pass
            else:
                self.logger.info('%s: vxlan already exists' % ifname)
                # if the vxlan already exists it's already cached

            remoteips = ifaceobj.get_attr_value('vxlan-remoteip')
            if remoteips:
                try:
                    for remoteip in remoteips:
                        IPv4Address(remoteip)
                except Exception as e:
                    self.log_error('%s: vxlan-remoteip: %s' %(ifaceobj.name, str(e)))

            if purge_remotes or remoteips:
                # figure out the diff for remotes and do the bridge fdb updates
                # only if provisioned by user and not by an vxlan external
                # controller.
                peers = self.ipcmd.get_vxlan_peers(ifaceobj.name, group)
                if local and remoteips and local in remoteips:
                    remoteips.remove(local)
                cur_peers = set(peers)
                if remoteips:
                    new_peers = set(remoteips)
                    del_list = cur_peers.difference(new_peers)
                    add_list = new_peers.difference(cur_peers)
                else:
                    del_list = cur_peers
                    add_list = []

                for addr in del_list:
                    try:
                        self.ipcmd.bridge_fdb_del(ifaceobj.name,
                                                  '00:00:00:00:00:00',
                                                  None, True, addr)
                    except:
                        pass

                for addr in add_list:
                    try:
                        self.ipcmd.bridge_fdb_append(ifaceobj.name,
                                                     '00:00:00:00:00:00',
                                                     None, True, addr)
                    except:
                        pass

    def _up(self, ifaceobj):
        self._vxlan_create(ifaceobj)

    def _down(self, ifaceobj):
        try:
            self.netlink.link_del(ifaceobj.name)
        except Exception, e:
            self.log_warn(str(e))

    def _query_check_n_update(self, ifaceobj, ifaceobjcurr, attrname, attrval,
                              running_attrval):
        if not ifaceobj.get_attr_value_first(attrname):
            return
        if running_attrval and attrval == running_attrval:
           ifaceobjcurr.update_config_with_status(attrname, attrval, 0)
        else:
           ifaceobjcurr.update_config_with_status(attrname, running_attrval, 1)

    def _query_check_n_update_addresses(self, ifaceobjcurr, attrname,
                                        addresses, running_addresses):
        if addresses:
            for a in addresses:
                if a in running_addresses:
                    ifaceobjcurr.update_config_with_status(attrname, a, 0)
                else:
                    ifaceobjcurr.update_config_with_status(attrname, a, 1)
            running_addresses = Set(running_addresses).difference(
                                                    Set(addresses))
        [ifaceobjcurr.update_config_with_status(attrname, a, 1)
                    for a in running_addresses]

    def _query_check(self, ifaceobj, ifaceobjcurr):
        ifname = ifaceobj.name

        if not netlink.cache.link_exists(ifname):
            return

        cached_vxlan_ifla_info_data = netlink.cache.get_link_info_data(ifname)

        if not cached_vxlan_ifla_info_data:
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj, self.get_mod_attrs(), -1)
            return

        for vxlan_attr_str, vxlan_attr_nl, callable_type in (
                ('vxlan-id', Link.IFLA_VXLAN_ID, int),
                ('vxlan-port', Link.IFLA_VXLAN_PORT, int),
                ('vxlan-ageing', Link.IFLA_VXLAN_AGEING, int),
                ('vxlan-svcnodeip', Link.IFLA_VXLAN_GROUP, IPv4Address),
                ('vxlan-physdev', Link.IFLA_VXLAN_LINK, lambda ifname: netlink.cache.get_ifindex(ifname)),
                ('vxlan-learning', Link.IFLA_VXLAN_LEARNING, lambda boolean_str: utils.get_boolean_from_string(boolean_str)),
        ):
            vxlan_attr_value = ifaceobj.get_attr_value_first(vxlan_attr_str)

            if not vxlan_attr_value:
                continue

            cached_vxlan_attr_value = cached_vxlan_ifla_info_data.get(vxlan_attr_nl)

            try:
                vxlan_attr_value_nl = callable_type(vxlan_attr_value)
            except Exception as e:
                self.logger.warning('%s: %s: %s' % (ifname, vxlan_attr_str, str(e)))
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, cached_vxlan_attr_value or 'None', 1)
                continue

            if vxlan_attr_value_nl == cached_vxlan_attr_value:
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, vxlan_attr_value, 0)
            else:
                ifaceobjcurr.update_config_with_status(vxlan_attr_str, cached_vxlan_attr_value or 'None', 1)

        #
        # vxlan-local-tunnelip
        #
        running_attrval = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_LOCAL)
        attrval = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if not attrval:
            attrval = self._vxlan_local_tunnelip
            # TODO: vxlan._vxlan_local_tunnelip should be a IPNetwork obj
            ifaceobj.update_config('vxlan-local-tunnelip', attrval)

        if running_attrval == self._clagd_vxlan_anycast_ip:
            # if local ip is anycast_ip, then let query_check to go through
            attrval = self._clagd_vxlan_anycast_ip

        self._query_check_n_update(
            ifaceobj,
            ifaceobjcurr,
            'vxlan-local-tunnelip',
            str(attrval),
            str(running_attrval)
        )

        #
        # vxlan-remoteip
        #
        purge_remotes = self._get_purge_remotes(ifaceobj)
        if purge_remotes or ifaceobj.get_attr_value('vxlan-remoteip'):
            # If purge remotes or if vxlan-remoteip's are set
            # in the config file, we are owners of the installed
            # remote-ip's, lets check and report any remote ips we don't
            # understand
            cached_svcnode = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP)

            self._query_check_n_update_addresses(
                ifaceobjcurr,
                'vxlan-remoteip',
                ifaceobj.get_attr_value('vxlan-remoteip'),
                self.ipcmd.get_vxlan_peers(ifaceobj.name, str(cached_svcnode))
            )

    def _query_running(self, ifaceobjrunning):
        ifname = ifaceobjrunning.name

        if not netlink.cache.link_exists(ifname):
            return

        if not netlink.cache.get_link_kind(ifname) == 'vxlan':
            return

        cached_vxlan_ifla_info_data = netlink.cache.get_link_info_data(ifname)

        if not cached_vxlan_ifla_info_data:
            return

        #
        # vxlan-id
        #
        vxlan_id = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_ID)

        if not vxlan_id:
            # no vxlan id, meaning this not a vxlan
            return

        ifaceobjrunning.update_config('vxlan-id', str(vxlan_id))

        #
        # vxlan-port
        #
        vxlan_port = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_PORT)

        if vxlan_port:
            ifaceobjrunning.update_config('vxlan-port', vxlan_port)

        #
        # vxlan-svcnode
        #
        vxlan_svcnode_value = cached_vxlan_ifla_info_data.get(Link.IFLA_VXLAN_GROUP)

        if vxlan_svcnode_value:
            vxlan_svcnode_value = str(vxlan_svcnode_value)
            ifaceobjrunning.update_config('vxlan-svcnode', vxlan_svcnode_value)

        #
        # vxlan-remoteip
        #
        purge_remotes = self._get_purge_remotes(None)
        if purge_remotes:
            # if purge_remotes is on, it means we own the
            # remote ips. Query them and add it to the running config
            attrval = self.ipcmd.get_vxlan_peers(ifname, vxlan_svcnode_value)
            if attrval:
                [ifaceobjrunning.update_config('vxlan-remoteip', a)
                            for a in attrval]

        #
        # vxlan-link
        # vxlan-ageing
        # vxlan-learning
        # vxlan-local-tunnelip
        #
        for vxlan_attr_name, vxlan_attr_nl, callable_netlink_value_to_string in (
                ('vxlan-physdev', Link.IFLA_VXLAN_LINK, self._get_ifname_for_ifindex),
                ('vxlan-ageing', Link.IFLA_VXLAN_AGEING, str),
                ('vxlan-learning', Link.IFLA_VXLAN_LEARNING, lambda value: 'on' if value else 'off'),
                ('vxlan-local-tunnelip', Link.IFLA_VXLAN_LOCAL, str),
        ):
            vxlan_attr_value = cached_vxlan_ifla_info_data.get(vxlan_attr_nl)

            if vxlan_attr_value is not None:
                vxlan_attr_value_str = callable_netlink_value_to_string(vxlan_attr_nl)

                if vxlan_attr_value:
                    ifaceobjrunning.update_config(vxlan_attr_name, vxlan_attr_value_str)

    @staticmethod
    def _get_ifname_for_ifindex(ifindex):
        """
        we need this middle-man function to query the cache
        cache.get_ifname can raise KeyError, we need to catch
        it and return None
        """
        try:
            return netlink.cache.get_ifname(ifindex)
        except KeyError:
            return None

    _run_ops = {'pre-up' : _up,
               'post-down' : _down,
               'query-checkcurr' : _query_check,
               'query-running' : _query_running}

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
                not self._is_vxlan_device(ifaceobj)):
            return
        self._init_command_handlers()

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
