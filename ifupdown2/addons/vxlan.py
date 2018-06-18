#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#


from sets import Set
from ipaddr import IPNetwork, IPv4Address, IPv4Network, AddressValueError

try:
    import ifupdown2.ifupdown.policymanager as policymanager

    from ifupdown2.nlmanager.nlmanager import Link

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.netlink import netlink
    from ifupdown2.ifupdownaddons.cache import *
    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    import ifupdown.policymanager as policymanager

    from nlmanager.nlmanager import Link

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.netlink import netlink

    from ifupdownaddons.cache import *
    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase


class vxlan(moduleBase):
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
                        'example': 'vxlan-port 4789',
                        'validrange': ['1', '65536'],
                        'default': '4789',
                    },
                    'vxlan-physdev':
                        {'help': 'vxlan physical device',
                         'example': ['vxlan-physdev eth1']},

                }}
    _clagd_vxlan_anycast_ip = ""
    _vxlan_local_tunnelip = None

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        self.ipcmd = None
        purge_remotes = policymanager.policymanager_api.get_module_globals(module_name=self.__class__.__name__, attr='vxlan-purge-remotes')
        if purge_remotes:
            self._purge_remotes = utils.get_boolean_from_string(purge_remotes)
        else:
            self._purge_remotes = False

    def syntax_check(self, ifaceobj, ifaceobj_getfunc):
        if self._is_vxlan_device(ifaceobj):
            if not ifaceobj.get_attr_value_first('vxlan-local-tunnelip') and not vxlan._vxlan_local_tunnelip:
                self.logger.warning('%s: missing vxlan-local-tunnelip' % ifaceobj.name)
                return False
            return self.syntax_check_localip_anycastip_equal(
                ifaceobj.name,
                ifaceobj.get_attr_value_first('vxlan-local-tunnelip') or vxlan._vxlan_local_tunnelip,
                vxlan._clagd_vxlan_anycast_ip
            )
        return True

    def syntax_check_localip_anycastip_equal(self, ifname, local_ip, anycast_ip):
        try:
            if IPNetwork(local_ip) == IPNetwork(anycast_ip):
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
                vxlan._clagd_vxlan_anycast_ip = clagd_vxlan_list[0]

            self._set_global_local_ip(ifaceobj)

        # If we should use a specific underlay device for the VXLAN
        # tunnel make sure this device is set up before the VXLAN iface.
        physdev = ifaceobj.get_attr_value_first('vxlan-physdev')

        if physdev:
            return [physdev]

        return None

    def _set_global_local_ip(self, ifaceobj):
        vxlan_local_tunnel_ip = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if vxlan_local_tunnel_ip and not vxlan._vxlan_local_tunnelip:
            vxlan._vxlan_local_tunnelip = vxlan_local_tunnel_ip

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

    def should_create_set_vxlan(self, link_exists, ifname, vxlan_id, local, learning, ageing, group):
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

        for attr_list, value in (
            ((ifname, 'linkinfo', Link.IFLA_VXLAN_ID), vxlan_id),
            ((ifname, 'linkinfo', Link.IFLA_VXLAN_AGEING), ageing),
            ((ifname, 'linkinfo', Link.IFLA_VXLAN_LOCAL), local),
            ((ifname, 'linkinfo', Link.IFLA_VXLAN_LEARNING), learning),
            ((ifname, 'linkinfo', Link.IFLA_VXLAN_GROUP), group),
        ):
            if value and not self.ipcmd.cache_check(attr_list, value):
                return True
        return False

    def _vxlan_create(self, ifaceobj):
        vxlanid = ifaceobj.get_attr_value_first('vxlan-id')
        if vxlanid:
            ifname = ifaceobj.name
            anycastip = self._clagd_vxlan_anycast_ip
            group = ifaceobj.get_attr_value_first('vxlan-svcnodeip')

            local = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
            if not local and vxlan._vxlan_local_tunnelip:
                local = vxlan._vxlan_local_tunnelip

            self.syntax_check_localip_anycastip_equal(ifname, local, anycastip)
            # if both local-ip and anycast-ip are identical the function prints a warning

            ageing = ifaceobj.get_attr_value_first('vxlan-ageing')
            vxlan_port = ifaceobj.get_attr_value_first('vxlan-port')
            physdev = ifaceobj.get_attr_value_first('vxlan-physdev')
            purge_remotes = self._get_purge_remotes(ifaceobj)

            link_exists = self.ipcmd.link_exists(ifname)

            if (not link_exists or
                not ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_PORT):
                vxlan_learning = ifaceobj.get_attr_value_first('vxlan-learning')
                if not vxlan_learning:
                    vxlan_learning = self.get_attr_default_value('vxlan-learning')
                learning = utils.get_boolean_from_string(vxlan_learning)
            else:
                learning = utils.get_boolean_from_string(
                                self.ipcmd.get_vxlandev_learning(ifname))

            if link_exists:
                vxlanattrs = self.ipcmd.get_vxlandev_attrs(ifname)
                # on ifreload do not overwrite anycast_ip to individual ip
                # if clagd has modified
                if vxlanattrs:
                    running_localtunnelip = vxlanattrs.get('local')
                    if (anycastip and running_localtunnelip and
                                anycastip == running_localtunnelip):
                        local = running_localtunnelip
                    if vxlanattrs.get('vxlanid') != vxlanid:
                        self.log_error('%s: Cannot change running vxlan id: '
                                       'Operation not supported' % ifname, ifaceobj)
            try:
                vxlanid = int(vxlanid)
            except:
                self.log_error('%s: invalid vxlan-id \'%s\'' % (ifname, vxlanid), ifaceobj)

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
                cache_port = vxlanattrs.get(Link.IFLA_VXLAN_PORT)
                if vxlan_port != cache_port:
                    self.logger.warning('%s: vxlan-port (%s) cannot be changed - to apply the desired change please run: ifdown %s && ifup %s'
                                        % (ifname, cache_port, ifname, ifname))
                    vxlan_port = cache_port

            if self.should_create_set_vxlan(link_exists, ifname, vxlanid, local, learning, ageing, group):
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
            self.ipcmd.link_delete(ifaceobj.name)
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
        if not self.ipcmd.link_exists(ifaceobj.name):
           return
        # Update vxlan object
        vxlanattrs = self.ipcmd.get_vxlandev_attrs(ifaceobj.name)
        if not vxlanattrs:
            ifaceobjcurr.check_n_update_config_with_status_many(ifaceobj,
                    self.get_mod_attrs(), -1)
            return
        self._query_check_n_update(ifaceobj, ifaceobjcurr, 'vxlan-id',
                       ifaceobj.get_attr_value_first('vxlan-id'),
                       vxlanattrs.get('vxlanid'))

        self._query_check_n_update(
            ifaceobj,
            ifaceobjcurr,
            'vxlan-port',
            ifaceobj.get_attr_value_first('vxlan-port'),
            str(vxlanattrs.get(Link.IFLA_VXLAN_PORT))
        )

        running_attrval = vxlanattrs.get('local')
        attrval = ifaceobj.get_attr_value_first('vxlan-local-tunnelip')
        if not attrval:
            attrval = vxlan._vxlan_local_tunnelip
            ifaceobj.update_config('vxlan-local-tunnelip', attrval)

        if running_attrval == self._clagd_vxlan_anycast_ip:
            # if local ip is anycast_ip, then let query_check to go through
            attrval = self._clagd_vxlan_anycast_ip
        self._query_check_n_update(ifaceobj, ifaceobjcurr, 'vxlan-local-tunnelip',
                                   attrval, running_attrval)

        self._query_check_n_update(ifaceobj, ifaceobjcurr, 'vxlan-svcnodeip',
                       ifaceobj.get_attr_value_first('vxlan-svcnodeip'),
                       vxlanattrs.get('svcnode'))

        purge_remotes = self._get_purge_remotes(ifaceobj)
        if purge_remotes or ifaceobj.get_attr_value('vxlan-remoteip'):
            # If purge remotes or if vxlan-remoteip's are set
            # in the config file, we are owners of the installed
            # remote-ip's, lets check and report any remote ips we don't
            # understand
            self._query_check_n_update_addresses(ifaceobjcurr, 'vxlan-remoteip',
                           ifaceobj.get_attr_value('vxlan-remoteip'),
                                                 self.ipcmd.get_vxlan_peers(ifaceobj.name, vxlanattrs.get('svcnode')))

        learning = ifaceobj.get_attr_value_first('vxlan-learning')
        if learning:
            running_learning = vxlanattrs.get('learning')
            if learning == 'yes' and running_learning == 'on':
                running_learning = 'yes'
            elif learning == 'no' and running_learning == 'off':
                running_learning = 'no'
            if learning == running_learning:
                ifaceobjcurr.update_config_with_status('vxlan-learning',
                                                        running_learning, 0)
            else:
                ifaceobjcurr.update_config_with_status('vxlan-learning',
                                                        running_learning, 1)
        ageing = ifaceobj.get_attr_value_first('vxlan-ageing')
        if not ageing:
            ageing = self.get_mod_subattr('vxlan-ageing', 'default')
        self._query_check_n_update(ifaceobj, ifaceobjcurr, 'vxlan-ageing',
                       ageing, vxlanattrs.get('ageing'))

        physdev = ifaceobj.get_attr_value_first('vxlan-physdev')

        if physdev:
            ifla_vxlan_link = vxlanattrs.get(Link.IFLA_VXLAN_LINK)

            if ifla_vxlan_link:
                self._query_check_n_update(
                    ifaceobj,
                    ifaceobjcurr,
                    'vxlan-physdev',
                    physdev,
                    netlink.get_iface_name(ifla_vxlan_link)
                )
            else:
                ifaceobjcurr.update_config_with_status('vxlan-physdev', physdev, 1)


    def _query_running(self, ifaceobjrunning):
        vxlanattrs = self.ipcmd.get_vxlandev_attrs(ifaceobjrunning.name)
        if not vxlanattrs:
            return
        attrval = vxlanattrs.get('vxlanid')
        if attrval:
            ifaceobjrunning.update_config('vxlan-id', vxlanattrs.get('vxlanid'))
        else:
            # if there is no vxlan id, this is not a vxlan port
            return

        ifaceobjrunning.update_config('vxlan-port', vxlanattrs.get(Link.IFLA_VXLAN_PORT))

        attrval = vxlanattrs.get('local')
        if attrval:
            ifaceobjrunning.update_config('vxlan-local-tunnelip', attrval)
        attrval = vxlanattrs.get('svcnode')
        if attrval:
            ifaceobjrunning.update_config('vxlan-svcnode', attrval)
        purge_remotes = self._get_purge_remotes(None)
        if purge_remotes:
            # if purge_remotes is on, it means we own the
            # remote ips. Query them and add it to the running config
            attrval = self.ipcmd.get_vxlan_peers(ifaceobjrunning.name, vxlanattrs.get('svcnode'))
            if attrval:
                [ifaceobjrunning.update_config('vxlan-remoteip', a)
                            for a in attrval]
        attrval = vxlanattrs.get('learning')
        if attrval and attrval == 'on':
            ifaceobjrunning.update_config('vxlan-learning', 'on')
        attrval = vxlanattrs.get('ageing')
        if attrval:
            ifaceobjrunning.update_config('vxlan-ageing', vxlanattrs.get('ageing'))

        ifla_vxlan_link = vxlanattrs.get(Link.IFLA_VXLAN_LINK)
        if ifla_vxlan_link:
            ifaceobjrunning.update_config(
                'vxlan-physdev',
                netlink.get_iface_name(ifla_vxlan_link)
            )

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
