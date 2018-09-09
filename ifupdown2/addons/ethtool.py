#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

try:
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager

    from ifupdown2.ifupdown.iface import *
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.exceptions import moduleNotSupported

    from ifupdown2.ifupdownaddons.utilsbase import *
    from ifupdown2.ifupdownaddons.LinkUtils import LinkUtils
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager

    from ifupdown.iface import *
    from ifupdown.utils import utils
    from ifupdown.exceptions import moduleNotSupported

    from ifupdownaddons.utilsbase import *
    from ifupdownaddons.LinkUtils import LinkUtils
    from ifupdownaddons.modulebase import moduleBase


class ethtool(moduleBase,utilsBase):
    """  ifupdown2 addon module to configure ethtool attributes """

    _modinfo = {'mhelp' : 'ethtool configuration module for interfaces',
                'attrs': {
                      'link-speed' :
                            {'help' : 'set link speed',
                             'validvals' : ['100',
                                            '1000',
                                            '10000',
                                            '25000',
                                            '40000',
                                            '50000',
                                            '100000'],
                             'example' : ['link-speed 1000'],
                             'default' : 'varies by platform and port'},
                      'link-duplex' :
                            {'help': 'set link duplex',
                             'example' : ['link-duplex full'],
                             'validvals' : ['half', 'full'],
                             'default' : 'full'},
                      'link-autoneg' :
                            {'help': 'set autonegotiation',
                             'example' : ['link-autoneg on'],
                             'validvals' : ['yes', 'no', 'on', 'off'],
                             'default' : 'varies by platform and port'},
                      'link-fec' :
                            {'help': 'set forward error correction mode',
                             'example' : ['link-fec rs'],
                             'validvals' : ['rs', 'baser', 'auto', 'off'],
                             'default' : 'varies by platform and port'}}}

    def __init__(self, *args, **kargs):
        moduleBase.__init__(self, *args, **kargs)
        if not os.path.exists(utils.ethtool_cmd):
            raise moduleNotSupported('module init failed: %s: not found' % utils.ethtool_cmd)
        self.ipcmd = None
        # keep a list of iface objects who have modified link attributes
        self.ifaceobjs_modified_configs = []

    def do_fec_settings(self, ifaceobj):
        feccmd = ''

        # attribute existed before but we must reset to default
        config_val = ifaceobj.get_attr_value_first('link-fec')
        default_val = policymanager.policymanager_api.get_iface_default(
                            module_name='ethtool',
                            ifname=ifaceobj.name,
                            attr='link-fec')

        if not default_val and not config_val:
            # there is no point in checking the running config
            # if we have no default and the user did not have settings
            return

        # check running values
        running_val = self.get_running_attr('fec', ifaceobj)
        if config_val and config_val == running_val:
            return

        if not config_val and default_val and default_val == running_val:
            # nothing configured but the default is running
            return

        # if we got this far, we need to change it
        if config_val and (config_val != running_val):
            # if the configured value is not set, set it
            feccmd = ' %s %s' % ("encoding", config_val)
        elif default_val and (default_val != running_val):
            # or if it has a default not equal to running value, set it
            feccmd = ' %s %s' % ("encoding", default_val)

        if feccmd:
            try:
                feccmd = ('%s --set-fec %s %s' %
                           (utils.ethtool_cmd, ifaceobj.name, feccmd))
                utils.exec_command(feccmd)
            except Exception, e:
                self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj)
        else:
            pass

    def do_speed_settings(self, ifaceobj, operation='post_up'):
        cmd = ''

        autoneg_to_configure = None
        speed_to_configure = None
        duplex_to_configure = None

        config_speed = ifaceobj.get_attr_value_first('link-speed')
        config_duplex = ifaceobj.get_attr_value_first('link-duplex')
        config_autoneg = ifaceobj.get_attr_value_first('link-autoneg')

        default_speed = policymanager.policymanager_api.get_iface_default(
                module_name='ethtool',
                ifname=ifaceobj.name,
                attr='link-speed'
            )

        default_duplex = policymanager.policymanager_api.get_iface_default(
                module_name='ethtool',
                ifname=ifaceobj.name,
                attr='link-duplex'
            )

        default_autoneg = policymanager.policymanager_api.get_iface_default(
                module_name='ethtool',
                ifname=ifaceobj.name,
                attr='link-autoneg'
        )

        # autoneg wins if provided by user and is on
        if config_autoneg and utils.get_boolean_from_string(config_autoneg):
            autoneg_to_configure = config_autoneg
            speed_to_configure = None
            duplex_to_configure = None
        elif config_speed:
            # Any speed settings configured by the user wins
            autoneg_to_configure = None
            speed_to_configure = config_speed
            duplex_to_configure = config_duplex
            if not config_duplex:
                duplex_to_configure = default_duplex
        else:
            # if user given autoneg config is off, we must respect that and
            # override any default autoneg config
            if config_autoneg and not utils.get_boolean_from_string(config_autoneg):
                default_autoneg = 'off'

            if default_autoneg and utils.get_boolean_from_string(default_autoneg):
                autoneg_to_configure = utils.get_onoff_bool(default_autoneg)
                speed_to_configure = None
                duplex_to_configure = None
            else:
                autoneg_to_configure = None
                speed_to_configure = default_speed
                duplex_to_configure = default_duplex

        if autoneg_to_configure:
            autoneg_to_configure = utils.get_onoff_bool(autoneg_to_configure)
            # check running values
            running_val = self.get_running_attr('autoneg', ifaceobj)
            if autoneg_to_configure != running_val:
                # if the configured value is not set, set it
                cmd += ' autoneg %s' % autoneg_to_configure
        else:
            force_set = False
            if speed_to_configure:
                # check running values
                if utils.get_boolean_from_string(self.get_running_attr('autoneg', ifaceobj) or 'off'):
                    cmd = 'autoneg off'
                    # if we are transitioning from autoneg 'on' to 'off'
                    # don't check running speed
                    force_set = True

                running_val = self.get_running_attr('speed', ifaceobj)
                if force_set or (speed_to_configure != running_val):
                    # if the configured value is not set, set it
                    cmd += ' speed %s' % speed_to_configure

            if duplex_to_configure:
                # check running values
                running_val = self.get_running_attr('duplex', ifaceobj)
                if force_set or (duplex_to_configure != running_val):
                    # if the configured value is not set, set it
                    cmd += ' duplex %s' % duplex_to_configure

        if cmd:
            try:
                cmd = ('%s -s %s %s' % (utils.ethtool_cmd, ifaceobj.name, cmd))
                utils.exec_command(cmd)
            except Exception, e:
                self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj, raise_error=False)

    def _pre_up(self, ifaceobj, operation='post_up'):
        """
        _pre_up and _pre_down will reset the layer 2 attributes to default policy
        settings.
        """
        if not self.ipcmd.link_exists(ifaceobj.name):
            return

        self.do_speed_settings(ifaceobj)
        self.do_fec_settings(ifaceobj)

    def _pre_down(self, ifaceobj):
        pass #self._post_up(ifaceobj,operation="_pre_down")

    def _query_check(self, ifaceobj, ifaceobjcurr):
        """
        _query_check() needs to compare the configured (or running)
        attribute with the running attribute.

        If there is nothing configured, we compare the default attribute with
        the running attribute and FAIL if they are different.
        This is because a reboot will lose their running attribute
        (the default will get set).
        """
        for attr in ['speed', 'duplex', 'autoneg', 'fec']:
            configured = ifaceobj.get_attr_value_first('link-%s'%attr)
            # if there is nothing configured, do not check
            if not configured:
                if not ifupdownflags.flags.WITHDEFAULTS:
                    continue
            default = policymanager.policymanager_api.get_iface_default(
                module_name='ethtool',
                ifname=ifaceobj.name,
                attr='link-%s'%attr)
            # if we have no default, do not bother checking
            # this avoids ethtool calls on virtual interfaces
            if not default:
                continue
            # autoneg comes from ethtool whereas speed and duplex from /sys/class
            running_attr = self.get_running_attr(attr, ifaceobj)
            if not running_attr:
                if not configured:
                    continue
                ifaceobjcurr.update_config_with_status('link-%s' % attr,
                                                       'unknown', 1)
                continue

            if attr == 'autoneg':
                if configured == 'yes' and running_attr == 'on':
                    running_attr = 'yes'
                elif configured == 'no' and running_attr == 'off':
                    running_attr = 'no'

            # we make sure we can get a running value first
            if (running_attr and configured and running_attr == configured):
                # PASS since running is what is configured
                ifaceobjcurr.update_config_with_status('link-%s'%attr,
                                                       running_attr, 0)
            elif (running_attr and configured and running_attr != configured):
                # We show a FAIL since it is not the configured or default
                ifaceobjcurr.update_config_with_status('link-%s'%attr,
                                                       running_attr, 1)
            elif (running_attr and default and running_attr == default):
                # PASS since running is default
                ifaceobjcurr.update_config_with_status('link-%s'%attr,
                                                       running_attr, 0)
            elif (default or configured):
                # We show a FAIL since it is not the configured or default
                ifaceobjcurr.update_config_with_status('link-%s'%attr,
                                                       running_attr, 1)
        return

    def get_autoneg(self,ethtool_output=None):
        """
        get_autoneg simply calls the ethtool command and parses out
        the autoneg value.
        """
        ethtool_attrs = ethtool_output.split()
        if ('Auto-negotiation:' in ethtool_attrs):
            return(ethtool_attrs[ethtool_attrs.index('Auto-negotiation:')+1])
        else:
            return(None)

    def get_fec_encoding(self,ethtool_output=None):
        """
        get_fec_encoding simply calls the ethtool show-fec command and parses out
        the fec encoding value.
        """
        try:
            for attr in ethtool_output.splitlines():
                if attr.startswith('FEC encodings'):
                    fec_attrs = attr.split()
                    return(fec_attrs[fec_attrs.index(':')+1])
        except Exception as e:
            self.logger.debug('ethtool: problems in ethtool set-fec output'
                               ' %s: %s' %(ethtool_output.splitlines(), str(e)))

        return(None)

    def get_running_attr(self,attr='',ifaceobj=None):
        if not ifaceobj or not attr:
            return
        running_attr = None
        try:
            if attr == 'autoneg':
                output = utils.exec_commandl([utils.ethtool_cmd, ifaceobj.name])
                running_attr = self.get_autoneg(ethtool_output=output)
            elif attr == 'fec':
                output = utils.exec_command('%s --show-fec %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                running_attr = self.get_fec_encoding(ethtool_output=output)
            else:
                running_attr = self.read_file_oneline('/sys/class/net/%s/%s' % \
                                                      (ifaceobj.name, attr))
        except Exception as e:
            # for nonexistent interfaces, we get an error (rc = 256 or 19200)
            self.logger.debug('ethtool: problems calling ethtool or reading'
                              ' /sys/class on iface %s for attr %s: %s' %
                              (ifaceobj.name, attr, str(e)))
        return running_attr


    def _query_running(self, ifaceobj, ifaceobj_getfunc=None):
        """
        _query_running looks at the speed and duplex from /sys/class
        and retreives autoneg from ethtool.  We do not report autoneg
        if speed is not available because this usually means the link is
        down and the autoneg value is not reliable when the link is down.
        """
        # do not bother showing swp ifaces that are not up for the speed
        # duplex and autoneg are not reliable.
        if not self.ipcmd.is_link_up(ifaceobj.name):
            return
        for attr in ['speed', 'duplex', 'autoneg']:
            default_val = policymanager.policymanager_api.get_iface_default(
                module_name='ethtool',
                ifname=ifaceobj.name,
                attr='link-%s'%attr)
            # do not continue if we have no defaults
            # this avoids ethtool calls on virtual interfaces
            if not default_val:
                continue
            running_attr = self.get_running_attr(attr, ifaceobj)

            # Only show the link attributes if they differ from defaults
            # to see the defaults, we should implement another flag (--with-defaults)
            if default_val == running_attr:
                continue

            # do not proceed if speed = 0
            if attr == 'speed' and running_attr and running_attr == '0':
                return
            if running_attr:
                ifaceobj.update_config('link-%s'%attr, running_attr)

        return

    def _query(self, ifaceobj, **kwargs):
        """ add default policy attributes supported by the module """
        for attr in ['speed', 'duplex', 'autoneg', 'fec']:
            if ifaceobj.get_attr_value_first('link-%s'%attr):
                continue
            default = policymanager.policymanager_api.get_iface_default(
                        module_name='ethtool',
                        ifname=ifaceobj.name,
                        attr='link-%s' %attr)
            if not default:
                continue
            ifaceobj.update_config('link-%s' %attr, default)

    _run_ops = {'pre-down' : _pre_down,
                'pre-up' : _pre_up,
                'query-checkcurr' : _query_check,
                'query-running' : _query_running,
                'query' : _query}

    def get_ops(self):
        """ returns list of ops supported by this module """
        return self._run_ops.keys()

    def _init_command_handlers(self):
        if not self.ipcmd:
            self.ipcmd = LinkUtils()

    def run(self, ifaceobj, operation, query_ifaceobj=None, **extra_args):
        """ run ethtool configuration on the interface object passed as
            argument

        Args:
            **ifaceobj** (object): iface object

            **operation** (str): any of 'post-up', 'query-checkcurr',
                'query-running'
        Kwargs:
            **query_ifaceobj** (object): query check ifaceobject. This is only
                valid when op is 'query-checkcurr'. It is an object same as
                ifaceobj, but contains running attribute values and its config
                status. The modules can use it to return queried running state
                of interfaces. status is success if the running state is same
                as user required state in ifaceobj. error otherwise.
        """
        if (ifaceobj.link_kind or
                    ifaceobj.link_privflags & ifaceLinkPrivFlags.LOOPBACK):
            return
        op_handler = self._run_ops.get(operation)
        if not op_handler:
            return
        self._init_command_handlers()
        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
