#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import re
import logging
import traceback
from functools import reduce

try:
    from ifupdown2.ifupdown.iface import ifaceStatus
    from ifupdown2.ifupdown.utils import utils

    import ifupdown2.ifupdown.exceptions as exceptions
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from ifupdown.iface import ifaceStatus
    from ifupdown.utils import utils

    import ifupdown.exceptions as exceptions
    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags


class NotSupported(Exception):
    pass


class ModuleBaseException(Exception):
    pass


class moduleBase(object):
    """ Base class for ifupdown addon modules

    Provides common infrastructure methods for all addon modules """

    def __init__(self, *args, **kargs):
        self.modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + self.modulename)

        # vrfs are a global concept and a vrf context can be applicable
        # to all global vrf commands. Get the default vrf-exec-cmd-prefix
        # here so that all modules can use it
        self.vrf_exec_cmd_prefix = policymanager.policymanager_api.get_module_globals('vrf', attr='vrf-exec-cmd-prefix')

        # explanations are shown in parse_glob
        self.glob_regexs = [re.compile(r"([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\]([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\](.*)"),
                            re.compile(r"([A-Za-z0-9\-]+[A-Za-z])(\d+)\-(\d+)(.*)"),
                            re.compile(r"([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\](.*)")]

        self._bridge_stp_user_space = None

        self.merge_modinfo_with_policy_files()

    def merge_modinfo_with_policy_files(self):
        """
            update addons modinfo dictionary with system/user defined values in policy files
            Any value can be updated except the module help "mhelp"

            We also check if the policy attributes really exist to make sure someone is not
            trying to "inject" new attributes to prevent breakages and security issue
        """
        attrs = dict(self.get_modinfo().get('attrs', {}))

        if not attrs:
            return

        error_msg = 'this attribute doesn\'t exist or isn\'t supported'

        # first check module_defaults
        for key, value in list(policymanager.policymanager_api.get_module_defaults(self.modulename).items()):
            if key not in attrs:
                self.logger.warning('%s: %s: %s' % (self.modulename, key, error_msg))
                continue
            attrs[key]['default'] = value

        # then check module_globals (overrides module_defaults)
        policy_modinfo = policymanager.policymanager_api.get_module_globals(self.modulename, '_modinfo')
        if policy_modinfo:
            policy_attrs = policy_modinfo.get('attrs', {})
            update_attrs = dict()

            for attr_name, attr_description in list(policy_attrs.items()):
                if attr_name not in attrs:
                    self.logger.warning('%s: %s: %s' % (self.modulename, attr_name, error_msg))
                else:
                    update_attrs[attr_name] = attr_description

            attrs.update(update_attrs)

        return attrs

    def log_warn(self, str, ifaceobj=None):
        """ log a warning if err str is not one of which we should ignore """
        if not self.ignore_error(str) and not ifupdownflags.flags.IGNORE_ERRORS:

            if ifaceobj:
                ifaceobj.set_status(ifaceStatus.WARNING)

            # we can't use logger.getEffectiveLevel or logger.level because
            # the root logger has level NOTSET, and each logging handler logs
            # at different level.
            stack = traceback.format_stack()
            f = traceback.format_exc()

            self.logger.debug("%s" % " ".join(stack)[:-1])
            self.logger.debug("%s" % f[:-1])

            self.logger.warning(str)

    def log_error(self, msg, ifaceobj=None, raise_error=True):
        """ log an err if err str is not one of which we should ignore and raise an exception """
        if not self.ignore_error(msg) and not ifupdownflags.flags.IGNORE_ERRORS:

            if ifaceobj:
                ifaceobj.set_status(ifaceStatus.ERROR)

            # we can't use logger.getEffectiveLevel or logger.level because
            # we have the root logger has level NOTSET, and each logging handler
            # logs at different level.
            stack = traceback.format_stack()
            f = traceback.format_exc()

            self.logger.debug("%s" % " ".join(stack)[:-1])
            self.logger.debug("%s" % f[:-1])

            if raise_error:
                raise ModuleBaseException(msg)
            else:
                self.logger.error(msg)

    def is_process_running(self, procName):
        try:
            utils.exec_command('%s -x %s' %
                               (utils.pidof_cmd, procName))
        except Exception:
            return False
        else:
            return True

    def get_ifaces_from_proc(self):
        ifacenames = []
        with open('/proc/net/dev') as f:
                lines = f.readlines()
                for line in lines[2:]:
                    ifacenames.append(line.split()[0].strip(': '))
        return ifacenames

    def parse_regex(self, ifacename, expr, ifacenames=None):
        try:
            proc_ifacenames = self.get_ifaces_from_proc()
        except Exception:
            self.logger.warning('%s: error reading ifaces from proc' %ifacename)

        for proc_ifacename in proc_ifacenames:
            try:
                if re.search(expr + '$', proc_ifacename):
                    yield proc_ifacename
            except Exception as e:
                raise ModuleBaseException('%s: error searching regex \'%s\' in %s (%s)'
                                %(ifacename, expr, proc_ifacename, str(e)))
        if not ifacenames:
            return
        for ifacename in ifacenames:
            try:
                if re.search(expr + '$', ifacename):
                    yield ifacename
            except Exception as e:
                raise ModuleBaseException('%s: error searching regex \'%s\' in %s (%s)'
                                %(ifacename, expr, ifacename, str(e)))

    def ifname_is_glob(self, ifname):
        """
        Used by iface where ifname could be swp7 or swp[1-10].300
        """
        if (self.glob_regexs[0].match(ifname) or
            self.glob_regexs[1].match(ifname) or
            self.glob_regexs[2].match(ifname)):
            return True
        return False

    def parse_glob(self, ifacename, expr):
        errmsg = ('error parsing glob expression \'%s\'' %expr +
                    ' (supported glob syntax: swp1-10.300 or swp[1-10].300' +
                    '  or swp[1-10]sub[0-4].300')

        if ',' in expr:
            self.logger.warning('%s: comma are not supported in glob: %s' % (ifacename, errmsg))
            yield expr
            return

        regexs = self.glob_regexs

        if regexs[0].match(expr):
            # the first regex checks for exactly two levels of ranges defined only with square brackets
            # (e.g. swpxyz[10-23]subqwe[0-4].100) to handle naming with two levels of port names.
            m = regexs[0].match(expr)
            mlist = m.groups()
            if len(mlist) < 7:
                # we have problems and should not continue
                raise ModuleBaseException('%s: error: unhandled glob expression %s\n%s' % (ifacename, expr,errmsg))

            prefix = mlist[0]
            suffix = mlist[6]
            start_index = int(mlist[1])
            end_index = int(mlist[2])
            sub_string = mlist[3]
            start_sub = int(mlist[4])
            end_sub = int(mlist[5])
            for i in range(start_index, end_index + 1):
                for j in range(start_sub, end_sub + 1):
                    yield prefix + '%d%s%d' % (i,sub_string,j) + suffix

        elif regexs[1].match(expr) or regexs[2].match(expr):
            # the second regex for 1 level with a range (e.g. swp10-14.100
            # the third regex checks for 1 level with [] (e.g. swp[10-14].100)
            start_index = 0
            end_index = 0
            if regexs[1].match(expr):
                m = regexs[1].match(expr)
            else:
                m = regexs[2].match(expr)
            mlist = m.groups()
            if len(mlist) != 4:
                raise ModuleBaseException('%s: ' %ifacename + errmsg + '(unexpected len)')
            prefix = mlist[0]
            suffix = mlist[3]
            start_index = int(mlist[1])
            end_index = int(mlist[2])
            for i in range(start_index, end_index + 1):
                yield prefix + '%d' %i + suffix

        else:
            # Could not match anything.
            self.logger.warning('%s: %s' %(ifacename, errmsg))
            yield expr

    def parse_port_list(self, ifacename, port_expr, ifacenames=None):
        """ parse port list containing glob and regex

        Args:
            port_expr (str): expression
            ifacenames (list): list of interface names. This needs to be specified if the expression has a regular expression
        """
        regex = 0
        glob = 0
        portlist = []

        if not port_expr:
            return None
        exprs = re.split(r'[\s\t]\s*', port_expr)
        self.logger.debug('%s: evaluating port expr \'%s\''
                         %(ifacename, str(exprs)))
        for expr in exprs:
            if expr == 'noregex':
                regex = 0
            elif expr == 'noglob':
                glob = 0
            elif expr == 'regex':
                regex = 1
            elif expr == 'glob':
                glob = 1
            elif regex:
                for port in self.parse_regex(ifacename, expr, ifacenames):
                    if port not in portlist:
                        portlist.append(port)
                regex = 0
            elif glob:
                for port in self.parse_glob(ifacename, expr):
                    portlist.append(port)
                glob = 0
            else:
                portlist.append(expr)
        if not portlist:
            return None
        return portlist

    def ignore_error(self, errmsg):
        if (ifupdownflags.flags.FORCE or re.search(r'exists', errmsg,
            re.IGNORECASE | re.MULTILINE)):
            return True
        return False

    def write_file(self, filename, strexpr):
        """ writes string to a file """
        try:
            self.logger.info('writing \'%s\'' %strexpr +
                ' to file %s' %filename)
            if ifupdownflags.flags.DRYRUN:
                return 0
            with open(filename, 'w') as f:
                f.write(strexpr)
        except IOError as e:
            self.logger.warning('error writing to file %s'
                %filename + '(' + str(e) + ')')
            return -1
        return 0

    def read_file(self, filename):
        """ read file and return lines from the file """
        try:
            self.logger.info('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readlines()
        except Exception:
            return None
        return None

    def read_file_oneline(self, filename):
        """ reads and returns first line from the file """
        try:
            self.logger.info('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readline().strip('\n')
        except Exception:
            return None
        return None

    def sysctl_set(self, variable, value):
        """ set sysctl variable to value passed as argument """
        utils.exec_command('%s %s=%s' %
                           (utils.sysctl_cmd, variable, value))

    def sysctl_get(self, variable):
        """ get value of sysctl variable """
        output = utils.exec_command('%s %s' %
                                    (utils.sysctl_cmd, variable))
        split = output.split('=')
        if len(split) > 1:
            return split[1].strip()
        return None

    def systcl_get_net_bridge_stp_user_space(self):
        if self._bridge_stp_user_space:
            return self._bridge_stp_user_space
        try:
            self._bridge_stp_user_space = self.sysctl_get('net.bridge.bridge-stp-user-space')
        except Exception:
            self._bridge_stp_user_space = 0

        return self._bridge_stp_user_space

    def set_iface_attr(self, ifaceobj, attr_name, attr_valsetfunc,
                       prehook=None, prehookargs=None):
        ifacename = ifaceobj.name
        attrvalue = ifaceobj.get_attr_value_first(attr_name)
        if attrvalue:
            if prehook:
                if prehookargs:
                    prehook(prehookargs)
                else:
                    prehook(ifacename)
            attr_valsetfunc(ifacename, attrvalue)

    def query_n_update_ifaceobjcurr_attr(self, ifaceobj, ifaceobjcurr,
                                       attr_name, attr_valgetfunc,
                                       attr_valgetextraarg=None):
        attrvalue = ifaceobj.get_attr_value_first(attr_name)
        if not attrvalue:
            return
        if attr_valgetextraarg:
            runningattrvalue = attr_valgetfunc(ifaceobj.name,
                                             attr_valgetextraarg)
        else:
            runningattrvalue = attr_valgetfunc(ifaceobj.name)
        if (not runningattrvalue or
            (runningattrvalue != attrvalue)):
            ifaceobjcurr.update_config_with_status(attr_name,
                runningattrvalue, 1)
        else:
            ifaceobjcurr.update_config_with_status(attr_name,
                runningattrvalue, 0)

    def dict_key_subset(self, a, b):
        """ returns a list of differing keys """
        return [x for x in a if x in b]

    def get_mod_attrs(self):
        """ returns list of all module attrs defined in the module _modinfo
            dict
        """
        try:
            retattrs = []
            attrsdict = self._modinfo.get('attrs')
            for attrname, attrvals in attrsdict.items():
                if not attrvals or attrvals.get('deprecated'):
                    continue
                retattrs.append(attrname)
                if 'aliases' in attrvals:
                    retattrs.extend(attrvals['aliases'])
            return retattrs
        except Exception:
            return None

    def get_mod_attr(self, attrname):
        """ returns module attr info """
        try:
            return self._modinfo.get('attrs', {}).get(attrname)
        except Exception:
            return None

    def get_mod_subattr(self, attrname, subattrname):
        """ returns module attrs defined in the module _modinfo dict"""
        try:
            return reduce(lambda d, k: d[k], ['attrs', attrname, subattrname],
                         self._modinfo)
        except Exception:
            return None

    def get_modinfo(self):
        """ return module info """
        try:
            return self._modinfo
        except Exception:
            return {}

    def get_attr_default_value(self, attrname):
        return self.get_modinfo().get('attrs', {}).get(attrname, {}).get('default')

    def get_overrides_ifupdown_scripts(self):
        """ return the ifupdown scripts replaced by the current module """
        try:
            return self.overrides_ifupdown_scripts
        except Exception:
            return []

    def _get_reserved_vlan_range(self):
        start = end = 0
        get_resvvlan = '/var/lib/ifupdown2/hooks/get_reserved_vlan_range.sh'
        if not os.path.exists(get_resvvlan):
            return (start, end)
        try:
            (s, e) = utils.exec_command(get_resvvlan).strip('\n').split('-')
            start = int(s)
            end = int(e)
        except Exception as e:
            self.logger.debug('%s failed (%s)' %(get_resvvlan, str(e)))
            # ignore errors
        return (start, end)

    def _get_vrf_context(self):
        vrfid = 'default'
        try:
            vrfid = utils.exec_command('/usr/sbin/ip vrf id').strip()
        except Exception as e:
            self.logger.debug('failed to get vrf id (%s)' %str(e))
            # ignore errors
            vrfid = None
        return vrfid

    def _handle_reserved_vlan(self, vlanid, logprefix='', end=-1):
        """ Helper function to check and warn if the vlanid falls in the
        reserved vlan range """
        error = False
        invalid_vlan = vlanid

        if self._resv_vlan_range[0] <= vlanid <= self._resv_vlan_range[1]:
            error = True
        elif end > 0:
            if self._resv_vlan_range[0] <= end <= self._resv_vlan_range[1]:
                error = True
                invalid_vlan = end
            elif vlanid < self._resv_vlan_range[0] and end > self._resv_vlan_range[1]:
                error = True
                invalid_vlan = self._resv_vlan_range[0]

        if error:
            raise exceptions.ReservedVlanException('%s: reserved vlan %d being used (reserved vlan range %d-%d)'
                                                   % (logprefix, invalid_vlan, self._resv_vlan_range[0], self._resv_vlan_range[1]))

        return error

    def _valid_ethaddr(self, ethaddr):
        """ Check if address is 00:00:00:00:00:00 """
        if not ethaddr or re.match('00:00:00:00:00:00', ethaddr):
            return False
        return True

    def _get_vlan_id_from_ifacename(self, ifacename):
        if '.' in ifacename:
            vid_str = ifacename.split('.', 2)
            vlen = len(vid_str)
            if vlen == 2:
                vid_str = vid_str[1]
            elif vlen == 3:
                vid_str = vid_str[2]
        elif ifacename.startswith('vlan'):
            vid_str = ifacename[4:]
        else:
            return -1
        try:
            vid = int(vid_str)
        except Exception:
            return -1
        return vid

    def _get_vlan_id(self, ifaceobj):
        """ Derives vlanid from iface name

        Example:
            Returns 1 for ifname vlan0001 returns 1
            Returns 1 for ifname vlan1
            Returns 1 for ifname eth0.1
            Returns 100 for ifname eth0.1.100
            Returns -1 if vlan id cannot be determined
        """
        vid_str = ifaceobj.get_attr_value_first('vlan-id')
        try:
            if vid_str: return int(vid_str)
        except Exception:
            return -1

        return self._get_vlan_id_from_ifacename(ifaceobj.name)
