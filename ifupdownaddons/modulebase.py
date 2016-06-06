#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os
import re
import io
import logging
import traceback

from ifupdown.utils import utils
from ifupdown.iface import *
import ifupdown.policymanager as policymanager
import ifupdown.ifupdownflags as ifupdownflags

class moduleBase(object):
    """ Base class for ifupdown addon modules

    Provides common infrastructure methods for all addon modules """

    def __init__(self, *args, **kargs):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)

        # vrfs are a global concept and a vrf context can be applicable
        # to all global vrf commands. Get the default vrf-exec-cmd-prefix
        # here so that all modules can use it
        self.vrf_exec_cmd_prefix = policymanager.policymanager_api.get_module_globals('vrf', attr='vrf-exec-cmd-prefix')

        # explanations are shown in parse_glob
        self.glob_regexs = [re.compile(r"([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\]([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\](.*)"),
                            re.compile(r"([A-Za-z0-9\-]+[A-Za-z])(\d+)\-(\d+)(.*)"),
                            re.compile(r"([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\](.*)")]


    def log_warn(self, str, ifaceobj=None):
        """ log a warning if err str is not one of which we should ignore """
        if not self.ignore_error(str):
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
            self.logger.warn(str)
            if ifaceobj:
                ifaceobj.set_status(ifaceStatus.WARNING)
        pass

    def log_error(self, str, ifaceobj=None, raise_error=True):
        """ log an err if err str is not one of which we should ignore and raise an exception """
        if not self.ignore_error(str):
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
            if ifaceobj:
                ifaceobj.set_status(ifaceStatus.ERROR)
            if raise_error:
                raise Exception(str)
        else:
            pass

    def is_process_running(self, procName):
        try:
            utils.exec_command('/bin/pidof -x %s' % procName)
        except:
            return False
        else:
            return True

    def get_ifaces_from_proc(self):
        ifacenames = []
        with open('/proc/net/dev') as f:
            try:
                lines = f.readlines()
                for line in lines[2:]:
                    ifacenames.append(line.split()[0].strip(': '))
            except:
                raise
        return ifacenames

    def parse_regex(self, ifacename, expr, ifacenames=None):
        try:
            proc_ifacenames = self.get_ifaces_from_proc()
        except:
            self.logger.warn('%s: error reading ifaces from proc' %ifacename)

        for proc_ifacename in proc_ifacenames:
            try:
                if re.search(expr + '$', proc_ifacename):
                    yield proc_ifacename
            except Exception, e:
                raise Exception('%s: error searching regex \'%s\' in %s (%s)'
                                %(ifacename, expr, proc_ifacename, str(e)))
        if not ifacenames:
            return
        for ifacename in ifacenames:
            try:
                if re.search(expr + '$', ifacename):
                    yield ifacename
            except Exception, e:
                raise Exception('%s: error searching regex \'%s\' in %s (%s)'
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
        regexs = self.glob_regexs

        if regexs[0].match(expr):
            # the first regex checks for exactly two levels of ranges defined only with square brackets
            # (e.g. swpxyz[10-23]subqwe[0-4].100) to handle naming with two levels of port names.
            m = regexs[0].match(expr)
            mlist = m.groups()
            if len(mlist) < 7:
                # we have problems and should not continue
                raise Exception('%s: error: unhandled glob expression %s\n%s' % (ifacename, expr,errmsg))

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
                raise Exception('%s: ' %ifacename + errmsg + '(unexpected len)')
            prefix = mlist[0]
            suffix = mlist[3]
            start_index = int(mlist[1])
            end_index = int(mlist[2])
            for i in range(start_index, end_index + 1):
                yield prefix + '%d' %i + suffix

        else:
            # Could not match anything.
            self.logger.warn('%s: %s' %(ifacename, errmsg))
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
        except IOError, e:
            self.logger.warn('error writing to file %s'
                %filename + '(' + str(e) + ')')
            return -1
        return 0

    def read_file(self, filename):
        """ read file and return lines from the file """
        try:
            self.logger.info('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readlines()
        except:
            return None
        return None

    def read_file_oneline(self, filename):
        """ reads and returns first line from the file """
        try:
            self.logger.info('reading \'%s\'' %filename)
            with open(filename, 'r') as f:
                return f.readline().strip('\n')
        except:
            return None
        return None

    def sysctl_set(self, variable, value):
        """ set sysctl variable to value passed as argument """
        utils.exec_command('sysctl %s=%s' % (variable, value))

    def sysctl_get(self, variable):
        """ get value of sysctl variable """
        return utils.exec_command('sysctl %s' % variable).split('=')[1].strip()

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
            for attrname, attrvals in attrsdict.iteritems():
                if not attrvals or attrvals.get('deprecated'):
                    continue
                retattrs.append(attrname)
            return retattrs
        except:
            return None

    def get_mod_attr(self, attrname):
        """ returns module attr info """
        try:
            return self._modinfo.get('attrs', {}).get(attrname)
        except:
            return None

    def get_mod_subattr(self, attrname, subattrname):
        """ returns module attrs defined in the module _modinfo dict"""
        try:
            return reduce(lambda d, k: d[k], ['attrs', attrname, subattrname],
                         self._modinfo)
        except:
            return None

    def get_modinfo(self):
        """ return module info """
        try:
            return self._modinfo
        except:
            return None

    def _get_reserved_vlan_range(self):
        start = end = 0
        get_resvvlan = '/usr/share/python-ifupdown2/get_reserved_vlan_range.sh'
        if not os.path.exists(get_resvvlan):
            return (start, end)
        try:
            (s, e) = utils.exec_command(get_resvvlan).strip('\n').split('-')
            start = int(s)
            end = int(e)
        except Exception, e:
            self.logger.debug('%s failed (%s)' %(get_resvvlan, str(e)))
            # ignore errors
            pass
        return (start, end)

    def _handle_reserved_vlan(self, vlanid, logprefix=''):
        """ Helper function to check and warn if the vlanid falls in the
        reserved vlan range """
        if vlanid in range(self._resv_vlan_range[0],
                           self._resv_vlan_range[1]):
           self.logger.error('%s: reserved vlan %d being used'
                   %(logprefix, vlanid) + ' (reserved vlan range %d-%d)'
                   %(self._resv_vlan_range[0], self._resv_vlan_range[1]))
           return True
        return False

    def _valid_ethaddr(self, ethaddr):
        """ Check if address is 00:00:00:00:00:00 """
        if not ethaddr or re.match('00:00:00:00:00:00', ethaddr):
            return False
        return True
