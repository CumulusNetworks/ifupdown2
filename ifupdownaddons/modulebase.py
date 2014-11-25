#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import re
import io
import logging
import subprocess
import traceback
from ifupdown.iface import *
#from ifupdownaddons.iproute2 import *
#from ifupdownaddons.dhclient import *
#from ifupdownaddons.bridgeutils import *
#from ifupdownaddons.mstpctlutil import *
#from ifupdownaddons.ifenslaveutil import *

class moduleBase(object):
    """ Base class for ifupdown addon modules

    Provides common infrastructure methods for all addon modules """

    def __init__(self, *args, **kargs):
        modulename = self.__class__.__name__
        self.logger = logging.getLogger('ifupdown.' + modulename)
        self.FORCE = kargs.get('force', False)
        """force interface configuration"""
        self.DRYRUN = kargs.get('dryrun', False)
        """only predend you are applying configuration, dont really do it"""
        self.NOWAIT = kargs.get('nowait', False)
        self.PERFMODE = kargs.get('perfmode', False)
        self.CACHE = kargs.get('cache', False)
        self.CACHE_FLAGS = kargs.get('cacheflags', 0x0)

    def log_warn(self, str):
        """ log a warning if err str is not one of which we should ignore """
        if not self.ignore_error(str):
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
            self.logger.warn(str)
        pass

    def log_error(self, str):
        """ log an err if err str is not one of which we should ignore and raise an exception """
        if not self.ignore_error(str):
            if self.logger.getEffectiveLevel() == logging.DEBUG:
                traceback.print_stack()
            raise Exception(str)
        else:
            pass

    def exec_command(self, cmd, cmdenv=None):
        """ execute command passed as argument.

        Args:
            cmd (str): command to execute

        Kwargs:
            cmdenv (dict): environment variable name value pairs
        """
        cmd_returncode = 0
        cmdout = ''

        try:
            self.logger.info('Executing ' + cmd)
            if self.DRYRUN:
                return cmdout
            ch = subprocess.Popen(cmd.split(),
                    stdout=subprocess.PIPE,
                    shell=False, env=cmdenv,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            cmdout = ch.communicate()[0]
            cmd_returncode = ch.wait()
        except OSError, e:
            raise Exception('could not execute ' + cmd +
                    '(' + str(e) + ')')
        if cmd_returncode != 0:
            raise Exception('error executing cmd \'%s\'' %cmd +
                '(' + cmdout.strip('\n ') + ')')
        return cmdout

    def exec_command_talk_stdin(self, cmd, stdinbuf):
        """ execute command passed as argument and write contents of stdinbuf
        into stdin of the cmd

        Args:
            cmd (str): command to execute
            stdinbuf (str): string to write to stdin of the cmd process
        """
        cmd_returncode = 0
        cmdout = ''

        try:
            self.logger.info('Executing %s (stdin=%s)' %(cmd, stdinbuf))
            if self.DRYRUN:
                return cmdout
            ch = subprocess.Popen(cmd.split(),
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    shell=False, env=cmdenv,
                    stderr=subprocess.STDOUT,
                    close_fds=True)
            cmdout = ch.communicate(input=stdinbuf)[0]
            cmd_returncode = ch.wait()
        except OSError, e:
            raise Exception('could not execute ' + cmd +
                    '(' + str(e) + ')')
        if cmd_returncode != 0:
            raise Exception('error executing cmd \'%s (%s)\''
                    %(cmd, stdinbuf) + '(' + cmdout.strip('\n ') + ')')
        return cmdout

    def get_ifaces_from_proc(self):
        ifacenames = []
        with open('/proc/net/dev') as f:
            try:
                lines = f.readlines()
                for line in lines:
                    ifacenames.append(line.split()[0].strip(': '))
            except:
                raise
        return ifacenames

    def parse_regex(self, expr, ifacenames=None):
        try:
            proc_ifacenames = self.get_ifaces_from_proc()
        except:
            self.logger.warn('error reading ifaces from proc')
        for proc_ifacename in proc_ifacenames:
            if re.search(expr + '$', proc_ifacename):
                yield proc_ifacename
        if not ifacenames:
            return
        for ifacename in ifacenames:
            if re.search(expr + '$', ifacename):
                yield ifacename

    def parse_glob(self, expr):
        errmsg = ('error parsing glob expression \'%s\'' %expr +
                    ' (supported glob syntax: swp1-10 or swp[1-10])')
        start_index = 0
        end_index = 0
        try:
            regexs = [re.compile(r"([A-Za-z0-9\-]+[A-Za-z])(\d+)\-(\d+)(.*)"),
                      re.compile(r"([A-Za-z0-9\-]+)\[(\d+)\-(\d+)\](.*)")]
            for r in regexs:
                m = r.match(expr)
                if not m:
                    continue
                mlist = m.groups()
                if len(mlist) != 4:
                    raise Exception(errmsg + '(unexpected len)')
                prefix = mlist[0]
                suffix = mlist[3]
                start_index = int(mlist[1])
                end_index = int(mlist[2])
        except:
            self.logger.warn(errmsg)
            pass
        if not start_index and not end_index:
            self.logger.warn(errmsg)
            yield expr
        else:
            for i in range(start_index, end_index + 1):
                yield prefix + '%d' %i + suffix

    def parse_port_list(self, port_expr, ifacenames=None):
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
        for expr in re.split(r'[\s\t]\s*', port_expr):
            if expr == 'noregex':
                regex = 0
            elif expr == 'noglob':
                glob = 0
            elif expr == 'regex':
                regex = 1
            elif expr == 'glob':
                glob = 1
            elif regex:
                for port in self.parse_regex(expr, ifacenames):
                    if port not in portlist:
                        portlist.append(port)
                regex = 0
            elif glob:
                for port in self.parse_glob(expr):
                    portlist.append(port)
                glob = 0
            else:
                portlist.append(expr)
        if not portlist:
            return None
        return portlist

    def ignore_error(self, errmsg):
        if (self.FORCE or re.search(r'exists', errmsg,
            re.IGNORECASE | re.MULTILINE)):
            return True
        return False

    def write_file(self, filename, strexpr):
        """ writes string to a file """
        try:
            self.logger.info('writing \'%s\'' %strexpr +
                ' to file %s' %filename)
            if self.DRYRUN:
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
        self.exec_command('sysctl %s=' %variable + '%s' %value)

    def sysctl_get(self, variable):
        """ get value of sysctl variable """
        return self.exec_command('sysctl %s' %variable).split('=')[1].strip()

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
        """ returns list of all module attrs defined in the module _modinfo dict"""
        try:
            return self._modinfo.get('attrs').keys()
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

    def get_flags(self):
        return dict(force=self.FORCE, dryrun=self.DRYRUN, nowait=self.NOWAIT,
                    perfmode=self.PERFMODE, cache=self.CACHE,
                    cacheflags=self.CACHE_FLAGS)

    def _get_reserved_vlan_range(self):
        start = end = 0
        get_resvvlan = '/usr/share/python-ifupdown2/get_reserved_vlan_range.sh'
        try:
            (s, e) = self.exec_command(get_resvvlan).strip('\n').split('-')
            start = int(s)
            end = int(e)
        except:
            # ignore errors
            pass
        return (start, end)
