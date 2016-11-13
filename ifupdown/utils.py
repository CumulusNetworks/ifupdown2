#!/usr/bin/python
#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#
# utils --
#    helper class
#

import os
import re
import shlex
import fcntl
import signal
import logging
import subprocess
import ifupdownflags

from functools import partial
from ipaddr import IPNetwork, IPAddress

def signal_handler_f(ps, sig, frame):
    if ps:
        ps.send_signal(sig)
    if sig == signal.SIGINT:
        raise KeyboardInterrupt

class utils():
    logger = logging.getLogger('ifupdown')
    DEVNULL = open(os.devnull, 'w')

    _string_values = {
        "on": True,
        "yes": True,
        "1": True,
        "off": False,
        "no": False,
        "0": False,
    }

    _binary_bool = {
        True: "1",
        False: "0",
    }

    _yesno_bool = {
        True: 'yes',
        False: 'no'
    }

    _onoff_bool = {
        'yes': 'on',
        'no': 'off'
    }

    @staticmethod
    def get_onoff_bool(value):
        if value in utils._onoff_bool:
            return utils._onoff_bool[value]
        return value

    @staticmethod
    def get_boolean_from_string(value):
        if value in utils._string_values:
            return utils._string_values[value]
        return False

    @staticmethod
    def get_yesno_boolean(bool):
        return utils._yesno_bool[bool]

    @staticmethod
    def boolean_support_binary(value):
        return utils._binary_bool[utils.get_boolean_from_string(value)]

    @staticmethod
    def is_binary_bool(value):
        return value == '0' or value == '1'

    @staticmethod
    def support_yesno_attrs(attrsdict, attrslist, ifaceobj=None):
        if ifaceobj:
            for attr in attrslist:
                value = ifaceobj.get_attr_value_first(attr)
                if value and not utils.is_binary_bool(value):
                    if attr in attrsdict:
                        bool = utils.get_boolean_from_string(attrsdict[attr])
                        attrsdict[attr] = utils.get_yesno_boolean(bool)
        else:
            for attr in attrslist:
                if attr in attrsdict:
                    attrsdict[attr] = utils.boolean_support_binary(attrsdict[attr])

    @classmethod
    def importName(cls, modulename, name):
        """ Import a named object """
        try:
            module = __import__(modulename, globals(), locals(), [name])
        except ImportError:
            return None
        return getattr(module, name)

    @classmethod
    def lockFile(cls, lockfile):
        try:
            fp = os.open(lockfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
            fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.fcntl(fp, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        except IOError:
            return False
        return True

    @classmethod
    def parse_iface_range(cls, name):
        # eg: swp1.[2-100]
        # return (prefix, range-start, range-end)
        # eg return ("swp1.", 1, 20, ".100")
        range_match = re.match("^([\w]+)\[([\d]+)-([\d]+)\]([\.\w]+)", name)
        if range_match:
            range_groups = range_match.groups()
            if range_groups[1] and range_groups[2]:
                return (range_groups[0], int(range_groups[1], 10),
                        int(range_groups[2], 10), range_groups[3])
        else:
            # eg: swp[1-20].100
            # return (prefix, range-start, range-end, suffix)
            # eg return ("swp", 1, 20, ".100")
            range_match = re.match("^([\w\.]+)\[([\d]+)-([\d]+)\]", name)
            if range_match:
                range_groups = range_match.groups()
                if range_groups[1] and range_groups[2]:
                    return (range_groups[0], int(range_groups[1], 10),
                            int(range_groups[2], 10))
        return None

    @classmethod
    def expand_iface_range(cls, name):
        ifacenames = []
        irange = cls.parse_iface_range(name)
        if irange:
            if len(irange) == 3:
                # eg swp1.[2-4], r = "swp1.", 2, 4)
                for i in range(irange[1], irange[2]):
                    ifacenames.append('%s%d' %(irange[0], i))
            elif len(irange) == 4:
                for i in range(irange[1], irange[2]):
                    # eg swp[2-4].100, r = ("swp", 2, 4, ".100")
                    ifacenames.append('%s%d%s' %(irange[0], i, irange[3]))
        return ifacenames

    @classmethod
    def is_ifname_range(cls, name):
        if '[' in name or ']' in name:
            return True
        return False

    @classmethod
    def check_ifname_size_invalid(cls, name=''):
        """ IFNAMSIZ in include/linux/if.h is 16 so we check this """
        IFNAMSIZ = 16
        if len(name) > IFNAMSIZ - 1:
            return True
        else:
            return False

    @classmethod
    def enable_subprocess_signal_forwarding(cls, ps, sig):
        signal.signal(sig, partial(signal_handler_f, ps))

    @classmethod
    def disable_subprocess_signal_forwarding(cls, sig):
        signal.signal(sig, signal.SIG_DFL)

    @classmethod
    def _log_command_exec(cls, cmd, stdin):
        if stdin:
            cls.logger.info('executing %s [%s]' % (cmd, stdin))
        else:
            cls.logger.info('executing %s' % cmd)

    @classmethod
    def _format_error(cls, cmd, cmd_returncode, cmd_output, stdin):
        if type(cmd) is list:
            cmd = ' '.join(cmd)
        if stdin:
            cmd = '%s [%s]' % (cmd, stdin)
        if cmd_output:
            return 'cmd \'%s\' failed: returned %d (%s)' % \
                   (cmd, cmd_returncode, cmd_output)
        else:
            return 'cmd \'%s\' failed: returned %d' % (cmd, cmd_returncode)

    @classmethod
    def get_normalized_ip_addr(cls, ifacename, ipaddrs):
        if not ipaddrs: return None
        if isinstance(ipaddrs, list):
                addrs = []
                for ip in ipaddrs:
                    if not ip:
                        continue
                    try:
                        addrs.append(str(IPNetwork(ip)) if '/' in ip else str(IPAddress(ip)))
                    except Exception as e:
                        cls.logger.warning('%s: %s' % (ifacename, e))
                return addrs
        else:
            try:
                return str(IPNetwork(ipaddrs)) if '/' in ipaddrs else str(IPAddress(ipaddrs))
            except Exception as e:
                cls.logger.warning('%s: %s' % (ifacename, e))
            return ipaddrs

    @classmethod
    def _execute_subprocess(cls, cmd,
                            env=None,
                            shell=False,
                            close_fds=False,
                            stdout=True,
                            stdin=None,
                            stderr=subprocess.STDOUT):
        """
        exec's commands using subprocess Popen
            Args:
                cmd, should be shlex.split if not shell
        returns: output

        Note: close_fds=True is affecting performance (2~3 times slower)
        """
        if ifupdownflags.flags.DRYRUN:
            return ''

        cmd_output = None
        try:
            ch = subprocess.Popen(cmd,
                                  env=env,
                                  shell=shell,
                                  close_fds=close_fds,
                                  stdin=subprocess.PIPE if stdin else None,
                                  stdout=subprocess.PIPE if stdout else cls.DEVNULL,
                                  stderr=stderr)
            utils.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            if stdout or stdin:
                cmd_output = ch.communicate(input=stdin)[0]
            cmd_returncode = ch.wait()
        except Exception as e:
            raise Exception('cmd \'%s\' failed (%s)' % (' '.join(cmd), str(e)))
        finally:
            utils.disable_subprocess_signal_forwarding(signal.SIGINT)
        if cmd_returncode != 0:
            raise Exception(cls._format_error(cmd,
                                              cmd_returncode,
                                              cmd_output,
                                              stdin))
        return cmd_output

    @classmethod
    def exec_user_command(cls, cmd, close_fds=False, stdout=True,
                          stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(cmd, stdin)
        return cls._execute_subprocess(cmd,
                                       shell=True,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

    @classmethod
    def exec_command(cls, cmd, env=None, close_fds=False, stdout=True,
                     stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(cmd, stdin)
        return cls._execute_subprocess(shlex.split(cmd),
                                       env=env,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

    @classmethod
    def exec_commandl(cls, cmdl, env=None, close_fds=False, stdout=True,
                      stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(' '.join(cmdl), stdin)
        return cls._execute_subprocess(cmdl,
                                       env=env,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

fcntl.fcntl(utils.DEVNULL, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
