#!/usr/bin/python
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
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

from functools import partial
from ipaddr import IPNetwork, IPAddress

try:
    from ifupdown2.ifupdown.iface import *

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except ImportError:
    from ifupdown.iface import *

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags


def signal_handler_f(ps, sig, frame):
    if ps:
        ps.send_signal(sig)
    if sig == signal.SIGINT:
        raise KeyboardInterrupt

class utils():
    logger = logging.getLogger('ifupdown')
    DEVNULL = open(os.devnull, 'w')
    vlan_aware_bridge_address_support = None

    _string_values = {
        "on": True,
        "yes": True,
        "1": True,
        "fast": True,
        "off": False,
        "no": False,
        "0": False,
        "slow": False
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

    _onoff_onezero = {
        '1' : 'on',
        '0' : 'off'
    }

    _yesno_onezero = {
        '1' : 'yes',
        '0' : 'no'
    }

    """
    Set debian path as default path for all the commands.
    If command not present in debian path, search for the
    commands in the other system directories.
    This search is carried out to handle different locations
    on different distros.
    If the command is not found in any of the system
    directories, command execution will fail because we have
    set default path same as debian path.
    """
    bridge_cmd      = '/sbin/bridge'
    ip_cmd          = '/bin/ip'
    brctl_cmd       = '/sbin/brctl'
    pidof_cmd       = '/bin/pidof'
    service_cmd     = '/usr/sbin/service'
    sysctl_cmd      = '/sbin/sysctl'
    modprobe_cmd    = '/sbin/modprobe'
    pstree_cmd      = '/usr/bin/pstree'
    ss_cmd          = '/bin/ss'
    vrrpd_cmd       = '/usr/sbin/vrrpd'
    ifplugd_cmd     = '/usr/sbin/ifplugd'
    mstpctl_cmd     = '/sbin/mstpctl'
    ethtool_cmd     = '/sbin/ethtool'
    systemctl_cmd   = '/bin/systemctl'
    dpkg_cmd        = '/usr/bin/dpkg'

    for cmd in ['bridge',
                'ip',
                'brctl',
                'pidof',
                'service',
                'sysctl',
                'modprobe',
                'pstree',
                'ss',
                'vrrpd',
                'ifplugd',
                'mstpctl',
                'ethtool',
                'systemctl',
                'dpkg'
                ]:
        if os.path.exists(vars()[cmd + '_cmd']):
            continue
        for path in ['/bin/',
                     '/sbin/',
                     '/usr/bin/',
                     '/usr/sbin/',]:
            if os.path.exists(path + cmd):
                vars()[cmd + '_cmd'] = path + cmd
            else:
                logger.debug('warning: path %s not found: %s won\'t be usable' % (path + cmd, cmd))

    @staticmethod
    def get_onff_from_onezero(value):
        if value in utils._onoff_onezero:
            return utils._onoff_onezero[value]
        return value

    @staticmethod
    def get_yesno_from_onezero(value):
        if value in utils._yesno_onezero:
            return utils._yesno_onezero[value]
        return value

    @staticmethod
    def get_onoff_bool(value):
        if value in utils._onoff_bool:
            return utils._onoff_bool[value]
        return value

    @staticmethod
    def get_boolean_from_string(value, default=False):
        return utils._string_values.get(value, default)

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

    @staticmethod
    def get_int_from_boolean_and_string(value):
        try:
            return int(value)
        except:
            return int(utils.get_boolean_from_string(value))

    @staticmethod
    def strip_hwaddress(hwaddress):
        if hwaddress and hwaddress.startswith("ether"):
            hwaddress = hwaddress[5:].strip()
        return hwaddress.lower() if hwaddress else hwaddress
        # we need to "normalize" the user provided MAC so it can match with
        # what we have in the cache (data retrieved via a netlink dump by
        # nlmanager). nlmanager return all macs in lower-case

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
    def get_ip_objs(cls, module_name, ifname, addrs_list):
        addrs_obj_list = []
        for a in addrs_list or []:
            try:
                addrs_obj_list.append(IPNetwork(a) if '/' in a else IPAddress(a))
            except Exception as e:
                cls.logger.warning('%s: %s: %s' % (module_name, ifname, str(e)))
        return addrs_obj_list

    @classmethod
    def get_ip_obj(cls, module_name, ifname, addr):
        if addr:
            try:
                return IPNetwork(addr) if '/' in addr else IPAddress(addr)
            except Exception as e:
                cls.logger.warning('%s: %s: %s' % (module_name, ifname, str(e)))
        return None

    @classmethod
    def is_addr_ip_allowed_on(cls, ifaceobj, syntax_check=False):
        if cls.vlan_aware_bridge_address_support is None:
            cls.vlan_aware_bridge_address_support = utils.get_boolean_from_string(
                policymanager.policymanager_api.get_module_globals(
                    module_name='address',
                    attr='vlan_aware_bridge_address_support'
                ),
                True
            )
        msg = ('%s: ignoring ip address. Assigning an IP '
               'address is not allowed on' % ifaceobj.name)
        if (ifaceobj.role & ifaceRole.SLAVE
                and not (ifaceobj.link_privflags & ifaceLinkPrivFlags.VRF_SLAVE)):
            up = None
            if ifaceobj.upperifaces:
                up = ifaceobj.upperifaces[0]
            msg = ('%s enslaved interfaces. %s'
                   % (msg, ('%s is enslaved to %s'
                            % (ifaceobj.name, up)) if up else '')).strip()
            if syntax_check:
                cls.logger.warning(msg)
            else:
                cls.logger.info(msg)
            return False
        elif (ifaceobj.link_kind & ifaceLinkKind.BRIDGE
              and ifaceobj.link_privflags & ifaceLinkPrivFlags.BRIDGE_VLAN_AWARE
              and not cls.vlan_aware_bridge_address_support
        ):
            msg = '%s bridge vlan aware interfaces' % msg
            if syntax_check:
                cls.logger.warning(msg)
            else:
                cls.logger.info(msg)
            return False
        return True

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
