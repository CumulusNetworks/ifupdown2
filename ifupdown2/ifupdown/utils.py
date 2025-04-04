#!/usr/bin/env python3
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
from shutil import which
import fcntl
import signal
import logging
import subprocess
import itertools

from functools import partial
from ipaddress import IPv4Address

try:
    from ifupdown2.ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags

    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
except (ImportError, ModuleNotFoundError):
    from ifupdown.iface import ifaceRole, ifaceLinkKind, ifaceLinkPrivFlags

    import ifupdown.policymanager as policymanager
    import ifupdown.ifupdownflags as ifupdownflags


def signal_handler_f(ps, sig, frame):
    if ps:
        ps.send_signal(sig)
    if sig == signal.SIGINT:
        raise KeyboardInterrupt


def default_commands():
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
    logger = logging.getLogger('ifupdown')
    default_cmds = """
        /sbin/bridge    /bin/ip           /sbin/brctl
        /bin/pidof      /usr/sbin/service /sbin/sysctl
        /sbin/modprobe  /usr/bin/pstree   /bin/ss
        /usr/sbin/vrrpd /usr/sbin/ifplugd /sbin/mstpctl
        /sbin/ethtool   /bin/systemctl    /usr/bin/dpkg
    """.split()
    logger.info("utils init command paths")
    for cmd in default_cmds:
        name = os.path.basename(cmd)
        path = which(name)
        if path:
            yield (name, path)
            continue
        logger.debug(f"warning: path {cmd} not found: {name} won't be usable")
        yield (name, cmd)


class MetaUtils(type):
    @classmethod
    def __prepare__(cls, _name, _bases):
        """ predefined class attributes """
        return {f'{prog}_cmd': path for prog, path in default_commands()}

    def __call__(cls, *_a, **_k):
        """ forbiden call """
        raise NotImplementedError("This class should not be instanciated")

    def __new__(cls, name, bases, attrs):
        """ finalize class definition (replacing methods to classmethods) """
        return type.__new__(cls, name, bases, {
            k: classmethod(v) if callable(v) else v for k, v in attrs.items()
        })


class utils(metaclass=MetaUtils):
    logger = logging.getLogger('ifupdown')
    DEVNULL = open(os.devnull, 'w')
    vlan_aware_bridge_address_support = None

    vni_max = 16777215

    _string_values = {
        "on": True,
        "yes": True,
        "1": True,
        "fast": True,
        "off": False,
        "no": False,
        "0": False,
        "slow": False,
        True: True,
        False: False
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

    mac_translate_tab = str.maketrans(":.-,", "    ")

    def mac_str_to_int(cls, hw_address):
        mac = 0
        if hw_address:
            pass
            for i in hw_address.translate(cls.mac_translate_tab).split():
                mac = mac << 8
                mac += int(i, 16)
        return mac

    def get_onff_from_onezero(cls, value):
        if value in cls._onoff_onezero:
            return cls._onoff_onezero[value]
        return value

    def get_yesno_from_onezero(cls, value):
        if value in cls._yesno_onezero:
            return cls._yesno_onezero[value]
        return value

    def get_onoff_bool(cls, value):
        if value in cls._onoff_bool:
            return cls._onoff_bool[value]
        return value

    def get_boolean_from_string(cls, value, default=False):
        return cls._string_values.get(value, default)

    def get_yesno_boolean(cls, bool):
        return cls._yesno_bool[bool]

    def boolean_support_binary(cls, value):
        return cls._binary_bool[cls.get_boolean_from_string(value)]

    def is_binary_bool(cls, value):
        return value == '0' or value == '1'

    def support_yesno_attrs(cls, attrsdict, attrslist, ifaceobj=None):
        if ifaceobj:
            for attr in attrslist:
                value = ifaceobj.get_attr_value_first(attr)
                if value and not cls.is_binary_bool(value):
                    if attr in attrsdict:
                        bool = cls.get_boolean_from_string(attrsdict[attr])
                        attrsdict[attr] = cls.get_yesno_boolean(bool)
        else:
            for attr in attrslist:
                if attr in attrsdict:
                    attrsdict[attr] = cls.boolean_support_binary(attrsdict[attr])

    def get_int_from_boolean_and_string(cls, value):
        try:
            return int(value)
        except Exception:
            return int(cls.get_boolean_from_string(value))

    def strip_hwaddress(cls, hwaddress):
        if hwaddress and hwaddress.startswith("ether"):
            hwaddress = hwaddress[5:].strip()
        return hwaddress.lower() if hwaddress else hwaddress
        # we need to "normalize" the user provided MAC so it can match with
        # what we have in the cache (data retrieved via a netlink dump by
        # nlmanager). nlmanager return all macs in lower-case

    def importName(cls, modulename, name):
        """ Import a named object """
        try:
            module = __import__(modulename, globals(), locals(), [name])
        except ImportError:
            return None
        return getattr(module, name)

    def lockFile(cls, lockfile):
        try:
            fp = os.open(lockfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
            fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.fcntl(fp, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        except IOError:
            return False
        return True

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

    def expand_iface_range(cls, name):
        ifrange = cls.parse_iface_range(name)
        if not ifrange:
            return []
        prefix, start, end = ifrange[0], ifrange[1], ifrange[2]
        suffix = '' if len(ifrange) <= 3 else ifrange[3]
        return [f'{prefix}{i}{suffix}' for i in range(start, end + 1)]

    def is_ifname_range(cls, name):
        if '[' in name or ']' in name:
            return True
        return False

    def check_ifname_size_invalid(cls, name=''):
        """ IFNAMSIZ in include/linux/if.h is 16 so we check this """
        IFNAMSIZ = 16
        if len(name) > IFNAMSIZ - 1:
            return True
        else:
            return False

    def enable_subprocess_signal_forwarding(cls, ps, sig):
        signal.signal(sig, partial(signal_handler_f, ps))

    def disable_subprocess_signal_forwarding(cls, sig):
        signal.signal(sig, signal.SIG_DFL)

    def _log_command_exec(cls, cmd, stdin):
        dry_run = "DRY-RUN: " if ifupdownflags.flags.DRYRUN else ""
        if stdin:
            cls.logger.info('%sexecuting %s [%s]' % (dry_run, cmd, stdin))
        else:
            cls.logger.info('%sexecuting %s' % (dry_run, cmd))

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
            cls.enable_subprocess_signal_forwarding(ch, signal.SIGINT)
            if stdout or stdin:
                cmd_output = ch.communicate(input=stdin.encode() if stdin else stdin)[0]
            cmd_returncode = ch.wait()
        except Exception as e:
            raise Exception('cmd \'%s\' failed (%s)' % (' '.join(cmd), str(e)))
        finally:
            cls.disable_subprocess_signal_forwarding(signal.SIGINT)

        cmd_output_string = cmd_output.decode() if cmd_output is not None else cmd_output

        if cmd_returncode != 0:
            raise Exception(cls._format_error(cmd,
                                              cmd_returncode,
                                              cmd_output_string,
                                              stdin))
        return cmd_output_string

    def exec_user_command(cls, cmd, env=None, close_fds=False, stdout=True,
                          stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(cmd, stdin)
        return cls._execute_subprocess(cmd,
                                       shell=True,
                                       env=env,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

    def exec_command(cls, cmd, env=None, close_fds=False, stdout=True,
                     stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(cmd, stdin)
        return cls._execute_subprocess(shlex.split(cmd),
                                       env=env,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

    def exec_commandl(cls, cmdl, env=None, close_fds=False, stdout=True,
                      stdin=None, stderr=subprocess.STDOUT):
        cls._log_command_exec(' '.join(cmdl), stdin)
        return cls._execute_subprocess(cmdl,
                                       env=env,
                                       close_fds=close_fds,
                                       stdout=stdout,
                                       stdin=stdin,
                                       stderr=stderr)

    def ints_to_ranges(cls, ints):
        for a, b in itertools.groupby(enumerate(ints), lambda x_y: x_y[1] - x_y[0]):
            b = list(b)
            yield b[0][1], b[-1][1]

    def ranges_to_ints(cls, rangelist):
        """ returns expanded list of integers given set of string ranges
        example: ['1', '2-4', '6'] returns [1, 2, 3, 4, 6]
        """
        result = []
        try:
            for part in rangelist:
                if '-' in part:
                    a, b = part.split('-')
                    a, b = int(a), int(b)
                    result.extend(list(range(a, b + 1)))
                else:
                    a = int(part)
                    result.append(a)
        except Exception:
            cls.logger.warning('unable to parse vids \'%s\'' %''.join(rangelist))
            pass
        return result

    def compress_into_ranges(cls, ids_ints):
        return ['%d' %start if start == end else '%d-%d' %(start, end)
                       for start, end in cls.ints_to_ranges(ids_ints)]

    def compress_into_ip_ranges(cls, ip_list):
        return [
            "%s" % IPv4Address(start) if start == end else "%s-%s" % (IPv4Address(start), IPv4Address(end)) for
            start, end in cls.ints_to_ranges(map(int, ip_list))
        ]

    def diff_ids(cls, ids1_ints, ids2_ints):
        return set(ids2_ints).difference(ids1_ints), set(ids1_ints).difference(ids2_ints)

    def compare_ids(cls, ids1, ids2, pvid=None, expand_range=True):
        """ Returns true if the ids are same else return false """

        if expand_range:
            ids1_ints = cls.ranges_to_ints(ids1)
            ids2_ints = cls.ranges_to_ints(ids2)
        else:
            ids1_ints = cls.ranges_to_ints(ids1)
            ids2_ints = ids2
        set_diff = set(ids1_ints).symmetric_difference(ids2_ints)
        if pvid and int(pvid) in set_diff:
            set_diff.remove(int(pvid))
        if set_diff:
            return False
        else:
            return True

    def get_vlan_vni_in_map_entry(cls, vlan_vni_map_entry):
        # a good example for map is bridge-vlan-vni-map attribute
        # format eg: <vlan>=<vni>
        # 1000-1004=5000-5004
        # 1000-1004=auto  /* here vni = vlan */
        # 1000-1004=auto-10 /* here vni = vlan - 10 */
        # 1000-1004=auto+10 /* here vni = vlan + 10 */

        vlan = None
        vni = None
        try:
            (vlan, vni) = vlan_vni_map_entry.split('=', 1)
            if vni == 'auto':
                vni = vlan
            elif vni.startswith('auto'):
                vnistart = 0
                vniend = 0
                if vni.startswith('auto+'):
                    vni = vni.split('+', 1)[1]
                    vint = int(vni)
                    if vint < 0:
                        raise Exception("invalid auto vni suffix %d" % (vint))
                    if '-' in vlan:
                        (vstart, vend) = vlan.split('-', 1)
                        vnistart = int(vstart) + vint
                        vniend = int(vend) + vint
                    else:
                        vnistart = int(vlan) + vint
                elif vni.startswith('auto-'):
                    vni = vni.split('-', 1)[1]
                    vint = int(vni)
                    if vint < 0:
                        raise Exception("invalid auto vni suffix %d" % (vint))
                    if '-' in vlan:
                        (vstart, vend) = vlan.split('-', 1)
                        vnistart = int(vstart) - vint
                        vniend = int(vend) - vint
                    else:
                        vnistart = int(vlan) - vint
                if (vnistart <= 0 or (vniend > 0 and (vniend < vnistart)) or
                    (vnistart > cls.vni_max) or (vniend > cls.vni_max)):
                        raise Exception("invalid vni - unable to derive auto vni %s" % (vni))
                if vniend > 0:
                    vni = '%d-%d' % (vnistart, vniend)
                else:
                    vni = '%d' % (vnistart)
        except Exception as e:
            raise Exception(str(e))
            return
        return (vlan, vni)

    def get_vlan_vnis_in_map(cls, vlan_vni_map):
        # a good example for map is bridge-vlan-vni-map attribute
        # format eg: <vlan>=<vni>
        # 1000-1004=5000-5004
        # 1000-1004=auto  /* here vni = vlan */
        # 1000-1004=auto-10 /* here vni = vlan - 10 */
        # 1000-1004=auto+10 /* here vni = vlan + 10 */
        vnis = []
        vlans = []
        for ventry in vlan_vni_map.split():
            try:
                (vlan, vni) = cls.get_vlan_vni_in_map_entry(ventry)
            except Exception as e:
                cls.logger.error("invalid vlan vni map entry - %s (%s)" % (ventry, str(e)))
                raise
            vlans.extend([vlan])
            vnis.extend([vni])
        return (vlans, vnis)

    def get_vni_mcastgrp_in_map(cls, vni_mcastgrp_map):
        vnid = {}
        for ventry in vni_mcastgrp_map.split():
            try:
                (vnis, mcastgrp) = ventry.split('=', 1)
                vnis_int = utils.ranges_to_ints([vnis])
                for v in vnis_int:
                    vnid[v] = mcastgrp
            except Exception as e:
                cls.logger.error("invalid vlan mcast grp map entry - %s (%s)" % (ventry, str(e)))
                raise
        return vnid

fcntl.fcntl(utils.DEVNULL, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
