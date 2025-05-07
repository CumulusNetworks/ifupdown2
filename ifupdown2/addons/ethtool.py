#!/usr/bin/env python3
#
# Copyright 2014-2017 Cumulus Networks, Inc. All rights reserved.
# Author: Roopa Prabhu, roopa@cumulusnetworks.com
#

import os

try:
    from ifupdown2.lib.addon import Addon

    import ifupdown2.ifupdown.ifupdownflags as ifupdownflags
    import ifupdown2.ifupdown.policymanager as policymanager
    import ifupdown2.ifupdown.statemanager as statemanager

    from ifupdown2.ifupdown.iface import ifaceLinkPrivFlags
    from ifupdown2.ifupdown.utils import utils
    from ifupdown2.ifupdown.exceptions import moduleNotSupported

    from ifupdown2.ifupdownaddons.utilsbase import *
    from ifupdown2.ifupdownaddons.modulebase import moduleBase
except ImportError:
    from lib.addon import Addon

    import ifupdown.ifupdownflags as ifupdownflags
    import ifupdown.policymanager as policymanager
    import ifupdown.statemanager as statemanager

    from ifupdown.iface import ifaceLinkPrivFlags
    from ifupdown.utils import utils
    from ifupdown.exceptions import moduleNotSupported

    from ifupdownaddons.utilsbase import *
    from ifupdownaddons.modulebase import moduleBase


class ethtool(Addon, moduleBase):
    """  ifupdown2 addon module to configure ethtool attributes """

    _modinfo = {
        "mhelp": "ethtool configuration module for interfaces",
        "attrs": {
            "link-speed": {
                "help": "set link speed",
                "validvals": [
                    "10",
                    "100",
                    "1000",
                    "10000",
                    "25000",
                    "40000",
                    "50000",
                    "100000",
                    "200000",
                    "400000"
                ],
                "example": ["link-speed 1000"],
                "default": "varies by platform and port"
            },
            "link-duplex": {
                "help": "set link duplex",
                "example": ["link-duplex full"],
                "validvals": ["half", "full"],
                "default": "full"
            },
            "link-autoneg": {
                "help": "set autonegotiation",
                "example": ["link-autoneg on"],
                "validvals": ["yes", "no", "on", "off"],
                "default": "varies by platform and port"
            },
            "link-fec": {
                "help": "set forward error correction mode",
                "example": ["link-fec rs"],
                "validvals": ["rs", "baser", "auto", "off"],
                "default": "varies by platform and port"
            },
            "link-lanes": {
                "help": "set lanes",
                "example": ["link-lanes 4"],
                "validvals": ["1", "2", "4", "8"],
                "default": "varies by platform and port"
            },
            'gro-offload': {
                'help': 'Generic Receive Offload',
                'example': ['gro-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'lro-offload': {
                'help': 'Large Receive Offload',
                'example': ['lro-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'gso-offload': {
                'help': 'Generic Segmentation Offload',
                'example': ['tso-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'tso-offload': {
                'help': 'TCP Segmentation Offload',
                'example': ['tso-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'ufo-offload': {
                'help': 'UDP Fragmentation Offload',
                'example': ['ufo-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'tx-offload': {
                'help': 'TX Checksum Offload',
                'example': ['tx-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'rx-offload': {
                'help': 'RX Checksum Offload',
                'example': ['rx-offload on'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'rx-vlan-filter': {
                'help': 'RX Vlan Filter',
                'example': ['rx-vlan-filter off'],
                'validvals': ['on', 'off'],
                'default': 'varies by interface'
            },
            'ring-rx': {
                'help': 'Ring RX Parameter',
                'example': ['ring-rx 512'],
                'validvals': ['max', '<number>'],
                'default': 'varies by interface'
            },
            'ring-tx': {
                'help': 'Ring TX Parameter',
                'example': ['ring-tx 512'],
                'validvals': ['max', '<number>'],
                'default': 'varies by interface'
            },
        }
    }

    def __init__(self, *args, **kargs):
        Addon.__init__(self)
        moduleBase.__init__(self, *args, **kargs)
        if not os.path.exists(utils.ethtool_cmd):
            raise moduleNotSupported('module init failed: %s: not found' % utils.ethtool_cmd)
        # keep a list of iface objects who have modified link attributes
        self.ifaceobjs_modified_configs = []
        # Cache for features
        self.feature_cache = None

        ignore_errors_policy = policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr='ethtool_ignore_errors'
        )
        try:
            self.ethtool_ignore_errors = utils.get_boolean_from_string(
                ignore_errors_policy,
                default=False,
            )
        except TypeError:
            self.logger.warning(
                "ethtool: invalid ethtool_ignore_errors policy; "
                "errors will not be ignored"
            )
            self.ethtool_ignore_errors = False

        single_speed_policy = (
            policymanager.policymanager_api.get_module_globals(
                module_name=self.__class__.__name__,
                attr="enable-single-speed-autoneg"
            )
        )
        try:
            self.single_all_speed_autoneg_enabled = (
                utils.get_boolean_from_string(
                    single_speed_policy,
                    default=False,
                )
            )
        except TypeError:
            self.logger.warning(
                "ethtool: invalid enable-single-speed-autoneg policy; "
                "feature disabled"
            )
            self.single_all_speed_autoneg_enabled = False
        self.single_all_speed_autoneg_map = {
            True: "0xFFFFFFFFFFFFFFFF",
            False: "0x8080808080808080",
        }

    def do_ring_settings(self, ifaceobj, attr_name, option):
        # Get the current configuration value and default value for the specified attribute
        config_val = ifaceobj.get_attr_value_first(attr_name)
        default_val = policymanager.policymanager_api.get_iface_default(
                            module_name='ethtool',
                            ifname=ifaceobj.name,
                            attr=attr_name)

        # Check which variable to use, config_val > default_val. If none are set, return.
        value = config_val or default_val
        if not value:
            return

        if value == "max":
            # Get the maximum value for the specified attribute
            max_val = self.get_max_attr(attr_name, ifaceobj)
            if not max_val:
                return
            value = max_val

        # Get the current running value
        running_val = self.get_running_attr(attr_name, ifaceobj)


        # If the value is the same as the running value, do nothing
        if value == running_val:
            return

        # Generate the ethtool command
        cmd = ('%s --set-ring %s %s %s' %
                    (utils.ethtool_cmd, ifaceobj.name, option, value))

        # Execute the ethtool command if command is generated
        if cmd:
            try:
                utils.exec_command(cmd)
            except Exception as e:
                self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj)


    def do_offload_settings(self, ifaceobj, attr_name, eth_name):
        default = 'default_' + eth_name
        config_val = ifaceobj.get_attr_value_first(attr_name)
        # Default
        default_val = None
        saved_ifaceobjs = statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name)
        if saved_ifaceobjs:
            default_val = saved_ifaceobjs[0].get_attr_value_first(default)
        if config_val or default_val:

            # get running value
            running_val = str(self.get_running_attr(eth_name, ifaceobj)).lower()
            # Save default value
            # Load state data
            if not default_val:
                ifaceobj.config[default] = [running_val]
            elif config_val:
                # resave for state
                ifaceobj.config[default] = [default_val]

            if not config_val:
                config_val = default_val

            if config_val and config_val != running_val:
                try:
                    cmd = ('%s -K %s %s %s' %
                            (utils.ethtool_cmd, ifaceobj.name, eth_name, config_val))
                    utils.exec_command(cmd)
                except Exception as e:
                    self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj)

        ignore_errors_policy = policymanager.policymanager_api.get_module_globals(
            module_name=self.__class__.__name__,
            attr='ethtool_ignore_errors'
        )
        try:
            self.ethtool_ignore_errors = utils.get_boolean_from_string(
                ignore_errors_policy,
                default=False,
            )
        except TypeError:
            self.ethtool_ignore_errors = False

    def do_lanes_settings(self, ifaceobj):
        lanescmd = ''

        # attribute existed before but we must reset to default
        config_val = ifaceobj.get_attr_value_first('link-lanes')
        default_val = policymanager.policymanager_api.get_iface_default(
                            module_name='ethtool',
                            ifname=ifaceobj.name,
                            attr='link-lanes')

        if not default_val and not config_val:
            # there is no point in checking the running config
            # if we have no default and the user did not have settings
            return False, None

        # use only lowercase values
        running_val = str(self.get_running_attr('lanes', ifaceobj)).lower()

        if config_val:
            config_val = config_val.lower()
        if default_val:
            default_val = default_val.lower()

        # check running values
        if config_val and config_val == running_val:
            return False, None

        if not config_val and default_val and default_val == running_val:
            # nothing configured but the default is running
            return False, None

        # if we got this far, we need to change it
        if config_val and (config_val != running_val):
            # if the configured value is not set, set it
            lanescmd = config_val
        elif default_val and (default_val != running_val):
            # or if it has a default not equal to running value, set it
            lanescmd = default_val

        return (True, f"lanes {lanescmd}") if lanescmd else (False, None)

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

        # use only lowercase values
        running_val = str(self.get_running_attr('fec', ifaceobj)).lower()

        if config_val:
            config_val = config_val.lower()
        if default_val:
            default_val = default_val.lower()

        # check running values
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
            except Exception as e:
                if not self.ethtool_ignore_errors:
                    self.log_error('%s: %s' %(ifaceobj.name, str(e)), ifaceobj)

    def do_speed_lane_duplex_autoneg_settings(self, ifaceobj, down=False):
        if self.single_all_speed_autoneg_enabled:
            self.single_speed_an_settings(ifaceobj, down)
        else:
            self.process_speed_lane_duplex_autoneg_settings(ifaceobj, down)

    @staticmethod
    def _value_is_set(value):
        return value is not None and value != ""

    def get_old_link_attrs_from_statemanager(self, ifname):
        old_ifaceobjs = (
            statemanager.statemanager_api.get_ifaceobjs(ifname) or []
        )
        old_attrs = [None, None, None, None]
        old_effective_autoneg = None
        old_effective_speed = None
        old_effective_duplex = None
        old_effective_lanes = None
        old_pending_lane_clear = None
        attr_names = (
            "link-speed",
            "link-duplex",
            "link-autoneg",
            "link-lanes",
        )

        for old_ifaceobj in old_ifaceobjs:
            if old_pending_lane_clear is None:
                pending_lane_clear = getattr(
                    old_ifaceobj,
                    "ethtool_pending_lane_clear",
                    None,
                )
                if isinstance(pending_lane_clear, dict):
                    old_pending_lane_clear = dict(pending_lane_clear)
            if old_effective_autoneg is None:
                old_effective_autoneg = getattr(
                    old_ifaceobj,
                    "ethtool_effective_autoneg",
                    None,
                )
            if old_effective_speed is None:
                old_effective_speed = getattr(
                    old_ifaceobj,
                    "ethtool_effective_speed",
                    None,
                )
            if old_effective_duplex is None:
                old_effective_duplex = getattr(
                    old_ifaceobj,
                    "ethtool_effective_duplex",
                    None,
                )
            if old_effective_lanes is None:
                old_effective_lanes = getattr(
                    old_ifaceobj,
                    "ethtool_effective_lanes",
                    None,
                )
            for index, attr_name in enumerate(attr_names):
                if old_attrs[index] is None:
                    old_attrs[index] = old_ifaceobj.get_attr_value_first(
                        attr_name
                    )

        return (
            tuple(old_attrs),
            old_effective_autoneg,
            old_effective_speed,
            old_effective_duplex,
            old_effective_lanes,
            old_pending_lane_clear,
        )

    @staticmethod
    def normalize_ethtool_data(autoneg, speed, duplex):
        return (
            utils.get_boolean_from_string(autoneg),
            int(speed) if speed is not None else None,
            str(duplex).lower() if duplex else "",
        )

    def get_advertise_bitmap(self, down, autoneg, speed):
        if not autoneg:
            return ""
        if down or speed is None:
            return self.single_all_speed_autoneg_map[True]
        return self.single_all_speed_autoneg_map[False]

    def validate_ethtool_speed(self, ifaceobj, ifname, config_speed):
        if not self._value_is_set(config_speed):
            return True, None

        try:
            speed = int(config_speed)
        except (TypeError, ValueError):
            self.log_error(
                "%s: link-speed is not a valid integer: %s"
                % (ifname, config_speed),
                ifaceobj,
            )
            return False, None

        if speed <= 0:
            self.log_error(
                "%s: link-speed must be a positive integer: %s"
                % (ifname, config_speed),
                ifaceobj,
            )
            return False, None

        return True, speed

    def get_lane_cache_clear_command(
            self,
            ifname,
            old_speed,
            old_autoneg,
            old_lanes,
            old_effective_autoneg,
            old_pending_lane_clear,
            target_autoneg,
            target_lanes,
            target_speed,
            target_duplex):
        if old_pending_lane_clear:
            old_speed = old_pending_lane_clear.get("speed", old_speed)
            old_lanes = old_pending_lane_clear.get("lanes", old_lanes)
            effective_old_autoneg = old_pending_lane_clear.get(
                "autoneg",
                False,
            )
        elif old_effective_autoneg is not None:
            effective_old_autoneg = old_effective_autoneg
        elif self._value_is_set(old_autoneg):
            effective_old_autoneg = old_autoneg
        elif self._value_is_set(old_speed):
            effective_old_autoneg = "off"
        else:
            effective_old_autoneg = None

        clear_speed = target_speed
        if clear_speed is None and self._value_is_set(old_speed):
            try:
                old_speed_int = int(old_speed)
                if old_speed_int > 0:
                    clear_speed = old_speed_int
            except (TypeError, ValueError):
                pass

        if (
                target_autoneg
                and self._value_is_set(effective_old_autoneg)
                and not utils.get_boolean_from_string(
                    effective_old_autoneg
                )
                and (old_lanes or old_pending_lane_clear)
                and not target_lanes
                and clear_speed is not None
        ):
            command = [
                utils.ethtool_cmd,
                "-s",
                ifname,
                "autoneg",
                "off",
                "speed",
                str(clear_speed),
            ]
            if target_duplex:
                command.extend(("duplex", target_duplex))
            return " ".join(command)
        return None

    def get_link_mode_restore_command(
            self,
            ifname,
            old_speed,
            old_duplex,
            old_autoneg,
            old_lanes,
            old_effective_autoneg,
            old_pending_lane_clear):
        if old_pending_lane_clear:
            old_speed = old_pending_lane_clear.get("speed", old_speed)
            old_duplex = old_pending_lane_clear.get("duplex", old_duplex)
            old_lanes = old_pending_lane_clear.get("lanes", old_lanes)
            old_effective_autoneg = old_pending_lane_clear.get(
                "autoneg",
                old_effective_autoneg,
            )
        if old_effective_autoneg is not None:
            autoneg = bool(old_effective_autoneg)
        elif self._value_is_set(old_autoneg):
            autoneg = utils.get_boolean_from_string(old_autoneg)
        elif self._value_is_set(old_speed):
            autoneg = False
        else:
            return None

        speed = None
        if self._value_is_set(old_speed):
            try:
                old_speed_int = int(old_speed)
                if old_speed_int > 0:
                    speed = old_speed_int
            except (TypeError, ValueError):
                pass

        command = [
            utils.ethtool_cmd,
            "-s",
            ifname,
            "autoneg",
            "on" if autoneg else "off",
        ]
        if speed is not None:
            command.extend(("speed", str(speed)))
        if old_duplex:
            command.extend(("duplex", str(old_duplex).lower()))
        if old_lanes:
            command.extend(("lanes", str(old_lanes)))
        advertise = self.get_advertise_bitmap(False, autoneg, speed)
        if advertise:
            command.extend(("advertise", advertise))
        return " ".join(command)

    def single_speed_an_settings(self, ifaceobj, down=False):
        ifname = ifaceobj.name
        if not ifname.startswith("swp"):
            self.process_speed_lane_duplex_autoneg_settings(
                ifaceobj,
                down,
            )
            return

        user_speed = ifaceobj.get_attr_value_first("link-speed")
        user_duplex = ifaceobj.get_attr_value_first("link-duplex")
        user_autoneg = ifaceobj.get_attr_value_first("link-autoneg")
        user_lanes = ifaceobj.get_attr_value_first("link-lanes")

        default_speed = policymanager.policymanager_api.get_iface_default(
            module_name="ethtool",
            ifname=ifname,
            attr="link-speed",
        )
        default_duplex = policymanager.policymanager_api.get_iface_default(
            module_name="ethtool",
            ifname=ifname,
            attr="link-duplex",
        )
        default_autoneg = policymanager.policymanager_api.get_iface_default(
            module_name="ethtool",
            ifname=ifname,
            attr="link-autoneg",
        )
        default_lanes = policymanager.policymanager_api.get_iface_default(
            module_name="ethtool",
            ifname=ifname,
            attr="link-lanes",
        )

        user_mode_intent = any(
            self._value_is_set(value)
            for value in (user_speed, user_autoneg)
        )
        default_mode_intent = any(
            self._value_is_set(value)
            for value in (default_speed, default_autoneg)
        )
        if not (
                default_mode_intent
                if down
                else user_mode_intent or default_mode_intent
        ):
            self.process_speed_lane_duplex_autoneg_settings(
                ifaceobj,
                down,
            )
            return

        (
            (old_speed, old_duplex, old_autoneg, old_lanes),
            old_effective_autoneg,
            old_effective_speed,
            old_effective_duplex,
            old_effective_lanes,
            old_pending_lane_clear,
        ) = (
            self.get_old_link_attrs_from_statemanager(ifname)
        )
        historical_speed = (
            old_effective_speed
            if old_effective_speed is not None
            else old_speed
        )
        historical_duplex = (
            old_effective_duplex
            if old_effective_duplex is not None
            else old_duplex
        )
        historical_lanes = (
            old_effective_lanes
            if old_effective_lanes is not None
            else old_lanes
        )
        if old_pending_lane_clear:
            previous_effective_autoneg = old_pending_lane_clear.get(
                "autoneg",
                old_effective_autoneg,
            )
        elif old_effective_autoneg is not None:
            previous_effective_autoneg = old_effective_autoneg
        elif self._value_is_set(old_autoneg):
            previous_effective_autoneg = (
                utils.get_boolean_from_string(old_autoneg)
            )
        elif self._value_is_set(old_speed):
            previous_effective_autoneg = False
        else:
            previous_effective_autoneg = None
        ifaceobj.ethtool_effective_autoneg = previous_effective_autoneg
        ifaceobj.ethtool_effective_speed = historical_speed
        ifaceobj.ethtool_effective_duplex = historical_duplex
        ifaceobj.ethtool_effective_lanes = historical_lanes
        ifaceobj.ethtool_pending_lane_clear = (
            dict(old_pending_lane_clear)
            if old_pending_lane_clear
            else None
        )

        if down:
            autoneg_raw = default_autoneg
            speed_raw = default_speed
            duplex_raw = default_duplex
            lanes_to_configure = default_lanes or ""
        else:
            autoneg_raw = (
                user_autoneg
                if self._value_is_set(user_autoneg)
                else default_autoneg
            )
            speed_raw = (
                user_speed
                if self._value_is_set(user_speed)
                else default_speed
            )
            duplex_raw = (
                user_duplex
                if self._value_is_set(user_duplex)
                else default_duplex
            )
            lanes_to_configure = user_lanes or default_lanes or ""

        speed_valid, speed_to_configure = self.validate_ethtool_speed(
            ifaceobj,
            ifname,
            speed_raw,
        )
        if not speed_valid:
            return

        autoneg_to_configure, _, duplex_to_configure = (
            self.normalize_ethtool_data(
                autoneg_raw,
                speed_to_configure,
                duplex_raw,
            )
        )
        if speed_to_configure is None and not autoneg_to_configure:
            self.log_error(
                "%s: link-speed is not set while link-autoneg is disabled"
                % ifname,
                ifaceobj,
            )
            return

        advertise_to_configure = self.get_advertise_bitmap(
            down,
            autoneg_to_configure,
            speed_to_configure,
        )
        command = [
            utils.ethtool_cmd,
            "-s",
            ifname,
            "autoneg",
            "on" if autoneg_to_configure else "off",
        ]
        if speed_to_configure is not None:
            command.extend(("speed", str(speed_to_configure)))
        if duplex_to_configure:
            command.extend(("duplex", duplex_to_configure))
        if lanes_to_configure:
            command.extend(("lanes", str(lanes_to_configure)))
        if advertise_to_configure:
            command.extend(("advertise", advertise_to_configure))

        lane_cache_clear_command = self.get_lane_cache_clear_command(
            ifname,
            historical_speed,
            old_autoneg,
            historical_lanes,
            old_effective_autoneg,
            old_pending_lane_clear,
            autoneg_to_configure,
            lanes_to_configure,
            speed_to_configure,
            duplex_to_configure,
        )
        if old_pending_lane_clear:
            pending_lane_clear = dict(old_pending_lane_clear)
        elif lane_cache_clear_command:
            pending_lane_clear = {
                "speed": historical_speed or speed_to_configure,
                "duplex": historical_duplex,
                "lanes": historical_lanes,
                "autoneg": previous_effective_autoneg,
            }
        else:
            pending_lane_clear = None
        ifaceobj.ethtool_pending_lane_clear = pending_lane_clear
        final_command = " ".join(command)

        prepare_error = None
        prepare_applied = False
        if lane_cache_clear_command:
            try:
                utils.exec_command(lane_cache_clear_command)
                prepare_applied = True
            except Exception as error:
                prepare_error = error

        final_error = None
        try:
            utils.exec_command(final_command)
        except Exception as error:
            final_error = error

        rollback_error = None
        if final_error and prepare_applied:
            restore_command = self.get_link_mode_restore_command(
                ifname,
                historical_speed,
                historical_duplex,
                old_autoneg,
                historical_lanes,
                old_effective_autoneg,
                old_pending_lane_clear,
            )
            if restore_command:
                try:
                    utils.exec_command(restore_command)
                except Exception as error:
                    rollback_error = error

        errors = [
            error for error in (
                prepare_error,
                final_error,
                rollback_error,
            )
            if error is not None
        ]
        if errors:
            error_message = "; ".join(str(error) for error in errors)
            if not self.ethtool_ignore_errors:
                self.log_error(
                    "%s: %s" % (ifname, error_message),
                    ifaceobj,
                )
            else:
                self.logger.warning("%s: %s" % (ifname, error_message))
            return

        ifaceobj.ethtool_effective_autoneg = autoneg_to_configure
        ifaceobj.ethtool_effective_speed = speed_to_configure
        ifaceobj.ethtool_effective_duplex = duplex_to_configure or None
        ifaceobj.ethtool_effective_lanes = lanes_to_configure or None
        ifaceobj.ethtool_pending_lane_clear = None

    def process_speed_lane_duplex_autoneg_settings(
            self, ifaceobj, down=False):

        force_speed_apply = False
        lanes_config_applied, lane_cmd_str = self.do_lanes_settings(ifaceobj)

        cmd_list = []

        if not down and not lanes_config_applied:
            # if link-lanes is removed from /e/n/i we need to reset it
            # to do so we reapply the speed
            for old_ifaceobj in statemanager.statemanager_api.get_ifaceobjs(ifaceobj.name) or []:
                if old_ifaceobj.get_attr_value_first("link-lanes"):
                    force_speed_apply = True

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

        if config_speed:
            fixed_speed = not utils.get_boolean_from_string(config_autoneg)
        else:
            effective_autoneg = (
                config_autoneg
                if config_autoneg is not None
                else default_autoneg
            )
            fixed_speed = bool(default_speed) and not (
                utils.get_boolean_from_string(effective_autoneg)
            )

        if (
                fixed_speed
                and not default_duplex
                and not ifaceobj.name.startswith("swp")
        ):
            default_duplex = self.get_attr_default_value("link-duplex")

        if down:
            config_speed = default_speed
            config_duplex = default_duplex
            config_autoneg = default_autoneg

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
                cmd_list.append(f"autoneg {autoneg_to_configure}")

                if autoneg_to_configure:
                    force_speed_apply = False
        else:
            force_set = False

            if force_speed_apply:
                if not speed_to_configure:
                    speed_to_configure = default_speed
                force_set = True

            if speed_to_configure:
                # check running values
                if utils.get_boolean_from_string(self.get_running_attr('autoneg', ifaceobj) or 'off'):
                    cmd_list.append("autoneg off")
                    # if we are transitioning from autoneg 'on' to 'off'
                    # don't check running speed
                    force_set = True

                running_val = self.get_running_attr('speed', ifaceobj)
                if force_set or (speed_to_configure != running_val):
                    # if the configured value is not set, set it
                    cmd_list.append(f"speed {speed_to_configure}")

            if duplex_to_configure:
                # check running values
                running_val = self.get_running_attr('duplex', ifaceobj)
                if force_set or (duplex_to_configure != running_val):
                    # if the configured value is not set, set it
                    cmd_list.append(f"duplex {duplex_to_configure}")

        if lane_cmd_str:
            cmd_list.append(lane_cmd_str)

        if cmd_list:
            try:
                utils.exec_command(f"{utils.ethtool_cmd} -s {ifaceobj.name} {' '.join(cmd_list)}")
            except Exception as e:
                if not self.ethtool_ignore_errors:
                    self.log_error('%s: %s' % (ifaceobj.name, str(e)), ifaceobj)

    def _pre_up(self, ifaceobj, operation='post_up'):
        """
        _pre_up and _pre_down will reset the layer 2 attributes to default policy
        settings.
        """
        if not self.cache.link_exists(ifaceobj.name):
            return

        self.do_speed_lane_duplex_autoneg_settings(ifaceobj)
        self.do_fec_settings(ifaceobj)
        self.do_ring_settings(ifaceobj, 'ring-rx', 'rx')
        self.do_ring_settings(ifaceobj, 'ring-tx', 'tx')
        self.do_offload_settings(ifaceobj, 'gro-offload', 'gro')
        self.do_offload_settings(ifaceobj, 'lro-offload', 'lro')
        self.do_offload_settings(ifaceobj, 'gso-offload', 'gso')
        self.do_offload_settings(ifaceobj, 'tso-offload', 'tso')
        self.do_offload_settings(ifaceobj, 'ufo-offload', 'ufo')
        self.do_offload_settings(ifaceobj, 'tx-offload', 'tx')
        self.do_offload_settings(ifaceobj, 'rx-offload', 'rx')
        self.do_offload_settings(ifaceobj, 'rx-vlan-filter', 'rx-vlan-filter')

    def _pre_down(self, ifaceobj):
        if not self.cache.link_exists(ifaceobj.name) or not ifaceobj.name.startswith("swp"):
            return
        self.do_speed_lane_duplex_autoneg_settings(ifaceobj, down=True)

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
            if not configured and not ifupdownflags.flags.WITHDEFAULTS:
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
            elif configured:
                # We show a FAIL since it is not the configured or default
                ifaceobjcurr.update_config_with_status('link-%s'%attr,
                                                       running_attr, 1)

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
                # ethtool syntax changed. using 'in' check supports both.
                if "Configured FEC encodings:" in attr:
                    fec_attrs = attr.split()
                    return(fec_attrs[fec_attrs.index('encodings:')+1])
        except Exception as e:
            self.logger.debug('ethtool: problems in ethtool set-fec output'
                               ' %s: %s' %(ethtool_output.splitlines(), str(e)))

        return(None)

    def get_offload_setting(self, ethtool_output, setting):

        value = None

        for line in ethtool_output.splitlines():
            if setting in line:
                if 'on' in line:
                    value = 'on'
                elif 'off' in line:
                    value = 'off'

                break

        return value

    def get_ring_setting(self, ethtool_output, setting, get_ring_max=False):
        value = None

        if get_ring_max:
            settings = ethtool_output.split('Current hardware settings:', 1)[0]
        else:
            settings = ethtool_output.split('Current hardware settings:', 1)[1]

        for line in settings.splitlines():
            if line.startswith(setting):
                value = line.split(':', 1)[1]
                return value.strip()

        return value

    def get_attr_value(self,attr='',ifaceobj=None,get_max=False):
        if not ifaceobj or not attr:
            return
        attr_value = None
        try:
            if attr == 'autoneg':
                output = utils.exec_commandl([utils.ethtool_cmd, ifaceobj.name])
                attr_value = self.get_autoneg(ethtool_output=output)
            elif attr == 'ring-rx':
                output = utils.exec_command('%s --show-ring %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_ring_setting(ethtool_output=output, setting='RX:', get_ring_max=get_max)
            elif attr == 'ring-tx':
                output = utils.exec_command('%s --show-ring %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_ring_setting(ethtool_output=output, setting='TX:', get_ring_max=get_max)
            elif attr == 'fec':
                output = utils.exec_command('%s --show-fec %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_fec_encoding(ethtool_output=output)
            elif attr == 'gro':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='generic-receive-offload')
            elif attr == 'lro':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='large-receive-offload')
            elif attr == 'gso':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='generic-segmentation-offload')
            elif attr == 'tso':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='tcp-segmentation-offload')
            elif attr == 'ufo':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='udp-fragmentation-offload')
            elif attr == 'rx':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='rx-checksumming')
            elif attr == 'tx':
                if not self.feature_cache:
                    self.feature_cache = utils.exec_command('%s --show-features %s'%
                                            (utils.ethtool_cmd, ifaceobj.name))
                attr_value = self.get_offload_setting(ethtool_output=self.feature_cache, setting='tx-checksumming')
            else:
                attr_value = self.io.read_file_oneline('/sys/class/net/%s/%s' % \
                                                      (ifaceobj.name, attr))
        except Exception as e:
            if not self.ethtool_ignore_errors:
                # for nonexistent interfaces, we get an error (rc = 256 or 19200)
                self.logger.debug('ethtool: problems calling ethtool or reading'
                                  ' /sys/class on iface %s for attr %s: %s' %
                                  (ifaceobj.name, attr, str(e)))
        return attr_value

    def get_running_attr(self,attr='',ifaceobj=None):
        return self.get_attr_value(attr=attr, ifaceobj=ifaceobj, get_max=False)

    def get_max_attr(self,attr='',ifaceobj=None):
        return self.get_attr_value(attr=attr, ifaceobj=ifaceobj, get_max=True)

    def _query_running(self, ifaceobj, ifaceobj_getfunc=None):
        """
        _query_running looks at the speed and duplex from /sys/class
        and retreives autoneg from ethtool.  We do not report autoneg
        if speed is not available because this usually means the link is
        down and the autoneg value is not reliable when the link is down.
        """
        # do not bother showing swp ifaces that are not up for the speed
        # duplex and autoneg are not reliable.
        if not self.cache.link_is_up(ifaceobj.name):
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
        return list(self._run_ops.keys())

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

        if operation == 'query-checkcurr':
            op_handler(self, ifaceobj, query_ifaceobj)
        else:
            op_handler(self, ifaceobj)
