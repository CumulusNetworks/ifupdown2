"""Bond primary regression tests; run with python3 -m unittest discover -s tests/unit."""

import unittest
from unittest.mock import Mock, patch

from ifupdown2.addons.bond import bond
from ifupdown2.ifupdown import ifupdownflags
from ifupdown2.ifupdown.iface import iface, ifaceStatus
from ifupdown2.lib.nlcache import NetlinkCacheIfnameNotFoundError
from ifupdown2.nlmanager.nlmanager import Link


class BondPrimaryTests(unittest.TestCase):
    def setUp(self):
        # Avoid initializing netlink sockets or touching the host network.
        self.addon = bond.__new__(bond)
        self.addon.logger = Mock()
        self.addon.cache = Mock()
        self.addon.get_saved_ifaceobj = Mock(return_value=None)
        self.addon._check_bond_mode_user_config = Mock()
        self.addon._bond_attr_set_list = bond._bond_attr_set_list + (
            ("bond-primary", Link.IFLA_BOND_PRIMARY, self.get_ifindex),
        )
        self.existing = {"nic0": 10, "nic1": 11}
        self.ifaceobj = iface({"name": "bond0"})
        self.ifaceobj.config = {
            "bond-slaves": ["nic0 nic1"],
            "bond-mode": ["active-backup"],
        }
        self.addCleanup(patch.stopall)
        patch.object(ifupdownflags.flags, "IGNORE_ERRORS", False).start()
        patch(
            "ifupdown2.addons.bond.policymanager.policymanager_api", Mock(
                get_iface_default=Mock(return_value=None))
        ).start()

    def get_ifindex(self, ifname):
        try:
            return self.existing[ifname]
        except KeyError:
            raise NetlinkCacheIfnameNotFoundError("ifname %s not present in cache" % ifname)

    def attrs(self, primary):
        self.ifaceobj.config["bond-primary"] = [primary]
        return self.addon.get_ifla_bond_attr_from_user_config(self.ifaceobj, False)

    def test_existing_primary_is_set(self):
        info = self.attrs("nic1")
        self.assertEqual(info[Link.IFLA_BOND_PRIMARY], 11)
        self.assertNotEqual(self.ifaceobj.status, ifaceStatus.WARNING)

    def test_missing_primary_is_skipped_with_warning(self):
        info = self.attrs("usb0")
        self.assertNotIn(Link.IFLA_BOND_PRIMARY, info)
        # the remaining attributes are still applied
        self.assertIn(Link.IFLA_BOND_MODE, info)
        self.assertEqual(self.ifaceobj.status, ifaceStatus.WARNING)
        self.addon.logger.warning.assert_called_with(
            "bond0: ignoring bond-primary usb0: device does not exist"
        )


if __name__ == "__main__":
    unittest.main()
