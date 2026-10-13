"""Bond regression tests; run with python3 -m unittest discover -s tests/unit."""

import unittest
from unittest.mock import Mock, call, patch

from ifupdown2.addons.bond import bond
from ifupdown2.ifupdown import ifupdownflags
from ifupdown2.ifupdown.iface import iface, ifaceStatus


class BondSlaveTests(unittest.TestCase):
    def setUp(self):
        # Avoid initializing netlink sockets or touching the host network.
        self.addon = bond.__new__(bond)
        self.addon.logger = Mock()
        self.addon.cache = Mock()
        self.addon.cache.link_exists.return_value = True
        self.addon.cache.link_is_up.return_value = False
        self.addon.cache.get_link_protodown.return_value = False
        self.addon.netlink = Mock()
        self.addon.iproute2 = Mock()
        self.addon.sysfs = Mock()
        self.addon.enable_ipv6_if_prev_brport = Mock()
        self.ifaceobj = iface({"name": "bond0"})
        self.slave_iface = iface({"name": "nic1"})
        self.ifaceobj_getfunc = Mock(return_value=[self.slave_iface])
        self.running = []
        self.addCleanup(patch.stopall)
        patch.object(ifupdownflags.flags, "IGNORE_ERRORS", False).start()

    def add_slaves(self, slaves, perfmode):
        self.ifaceobj.priv_data = slaves
        with patch.object(ifupdownflags.flags, "PERFMODE", perfmode):
            return self.addon._add_slaves(
                self.ifaceobj, self.running, self.ifaceobj_getfunc
            )

    def test_missing_slave_does_not_block_available_slaves(self):
        for perfmode in (False, True):
            for slaves in (["missing", "nic1"], ["nic1", "missing"]):
                with self.subTest(perfmode=perfmode, slaves=slaves):
                    self.running = []
                    self.addon.netlink.reset_mock()
                    self.addon.cache.link_exists.side_effect = lambda name: name != "missing"
                    self.assertEqual(self.add_slaves(slaves, perfmode), ["nic1"])
                    self.addon.netlink.link_set_master.assert_called_once_with("nic1", "bond0")
                    self.assertEqual(self.ifaceobj.status, ifaceStatus.ERROR)
                    self.addon.logger.error.assert_called_with(
                        "bond0: skipping slave missing, does not exist"
                    )

    def test_all_slaves_missing(self):
        for perfmode in (False, True):
            with self.subTest(perfmode=perfmode):
                self.addon.cache.link_exists.return_value = False
                self.assertEqual(self.add_slaves(["missing0", "missing1"], perfmode), [])
                self.addon.netlink.link_set_master.assert_not_called()
                self.assertEqual(self.ifaceobj.status, ifaceStatus.ERROR)

    def test_failed_enslavement_does_not_block_next_slave(self):
        for perfmode in (False, True):
            with self.subTest(perfmode=perfmode):
                self.running = []
                self.addon.netlink.reset_mock()
                self.addon.netlink.link_set_master.side_effect = [
                    RuntimeError("No such device"), None
                ]
                self.assertEqual(self.add_slaves(["nic0", "nic1"], perfmode), ["nic1"])
                self.assertEqual(self.addon.netlink.link_set_master.call_args_list, [
                    call("nic0", "bond0"), call("nic1", "bond0")
                ])
                self.assertEqual(self.ifaceobj.status, ifaceStatus.ERROR)
                self.addon.logger.error.assert_called_with(
                    "bond0: failed to enslave nic0: No such device"
                )

    def test_slave_disappearing_before_link_down_does_not_block_next_slave(self):
        self.addon.cache.link_is_up.side_effect = lambda name: name == "nic0"
        self.addon.netlink.link_down_force.side_effect = RuntimeError("No such device")
        self.assertEqual(self.add_slaves(["nic0", "nic1"], True), ["nic1"])
        self.addon.netlink.link_set_master.assert_called_once_with("nic1", "bond0")
        self.assertEqual(self.ifaceobj.status, ifaceStatus.ERROR)

    def test_duplicates_and_existing_slaves_are_not_enslaved_again(self):
        self.running = ["nic0"]
        self.assertEqual(self.add_slaves(["nic0", "nic1", "nic1"], True), ["nic0", "nic1"])
        self.addon.netlink.link_set_master.assert_called_once_with("nic1", "bond0")
        self.assertNotEqual(self.ifaceobj.status, ifaceStatus.ERROR)

    def test_up_continues_with_successfully_enslaved_slaves(self):
        self.ifaceobj.priv_data = ["nic0", "nic1"]
        self.addon.create_or_set_bond_config = Mock(return_value=(True, self.running))
        self.addon.set_bond_mac = Mock()
        self.addon.netlink.link_set_master.side_effect = [RuntimeError("No such device"), None]
        with patch.object(ifupdownflags.flags, "PERFMODE", True):
            self.addon._up(self.ifaceobj, self.ifaceobj_getfunc)
        self.addon.set_bond_mac.assert_called_once_with(True, self.ifaceobj, ["nic1"])
        self.assertEqual(self.ifaceobj.status, ifaceStatus.ERROR)


if __name__ == "__main__":
    unittest.main()
