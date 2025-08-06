from .conftest import ENI, assert_identical_json

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_address(ssh, setup, get_json):
    ssh.ifup_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("address.ifquery.ac.json"))


def test_address_gateway(ssh, setup, get_json):
    assert ssh.translate_swp_xx(
        "error: swp_AA_: cmd '/bin/ip route replace default via 10.1.14.3 proto kernel dev swp_AA_' failed: "
        "returned 2 (Error: Nexthop has invalid gateway.\n)\nwarning: br1: untagged bridge not found. "
        "Please configure a bridge with untagged bridge ports to avoid Spanning Tree Interoperability issue.\n"
    ) == ssh.ifup_a(return_stderr=True, expected_status=1)

    assert_identical_json(ssh.ifquery_ac_json(), get_json("address_gateway.ifquery.ac.json"))

    ssh.run(f"sed -i 's/address .*//' {ENI}")

    assert ssh.translate_swp_xx(
        "info: executing /bin/ip route replace default via 10.1.14.3 proto kernel dev swp_AA_"
    ) in ssh.ifreload_av(expected_status=1)

    assert_identical_json(ssh.ifquery_ac_json(), get_json("address_gateway.empty_addrs.ifquery.ac.json"))


def test_evpn_vab_clag_riot_flood_sup_off_config_tors2(ssh, setup, get_json):
    ssh.ifup_a()

    assert_identical_json(ssh.ifquery_ac_json(), get_json("EvpnVabClagRiotFloodSupOffConfig.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vx-1000 | grep nolearning | grep 'learning off'")
    ssh.run_assert_success("ip -d -o link show vx-1001 | grep nolearning | grep 'learning off'")

    ssh.ifdown("vx-1000 vx-1001")
    ssh.ifup("vx-1000 vx-1001")

    assert_identical_json(ssh.ifquery_ac_json(), get_json("EvpnVabClagRiotFloodSupOffConfig.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vx-1000 | grep nolearning | grep 'learning off'")
    ssh.run_assert_success("ip -d -o link show vx-1001 | grep nolearning | grep 'learning off'")

    ssh.ifreload_a()

    assert_identical_json(ssh.ifquery_ac_json(), get_json("EvpnVabClagRiotFloodSupOffConfig.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vx-1000 | grep nolearning | grep 'learning off'")
    ssh.run_assert_success("ip -d -o link show vx-1001 | grep nolearning | grep 'learning off'")

    ssh.ifup("uplink hostbond3 bridge vlan1000")
    ssh.ifreload_a()

    assert_identical_json(ssh.ifquery_ac_json(), get_json("EvpnVabClagRiotFloodSupOffConfig.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vx-1000 | grep nolearning | grep 'learning off'")
    ssh.run_assert_success("ip -d -o link show vx-1001 | grep nolearning | grep 'learning off'")

    ssh.run_assert_success("echo '1' > /sys/class/net/vx-1001/brport/learning")
    ssh.run_assert_success("ip link set dev vx-1001 type vxlan learning")
    ssh.ifup("vx-1001")

    assert_identical_json(ssh.ifquery_ac_json(), get_json("EvpnVabClagRiotFloodSupOffConfig.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vx-1001 | grep nolearning | grep 'learning off'")


def test_interfaces_vrr_vrf(ssh, setup, get_json):
    ifquery_ac_1_json = get_json("interfaces.vrr_vrf.ifquery.ac.1.json")
    ifquery_ac_2_json = get_json("interfaces.vrr_vrf.ifquery.ac.2.json")

    ssh.ifup_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("bond0")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), ifquery_ac_2_json)
    ssh.ifup("bond0")
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("peerlink")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.3.json"))
    ssh.ifup("peerlink")
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("myvrf")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.4.json"))

    ssh.ifdown("bond0")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.5.json"))

    ssh.ifreload_diff = False
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("bridge")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.6.json"))
    ssh.ifup("bridge")
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("bond0")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), ifquery_ac_2_json)
    ssh.ifup("bond0")
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)

    ssh.ifdown("bridge.901")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.7.json"))
    ssh.ifdown("bond0")
    assert_identical_json(ssh.ifquery_ac_json(expected_status=1), get_json("interfaces.vrr_vrf.ifquery.ac.8.json"))

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), ifquery_ac_1_json)
    ssh.ifreload_diff = True


def test_vxlandev_sanity(ssh, setup, get_json):
    ssh.ifup_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("vxlan_sanity.ifquery.ac.json"))

    ssh.run_assert_success("ip -d -o link show vxlan1000 | grep nolearning")
    ssh.run_assert_success("ip -d -o link show vxlan10200 | grep 'learning on'  | wc -l | grep '^1$'")

    ssh.run_assert_success(f"sed -i 's/vxlan-id 42/vxlan-id 43/' {ENI}")
    assert ssh.ifup("vx0", expected_status=1, return_stderr=True) == "error: vx0: Cannot change running vxlan id (42): Operation not supported\n"

    ssh.run_assert_success(f"sed -i 's/vxlan-id 43/vxlan-id 42/' {ENI}")
    ssh.ifquery_c("vx0")

    ssh.run_assert_success(f"sed -i 's/vxlan-remoteip 172.16.22.128/vxlan-remoteip 172.16.22.43/' {ENI}")
    ssh.ifup("vx0")
    ssh.ifquery_c("vx0")
