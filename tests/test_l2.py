import logging
import json

import pytest

from .conftest import assert_identical_json, ENI, ENI_D

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_bond(ssh, setup, get_json):
    bond_ifquery_ac_json = get_json("bond.ifquery.ac.json")

    stderr = ssh.ifreload_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )
    assert_identical_json(ssh.ifquery_ac_json(), bond_ifquery_ac_json)

    ifreload_output = ssh.ifreload_av()
    assert_identical_json(ssh.ifquery_ac_json(), bond_ifquery_ac_json)

    # Check that bonds are not flapped when there's no config change.
    for string in [
        "bond0 down",
        "bond1 down",
        "bond2 down",
        "bond3 down",
        "bond5 down",
        "bond6 down",
    ]:
        assert string not in ifreload_output

    ssh.run_assert_success(
        "cp /etc/network/interfaces /tmp/.interfaces ; "
        "sed -E 's/\\s+0/ _ZERO_/' /tmp/.interfaces | "
        "sed -E 's/\\s+1/ 0/' | sed -E 's/_ZERO_/ 1/' > /etc/network/interfaces")
    ssh.run_assert_success(
        "cp /etc/network/interfaces /tmp/.interfaces ; "
        "sed -E 's/\\s+yes/ _YES_/' /tmp/.interfaces | "
        "sed -E 's/\\s+no/ yes/' | sed -E 's/_YES_/ no/' > /etc/network/interfaces"
    )
    ssh.run_assert_success("sed -i.back -E 's/\\s+255/ 0/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+balance-rr/ 0/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+active-backup/ 1/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+balance-xor/ 2/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+broadcast/ 3/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+802.3ad/ 4/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+balance-tlb/ 5/' /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/\\s+balance-alb/ 6/' /etc/network/interfaces")
    ssh.run_assert_success(
        "cp /etc/network/interfaces /tmp/.interfaces ; "
        "sed -E 's/\\s+layer2\\s*$/ _LAYER2_/' /tmp/.interfaces | "
        "sed -E 's/\\s+layer3\\+4/ layer2/' | sed -E 's/_LAYER2_/ layer3\\+4/' "
        "> /etc/network/interfaces")
    ssh.run_assert_success("sed -i.back -E 's/bond-updelay 65535//' /etc/network/interfaces")

    ifreload_output = ssh.ifreload_av()
    assert ssh.ifquery_ac_json() == get_json("bond.flipped.values.ifquery.ac.json")

    for string in [
        "bond3 down",
        "bond5 down",
        "bond6 down",
    ]:
        assert string not in ifreload_output

    ssh.scp("tests/scp/bond.default.eni", ENI)

    ssh.ifreload_a()
    ssh.ifquery_ac()


def test_bond_lacp(ssh, setup, get_json):
    bond_lacp_ifquery_ac_json = get_json("bond_lacp.ifquery.ac.json")
    bond_lacp_flipped_ifquery_ac_json = get_json("bond_lacp.flipped.values.ifquery.ac.json")

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), bond_lacp_ifquery_ac_json)

    ifreload_output = ssh.ifreload_av()
    assert_identical_json(ssh.ifquery_ac_json(), bond_lacp_ifquery_ac_json)

    # Check that bonds are not flapped when there's no config change.
    for string in [
        "bond4 down",
        "bond7 down",
        "bond8 down",
        "bond9 down",
    ]:
        assert string not in ifreload_output

    ssh.run_assert_success(
        r'cp /etc/network/interfaces /tmp/.interfaces ; '
        r'sed -E "s/\s+0/ _ZERO_/" /tmp/.interfaces | sed -E "s/\s+1/ 0/" | sed -E "s/_ZERO_/ 1/" > /etc/network/interfaces'
    )
    ssh.run_assert_success(
        r'cp /etc/network/interfaces /tmp/.interfaces ; '
        r'sed -E "s/\s+yes/ _YES_/" /tmp/.interfaces | sed -E "s/\s+no/ yes/" | sed -E "s/_YES_/ no/" > /etc/network/interfaces'
    )
    ssh.run_assert_success(r'sed -i.back -E "s/\s+802.3ad/ 4/" /etc/network/interfaces')

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), bond_lacp_flipped_ifquery_ac_json)

    ifreload_output = ssh.ifreload_av()
    assert_identical_json(ssh.ifquery_ac_json(), bond_lacp_flipped_ifquery_ac_json)

    # Check that bonds are not flapped when there's no config change.
    for string in [
        "bond4 down",
        "bond7 down",
        "bond8 down",
        "bond9 down",
    ]:
        assert string not in ifreload_output


def test_bridge1(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge1.ifquery.ac.json"))
    assert_identical_json(ssh.bridge_vlan_show_json(), get_json("bridge1.vlan.show.json"))


def test_bridge2(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge2.ifquery.ac.json"))
    assert_identical_json(ssh.bridge_vlan_show_json(), get_json("bridge2.vlan.show.json"))


def test_bridge3(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge3.ifquery.ac.json"))
    assert_identical_json(ssh.bridge_vlan_show_json(), get_json("bridge3.vlan.show.json"))


def test_bridge4(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge4.ifquery.ac.json"))
    assert_identical_json(ssh.bridge_vlan_show_json(), get_json("bridge4.vlan.show.json"))


def test_bridge5(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge5.ifquery.ac.json"))
    assert_identical_json(ssh.bridge_vlan_show_json(), get_json("bridge5.vlan.show.json"))


def test_bridge6_multiple_bridge_ports_lines(ssh, setup, get_json):
    ssh.ifreload_a()
    assert ssh.ifquery_ac_json() == get_json("bridge6_multiple_bridge_ports_lines.ifquery.ac.json")


def test_bridge7_macvlans(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge7_macvlans.ifquery.ac.json"))


def test_bridge8_reserved_vlans(ssh, setup, get_file):
    assert "reserved vlan 3725 being used (reserved vlan range 3725-3999)" in ssh.ifreload_a(return_stderr=True, expected_status=1)


def test_bridge9_multiple_vlan_aware_bridge(ssh, get_json):
    multiple_bridge_support = ssh.run_assert_success(
        "sed -n "
        "'s/^multiple_vlan_aware_bridge_support=//p' "
        "/etc/network/ifupdown2/ifupdown2.conf"
    ).strip()
    if multiple_bridge_support != "1":
        pytest.skip(
            "requires multiple_vlan_aware_bridge_support=1; "
            "the public Debian default remains 0"
        )

    # Apply the fixture only after the host capability check. The generic
    # setup fixture would otherwise copy an unsupported config before skip.
    ssh.ifdown_x_eth0_x_mgmt()
    ssh.scp("tests/eni/bridge9_multiple_vlan_aware_bridge.eni", ENI)
    ssh.run(f"rm -f {ENI_D}/*")

    ssh.ifreload_diff = False
    ssh.ifreload_a()
    _, stdout, stderr, exit_status = ssh.run(f"bridge -j vlan show dev swp_AA_")
    stdout_str: str = stdout.read().decode("utf-8")
    assert_identical_json(json.loads(stdout_str), get_json("bridge9_multiple_vlan_aware_bridge.bridge_vlan_swp_AA_1.json"))
    _, stdout, stderr, exit_status = ssh.run(f"bridge -j vlan show dev swp_BB_")
    stdout_str: str = stdout.read().decode("utf-8")
    assert_identical_json(json.loads(stdout_str), get_json("bridge9_multiple_vlan_aware_bridge.bridge_vlan_swp_BB_1.json"))

    # Replace "bridge-ports swp_AA_" with "bridge-ports swp_BB_" and vice-versa
    ssh.run_assert_success(f"sed -i 's/\<bridge-ports swp_AA_\>/bridge-ports swp_CC_/g' {ENI}")
    ssh.run_assert_success(f"sed -i 's/\<bridge-ports swp_BB_\>/bridge-ports swp_AA_/g' {ENI}")
    ssh.run_assert_success(f"sed -i 's/\<bridge-ports swp_CC_\>/bridge-ports swp_BB_/g' {ENI}")
    ssh.ifreload_diff = False
    ssh.ifreload_a()
    _, stdout, stderr, exit_status = ssh.run(f"bridge -j vlan show dev swp_AA_")
    stdout_str: str = stdout.read().decode("utf-8")
    assert_identical_json(json.loads(stdout_str), get_json("bridge9_multiple_vlan_aware_bridge.bridge_vlan_swp_AA_2.json"))
    _, stdout, stderr, exit_status = ssh.run(f"bridge -j vlan show dev swp_BB_")
    stdout_str: str = stdout.read().decode("utf-8")
    assert_identical_json(json.loads(stdout_str), get_json("bridge9_multiple_vlan_aware_bridge.bridge_vlan_swp_BB_2.json"))


def test_bridge_access(ssh, setup, get_json):
    bridge_ifquery_ac_json = get_json("bridge_access.ifquery.ac.json")
    bridge_vlan_show_json = get_json("bridge_access.vlan.show.json")

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), bridge_ifquery_ac_json)
    assert_identical_json(ssh.bridge_vlan_show_json(), bridge_vlan_show_json)

    ssh.ifdown("vxlan1")

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), bridge_ifquery_ac_json)
    assert_identical_json(ssh.bridge_vlan_show_json(), bridge_vlan_show_json)


def test_bridge_attr_back_to_default(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge_attr_back_to_default.ifquery.ac.json"))

    ssh.scp("tests/scp/bridge_attr_back_to_default.after.eni", ENI)

    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge_attr_back_to_default.after.ifquery.ac.json"))

    ssh.run_assert_success("cat /sys/class/net/br0/bridge/vlan_filtering | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/stp_state | grep ^2$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/priority | grep ^32768$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/ageing_time | grep ^180000$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/forward_delay | grep ^1500$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/hello_time | grep ^200$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/max_age | grep ^2000$")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/path_cost | grep ^100$")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/priority | grep ^8$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_last_member_count | grep ^2$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_router | grep ^1$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_snooping | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_startup_query_count | grep ^2$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_query_use_ifaddr | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_querier | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/hash_elasticity | grep ^16$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/hash_max | grep ^4096$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_last_member_interval | grep ^100$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_membership_interval | grep ^26000$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_querier_interval | grep ^25500$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_query_interval | grep ^12500$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_query_response_interval | grep ^1000$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_startup_query_interval | grep ^31")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/multicast_fast_leave | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/learning | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_igmp_version | grep ^2$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_mld_version | grep ^1$")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/unicast_flood | grep ^1$")
    ssh.run_assert_success("cat /sys/class/net/vx42/brport/multicast_flood | grep ^1$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/vlan_protocol | grep ^0x8100$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/vlan_stats_enabled | grep ^0$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/multicast_stats_enabled | grep ^1$")
    ssh.run_assert_success("cat /sys/class/net/br0/bridge/group_fwd_mask | grep ^0x0$")


def test_bridge_igmp_version(ssh, setup, get_json):
    ssh.ifreload_a()
    ssh.run_assert_success("cat /sys/class/net/br2/bridge/multicast_igmp_version | grep 2")
    ssh.run_assert_success("cat /sys/class/net/br2/bridge/multicast_mld_version | grep 1")
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge_igmp_version.ifquery.ac.json"))


def test_bridge_l2protocol_tunnel(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("bridge_l2protocol_tunnel.ifquery.ac.json"))


def test_bridge_new_attribute(ssh, setup, get_json):
    ssh.scp("tests/scp/bridge_new_attribute_learning_arp_nd_suppress.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_learning_arp_nd_suppress.before.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev vxlan10101 | grep ' learning off '")
    ssh.run_assert_success("cat /sys/class/net/vxlan10101/brport/learning | grep '0'")
    ssh.run_assert_success("ip -d -o link show dev vxlan10101 | grep ' neigh_suppress on '")
    ssh.run_assert_success("ip -d -o link show dev vxlan10102 | grep ' learning off '")
    ssh.run_assert_success("cat /sys/class/net/vxlan10102/brport/learning | grep '0'")
    ssh.run_assert_success("ip -d -o link show dev vxlan10102 | grep ' neigh_suppress on '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_learning_arp_nd_suppress.before.eni")

    ssh.scp("tests/scp/bridge_new_attribute_learning_arp_nd_suppress.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_learning_arp_nd_suppress.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev vxlan10101 | grep ' nolearning '")
    ssh.run_assert_success("cat /sys/class/net/vxlan10101/brport/learning | grep '0'")
    ssh.run_assert_success("ip -d -o link show dev vxlan10101 | grep ' neigh_suppress on '")
    ssh.run_assert_success("ip -d -o link show dev vxlan10102 | grep ' nolearning '")
    ssh.run_assert_success("cat /sys/class/net/vxlan10102/brport/learning | grep '0'")
    ssh.run_assert_success("ip -d -o link show dev vxlan10102 | grep ' neigh_suppress on '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_learning_arp_nd_suppress.after.eni")
    ssh.ifdown_x_eth0_x_mgmt()

    ssh.scp("tests/scp/bridge_new_attribute_ipforward_vlan_protocol_mcstats.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_ipforward_vlan_protocol_mcstats.before.ifquery.ac.json")
    )
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_AA_.forwarding | grep 'net.ipv4.conf.swp_AA_.forwarding = 0'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_AA_.forwarding | grep 'net.ipv6.conf.swp_AA_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_BB_.forwarding | grep 'net.ipv4.conf.swp_BB_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_BB_.forwarding | grep 'net.ipv6.conf.swp_BB_.forwarding = 0'")
    ssh.run_assert_success("sysctl net.ipv4.conf.br2.forwarding | grep 'net.ipv4.conf.br2.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.br2.forwarding | grep 'net.ipv6.conf.br2.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_DD_.forwarding | grep 'net.ipv4.conf.swp_DD_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_DD_.forwarding | grep 'net.ipv6.conf.swp_DD_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_EE_.forwarding | grep 'net.ipv4.conf.swp_EE_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_EE_.forwarding | grep 'net.ipv6.conf.swp_EE_.forwarding = 1'")
    ssh.run_assert_success("ip -o -d link show dev vlan100 | grep ' vlan protocol 802.1ad '")
    ssh.run_assert_success("ip -o -d link show dev br3 | grep ' mcast_stats_enabled 0 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_ipforward_vlan_protocol_mcstats.before.eni")
    ssh.ifdown_x_eth0_x_mgmt()

    ssh.scp("tests/scp/bridge_new_attribute_ipforward_vlan_protocol_mcstats.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_ipforward_vlan_protocol_mcstats.after.ifquery.ac.json")
    )
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_AA_.forwarding | grep 'net.ipv4.conf.swp_AA_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_AA_.forwarding | grep 'net.ipv6.conf.swp_AA_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_BB_.forwarding | grep 'net.ipv4.conf.swp_BB_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_BB_.forwarding | grep 'net.ipv6.conf.swp_BB_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.br2.forwarding | grep 'net.ipv4.conf.br2.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.br2.forwarding | grep 'net.ipv6.conf.br2.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_DD_.forwarding | grep 'net.ipv4.conf.swp_DD_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_DD_.forwarding | grep 'net.ipv6.conf.swp_DD_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv4.conf.swp_EE_.forwarding | grep 'net.ipv4.conf.swp_EE_.forwarding = 1'")
    ssh.run_assert_success("sysctl net.ipv6.conf.swp_EE_.forwarding | grep 'net.ipv6.conf.swp_EE_.forwarding = 1'")
    ssh.run_assert_success("ip -o -d link show dev vlan100 | grep ' vlan protocol 802.1Q '")
    ssh.run_assert_success("ip -o -d link show dev br3 | grep ' mcast_stats_enabled 1 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_ipforward_vlan_protocol_mcstats.after.eni")
    ssh.ifdown_x_eth0_x_mgmt()

    ssh.scp("tests/scp/bridge_new_attribute_vlan_protocol_stats.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_vlan_protocol_stats.before.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' vlan_protocol 802.1ad '")
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' vlan_stats_enabled 1 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' vlan_protocol 802.1ad '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' vlan_stats_enabled 0 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_vlan_protocol_stats.before.eni")

    ssh.scp("tests/scp/bridge_new_attribute_vlan_protocol_stats.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_vlan_protocol_stats.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' vlan_stats_enabled 1 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' vlan_stats_enabled 0 '")
    ssh.ifdown_x_eth0_x_mgmt()
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_vlan_protocol_stats.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' vlan_stats_enabled 1 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' vlan_stats_enabled 0 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_vlan_protocol_stats.after.eni")
    ssh.ifdown_x_eth0_x_mgmt()

    ssh.scp("tests/scp/bridge_new_attribute_ucast_mcast_flood.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_ucast_mcast_flood.before.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev swp_AA_ | grep ' flood on '")
    ssh.run_assert_success("ip -d -o link show dev swp_AA_ | grep ' mcast_flood on '")
    ssh.run_assert_success("ip -d -o link show dev swp_BB_ | grep ' flood on '")
    ssh.run_assert_success("ip -d -o link show dev swp_BB_ | grep ' mcast_flood on '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_ucast_mcast_flood.before.eni")

    ssh.scp("tests/scp/bridge_new_attribute_ucast_mcast_flood.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_ucast_mcast_flood.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev swp_AA_ | grep ' flood off '")
    ssh.run_assert_success("ip -d -o link show dev swp_AA_ | grep ' mcast_flood off '")
    ssh.run_assert_success("ip -d -o link show dev swp_BB_ | grep ' flood off '")
    ssh.run_assert_success("ip -d -o link show dev swp_BB_ | grep ' mcast_flood off '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_ucast_mcast_flood.after.eni")
    ssh.ifdown_x_eth0_x_mgmt()

    ssh.scp("tests/scp/bridge_new_attribute_igmp_mld.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_igmp_mld.before.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' mcast_igmp_version 3 '")
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' mcast_mld_version 2 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' mcast_igmp_version 3 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' mcast_mld_version 2 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_igmp_mld.before.eni")

    ssh.scp("tests/scp/bridge_new_attribute_igmp_mld.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("bridge_new_attribute_igmp_mld.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' mcast_igmp_version 2 '")
    ssh.run_assert_success("ip -d -o link show dev br0 | grep ' mcast_mld_version 1 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' mcast_igmp_version 2 '")
    ssh.run_assert_success("ip -d -o link show dev br1 | grep ' mcast_mld_version 1 '")
    ssh.run_assert_success("rm /etc/network/interfaces.d/bridge_new_attribute_igmp_mld.after.eni")


def test_cm_11485_vlan_device_name_vlan(ssh, setup, get_json):
    assert ssh.ifreload_a(expected_status=1, return_stderr=True) == ssh.translate_swp_xx(
        "error: bond0: sub interfaces are not allowed on bond slave: swp_BB_ (swp_BB_.1005)\n"
    )
    assert_identical_json(
        ssh.ifquery_ac_json(expected_status=1),
        get_json("cm_11485_vlan_device_name_vlan.ifquery.ac.json")
    )


def test_interfaces_link_state(ssh, setup, get_json):
    """Link state checks use the kernel's administrative UP flag."""
    ssh.scp("tests/scp/interfaces_link_state.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("interfaces_link_state.before.ifquery.ac.json")
    )

    ssh.assert_interface_admin_down("bridge3")

    ssh.assert_interface_admin_up("swp_AA_")
    ssh.assert_interface_admin_up("swp_BB_")
    ssh.assert_interface_admin_up("bridge1")
    ssh.assert_interface_admin_up("bridge2")
    ssh.assert_interface_admin_up("bridge4")

    ssh.run_assert_success("rm /etc/network/interfaces.d/interfaces_link_state.before.eni")

    ssh.scp("tests/scp/interfaces_link_state.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("interfaces_link_state.after.ifquery.ac.json")
    )

    ssh.assert_interface_admin_down("swp_BB_")
    ssh.assert_interface_admin_down("bridge4")

    ssh.assert_interface_admin_up("bridge1")
    ssh.assert_interface_admin_up("bridge2")
    ssh.assert_interface_admin_up("bridge3")

    ssh.run_assert_success("rm /etc/network/interfaces.d/interfaces_link_state.after.eni")


def test_mac1(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("mac1.ifquery.ac.json"))


def test_bridge_new_port_admin_l2(ssh, setup):
    """A new bridge port is restored up after protected enslavement."""
    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )
    ssh.scp("tests/eni/bridge_new_port_admin_l2.after.eni", ENI)
    reload_output = ssh.ifreload_av()
    assert "skipping link-up for bridge port" in reload_output
    ssh.run_assert_success(
        "ip -o link show dummy_new | grep -w 'master br_new'"
    )
    ssh.run_assert_success(
        "ip -o link show dummy_new | grep -w UP"
    )

    ssh.ifdown("br_new dummy_new")
    assert ssh.run("ip link show br_new")[3] != 0
    assert ssh.run("ip link show dummy_new")[3] != 0


def test_bridge_existing_port_no_flap_l2(ssh, setup):
    """Changing VLANs on an existing bridge port does not flap its link."""
    monitor_log = "/tmp/ifupdown2-bridge-existing-monitor.log"
    monitor_pid = "/tmp/ifupdown2-bridge-existing-monitor.pid"
    ssh.run_assert_success(f"rm -f {monitor_log} {monitor_pid}")

    ssh.ifup_a()
    ssh.run_assert_success("ip link set dev dummy_existing up")
    ssh.run_assert_success(
        "ip -o link show dummy_existing | grep -w 'master br_existing'"
    )

    ssh.run_assert_success(
        "nohup timeout 30 stdbuf -oL ip monitor link dev dummy_existing "
        f"> {monitor_log} 2>&1 < /dev/null & echo $! > {monitor_pid}"
    )
    ssh.run_assert_success(
        f"test -s {monitor_pid} && kill -0 $(cat {monitor_pid}) && sleep 1"
    )

    ssh.run_assert_success(
        f"sed -i 's/bridge-access 100/bridge-access 200/' {ENI}"
    )
    ssh.ifup("dummy_existing")

    ssh.run_assert_success(
        f"kill $(cat {monitor_pid}) 2>/dev/null || true; sleep 1"
    )
    monitor_output = ssh.run_assert_success(f"cat {monitor_log}").lower()
    assert not any(
        "state down" in line for line in monitor_output.splitlines()
    )
    ssh.run_assert_success(
        "ip -o link show dummy_existing | grep -w UP"
    )

    ssh.ifdown("br_existing dummy_existing")
    ssh.run_assert_success(f"rm -f {monitor_log} {monitor_pid}")
    assert ssh.run("ip link show br_existing")[3] != 0
    assert ssh.run("ip link show dummy_existing")[3] != 0


def test_vlan_bridge_binding_scope_l2(ssh, setup):
    """Bridge binding applies to SVIs, not ordinary VLAN devices."""
    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )

    ordinary_vlan = ssh.run_assert_success(
        "ip -d -o link show vlan100"
    )
    assert "BRIDGE_BINDING" not in ordinary_vlan

    bridge_svi = ssh.run_assert_success(
        "ip -d -o link show br_bind.200"
    )
    assert "BRIDGE_BINDING" in bridge_svi

    ssh.ifdown("br_bind.200 br_bind vlan100 swp_AA_ swp_BB_")
    for ifname in ("br_bind.200", "br_bind", "vlan100"):
        assert ssh.run(f"ip link show {ifname}")[3] != 0
    for ifname in ("swp_AA_", "swp_BB_"):
        ssh.run_assert_success(f"ip link show {ifname}")


def test_bond_dummy_mac_l2(ssh, setup):
    """Missing slave state and dummy permanent-MAC data remain non-fatal."""
    ssh.ifup_a()
    ssh.run_assert_success(
        "ip -d -o link show bond_dummy | grep -w 'bond'"
    )
    ssh.run_assert_success(
        "ip -o link show dummy0 | grep -w 'master bond_dummy'"
    )

    # Re-apply an existing bond after removing its configured member list.
    # The running-slave cache can be absent here; MAC synchronization must not
    # iterate None or require permanent hardware-address data from dummy0.
    ssh.run_assert_success(
        f"sed -i '/bond-slaves dummy0/d' {ENI}"
    )
    ssh.ifup("bond_dummy")
    ssh.run_assert_success(
        "ip -d -o link show bond_dummy | grep -w 'bond'"
    )

    ssh.ifdown("bond_dummy dummy0")
    assert ssh.run("ip link show bond_dummy")[3] != 0
    assert ssh.run("ip link show dummy0")[3] != 0


def test_master_conflict_l2(ssh, setup):
    """Conflicting masters cannot steal members; valid moves remain allowed."""
    ssh.ifup_a()
    ssh.run_assert_success(
        "ip -o link show dummy_bond | grep -w 'master bond_guard'"
    )
    ssh.run_assert_success(
        "ip -o link show dummy_vrf | grep -w 'master vrf_guard'"
    )

    # Misconfigure both existing members as bridge ports as well.
    ssh.run_assert_success(
        f"sed -i '/iface br_guard/a\\    "
        f"bridge-ports dummy_bond dummy_vrf' {ENI}"
    )
    _, stdout, stderr, _ = ssh.run("ifup br_guard")
    output = stdout.read().decode("utf-8") + stderr.read().decode("utf-8")
    assert "skipping bridge enslavement" in output

    # Neither existing master may lose its member.
    ssh.run_assert_success(
        "ip -o link show dummy_bond | grep -w 'master bond_guard'"
    )
    ssh.run_assert_success(
        "ip -o link show dummy_vrf | grep -w 'master vrf_guard'"
    )
    assert ssh.run(
        "ls /sys/class/net/br_guard/brif | grep -w dummy_bond"
    )[3] != 0
    assert ssh.run(
        "ls /sys/class/net/br_guard/brif | grep -w dummy_vrf"
    )[3] != 0

    # Remove the old VRF ownership from configuration. The now-valid move of
    # dummy_vrf into the bridge must not be blocked by the conflict guard.
    ssh.run_assert_success(
        f"sed -i "
        f"-e 's/bridge-ports dummy_bond dummy_vrf/bridge-ports dummy_vrf/' "
        f"-e '/^    vrf vrf_guard$/d' {ENI}"
    )
    ssh.ifup("br_guard", ignore_stderr=True)
    ssh.run_assert_success(
        "ip -o link show dummy_vrf | grep -w 'master br_guard'"
    )
    ssh.run_assert_success(
        "ip -o link show dummy_bond | grep -w 'master bond_guard'"
    )

    ssh.run_assert_success(
        f"sed -i '/bridge-ports dummy_vrf/d' {ENI}"
    )
    ssh.ifdown(
        "br_guard bond_guard vrf_guard dummy_bond dummy_vrf",
        ignore_stderr=True,
    )
    for ifname in (
            "br_guard", "bond_guard", "vrf_guard",
            "dummy_bond", "dummy_vrf"):
        assert ssh.run(f"ip link show {ifname}")[3] != 0


def test_pvid_vni_protection_l2(ssh, setup):
    """Repeated SVD recreation keeps the VLAN 1 tunnel mapping intact.

    A collect-metadata VXLAN receives an implicit VLAN 1 PVID when it joins the
    bridge. Reload must not treat that kernel-created PVID as stale because
    deleting it also removes the VLAN-to-VNI tunnel mapping.
    """
    iterations = 20

    try:
        for iteration in range(iterations):
            for ifname in ("br_pvid", "vxlan_pvid"):
                ssh.run(f"ip link del {ifname} 2>/dev/null; true")
                assert ssh.run(f"ip link show {ifname}")[3] != 0

            verbose_output = ssh.ifreload_av(ignore_stdout=True)
            tunnel_output = ssh.run_assert_success(
                "bridge vlan tunnelshow dev vxlan_pvid"
            )
            mapping_present = any(
                line.split()[-2:] == ["1", "5001"]
                for line in tunnel_output.splitlines()
            )

            assert mapping_present, (
                f"iteration {iteration + 1}/{iterations}: "
                f"VLAN 1 to VNI 5001 mapping is missing: {tunnel_output!r}"
            )
            assert (
                "vlan del vid 1 untagged pvid dev vxlan_pvid"
                not in verbose_output
            ), (
                f"iteration {iteration + 1}/{iterations}: "
                "reload deleted the VNI-mapped PVID"
            )
    finally:
        ssh.run("ifdown br_pvid vxlan_pvid 2>/dev/null; true")

    assert ssh.run("ip link show br_pvid")[3] != 0
    assert ssh.run("ip link show vxlan_pvid")[3] != 0


def test_pvrst_phase_cache_l2(ssh, setup):
    """Diff reload reevaluates global PVRST mode between scheduler phases."""
    _, stdout, stderr, _ = ssh.run("mstpctl --help")
    help_output = (
        stdout.read().decode("utf-8") +
        stderr.read().decode("utf-8")
    )
    if "setmodepvrst" not in help_output:
        pytest.skip("mstpctl does not support PVRST mode")

    cleanup_succeeded = False
    cleanup_output = ""
    cleanup_protocol = None
    try:
        ssh.ifreload_diff = False
        ssh.ifreload_a()
        initial_state = json.loads(
            ssh.run_assert_success(
                "mstpctl showstpbridge json br_pvrst"
            )
        )
        assert initial_state.get("protocol") == "rstp"

        ssh.scp("tests/eni/pvrst_phase_cache_l2.after.eni", ENI)
        ssh.ifreload_diff = True
        apply_output = ssh.ifreload_av(ignore_stdout=True)

        assert "mstpctl setmodepvrst" in apply_output
        bridge_state = json.loads(
            ssh.run_assert_success(
                "mstpctl showstpbridge json br_pvrst"
            )
        )
        assert bridge_state.get("protocol") == "rapid-pvst"
    finally:
        try:
            ssh.scp("tests/eni/pvrst_phase_cache_l2.eni", ENI)
            ssh.ifreload_diff = True
            cleanup_output = ssh.ifreload_av(ignore_stdout=True)
            cleanup_state = json.loads(
                ssh.run_assert_success(
                    "mstpctl showstpbridge json br_pvrst"
                )
            )
            cleanup_protocol = cleanup_state.get("protocol")
            cleanup_succeeded = True
        finally:
            if not cleanup_succeeded:
                ssh.run("mstpctl clearmodepvrst 2>/dev/null; true")
            ssh.run(
                "ifdown br_pvrst swp_AA_ swp_BB_ swp_CC_ "
                "2>/dev/null; true"
            )

    assert "mstpctl clearmodepvrst" in cleanup_output
    assert cleanup_protocol == "rstp"
    assert ssh.run("ip link show br_pvrst")[3] != 0
    for ifname in ("swp_AA_", "swp_BB_", "swp_CC_"):
        ssh.run_assert_success(f"ip link show {ifname}")
