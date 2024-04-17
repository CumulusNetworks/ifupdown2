import logging

from .conftest import assert_identical_json, ENI, ENI_D

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_bond(ssh, setup, get_json):
    bond_ifquery_ac_json = get_json("bond.ifquery.ac.json")

    ssh.ifreload_a()
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
    ssh.scp("tests/scp/interfaces_link_state.before.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("interfaces_link_state.before.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -br link show dev swp_AA_ | grep DOWN")
    ssh.run_assert_success("ip -br link show dev swp_BB_ | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge1 | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge2 | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge3 | grep DOWN")
    ssh.run_assert_success("ip -br link show dev bridge4 | grep UP")
    ssh.run_assert_success("rm /etc/network/interfaces.d/interfaces_link_state.before.eni")

    ssh.scp("tests/scp/interfaces_link_state.after.eni", ENI_D)
    ssh.ifreload_a()
    assert_identical_json(
        ssh.ifquery_ac_json(),
        get_json("interfaces_link_state.after.ifquery.ac.json")
    )
    ssh.run_assert_success("ip -br link show dev swp_BB_ | grep DOWN")
    ssh.run_assert_success("ip -br link show dev bridge1 | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge2 | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge3 | grep UP")
    ssh.run_assert_success("ip -br link show dev bridge4 | grep DOWN")
    ssh.run_assert_success("rm /etc/network/interfaces.d/interfaces_link_state.after.eni")


def test_mac1(ssh, setup, get_json):
    ssh.ifreload_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("mac1.ifquery.ac.json"))
