from .conftest import ENI, assert_identical_json

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_address(ssh, setup, get_json):
    ssh.ifup_a()
    assert_identical_json(ssh.ifquery_ac_json(), get_json("address.ifquery.ac.json"))


def test_address_gateway(ssh, setup):
    """A 'gateway' configured on an interface that is also 'link-down yes'.

    The kernel refuses to install a default route while the gateway's link is
    down, so ifupdown2 skips the gateway on a kept-down interface through the
    KEEP_LINK_DOWN guard in address._add_delete_gateway. ifup then
    succeeds (no 'Nexthop ... is not up' error) and installs no default route
    via that interface, while the interface's address is still configured.

    The former behavior errored while adding the unreachable gateway.
    """
    # ifup now succeeds; br1 emits an unrelated STP warning.
    ssh.ifup_a(ignore_stderr=True)

    # The interface address is still configured (only the gateway is skipped).
    ssh.run_assert_success("ip -o addr show swp_AA_ | grep '10.0.14.3/14'")

    # The configured link-down state is actually in effect.
    assert ssh.run("ip -o link show swp_AA_ | grep -w UP")[3] != 0

    # No default route was installed via the kept-down interface.
    _, stdout, _, _ = ssh.run("ip route show default dev swp_AA_")
    assert stdout.read().decode().strip() == "", \
        "no default route should be installed via a link-down interface"


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


def test_dhcp6_release_link_down_l3(ssh, setup):
    """A failed DHCPv6 release on a kept-down link remains non-fatal."""
    pidfile = "/run/dhclient6.dum_d6.pid"
    leasefile = "/var/lib/dhcp/dhclient6.dum_d6.leases"
    ssh.run_assert_success(f"rm -f {pidfile} {leasefile}")

    # The dhcp addon runs after the link has been forced down. Its release
    # command therefore has no IPv6 link-local source address, but ifup must
    # continue and leave the configured interface down.
    ssh.ifup_a()
    assert ssh.run("ip link show dum_d6")[3] == 0
    assert ssh.run("ip -o link show dum_d6 | grep -w UP")[3] != 0
    assert ssh.run(f"test -e {pidfile}")[3] != 0

    # Prove the underlying command really fails in this state; the successful
    # ifup above depends on _dhcp_down isolating that exception.
    _, _, _, release_status = ssh.run(
        f"/sbin/dhclient -6 -r -pf {pidfile} "
        f"-lf {leasefile} dum_d6"
    )
    assert release_status != 0

    ssh.ifdown("dum_d6")
    assert ssh.run("ip link show dum_d6")[3] != 0
    ssh.run_assert_success(f"rm -f {pidfile} {leasefile}")


def test_ipv6_primary_purge_l3(ssh, setup):
    """An IPv4 primary change never transiently deletes retained IPv6."""
    monitor_log = "/tmp/ifupdown2-ipv6-primary-monitor.log"
    monitor_pid = "/tmp/ifupdown2-ipv6-primary-monitor.pid"
    ssh.run_assert_success(f"rm -f {monitor_log} {monitor_pid}")

    ssh.ifup_a()
    ssh.run_assert_success(
        "ip -o address show dev dum_purge | grep '192.0.2.1/24'"
    )
    ssh.run_assert_success(
        "ip -6 -o address show dev dum_purge | grep '2001:db8:43::1/64'"
    )
    ssh.run_assert_success(
        "ip -6 -o address show dev dum_purge | grep '2001:db8:43::2/64'"
    )

    ssh.run_assert_success(
        "nohup timeout 30 stdbuf -oL ip monitor address dev dum_purge "
        f"> {monitor_log} 2>&1 < /dev/null & echo $! > {monitor_pid}"
    )
    ssh.run_assert_success(
        f"test -s {monitor_pid} && kill -0 $(cat {monitor_pid}) && sleep 1"
    )

    # Promote the secondary IPv4 address and explicitly remove only IPv6 ::2.
    ssh.run_assert_success(
        f"sed -i -e '/address 192\\.0\\.2\\.1\\/24/d' "
        f"-e '/address 2001:db8:43::2\\/64/d' {ENI}"
    )
    ssh.ifup("dum_purge")

    ssh.run_assert_success(
        f"kill $(cat {monitor_pid}) 2>/dev/null || true; sleep 1"
    )
    monitor_output = ssh.run_assert_success(f"cat {monitor_log}").lower()

    # Explicitly removed IPv6 is deleted, while retained IPv6 never flaps.
    assert any(
        "deleted" in line and "2001:db8:43::2/64" in line
        for line in monitor_output.splitlines()
    )
    assert not any(
        "deleted" in line and "2001:db8:43::1/64" in line
        for line in monitor_output.splitlines()
    )

    assert ssh.run(
        "ip -o address show dev dum_purge | grep '192.0.2.1/24'"
    )[3] != 0
    ssh.run_assert_success(
        "ip -o address show dev dum_purge | grep '192.0.2.2/24'"
    )
    ssh.run_assert_success(
        "ip -6 -o address show dev dum_purge | grep '2001:db8:43::1/64'"
    )
    assert ssh.run(
        "ip -6 -o address show dev dum_purge | grep '2001:db8:43::2/64'"
    )[3] != 0

    ssh.ifdown("dum_purge")
    ssh.run_assert_success(f"rm -f {monitor_log} {monitor_pid}")
