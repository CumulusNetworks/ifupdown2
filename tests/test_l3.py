from .conftest import ENI, assert_identical_json

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_address(ssh, setup, get_json):
    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )
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


def test_boolean_aliases_l3(ssh):
    """The deployed runtime accepts distutils-compatible boolean aliases."""
    ssh.run_assert_success(
        "python3 -c '"
        "import sys; "
        "sys.path.insert(0, \"/usr/share/ifupdown2\"); "
        "from ifupdown.utils import utils; "
        "expected={\"y\":True,\"true\":True,\"t\":True,"
        "\"n\":False,\"false\":False,\"f\":False}; "
        "assert all(utils.get_boolean_from_string(k, default=not v) is v "
        "for k,v in expected.items()); "
        "assert utils.get_int_from_boolean_and_string(\"true\") == 1; "
        "assert utils.get_int_from_boolean_and_string(\"false\") == 0'"
    )


def test_addressvirtual_fdb_cleanup_l3(ssh, setup):
    """Changing a virtual MAC removes its old bridge FDB entry."""
    old_mac = "00:00:5e:00:01:01"
    new_mac = "00:00:5e:00:01:02"

    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )
    ssh.run_assert_success(
        f"bridge fdb show br br_av | grep -i '{old_mac}' | grep 'vlan 100'"
    )
    ssh.run_assert_success(
        "ip -o addr show br_av-100-v0 | grep '192.0.2.1/24'"
    )

    ssh.run_assert_success(
        f"sed -i 's/{old_mac}/{new_mac}/' {ENI}"
    )
    ssh.ifup("br_av.100")

    assert ssh.run(
        f"bridge fdb show br br_av | grep -i '{old_mac}' | grep 'vlan 100'"
    )[3] != 0
    ssh.run_assert_success(
        f"bridge fdb show br br_av | grep -i '{new_mac}' | grep 'vlan 100'"
    )
    ssh.run_assert_success(
        "ip -o addr show br_av-100-v0 | grep '192.0.2.1/24'"
    )

    ssh.ifdown("br_av.100 br_av dummy_av")
    for ifname in ("br_av.100", "br_av", "br_av-100-v0", "dummy_av"):
        assert ssh.run(f"ip link show {ifname}")[3] != 0


def test_vxlan_ipv6_local_tunnelip_l3(ssh, setup):
    """An IPv6 local tunnel address is applied and reported in queries."""
    local = "2001:db8:6000::1"

    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )

    ssh.run_assert_success(
        f"ip -d -o link show vxlan6 | grep 'vxlan id 6000' | "
        f"grep 'local {local}'"
    )
    ssh.ifquery_c("vxlan6")

    running = ssh.ifquery(
        "--running vxlan6",
        return_stdout=True,
    )
    assert f"vxlan-local-tunnelip {local}" in running

    ssh.ifreload_a()
    ssh.run_assert_success(
        f"ip -d -o link show vxlan6 | grep 'local {local}'"
    )

    ipv6_ifindex = ssh.run_assert_success(
        "cat /sys/class/net/vxlan6/ifindex"
    ).strip()
    ipv4_local = "192.0.2.60"
    ssh.run_assert_success(
        f"sed -i 's/vxlan-local-tunnelip {local}/"
        f"vxlan-local-tunnelip {ipv4_local}/' {ENI}"
    )
    reload_output = ssh.ifreload_av()
    assert "address family changed to IPv4" in reload_output
    ssh.run_assert_success(
        f"ip -d -o link show vxlan6 | grep 'local {ipv4_local}'"
    )
    ipv4_ifindex = ssh.run_assert_success(
        "cat /sys/class/net/vxlan6/ifindex"
    ).strip()
    assert ipv4_ifindex != ipv6_ifindex

    ssh.run_assert_success(
        f"sed -i 's/vxlan-local-tunnelip {ipv4_local}/"
        f"vxlan-local-tunnelip {local}/' {ENI}"
    )
    reload_output = ssh.ifreload_av()
    assert "address family changed to IPv6" in reload_output
    ssh.run_assert_success(
        f"ip -d -o link show vxlan6 | grep 'local {local}'"
    )
    assert ssh.run_assert_success(
        "cat /sys/class/net/vxlan6/ifindex"
    ).strip() != ipv4_ifindex

    ssh.ifdown("vxlan6 dummy_vx6")
    assert ssh.run("ip link show vxlan6")[3] != 0
    assert ssh.run("ip link show dummy_vx6")[3] != 0


def test_vxlan_cached_local_reset_runtime_l3(ssh):
    """Cached IPv4/IPv6 local removal uses the deployed object's family."""
    ssh.run_assert_success(
        """PYTHONPATH=/usr/share/ifupdown2 python3 - <<'PY'
from addons.vxlan import vxlan
import addons.vxlan as vxlan_module
import nlmanager.ipnetwork as ipnetwork
from nlmanager.nlpacket import Link

class Iface:
    name = "vxreset"

    @staticmethod
    def get_attr_value_first(name):
        return None

class Logger:
    @staticmethod
    def info(*args):
        pass

addon = object.__new__(vxlan)
addon._vxlan_local_tunnelip = None
addon._clagd_vxlan_anycast_ip = ""
addon.logger = Logger()
vxlan_module.policymanager.policymanager_api.get_attr_default = (
    lambda **kwargs: None
)

for attribute, address in (
    (Link.IFLA_VXLAN_LOCAL, "192.0.2.10"),
    (Link.IFLA_VXLAN_LOCAL6, "2001:db8::10"),
):
    request = {}
    local = addon._vxlan__config_vxlan_local_tunnelip(
        "vxreset",
        Iface(),
        True,
        request,
        {attribute: ipnetwork.IPNetwork(address)},
    )
    assert local is None
    assert request == {attribute: None}
PY"""
    )


def test_mctp_route_runtime_l3(ssh):
    """The deployed parser treats MCTP route attributes as opaque data."""
    ssh.run_assert_success(
        """PYTHONPATH=/usr/share/ifupdown2 python3 - <<'PY'
from nlmanager.nlpacket import (
    AF_MCTP,
    AF_FAMILY,
    AttributeGeneric,
    Route,
    RTM_NEWROUTE,
)

route = Route(RTM_NEWROUTE, False, use_color=False)
route.family = AF_MCTP
route.dst_len = 8
attribute = route.add_attribute(Route.RTA_DST, bytes([8]))

assert AF_MCTP == 45
assert AF_FAMILY[AF_MCTP] == "AF_MCTP"
assert isinstance(attribute, AttributeGeneric)
assert route.get_prefix_string() == "mctp:8/8"
assert route.get_nexthops() == []
PY"""
    )


def test_multipath_route_runtime_l3(ssh):
    """The deployed parser handles mixed and truncated multipath nexthops."""
    ssh.run_assert_success(
        """PYTHONPATH=/usr/share/ifupdown2 python3 - <<'PY'
import socket
from struct import pack
from nlmanager.nlpacket import AttributeRTA_MULTIPATH, Route

def device(ifindex):
    return pack("=HBBL", 8, 0, 0, ifindex)

def gateway(ifindex, address):
    return (
        pack("=HBBL", 16, 0, 0, ifindex)
        + pack("=HH", 8, Route.RTA_GATEWAY)
        + socket.inet_pton(socket.AF_INET, address)
    )

def decode(payload):
    raw = pack("=HH", 4 + len(payload), Route.RTA_MULTIPATH) + payload
    attribute = AttributeRTA_MULTIPATH(
        Route.RTA_MULTIPATH,
        "RTA_MULTIPATH",
        socket.AF_INET,
        None,
    )
    attribute.decode(None, raw)
    return attribute.value

value = decode(device(5) + gateway(7, "192.0.2.2"))
assert value[0] == (None, 5, 0, 0)
assert str(value[1][0]) == "192.0.2.2"
assert value[1][1:] == (7, 0, 0)
assert decode(bytes([8, 0])) == ()
PY"""
    )


def test_source_directory_missing_path_runtime_l3(ssh):
    """The deployed parser reports missing source-directory paths."""
    _, stdout, stderr, status = ssh.run(
        """PYTHONPATH=/usr/share/ifupdown2 python3 - <<'PY'
from ifupdown.networkinterfaces import networkInterfaces

for line in ("source-directory", "source-directory ", "source-directory\\t"):
    parser = networkInterfaces(interfacesfile="/tmp/interfaces")
    assert parser.process_source_directory([line], 0, 7) == 0
    assert parser.errors == 1
PY"""
    )
    assert status == 0
    assert stdout.read().decode("utf-8") == ""
    expected = "/tmp/interfaces: line7: unable to read source-directory line\n"
    assert stderr.read().decode("utf-8") == expected * 3


def test_vxlan_missing_local_l3(ssh, setup):
    """An L3VXI can be created without a local tunnel address."""
    stderr = ssh.ifup_a(return_stderr=True)
    if stderr:
        assert stderr == (
            "warning: netlink: mgmt: cannot delete address 127.0.1.1/8 "
            "dev mgmt: operation failed with "
            "'Cannot assign requested address' (99)\n"
        )

    ssh.run_assert_success(
        "ip -d -o link show vxmeta | grep 'vxlan external' | "
        "grep 'vnifilter' | grep 'nolearning'"
    )
    ssh.run_assert_success(
        "ip -o link show vxmeta | grep 'master vrf_meta'"
    )
    ssh.run_assert_success(
        "bridge -j vni show dev vxmeta | grep '100'"
    )
    ssh.ifquery_c("vxmeta")
    running = ssh.ifquery(
        "--running vxmeta",
        return_stdout=True,
    )
    assert "vxlan-local-tunnelip" not in running

    ssh.ifreload_a()
    ssh.run_assert_success(
        "ip -d -o link show vxmeta | grep 'vxlan external' | grep 'vnifilter'"
    )

    ssh.ifdown("vxmeta vrf_meta")
    assert ssh.run("ip link show vxmeta")[3] != 0
    assert ssh.run("ip link show vrf_meta")[3] != 0


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
    reconcile_stderr = ssh.ifup(
        "dum_purge",
        return_stderr=True,
    )
    if reconcile_stderr:
        assert "cannot delete address 192.0.2.2/24" in reconcile_stderr
        assert "2001:db8:43::" not in reconcile_stderr

    ssh.run_assert_success(
        f"kill $(cat {monitor_pid}) 2>/dev/null || true; sleep 1"
    )
    monitor_output = ssh.run_assert_success(f"cat {monitor_log}").lower()

    # Confirm the monitor observed the IPv4 transition and retained IPv6 never
    # flapped. Explicit IPv6 removal is asserted from final kernel state below.
    assert "192.0.2" in monitor_output
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
