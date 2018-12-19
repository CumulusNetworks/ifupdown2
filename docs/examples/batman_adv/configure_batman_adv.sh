#!/usr/bin/env bash

echo "Installing batman-adv module on debian/ubuntu"
echo ""
echo "Batman is a Layer2-Mesh protocol which uses Ethernet devices (like eth*,
vlans, etc.) to communicate with peers and provides access to the L2-mesh via
a batX interface. You can only create a batman instance if at least one batman-
-iface (read: an interface where the mesh protocol is spoken on) is present and
added to the batman-mesh-instance."
echo "More info: https://en.wikipedia.org/wiki/B.A.T.M.A.N."
echo ""

echo "installing batctl: apt-get install batctl"
apt-get install batctl
echo ""
echo ""

echo "loading batman-adv module: modprobe batman-adv"
modprobe batman-adv
echo ""

echo "usefull commands:
$ batctl if add \$IFACE
$ batctl -m bat0 if add \$IFACE"
echo "please read: man batctl"
echo ""
echo ""

echo "configuration example:
$ cat /etc/network/interfaces

auto bat0
iface bat0
      batman-ifaces \$IFACE [\$IFACES...]
      batman-ifaces-ignore-regex .*_nodes
      batman-hop-penalty 23
      address 192.0.2.42/24
$
$
$ ifreload -a
$ ifquery -a -c
auto bat0
iface bat0                                                          [pass]
	batman-ifaces tap0 tap1                                     [pass]
	batman-ifaces-ignore-regex .*_nodes                         [pass]
	batman-hop-penalty 23                                       [pass]
	address 192.0.2.42/24                                       [pass]

$"
