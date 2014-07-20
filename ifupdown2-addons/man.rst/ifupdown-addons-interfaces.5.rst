==========================
ifupdown-addons-interfaces
==========================
---------------------------------------------------------
ifupdown2 addon modules interface configuration
---------------------------------------------------------
:Author: roopa@cumulusnetworks.com
:Date:   2013-09-25
:Copyright: Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
:Version: 0.1
:Manual section: 5


DESCRIPTION
===========
    ifupdown2 addon modules add incremental functionality to
    core ifupdown2 tool.
           
    All installed addon modules are executed on every interface
    listed in the interfaces file. Addon modules are installed under
    /usr/share/ifupdownaddons. To see the list of active addon
    modules, see ifaddon(8).

    Addon modules add new attributes to the interfaces(5) file.
    Below is a list of attribute options provided by each module.
    These can be listed under each iface section in the interfaces(5)
    file.  


EXAMPLES
========
    Listed below are addon modules and their supported attributes.
    The attributes if applicable go under the iface section in the
    interfaces(5) file.

    **ethtool**: ethtool configuration module for interfaces


      **link-duplex**

        **help**: set link duplex


        **required**: False

        **default**: half

        **validvals**: half,full

        **example**:
            link-duplex full


      **link-autoneg**

        **help**: set autonegotiation


        **required**: False

        **default**: off

        **validvals**: on,off

        **example**:
            link-autoneg on


      **link-speed**

        **help**: set link speed


        **required**: False

        **example**:
            link-speed 1000



    **bridge**: bridge configuration module


      **bridge-mcqifaddr**

        **help**: set multicast query to use ifaddr


        **required**: False

        **default**: 0

        **example**:
            bridge-mcqifaddr 0


      **bridge-gcint**

        **help**: bridge garbage collection interval in secs


        **required**: False

        **default**: 4

        **example**:
            bridge-gcint 4


      **bridge-mcsqc**

        **help**: set multicast startup query count


        **required**: False

        **default**: 2

        **example**:
            bridge-mcsqc 2


      **bridge-stp**

        **help**: bridge-stp yes/no


        **required**: False

        **default**: no

        **validvals**: yes,on,off,no

        **example**:
            bridge-stp no


      **bridge-mcsqi**

        **help**: set multicast startup query interval (in secs)


        **required**: False

        **default**: 31

        **example**:
            bridge-mcsqi 31


      **bridge-mcmi**

        **help**: set multicast membership interval (in secs)


        **required**: False

        **default**: 260

        **example**:
            bridge-mcmi 260


      **bridge-ports**

        **help**: bridge ports


        **required**: True

        **example**:
            bridge-ports swp1.100 swp2.100 swp3.100

            bridge-ports glob swp1-3.100

            bridge-ports regex (swp[1|2|3].100)


      **bridge-mcsnoop**

        **help**: set multicast snooping


        **required**: False

        **default**: 1

        **example**:
            bridge-mcsnoop 1


      **bridge-maxwait**

        **help**: forces to time seconds the maximum time that the Deb
        ian bridge setup  scripts will wait for the bridge ports to ge
        t to the forwarding status, doesn't allow factional part. If i
        t is equal to 0 then no waiting is done


        **required**: False

        **default**: 0

        **example**:
            bridge-maxwait 3


      **bridge-pathcosts**

        **help**: bridge set port path costs


        **required**: False

        **default**: 100

        **example**:
            bridge-pathcosts swp1=100 swp2=100


      **bridge-portprios**

        **help**: bridge port prios


        **required**: False

        **default**: 32

        **example**:
            bridge-portprios swp1=32 swp2=32


      **bridge-fd**

        **help**: bridge forward delay


        **required**: False

        **default**: 15

        **example**:
            bridge-fd 15


      **bridge-ageing**

        **help**: bridge ageing


        **required**: False

        **default**: 300

        **example**:
            bridge-ageing 300


      **bridge-hello**

        **help**: bridge set hello time


        **required**: False

        **default**: 2

        **example**:
            bridge-hello 2


      **bridge-mcquerier**

        **help**: set multicast querier


        **required**: False

        **default**: 0

        **example**:
            bridge-mcquerier 0


      **bridge-mclmc**

        **help**: set multicast last member count


        **required**: False

        **default**: 2

        **example**:
            bridge-mclmc 2


      **bridge-mcrouter**

        **help**: set multicast router


        **required**: False

        **default**: 1

        **example**:
            bridge-mcrouter 1


      **bridge-portmcrouter**

        **help**: set port multicast routers


        **required**: False

        **default**: 1

        **example**:
            bridge-portmcrouter swp1=1 swp2=1


      **bridge-mclmi**

        **help**: set multicast last member interval (in secs)


        **required**: False

        **default**: 1

        **example**:
            bridge-mclmi 1


      **bridge-hashmax**

        **help**: set hash max


        **required**: False

        **default**: 4096

        **example**:
            bridge-hashmax 4096


      **bridge-waitport**

        **help**: wait for a max of time secs for the specified ports 
        to become available,if no ports are specified then those speci
        fied on bridge-ports will be used here. Specifying no ports he
        re should not be used if we are using regex or "all" on bridge
        _ports,as it wouldnt work.


        **required**: False

        **default**: 0

        **example**:
            bridge-waitport 4


      **bridge-mcqri**

        **help**: set multicast query response interval (in secs)


        **required**: False

        **default**: 10

        **example**:
            bridge-mcqri 10


      **bridge-hashel**

        **help**: set hash elasticity


        **required**: False

        **default**: 4096

        **example**:
            bridge-hashel 4096


      **bridge-mcqpi**

        **help**: set multicast querier interval (in secs)


        **required**: False

        **default**: 255

        **example**:
            bridge-mcqpi 255


      **bridge-bridgeprio**

        **help**: bridge priority


        **required**: False

        **default**: 32768

        **example**:
            bridge-bridgeprio 32768


      **bridge-maxage**

        **help**: bridge set maxage


        **required**: False

        **default**: 20

        **example**:
            bridge-maxage 20


      **bridge-portmcfl**

        **help**: port multicast fast leave


        **required**: False

        **default**: 0

        **example**:
            bridge-portmcfl swp1=0 swp2=0


      **bridge-mcqi**

        **help**: set multicast query interval (in secs)


        **required**: False

        **default**: 125

        **example**:
            bridge-mcqi 125



    **usercmds**: user commands for interfaces


      **down**

        **help**: run command at interface down


        **required**: False

      **post-up**

        **help**: run command after interface bring up


        **required**: False

      **up**

        **help**: run command at interface bring up


        **required**: False

      **pre-down**

        **help**: run command before bringing the interface down


        **required**: False

      **pre-up**

        **help**: run command before bringing the interface up


        **required**: False

      **post-down**

        **help**: run command after bringing interface down


        **required**: False


    **mstpctl**: mstp configuration module for bridges


      **mstpctl-fdelay**

        **help**: set forwarding delay


        **required**: False

        **default**: 15

        **example**:
            mstpctl-fdelay 15


      **mstpctl-txholdcount**

        **help**: bridge transmit holdcount


        **required**: False

        **default**: 6

        **example**:
            mstpctl-txholdcount 6


      **mstpctl-portautoedge**

        **help**: enable/disable auto transition to/from edge state of
        the port


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portautoedge swp1=yes swp2=yes


      **mstpctl-portrestrrole**

        **help**: enable/disable port ability to take root role of the
        port


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portrestrrole swp1=no swp2=no


      **mstpctl-portnetwork**

        **help**: enable/disable bridge assurance capability for a por
        t


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portnetwork swp1=no swp2=no


      **mstpctl-portp2p**

        **help**: bridge port p2p detection mode


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portp2p swp1=no swp2=no


      **mstpctl-treeprio**

        **help**: tree priority


        **required**: False

        **default**: 32768

        validrange: 0-65535

        **example**:
            mstpctl-treeprio 32768


      **mstpctl-treeportprio**

        **help**: port priority for MSTI instance


        **required**: False

        **default**: 128

        validrange: 0-240

        **example**:
            mstpctl-treeportprio swp1=128 swp2=128


      **mstpctl-hello**

        **help**: set hello time


        **required**: False

        **default**: 2

        **example**:
            mstpctl-hello 2


      **mstpctl-ageing**

        **help**: ageing time


        **required**: False

        **default**: 300

        **example**:
            mstpctl-ageing 300


      **mstpctl-portadminedge**

        **help**: enable/disable initial edge state of the port


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portadminedge swp1=no swp2=no


      **mstpctl-maxage**

        **help**: max message age


        **required**: False

        **default**: 20

        **example**:
            mstpctl-maxage 20


      **mstpctl-maxhops**

        **help**: bridge max hops


        **required**: False

        **default**: 15

        **example**:
            mstpctl-maxhops 15


      **mstpctl-portrestrtcn**

        **help**: enable/disable port ability to propagate received to
        pology change notification of the port


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portrestrtcn swp1=no swp2=no


      **mstpctl-portpathcost**

        **help**: bridge port path cost


        **required**: False

        **default**: 0

        **example**:
            mstpctl-portpathcost swp1=0 swp2=1


      **mstpctl-portadminage**

        **help**: bridge port admin age


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portadminage swp1=no swp2=no


      **mstpctl-portbpdufilter**

        **help**: enable/disable bpdu filter on a port


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-portbpdufilter swp1=no swp2=no


      **mstpctl-forcevers**

        **help**: bridge force stp version


        **required**: False

        **default**: rstp

        **example**:
            mstpctl-forcevers rstp


      **mstpctl-treeportcost**

        **help**: port tree cost


        **required**: False

      **mstpctl-bpduguard**

        **help**: enable/disable bpduguard


        **required**: False

        **default**: no

        **validvals**: yes,no

        **example**:
            mstpctl-bpduguard swp1=no swp2=no



    **vlan**: vlan module configures vlan interfaces.This module under
    stands vlan interfaces with dot notations. eg swp1.100. Vlan inter
    faces with any other names need to have raw device and vlan id att
    ributes


      **vlan-id**

        **help**: vlan id


        **required**: False

      **vlan-raw-device**

        **help**: vlan raw device


        **required**: False


    **ifenslave**: bond configuration module


      **bond-miimon**

        **help**: bond miimon


        **required**: False

        **default**: 0

        validrange: 0-255

        **example**:
            bond-miimon 0


      **bond-slaves**

        **help**: bond slaves


        **required**: True

        **example**:
            bond-slaves swp1 swp2

            bond-slaves glob swp1-2

            bond-slaves regex (swp[1|2)


      **bond-mode**

        **help**: bond mode


        **required**: False

        **default**: balance-rr

        **validvals**: balance-rr,active-backup,balance-xor,broadcast,802.3ad,balance-tlb,balance-alb

        **example**:
            bond-mode 802.3ad


      **bond-num-grat-arp**

        **help**: bond use carrier


        **required**: False

        **default**: 1

        validrange: 0-255

        **example**:
            bond-num-grat-arp 1


      **bond-ad-sys-mac-addr**

        **help**: 802.3ad system mac address


        **required**: False

        **default**: 00:00:00:00:00:00

        **example**:
            bond-ad-sys-mac-addr 00:00:00:00:00:00


      **bond-use-carrier**

        **help**: bond use carrier


        **required**: False

        **default**: 1

        **validvals**: 0,1

        **example**:
            bond-use-carrier 1


      **bond-lacp-rate**

        **help**: bond use carrier


        **required**: False

        **default**: 0

        **validvals**: 0,1

        **example**:
            bond-lacp-rate 0


      **bond-min-links**

        **help**: bond min links


        **required**: False

        **default**: 0

        **example**:
            bond-min-links 0


      **bond-num-unsol-na**

        **help**: bond slave devices


        **required**: False

        **default**: 1

        validrange: 0-255

        **example**:
            bond-num-unsol-na 1


      **bond-ad-sys-priority**

        **help**: 802.3ad system priority


        **required**: False

        **default**: 65535

        **example**:
            bond-ad-sys-priority 65535


      **bond-xmit-hash-policy**

        **help**: bond slave devices


        **required**: False

        **default**: layer2

        **validvals**: layer2,layer3+4,layer2+3

        **example**:
            bond-xmit-hash-policy layer2



    **address**: address configuration module for interfaces


      **broadcast**

        **help**: broadcast address


        **required**: False

        **example**:
            broadcast 10.0.1.255


      **hwaddress**

        **help**: hw address


        **required**: False

        **example**:
            hwaddress 44:38:39:00:27:b8


      **alias**

        **help**: description/alias


        **required**: False

        **example**:
            alias testnetwork


      **address**

        **help**: ipv4 or ipv6 addresses


        **required**: False

        **example**:
            address 10.0.12.3/24

            address 2000:1000:1000:1000:3::5/128


      **scope**

        **help**: scope


        **required**: False

        **example**:
            scope host


      **preferred-lifetime**

        **help**: preferred lifetime


        **required**: False

        **example**:
            preferred-lifetime forever

            preferred-lifetime 10


      **gateway**

        **help**: default gateway


        **required**: False

        **example**:
            gateway 255.255.255.0


      **mtu**

        **help**: interface mtu


        **required**: False

        **default**: 1500

        **example**:
            mtu 1600



SEE ALSO
========
    interfaces(5),
    ifup(8),
    ip(8),
    mstpctl(8),
    brctl(8),
    ethtool(8)
