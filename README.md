ifupdown2
=========

ifupdown2 is a alternate implementation of debian's network interface manager
ifupdown.

ifupdown2 provides the required infrastructure to parse, schedule and
manage interface configuration. Also provides default python addon modules
for network interface configuration.


Note: Previously ifupdown2 came as two packages: python-ifupdown2 and
python-ifupdown2-addons. python-ifupdown2-addons contents are now merged into
python-ifupdown2 package (python-ifupdown2-addons package is hence deprecated).

Install
=======

## dependencies

To install the mandatory dependencies please execute the following command:
```
apt-get install python-ipaddr
apt-get install python-argcomplete
```

More recommended dependencies:
```
apt-get install bridge-utils
apt-get install ethtool
```

## debian & Ubuntu

To get our lastest version that is available on the debian repositories for your current OS just type
`apt-get install ifupdown2`

## Ubuntu users (anything bellow version Artful)

We highly recommend that you build your own debs or WGET a deb from the debian repo as we have trouble backporting our latest fixes and features in Zesty, Xenial and bellow.

```
wget http://ftp.us.debian.org/debian/pool/main/i/ifupdown2/ifupdown2_1.0~git20170314-1_all.deb
dpkg -i ifupdown2_1.0~git20170314-1_all.deb
```

## build your own deb

If ever the repositories for your OS version doesn't include latest ifupdown2 you can always build your own deb

To buid on Ubuntu and debian you'll some extra packages:

```
apt-get install build-essential dh-systemd dh-make python-docutils
```

Then run the following commands:

```
dpkg-buildpackage -us -uc -d
```

On the master branch this simple command should produce a `.deb` file that you can install using `dpkg -i`

On the `debian-prep2` branch, you'll need to run:

```
cd /path/to/ifupdown2/source/folder
git archive --format=tar HEAD | xz -9 -c >../ifupdown2_1.0~git20170314.orig.tar.xz && dpkg-buildpackage -us -uc -d
```

Note that the name of the tar archive needs to match the latest version present in the changelog. We usually use the date of the upload to tag a new version. In this previous example it was `20170314`

If you are experiencing any issues please feel free to open a new issue.

