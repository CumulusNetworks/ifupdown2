python-ifupdown2
================

This package is a replacement for the debian ifupdown package.
It is ifupdown re-written in python. It maintains the original ifupdown
pluggable architecture and extends it further.

The python-ifupdown2 package provides the infrastructure for
parsing /etc/network/interfaces file, loading, scheduling and state
management of interfaces.

It dynamically loads python modules from /usr/share/ifupdownmodules (provided
 by the python-ifupdown2-addons package). To remain compatible with other
packages that depend on ifupdown, it also executes scripts under /etc/network/.
To make the transition smoother, a python module under
/usr/share/ifupdownmodules will override a script by the same name under
/etc/network/.

It publishes an interface object which is passed to all loadble python
modules. For more details on adding a addon module, see the section on
adding python modules.


pluggable python modules:
=========================
Unlike original ifupdown, all interface configuration is moved to external
python modules. That includes inet, inet6 and dhcp configurations.

A set of default modules are provided by the python-ifupdown2-addons deb.

python-ifupdown2 expects a few things from the pluggable modules:
- the module should implement a class by the same name
- the interface object (class iface) and the operation to be performed is
  passed to the modules
- the python addon class should provide a few methods:
	- run() : method to configure the interface.
	- get_ops() : must return a list of operations it supports.
		eg: 'pre-up', 'post-down'
	- get_dependent_ifacenames() : must return a list of interfaces the
	  interface is dependent on. This is used to build the dependency list
	  for sorting and executing interfaces in dependency order.
	- if the module supports -r option to ifquery, ie ability to construct the
      ifaceobj from running state, it can optionally implement the
      get_dependent_ifacenames_running() method, to return the list of
      dependent interfaces derived from running state of the interface.
      This is different from get_dependent_ifacenames() where the dependent
      interfaces are derived from the interfaces config file (provided by the
      user).

Example: Address handling module /usr/share/ifupdownaddons/address.py


build
=====
- get source

- install build dependencies:
    apt-get install python-stdeb
    apt-get install python-docutils

- cd <python-ifupdown2 sourcedir> && ./build.sh

  (generates python-ifupdown2-<ver>.deb)

install
=======

- remove existing ifupdown package
  dpkg -r ifupdown

- install python-ifupdown2 using `dpkg -i`

- or install from deb
    dpkg -i python-ifupdown2-<ver>.deb

- note that python-ifupdown2 requires python-ifupdown2-addons package to
  function. And python-ifupdown2-addons deb has an install dependency on
  python-ifupdown2
