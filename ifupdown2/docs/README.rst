ifupdown2
=========

This package is a replacement for the debian ifupdown package.
It is ifupdown re-written in python. It maintains the original ifupdown
pluggable architecture and extends it further.

ifupdown2 package provides the infrastructure for
parsing /etc/network/interfaces file, loading, scheduling and state
management of interfaces.

It dynamically loads python modules from /usr/share/ifupdown2/addons.

It publishes an interface object which is passed to all loadble python
modules. For more details on adding a addon module, see the section on
adding python modules.

install
=======

- ifupdown2 conflicts with existing ifupdown. Hence remove existing
ifupdown package
  dpkg -r ifupdown

- install ifupdown2 using `dpkg -i <ifupdown2_*.deb>` or apt-get install ifupdown2

New things:
==========
- new ifreload command to reload changed interfaces
- ifup on an already up interface reapplies all config without bringing
the interface down
- new command line options to ifup/ifdown and ifquery (check with -h option)
- new ifupdown2 config file: /etc/network/ifupdown2/ifupdown2.conf
- support for mako templates
    - install python-mako and enable mako in ifupdown2.conf
        * apt-get install python-mako
        * uncomment the following lines in /etc/network/ifupdown2/ifupdown2.conf
            template_engine=mako
            template_lookuppath=/etc/network/ifupdown2/templates

pluggable python modules:
=========================
Unlike original ifupdown, all interface configuration is moved to external
python modules. That includes inet, inet6 and dhcp configurations.

A set of default modules are included in the package.

ifupdown2 expects a few things from the pluggable modules:
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

Example: Address handling module /usr/share/ifupdown2/addons/address.py

