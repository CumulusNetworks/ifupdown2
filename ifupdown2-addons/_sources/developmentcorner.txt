Development Corner
==================

Writing a ifupdown2 addon module
--------------------------------
ifupdown2 addon modules are part of the python-ifupdown2-addons package.
They are installed under /usr/share/ifupdownaddons directory on the target
system.

The center of the universe for an addon module is the 'class iface' object
exported by the python-ifupdown2 package.

The iface object is modeled after an iface entry in the user provided network
configuration file (eg. /etc/network/interfaces). For more details see
the api reference for the iface class.

ifupdown2 dynamically loads a python addon module. It expects the addon module
to implement a few methods.

* all addon modules must inherit from moduleBase class
* the module must implement a class by the same name
* the network interface object (class iface) and the operation to be performed
  is passed to the modules. Operation can be any of 'pre-up', 'up', 'post-up',
  'pre-down', 'down', 'post-down', 'query-check', 'query-running'.
  The module can choose to support a subset or all operations.
  In cases when the operation is query-check, the module must compare between
  the given and running state and return the checked state of the object in
  queryobjcur passed as argument to the run menthod.
* the python addon class must provide a few methods:
    * run() : method to configure the interface.
    * get_ops() : must return a list of operations it supports.
      eg: 'pre-up', 'post-down'
    * get_dependent_ifacenames() : must return a list of interfaces the
      supported interface is dependent on. This is used to build the
      dependency list for sorting and executing interfaces in dependency order.
    * if the module supports -r option to ifquery, ie ability to construct the
      ifaceobj from running state, it can optionally implement the
      get_dependent_ifacenames_running() method, to return the list of
      dependent interfaces derived from running state of the interface.
      This is different from get_dependent_ifacenames() where the dependent
      interfaces are derived from the interfaces config file (provided by the
      user).
    * provide a dictionary of all supported attributes in the _modinfo
      attribute. This is useful for syntax help and man page generation.

python-ifupdown2-addons package also installs ifupdownaddons python package
that contains helper modules for all addon modules. Its optional for the addon
module to use this package.

see example address handling module /usr/share/ifupdownaddons/address.py

API reference
-------------
.. toctree::
   :maxdepth: 2

   addonsapiref.rst
   addonshelperapiref.rst
