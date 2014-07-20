Development Corner
==================

Writing a ifupdown2 addon module
--------------------------------
ifupdown2 addon modules are part of the python-ifupdown2 package.
They are installed under /usr/share/ifupdownaddons directory on the target box.

The center of the universe for an addon module is the 'class iface' object
exported by the python-ifupdown2 package.

The iface object contains all config the user wanted. For more details see
the api refernce for the iface class.

ifupdown2 invokes the addon module by invoking a few methods. And hence
it expects a few interfaces from the addon modules.

* all modules must inherit from moduleBase class
* the module should implement a class by the same name
* the interface object (class iface) and the operation to be performed is
  passed to the modules. In cases when the operation is query-check, where
  the module has to compare between the given and running state, the module
  also takes an addional queryobjcur iface object
* the python addon class should provide a few methods:
    * run() : method to configure the interface.
    * get_ops() : must return a list of operations it supports.
      eg: 'pre-up', 'post-down'
    * get_dependent_ifacenames() : must return a list of interfaces the
      interface is dependent on. This is used to build the dependency list
      for sorting and executing interfaces in dependency order.
    * if the module supports -r option to ifquery, ie ability to construct the
      ifaceobj from running state, it can optionally implement the
      get_dependent_ifacenames_running() method, to return the list of
      dependent interfaces derived from running state of the interface.
      This is different from get_dependent_ifacenames() where the dependent
      interfaces are derived from the interfaces config file (provided by the
      user).
    * provide a dictionary of all supported attributes in the _modinfo
      attribute. This is useful for syntax help and man page generation.

python-ifupdown2 package also installs a ifupdownaddons python package that
contains helper modules for all addon modules.

see example address handling module /usr/share/ifupdownaddons/address.py

apiref
------
.. toctree::
   :maxdepth: 2

   addonsapiref.rst
   addonshelperapiref.rst
