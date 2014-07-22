python-ifupdown2-addons
-----------------------

The python-ifupdown2-addons package contains ifupdown2 addon modules.

addon modules are responsible for applying interface configuration.
The modules are installed under /usr/share/ifupdownmodules.

Each module can declare its own set of supported attributes. Each module
is passed the iface object (which is a representation of /etc/network/interfaces
iface entry). Each module is also passed the operation to be performed.

Example modules are /usr/share/ifupdownmodules/address.py,
/usr/share/ifupdownmodules/bridge.py etc

The order in which these modules are invoked is listed in 
/var/lib/ifupdownaddons/addons.conf. There is a ifaddon utility in the works
to better manage the module ordering.

For details on how to add a module, see the api reference and development
documentation.
