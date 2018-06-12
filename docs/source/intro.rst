python-ifupdown2
----------------

The python-ifupdown2 package provides the infrastructure for
parsing /etc/network/interfaces file, loading, scheduling, template parsing,
state management and interface dependency generation of interfaces.
It dynamically loads python addon modules from /usr/share/ifupdownmodules.
To remain compatible with other packages that depend on ifupdown, it also
executes scripts under /etc/network/. To make the transition smoother, a
python module under /usr/share/ifupdownmodules will override a script by
the same name under /etc/network/. ifupdown2 publishes an interface object which
is passed to all loadble python addon modules. All lodable modules are
called for every interface declared in the /etc/network/interfaces file.

Addon modules are responsible for applying interface configuration.
python-ifupdown2 ships with a set of default addon modules. Each module can
declare its own set of supported attributes. Each module is passed the iface
object (which is a representation of /etc/network/interfaces
iface entry). Each module is also passed the operation to be performed.

Example modules are /usr/share/ifupdownmodules/address.py,
/usr/share/ifupdownmodules/bridge.py etc

The order in which these modules are invoked is listed in
/var/lib/ifupdownaddons/addons.conf. There is an ifaddon utility in the works
to better manage the module ordering.

For more details on adding an addon module, see the section on adding python
modules. For details on how to write a module, see the api reference and
development documentation.

