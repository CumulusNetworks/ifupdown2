from distutils.core import setup

setup(name='ifupdown2-addons',
      version='0.1',
      description = "ifupdown2 addon python modules",
      author='Roopa Prabhu',
      author_email='roopa@cumulusnetworks.com',
      url='cumulusnetworks.com',
      packages=['ifupdownaddons'],
      data_files=[('share/man/man5/',
                                ['man/ifupdown-addons-interfaces.5']),
                  ('/usr/share/ifupdownaddons/', ['addons/bridge.py',
                      'addons/ifenslave.py', 'addons/vlan.py',
                      'addons/mstpctl.py', 'addons/address.py',
                      'addons/dhcp.py', 'addons/usercmds.py',
                      'addons/ethtool.py']),
                  ('/var/lib/ifupdownaddons/', ['config/addons.conf'])])
