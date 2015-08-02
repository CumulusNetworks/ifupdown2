from distutils.core import setup

setup(name='ifupdown2',
      version='1.0',
      description = "ifupdown 2",
      author='Roopa Prabhu',
      author_email='roopa@cumulusnetworks.com',
      url='cumulusnetworks.com',
      packages=['ifupdown', 'ifupdownaddons'],
      data_files=[('/etc/network/ifupdown2/',
                      ['config/ifupdown2.conf']),
                  ('/etc/bash_completion.d/', ['completion/ifup']),
                  ('/usr/share/ifupdown2/addons', ['addons/bridge.py',
                      'addons/ifenslave.py', 'addons/vlan.py',
                      'addons/mstpctl.py', 'addons/address.py',
                      'addons/dhcp.py', 'addons/usercmds.py',
                      'addons/ethtool.py', 'addons/loopback.py',
                      'addons/addressvirtual.py', 'addons/vxlan.py',
                      'addons/bridgevlan.py']),
                  ('/etc/network/ifupdown2/', ['config/addons.conf']),
                  ('/var/lib/ifupdown2/policy.d/', []),
                  ('/etc/network/ifupdown2/policy.d/', [])
                  ]
      )
