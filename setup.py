from distutils.core import setup
from distutils.command.install import install as _install

import os


def _mkdir(path):
    try:
        os.mkdir(path)
    except:
        pass


def _symlink(dest, source):
    try:
        os.symlink(source, dest)
    except:
        pass


def _post_install(param):
    _mkdir('/etc/network/interfaces.d/')
    _mkdir('/var/lib/ifupdown2/policy.d/')
    _mkdir('/var/lib/ifupdown2/hooks/')
    _symlink('/sbin/ifup', '/usr/share/ifupdown2/ifupdown2')
    _symlink('/sbin/ifdown', '/usr/share/ifupdown2/ifupdown2')
    _symlink('/sbin/ifquery', '/usr/share/ifupdown2/ifupdown2')
    _symlink('/sbin/ifreload', '/usr/share/ifupdown2/ifupdown2')


class install(_install):
    def run(self):
        _install.run(self)
        self.execute(_post_install, (self.install_lib,),
                     msg="Running post install task")


class uninstall(_install):
    def run(self):
        import subprocess
        try:
            subprocess.call("rm -rf /usr/share/ifupdown2/", shell=True)
        except:
            pass


setup(name='ifupdown2',
      version='1.1',
      description='ifupdown 2',
      license='LICENSE',
      author='Roopa Prabhu',
      author_email='roopa@cumulusnetworks.com',
      maintainer='Julien Fortin',
      maintainer_email='julien@cumulusnetworks.com',
      url='https://github.com/CumulusNetworks/ifupdown2/',
      download_url='https://github.com/CumulusNetworks/ifupdown2/tarball/pypi-release-01',
      packages=['ifupdown', 'ifupdownaddons'],
      data_files=[('/etc/network/ifupdown2/',
                   ['config/ifupdown2.conf']),
                  ('/etc/bash_completion.d/', ['completion/ifup']),
                  ('/usr/share/ifupdown2/addons/', ['addons/bridge.py',
                                                    'addons/bond.py',
                                                    'addons/vlan.py',
                                                    'addons/mstpctl.py',
                                                    'addons/address.py',
                                                    'addons/dhcp.py',
                                                    'addons/usercmds.py',
                                                    'addons/ethtool.py',
                                                    'addons/addressvirtual.py',
                                                    'addons/vxlan.py',
                                                    'addons/link.py',
                                                    'addons/vrf.py',
                                                    'addons/bridgevlan.py',
                                                    'addons/batman_adv.py']),
                  ('/usr/share/ifupdown2/nlmanager/',
                   ['nlmanager/nllistener.py',
                    'nlmanager/nlmanager.py',
                    'nlmanager/nlpacket.py',
                    'nlmanager/__init__.py',
                    'nlmanager/README']),
                  ('/usr/share/ifupdown2/ifupdown/', ['ifupdown/exceptions.py',
                                                      'ifupdown/graph.py',
                                                      'ifupdown/iface.py',
                                                      'ifupdown/iff.py',
                                                      'ifupdown/ifupdownbase.py',
                                                      'ifupdown/ifupdownconfig.py',
                                                      'ifupdown/ifupdownflags.py',
                                                      'ifupdown/ifupdownmain.py',
                                                      'ifupdown/netlink.py',
                                                      'ifupdown/networkinterfaces.py',
                                                      'ifupdown/policymanager.py',
                                                      'ifupdown/scheduler.py',
                                                      'ifupdown/statemanager.py',
                                                      'ifupdown/template.py',
                                                      'ifupdown/utils.py']),
                  ('/usr/share/ifupdown2/ifupdownaddons/',
                   ['ifupdownaddons/bondutil.py',
                    'ifupdownaddons/bridgeutils.py',
                    'ifupdownaddons/cache.py',
                    'ifupdownaddons/dhclient.py',
                    'ifupdownaddons/iproute2.py',
                    'ifupdownaddons/modulebase.py',
                    'ifupdownaddons/mstpctlutil.py',
                    'ifupdownaddons/systemutils.py',
                    'ifupdownaddons/utilsbase.py']),
                  ('/usr/share/ifupdown2/', ['sbin/ifupdown2']),
                  ('/usr/share/ifupdown2/sbin/', ['sbin/start-networking']),
                  ('/etc/network/ifupdown2/', ['config/addons.conf']),
                  ('/etc/network/ifupdown2/', ['config/addons.conf']),
                  ('/var/lib/ifupdown2/policy.d/', []),
                  ('/etc/network/ifupdown2/policy.d/', [])],
      cmdclass={
          'install': install,
          'uninstall': uninstall,
          'remove': uninstall
      }
      )
