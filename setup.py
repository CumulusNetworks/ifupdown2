import errno
import os
import subprocess

from setuptools import find_packages, setup
from setuptools.command.install import install

import warnings

DATA_FILES = [('/etc/network/ifupdown2/',
               ['config/ifupdown2.conf']),
              ('/etc/bash_completion.d/',
               ['completion/ifup']),
              ('/usr/share/ifupdown2/addons/',
               ['addons/bridge.py',
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
                'addons/bridgevlan.py']),
              ('/usr/share/ifupdown2/nlmanager/',
               ['nlmanager/nllistener.py',
                'nlmanager/nlmanager.py',
                'nlmanager/nlpacket.py',
                'nlmanager/__init__.py',
                'nlmanager/README']),
              ('/etc/network/ifupdown2/', ['config/addons.conf']),
              ('/var/lib/ifupdown2/policy.d/', []),
              ('/etc/network/ifupdown2/policy.d/', []),
              ('/usr/share/ifupdown2/',
               ['sbin/ifupdown2',
                'sbin/ifupdown2d']),
              ('/usr/share/ifupdown2/sbin/',
               ['sbin/start-networking'])
              ]

INSTALL_REQUIRES = [
    'docutils>=0.12',
    'argcomplete==0.8.1',
    'ipaddr==2.1.11',
]


def force_symlink(file1, file2):
    try:
        os.symlink(file1, file2)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(file2)
            os.symlink(file1, file2)


class InstallCommand(install):
    user_options = install.user_options + [
        ('overwrite-sbin', None, "(WARNING) Overwrite files in /sbin"),
        ('purge-ifupdown', None, "(WARNING) Purge 'ifupdown' package")
    ]

    boolean_options = install.boolean_options + [
        'overwrite-sbin', 'purge-ifupdown'
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.overwrite_sbin = False
        self.purge_ifupdown = False

    def do_install_sbin(self):
        """Overwrite files in /sbin """
        for suffix in ('up', 'down', 'reload', 'query'):
            force_symlink('/usr/share/ifupdown2/ifupdown2',
                          '/sbin/if' + suffix)

    def do_purge_ifupdown(self):
        """Purge original ifupdown package"""
        try:
            subprocess.call(['apt-get', 'purge', '-y', '-q', 'ifupdown'])
        except OSError as e:
            emsg = "Could not purge 'ifupdown'."
            if e.errno == errno.EPERM:
                emsg = "You need root permissions."
            warnings.warn(emsg)

    def run(self):
        install.run(self)
        if self.purge_ifupdown:
            self.do_purge_ifupdown()
        if self.overwrite_sbin:
            self.do_install_sbin()


setup(name='ifupdown2',
      version='1.1',
      description="ifupdown 2",
      author='Roopa Prabhu',
      author_email='roopa@cumulusnetworks.com',
      url='cumulusnetworks.com',
      packages=find_packages(),
      data_files=DATA_FILES,
      setup_requires=['setuptools'],
      install_requires=INSTALL_REQUIRES,
      cmdclass={'install': InstallCommand},
      )
