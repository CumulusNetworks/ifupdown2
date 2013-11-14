from distutils.core import setup

setup(name='ifupdown2',
      version='0.1',
      description = "ifupdown 2",
      author='Roopa Prabhu',
      author_email='roopa@cumulusnetworks.com',
      url='cumulusnetworks.com',
      package_dir = {'ifupdown' : 'pkg'},
      packages=['ifupdown'],
      scripts = ['sbin/ifupdown'],
      data_files=[('share/man/man8/',
                      ['man/ifup.8', 'man/ifdown.8', 'man/ifquery.8']),
                  ('/etc/init.d/',
                      ['init.d/networking']),
                  ('/sbin/', ['sbin/ifupdown']),
                  ('/usr/share/doc/ifupdown/examples/',
                      ['docs/examples/interfaces'])]
      )
