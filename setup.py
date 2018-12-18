#!/usr/bin/env python
# Copyright (C) 2013  Jamie Duncan (jduncan@redhat.com)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from setuptools import setup

version = '0.3.69'
name = 'soscleaner'

setup(
    name=name,
    license='GPLv2+',
    version=version,
    description='To clean and filter sensitive data from a standard sosreport or any data files',
    author='Jamie Duncan',
    author_email='jduncan@redhat.com',
    url='https://github.com/jduncan-rva/SOSCleaner',
    download_url="https://github.com/jduncan-rva/soscleaner/releases/tags/%s" % version,
    maintainer='Jamie Duncan',
    maintainer_email='jduncan@redhat.com',
    long_description='%s is an application to help obfuscate sensitive data from a standard sosreport' % name,
    install_requires=[
        'python_magic',
        'ipaddr',
    ],
    package_dir={'': 'soscleaner'},
    test_suite='test_soscleaner',
    py_modules=['soscleaner'],
    scripts=['scripts/soscleaner'],
    data_files=[
            ('/usr/share/doc/%s-%s' % (name, version), ['LICENSE']),
            ('/usr/share/man/man8', ['doc/soscleaner.8.gz']),
        ],
    )
