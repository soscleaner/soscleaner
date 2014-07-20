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

version = '0.2.1'
name = 'soscleaner'

setup(
    name=name,
    license = 'GPLv2',
    version=version,
    description='To clean and filter sensitive data from a standard sosreport',
    author='Jamie Duncan',
    author_email='jduncan@redhat.com',
    url='https://github.com/jduncan-rva/SOSCleaner',
    maintainer='Jamie Duncan',
    maintainer_email = 'jduncan@redhat.com',
    long_description='%s is an application to help obfuscate sensitive data from a standard sosreport' % name,
    package_dir={'': 'src'},
    # packages=['python_magic'],
    py_modules=['soscleaner'],
    test_suite = 'tests',
    scripts = ['scripts/soscleaner'],
    data_files=[
            ('/usr/share/doc/%s-%s' % (name,version), ['doc/LICENSE']),
            ('/usr/share/man/man8', ['doc/soscleaner.8.gz']),
        ],
    )


