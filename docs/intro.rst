.. the front of the index page

============
Overview
============

Purpose
-------

The goal of soscleaner's documentation is to provide not only insight into how the code works, but also the logic behind what is obfuscated and why.

Important Links
----------------

Soscleaner's build processes are all completely available online.

================  ====================
Source Code       `Github <https://github.com/jduncan-rva/soscleaner>`__
Issues            `Github <https://github.com/jduncan-rva/soscleaner/issues>`__
Project Tracking  `Github <https://github.com/jduncan-rva/soscleaner/projects/1>`__
RPMs              `Fedora Copr <https://copr.fedorainfracloud.org/coprs/jduncan/soscleaner/>`__
Python Packages   `PyPi <https://pypi.org/project/soscleaner/>`__
Code Coverage     `Coveralls <https://coveralls.io/github/jduncan-rva/soscleaner>`__
CI/CD             `Travis CI <https://travis-ci.com/jduncan-rva/soscleaner>`__
================  ====================

Obfuscated data types
----------------------

Hostnames and Domainnames
``````````````````````````
Soscleaner obfuscates all domains specified by the -d option when executed, as well as the domain name of the given host in an sosreport. Subdomains for these are automatically obfuscated as unique objects.

IPv4 addresses
```````````````
IPv4 addresses are obfuscated, with each network being assigned a unique obfuscated counterpart with the same subnet mask. More information can be found at :ref:`Network Obfuscation`

User-specified keywords
````````````````````````
Users can specify a list of keywords at runtime to find and obfuscate.

System Usernames
`````````````````
Users can be supplied in a line-delimited file. The contents of the ``last`` file in an sosreport is also incorporated into this obfuscation.

MAC addresses
``````````````
MAC addresses are randomized consistently throughout an entire sosreport or any dataset.
