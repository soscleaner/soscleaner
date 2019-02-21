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
Source Code       :github_url:`Github <soscleaner>`
Issues            :github_issues_url:`Github <soscleaner>`
Project Tracking  :github_project_url:`Github <1>`
RPMs              :rpm_url:`Fedora Copr <soscleaner>`
Python Packages   :pypi_url:`PyPi <soscleaner>`
Code Coverage     :code_coverage_url:`Coveraalls <soscleaner>`
CI/CD             :ci_cd_url:`Travis-CI <soscleaner>`
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
