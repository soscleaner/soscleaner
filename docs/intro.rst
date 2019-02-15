.. the front of the index page

============
Overview
============

Purpose
-------

The goal of soscleaner's documentation is to provide not only insight into how the code works, but also the logic behind what is obfuscated and why.

Current obfuscations
--------------------
:Hostnames and Domainnames: Soscleaner obfuscates all domains specified by the -d option when executed, as well as the domain name of the given host in an sosreport. Subdomains for these are automatically obfuscated as unique objects.
:IPv4 addresses: IPv4 addresses are obfuscated, with each network being assigned a unique obfuscated counterpart with the same subnet mask. More information can be found at :ref:`Network Obfuscation Information`
:User-specified keywords: Users can specify a list of keywords at runtime to find and obfuscate
:System Usernames: Users can be supplied in a line-delimited file. The contents of the ``last`` file in an sosreport is also incorporated into this obfuscation.
:MAC addresses: MAC addresses are randomized consistently throughout an entire sosreport or any dataset.
