SOSCleaner
==========
Purpose
-------
SOSCleaner is intended to help users in environments that have data restrictions clean up an sosreport so it can be safely uploaded to a support group for analysis. IT IS NOT all that should be done for this process, but it intended to help with the most common and repetitive items.

What Does it Do?
----------------
* Scrubs Binary Files - Binary Files cannot easily be visually scanned. They are left out of a 'cleaned' sosreport
* IP Address Obfuscation - IPv4 addresses throughout the sosreport are obfuscated consistently throughout all files.  For example, if 192.168.100.5 is obfuscated to 10.0.0.68, it will appear as 10.0.0.68 in all files within the sosreport. This means that troubleshooting can still take place.
* Hostname Obfuscation - Hostnames are obfuscated consistently troughout all files, much like the IP Address functionality. Based on the system's hostname, if the hostname for the system in question is an FQDN (Fully Qualified Domain Name), all hostnames on that domain are obfuscated. If the hostname is NOT an FQDN, then all examples of that hostname itself are obfuscated.

Project Information
--------------------
* Maintainer - Jamie Duncan (jduncan@redhat.com)
* Source and Issues - https://github.com/jduncan-rva/soscleaner
* Git Hub Pages - http://jduncan-rva.github.io/soscleaner/
* Mailing List - If this gets off the ground
Usage Basics
------------
* As a Python Module
```
from SOSCleaner import SOSCleaner
x = SOSCleaner('path/to/sosreport/directory')
x.clean_report()
```
