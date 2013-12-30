SOSCleaner
==========
Purpose
-------
SOSCleaner is intended to help users in environments that have data restrictions clean up an sosreport so it can be safely uploaded to a support group for analysis. IT IS NOT all that should be done for this process, but it intended to help with the most common and repetitive items.

What Does it Do?
----------------
* Scrubs Binary Files - Binary Files cannot easily be visually scanned. They are left out of a 'cleaned' sosreport
* IP Address Obfuscation - IPv4 addresses in the sosreport are obfuscated consistently throughout all files.  For example, if 192.168.100.5 is obfuscated to 10.0.0.68, it will appear as 10.0.0.68 in all files within the sosreport. This means that troubleshooting can still take place.
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

* If intalling the RPM and/or using the executable 

```
$ /usr/bin/soscleaner --help
Usage: soscleaner -s [-l -c -r]

Options:
  -h, --help            show this help message and exit
  -l LOGLEVEL, --log_level=LOGLEVEL
                        The Desired Log Level (default = INFO) Options are
                        DEBUG, INFO, WARNING, ERROR
  -r, --reporting       Create CSV output for IP and Hostname databases
  -s SOSREPORT, --sosreport=SOSREPORT
                        The SOSReport that is to be cleaned

```

How Do I See The Obfuscated Data?
---------------------------------
The data is available from within the Python class, and as an option passed into the executable script.

* If accessing the Python class directly 

```
from SOSCleaner import SOSCleaner
x = SOSCleaner('path/to/sosreport/directory')
x.clean_report()

x.ip_db
{'192.168.1.4':'10.10.10.123', ...}

x.hn_db
{'server1.myserverfarm.com':'host0.example.com'}
```

* If passing the -r option to soscleaner

```
$ sudo soscleaner -s ~/sosreport.tar.gz -r
[sudo] password for jduncan:
Working Directory - /tmp/soscleaner-20131209111927
$ ll /tmp/soscleaner*
-rw-r--r--. 1 root root      54 Dec  9 06:19 /tmp/soscleaner-20131209111927-hostname.csv
-rw-r--r--. 1 root root    3442 Dec  9 06:19 /tmp/soscleaner-20131209111927-ip.csv
-rw-r--r--. 1 root root    1676 Dec  9 06:20 /tmp/soscleaner-20131209111927.log
-rw-r--r--. 1 root root 4834715 Dec  9 06:20 /tmp/soscleaner-20131209111927.tar.gz

```

* soscleaner-<id>-hostname.csv is a csv of hostnames that have been obfuscated
* soscleaner-<id>-ip.csv is a csv of ip addresses that have been obfuscated
 
What Is Created?
----------------

* soscleaner-<id>.log is a log of all events that occurred
* soscleaner-<id>.tar.gz is a gzip'd tarball containing the obfuscated sosreport
* soscleaner-<id>-hostname.csv is a csv of hostnames that have been obfuscated (when using the -r option)
* soscleaner-<id>-ip.csv is a csv of ip addresses that have been obfuscated (when using the -r option)
