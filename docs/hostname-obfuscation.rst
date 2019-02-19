.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>

=============================
Host and domain obfuscation
=============================

Host and domain obfuscation overview
------------------------------------
SOSCleaner has completely re-written the host and domain obfuscation engine for the 0.4.0 release. In previous releases, all hostnames were obfuscated to `obfuscateddomain.com`. This could be confusing when troubleshooting issues across multiple domains.

Filing hostname bugs
```````````````````````
Please open hostname obfuscation bugs using the :github_issues_url:`hostname obfuscation bug template <new?assignees=&labels=Obfuscation+Engine%2C+host+and+domain+obfuscation&template=hostname-obfuscation-bug.md&title=%5Bbug%5D%5Bhostnames%5D>`. This will ensure the proper labels are applied and we can move forward quickly with your issue.

Domain database
--------------------
Domains

Adding domains to the domain database
``````````````````````````````````````

Obfuscating subdomains
```````````````````````

Hostname database
-------------------



Obfuscation workflow
---------------------

.. graphviz::

  digraph G {
          fontname = "Bitstream Vera Sans"
          fontsize = 12

          node [
                  fontname = "Bitstream Vera Sans"
                  fontsize = 12
                  shape = "record"
          ]

          edge [
                  fontname = "Bitstream Vera Sans"
                  fontsize = 12
          ]

          clean_line [
            label = "{self._clean_line|\l + line: string\l + file: string\l}"
          ]

          sub_hostname [
            label = "{self._sub_hostname|\l + line: string}"
          ]

          clean_line -> sub_hostname
  }
