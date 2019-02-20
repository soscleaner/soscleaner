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
Domains that are obfuscation are maintained in ``self.dn_db``, a dictionary, in ``{'original_domain1': 'obfuscated_domain1',...}`` format. Domains are obfuscated in addition to full hostnames because the domain in a configuration or in a log often makes a big difference in fixing or finding an issue.

Adding domains to the domain database
``````````````````````````````````````
If obfuscating an sosreport, the `FQDN <https://en.wikipedia.org/wiki/Fully_qualified_domain_name>`__ of the report host is split between host and domain, and the domain is automatically added to ``self.dn_db``.

Additional domains can be slated for obfuscation using the ``-d`` parameter on the command line. Multiple domains can be added by using multiple ``-d`` parameters, for example:

``# soscleaner -d example.com -d foo.com -d someotherdomain.com mysosreport.tar.xz``

would add ``example.com``, ``foo.com``, and ``someotherdomain.com`` to ``self.domains``.

Default domains
````````````````
In addition to the host's domainname and any additional domains, soscleaner automatically adds ``redhat.com`` and ``localhost.localdomain`` to ``self.dn_db``.

Processing domains
```````````````````
After the desired entries are added to ``self.domains`` using the above processes, ``self._domains2db()`` is called by, ``self.clean_report()`` to add all the entries to ``self.dn_db`` with their obfuscated counterparts.

Obfuscating subdomains
```````````````````````
Each line in each file processed by soscleaner is processed by ``self._clean_line()``, which calls ``self._sub_hostname()``. This function uses a regular expression to match anything in the current line that is potentially a domain.

``potential_hostnames = re.findall(r'\b[a-zA-Z0-9-\.]{1,200}\.[a-zA-Z]{1,63}\b', line)``

The matches in ``potential_hostnames`` are validated againt the list of known domains using ``self._validate_domainname()``. If the potential domain turns out to be a subdomain of a known domain, the newly matched subdomain is added to ``self.dn_db`` using ``self._dn2db()``. For example, if ``example.com`` is a known domain, and a potential match is ``apps.example.com``, ``apps.example.com`` will be added to the domain database and used for obfuscation going forward.

Hostname database
-------------------
One of the primary functions of SOSCleaner is to obfuscate hostnames when they're found in a file beyond just the hostname of the server itself. To aid in troubleshooting, domain names are obfuscated separately. This is to keep the integrity of the data, even though the data is being obfuscated. Obfuscated hostnames are tracked in ``self.hn_db``, a dictionary, using the ``{'original_host1': 'obfuscated_host1',...}`` format.

Default hostnames
``````````````````
If processing a sosreport the hostname of the sosreport host is added to ``self.hn_db``.

Adding hostnames
``````````````````
When a hostname is found that is a member of a known domain in ``self.dn_db``, it is obfuscated as ``hostX.obfuscatedomainY.com``, with X being an incremented number equal to the current total of found hosts, ``self.hostname_count``. Y is equal to the unique value assigned to the corresponding domain.

Host short name
````````````````
There are many occurrences of the host-only part of the server's hostname in an sosreport and log files in general. These are obfuscated explicitly in ``self._sub_hostname()``. When an soscleaner run is started, the host's hostname is stored as ``self.hostname``. This is explicitly searched for in each line by soscleaner.

Short domains
``````````````
There are a few short domain names that soscleaner obfuscates. By default, ``localhost`` and ``localdomain`` are added to ``self.short_domains``, and are explicitly searched out and replaced in each line.

.. admonition:: Short domains aren't editable

  Currently there isn't a way to add additional entries to ``self.short_domains``.
