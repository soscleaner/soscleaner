.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>

================
User obfuscation
================

User obfuscation overview
--------------------------
When obfuscating an sosreport, soscleaner uses the usernames in ``sos_commands/last/lastlog`` to populate ``self.user_db``. This database is stored as a dictionary using a ``{'user': 'obfuscated_user', ...}`` format. ``self.user_db`` is populated using ``self._process_users_file()`` called early in ``self.clean_report()``. Each line is passed into ``self._sub_username()`` in ``self._clean_line()`` as part of the obfuscation process.

What constitutes a username?
`````````````````````````````
Usernames are anything in the ``Username`` column of ``sos_commands/last/lastlog``:

::

  Username         Port     From             Latest
  root             pts/0    lnyce80te.elab.c Fri Feb 15 09:40:56 -0600 2019
  bin                                        **Never logged in**
  daemon                                     **Never logged in**
  adm                                        **Never logged in**
  lp                                         **Never logged in**
  sync                                       **Never logged in**
  shutdown                                   **Never logged in**

SOSCleaner does ignore a few common system users: ``('reboot', 'shutdown', 'wtmp')``.

..admonition:: Adding usernames after soscleaner starts

  Currently usernames can't be added to soscleaner after the run starts.

Filing user bugs
```````````````````````
Please open user obfuscation bugs using the :github_issues_url:`user obfuscation bug template <new?assignees=&labels=Exception+Engine%2C+username+obfuscation&template=username-obfuscation-bug.md&title=%5BBUG%5D%5Busers%5D>`. This will ensure the proper labels are applied and we can move forward quickly with your issue.

Username report
---------------
At the conclusion of a soscleaner run, the supplied username mappings are recorded in ``self.report_dir/<SESSION_ID>-username.csv``. If an SOSCleaner session fails to complete, this report isn't created.
