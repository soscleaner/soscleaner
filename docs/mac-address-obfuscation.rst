.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>

=======================
MAC Address obfuscation
=======================

MAC address overview
---------------------
MAC addresses are found in a line using the ``re.compile(ur'(?:[0-9a-fA-F]:?){12}')`` Python regular expression. For each match, a random valid MAC address is generated and saved in ``self.mac_db`` using the ``{'mac_address': 'obfuscated_mac_address', ...}`` format.

..admonition:: False Positives

  This is a new feature for the 0.4.0 release of soscleaner. Please report any issues you find regarding false-positives!


Filing MAC bugs
----------------
Please open MAC obfuscation bugs using the :github_issues_url:`MAC obfuscation bug template <new?assignees=&labels=MAC+obfuscation%2C+Obfuscation+Engine&template=mac-obfuscation-bug.md&title=%5BBUG%5D%5Bmac%5D>`. This will ensure the proper labels are applied and we can move forward quickly with your issue.

MAC address report
-------------------
At the conclusion of a soscleaner run, the supplied MAC address mappings are recorded in ``self.report_dir/<SESSION_ID>-mac.csv``. If an SOSCleaner session fails to complete, this report isn't created.
