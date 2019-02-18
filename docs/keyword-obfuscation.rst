.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>

===================
Keyword obfuscation
===================

SOSCleaner can take any arbitrary list of keywords and effectively obfuscate them in a sosreport or in a dataset. This can be extremely useful if you have particular key values, parameters from your IDP (Identity Provider). These are only matched against `whole words <https://www.regular-expressions.info/wordboundaries.html>`__.

Filing keyword bugs
-------------------
Please open keyword obfuscation bugs using the :github_issues_url:`keyword obfuscation bug template <new?assignees=&labels=Exception+Engine%2C+keyword+obfuscation&template=keyword-obfuscation-bug.md&title=%5BBUG%5D%5Bkeywords%5D>`. This will ensure the proper labels are applied and we can move forward quickly with your issue.

How soscleaner handles keywords
--------------------------------
The obfuscation engine for keywords is straightforward. Using the `-k` option on the command line supplies a line-delimited file of keywords. These keywords are then matched against whole words in every line of every file in an sosreport or dataset.

Keyword report
---------------
At the conclusion of a soscleaner run, the supplied keyword mappings are recorded in ``self.report_dir/<SESSION_ID>-kw.csv``. If an SOSCleaner session fails to complete, this report isn't created.
