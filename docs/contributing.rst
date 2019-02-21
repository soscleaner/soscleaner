.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>
.. _docs admin: jamie.e.duncan@gmail.com

=============
Contributing
=============
The easiest way to get and stay up to date is with by using the :dev_group_url:`soscleaner-dev mailing list <soscleaner-dev>`. While productions releases are announced on :dev_group_url:`soscleaner-announce <soscleaner-announce>`, most discussion happens on the dev mailing list.

Code contributions
-------------------
Of course code contributions are welcome. Please follow the standard Github PR process.


Testing
--------
SOSCleaner uses a full suite of unit tests for automated testing during each build. The CI/CD platform for SOSCleaner is :ci_cd_url:`Travis-CI <soscleaner>`. Test code coverage is ~100% and tracked on :code_coverage_url:`Coveraalls <soscleaner>`.

The most important testing, however, is real world testing. So please, contribute in that way all you want. Some examples:

  - Run soscleaner against sosreports with different plugins enabled and report back what isn't obfuscated. Report things that aren't obfuscated, plugins that increase run time significantly, or things that just don't look right to you.
  - Run different datasets through soscleaner and report things that don't work correctly. Things like:

    - packet captures
    - dumps from various platforms like kubernetes
    - whatever else you can think of

Bugs and QA
------------
Going hand in hand with Testing is reporting bugs and helping out with Quality Assurance. This is a *very* small open source project, but we do our best to test everything that we can think of. But if you have a use case that's not covered, :github_issues_url:`file a bug <soscleaner>`! It's the only way SOSCleaner will improve.

Documentation
--------------
Docs for SOSCleaner are written using `RestructuredText <http://docutils.sourceforge.net/rst.html>`__ and hosted at `Read The Docs <https://readthedocs.org>`__. If you're interested in contributing, please `docs admin`_.
