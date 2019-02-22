.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>
.. _docs admin: jamie.e.duncan@gmail.com

=============
Contributing
=============
The easiest way to get and stay up to date is with by using the :dev_group_url:`soscleaner-dev mailing list <soscleaner-dev>`. While productions releases are announced on :dev_group_url:`soscleaner-announce <soscleaner-announce>`, most discussion happens on the dev mailing list.

Code contributions
-------------------
Of course code contributions are welcome. Please follow the standard Github PR process.

Commit format
--------------
We've just started using `gitchangelog <https://pypi.org/project/gitchangelog/>`__ to format git commits and generate a changelog. Please follow their example file like below:

::

  Format:

  ACTION: [AUDIENCE:] COMMIT_MSG [!TAG ...]

  Description:
  ACTION is one of 'chg', 'fix', 'new'

      Is WHAT the change is about.

      'chg' is for refactor, small improvement, cosmetic changes...
      'fix' is for bug fixes
      'new' is for new features, big improvement

  AUDIENCE is optional and one of 'dev', 'usr', 'pkg', 'test', 'doc'

      Is WHO is concerned by the change.

      'dev'  is for developpers (API changes, refactors...)
      'usr'  is for final users (UI changes)
      'pkg'  is for packagers   (packaging changes)
      'test' is for testers     (test only related changes)
      'doc'  is for doc guys    (doc only changes)

  COMMIT_MSG is ... well ... the commit message itself.

  TAGs are additionnal adjective as 'refactor' 'minor' 'cosmetic'

      They are preceded with a '!' or a '@' (prefer the former, as the
      latter is wrongly interpreted in github.) Commonly used tags are:

      'refactor' is obviously for refactoring code only
      'minor' is for a very meaningless change (a typo, adding a comment)
      'cosmetic' is for cosmetic driven change (re-indentation, 80-col...)
      'wip' is for partial functionality but complete subfunctionality.

  Example:

  new: usr: support of bazaar implemented
  chg: re-indentend some lines !cosmetic
  new: dev: updated code to be compatible with last version of killer lib.
  fix: pkg: updated year of licence coverage.
  new: test: added a bunch of test around user usability of feature X.
  fix: typo in spelling my name in comment. !minor

  Please note that multi-line commit message are supported, and only the
  first line will be considered as the "summary" of the commit message. So
  tags, and other rules only applies to the summary.  The body of the commit
  message will be displayed in the changelog without reformatting.


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
