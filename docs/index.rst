.. SOSCleaner documentation master file, created by
   sphinx-quickstart on Mon Feb 11 20:58:39 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. sectionauthor:: Jamie Duncan <jamie.e.duncan@gmail.com>

===========
SOSCleaner
===========

Soscleaner is an open-source tool to take an `sosreport <https://access.redhat.com/solutions/3592>`__, or any arbitrary dataset, and sanely obfuscate potentially sensitive information so it can be shared with outside parties for support. An unaltered copy of the data is maintained by the user so data can be mapped and suggestions supplied by a support team can still be actionable, even without the sensitive information.

.. toctree::
   :maxdepth: 2
   :numbered:
   :Caption: Index
   :name: mastertoc

   intro
   network-obfuscation
   hostname-obfuscation
   mac-address-obfuscation
   keyword-obfuscation
   user-obfuscation
   contributing
   commandline
   docstrings
   license
