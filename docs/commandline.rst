=================
Using soscleaner
=================

CLI quickstart
---------------

CLI help output
````````````````
The default way to use SOSCleaner is using the command-line application of the same name.

::

  Usage: soscleaner <OPTIONS> /path/to/sosreport

  Options:
    --version             show program's version number and exit
    -h, --help            show this help message and exit
    -l LOGLEVEL, --log_level=LOGLEVEL
                          The Desired Log Level (default = INFO) Options are
                          DEBUG, INFO, WARNING, ERROR
    -d DOMAIN, --domain=DOMAIN
                          additional domain to obfuscate (optional). use a flag
                          for each additional domain
    -f FILES, --file=FILES
                          addtional files to be analyzed in addition to or in
                          exception of sosreport
    -q, --quiet           disable output to STDOUT
    -k KEYWORD, --keyword=KEYWORD
                          additional keywords to obfuscate. use multiple times
                          for multiple keywords
    -K KEYWORDS_FILE, --keywords_file=KEYWORDS_FILE
                          line-delimited list of keywords to obfuscate
    -H HOSTNAMEPATH, --hostname-path=HOSTNAMEPATH
                          optional path to hostname file.
    -n NETWORK, --network=NETWORK
                          networks to be obfuscatedi (optional). by default it
                          looks through known routes to generate a list from a
                          sosreport
    -u USER, --user=USER  additional usernames to obfuscate in the sosreport or
                          dataset - one user per flag
    -U USERS_FILE, --users-file=USERS_FILE
                          line-delimited list of users to obfuscate
    -o DIRECTORY, --output-dir=DIRECTORY
                          Directory to store soscleaner obfuscated sosreport or
                          dataset
    -m, --macs            disable MAC address obfuscation

Using a config file
--------------------
If you find yourself having to use additional command line options a lot, you can create a config file at ``/etc/soscleaner.conf`` to handle these default values for you. A sample config file:

.. code-block:: ini
  :linenos:

  [Default]
  loglevel = debug  # the loglevel to run at, default is 'info'
  root_domain = example.com  # domain to use for obfuscation
  quiet = True # defaults to False, True suppresses output to stdout

  [DomainConfig]
  domains: example.com,foo.com,domain.com  # additional domains to obfuscate

  [KeywordConfig]
  keywords: foo,bar,some,other,words  # keywords to obfuscate
  keyword_files: keywords.txt  # keyword files to obfuscate

  [NetworkConfig]
  networks: 172.16.0.0/16  # additional networks to obfuscate

  [MacConfig]
  obfuscate_macs = False  # True/False (defaults to True) - if False MAC obfuscation will not occur

Using within a python prompt
-----------------------------
SOSCleaner is a python library at its heart, and can be used in other applications as a library. The following sample is useful when testing SOSCleaner functionality from a python prompt, like when we're writing unit tests and other such incredibly fun activities.

.. code-block:: python
   :linenos:

    from soscleaner import SOSCleaner
    cleaner = SOSCleaner()
    cleaner.loglevel = 'DEBUG'
    cleaner.origin_path, cleaner.dir_path, cleaner.session, cleaner.logfile, cleaner.uuid = cleaner._prep_environment()
    cleaner._start_logging(cleaner.logfile)

Once the ``cleaner`` instance has been created, you can begin to populate the data structures. For example:

.. code-block:: python
   :linenos:

    cleaner.hostname = 'somehost'
    cleaner.domainname = 'example.com'
    cleaner.domains.append('foo.com')
    cleaner._domains2db()
