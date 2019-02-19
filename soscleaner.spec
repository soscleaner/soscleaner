%global srcname soscleaner

Summary: To clean and filter sensitive data from a standard sosreport
Name: soscleaner
Version: 0.3.100
Release: 1%{dist}
Source0: https://github.com/jduncan-rva/%{srcname}/archive/v%{version}.tar.gz
License: GPLv2
BuildArch: noarch
Requires: file
Requires: python-ipaddr
BuildRequires: python-setuptools
BuildRequires: file
BuildRequires: python-ipaddr
Url: https://github.com/jduncan-rva/SOSCleaner

%if 0%{?srpm_build}
%undefine dist
%endif

%description
SOSCleaner helps filter out controlled or sensitive data from an SOSReport

%prep
%autosetup -n %{srcname}-%{version}

%check
%{__python2} setup.py test

%build
%{__python2} setup.py build

%install
%py2_install

%files
%{python2_sitelib}/%{name}*
%{_bindir}/soscleaner

%changelog
* Tue Nov 27 2018 Jamie Duncan <jduncan@redhat.com> 0.3.0-2
- minor tweaks to spec file and setup.py in prep for 0.3.1
- working to get copr builds working again

* Wed Jul 6 2016 Jamie Duncan <jduncan@redhat.com> 0.3.0-1
- network refactoring for network awareness - #46
- multiple hostname optimizations and bugfixes - #51 #50 #48

* Sat Sep 13 2014 Jamie Duncan <jduncan@redhat.com> 0.2.2-1
- ability to scrub arbitrary keywords from lists - #41
- updated move to RedHatGov - #40
- stronger processing for /etc/hosts - #38
- better error announcements when user is not root - #37
- artifact location is configurable - #39

* Sun Jul 20 2014 Jamie Duncan <jduncan@redhat.com> 0.2.1-1
- cleaned up version and help output for binary - #29,#35
- made uuid random instead of time-based - #36
- allow for aritrary file scanning - #28

* Mon Jul 7 2014 Jamie Duncan <jduncan@redhat.com> 0.2-1
- added quiet mode option - fixes #25
- allow for better hostname matching - fixes #20
- updated docs - fixes #19 and #23
- class naming consistency - fixes #22
- made clean_report() more powerful and easier to create objects - fixes #21
- additional domains to be scrubbed - fixes #8

* Thu Jun 26 2014 Jamie Duncan <jduncan@redhat.com> 0.1-14
- print help statement if no sosreport is passed in. fixes #16
- updating man page to reflect new parameter workflow. updates #15
- handling issue where hostname file in sosreport does not exist. fixes #17

* Tue Jun 24 2014 Jamie Duncan <jduncan@redhat.com> 0.1-13
- added disclaimer to beginning of stdout. fixes #14
- cleaned up logging and made it a little prettier

* Sat Jun 07 2014 Jamie Duncan <jduncan@redhat.com> 0.1-12
- pulled in merge from brm to fix #

* Tue Jun 03 2014 Jamie Duncan <jduncan@redhat.com> 0.1-12
- rebuilt the entire process to be inline with Fedora standards, I hope

* Tue Jun 03 2014 Jamie Duncan <jduncan@redhat.com> 0.1-11
- refactored packaging and clean up
- dropped included version of python-magic - so no RHEL 5 functionality

* Mon Nov 25 2013 Jamie Duncan <jduncan@redhat.com> 0.1-1
- initial buildout
