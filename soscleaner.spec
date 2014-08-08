%{!?__python2: %global __python2 /usr/bin/python2}
%global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")

Summary: To clean and filter sensitive data from a standard sosreport
Name: soscleaner
Version: 0.2.1
Release: 1%{dist}
Source0: http://people.redhat.com/jduncan/%{name}/%{name}-%{version}.tar.gz
License: GPLv2
BuildArch: noarch
Requires: python-magic
BuildRequires: python2-devel
BuildRequires: python-setuptools
Url: https://github.com/RedHatGov/SOSCleaner

%description
SOSCleaner helps filter out controlled or sensitive data from an SOSReport

%prep
%setup -q -n %{name}-%{version}

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --root=$RPM_BUILD_ROOT

%files
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/*
%{_mandir}/man8/%{name}.8*
%{python2_sitelib}/%{name}*
%{_bindir}/soscleaner

%changelog
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
