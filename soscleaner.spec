Summary: To clean and filter sensitive data from a standard sosreport
Name: soscleaner
Version: 0.1
Release: 13%{dist}
Source0: http://people.redhat.com/jduncan/%{name}/%{name}-%{version}.tar.gz
License: GPLv2
BuildArch: noarch
Requires: python-magic
BuildRequires: python2-devel
BuildRequires: python-setuptools
Url: https://github.com/jduncan-rva/SOSCleaner

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
%{python2_sitelib}/*egg-info
%{python2_sitelib}/SOSCleaner*
%{_bindir}/soscleaner

%changelog
* Tue Jun 24 2014 Jamie Duncan <jduncan@redhat.com> 0.1-13
- added disclaimer to beginning of stdout. fixes #14

* Sat Jun 07 2014 Jamie Duncan <jduncan@redhat.com> 0.1-12
- pulled in merge from brm to fix #

* Tue Jun 03 2014 Jamie Duncan <jduncan@redhat.com> 0.1-12
- rebuilt the entire process to be inline with Fedora standards, I hope

* Tue Jun 03 2014 Jamie Duncan <jduncan@redhat.com> 0.1-11
- refactored packaging and clean up
- dropped included version of python-magic - so no RHEL 5 functionality

* Mon Nov 25 2013 Jamie Duncan <jduncan@redhat.com> 0.1-1
- initial buildout
