%define name SOSCleaner
%define version 0.1
%define unmangled_version 0.1
%define release 1

Summary: To clean and filter sensitive data from a standard sosreport
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: GPLv2
Group: Applications
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Jamie Duncan <jduncan@redhat.com>
Packager: Jamie Duncan <jduncan@redhat.com>
Url: https://github.com/jduncan-rva/SOSCleaner

%description
SOSCleaner is an application to filer out sensitive and un-scan-able data from a standard sosreport

%prep
%setup -n %{name}-%{unmangled_version}

%build
python setup.py build

%install
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc README README.md LICENSE

%changelog
* Mon Nov 25 2013 Jamie Duncan <jduncan@redhat.com> 0.1-1
- initial buildout
