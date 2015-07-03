%define debug_package %{nil}

Version: %{op5version}
Release: %{op5release}%{?dist}
URL: https://github.com/c-kr/check_json
Prefix: /opt/plugins
License: GPLv2+
Group: Applications/System
Source: %name-%version.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
BuildArch: i386 x86_64
Name: monitor-plugin-check_snmp_plugins
Summary: Nagios compatible plugins to check linux systems over SNMP

%package -n monitor-plugin-check_snmp_disk
Summary: Nagios compatible plugins to check disks over SNMP

Requires: net-snmp-libs
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: check-devel
BuildRequires: valgrind
BuildRequires: net-snmp-devel

BuildRequires: op5-phpunit
%if 0%{?suse_version}
BuildRequires: php53-posix
%else
BuildRequires: php-process
%endif

%description
%{summary}

%description -n monitor-plugin-check_snmp_disk
%{summary}

%prep
%setup -q

%build
echo %{version} > .version_number
autoreconf -i
%configure --libexecdir=%{prefix}
make V=1

%check
%__make check

%install
rm -rf %buildroot
mkdir -p %buildroot%prefix/
%make_install
mkdir -p %buildroot%prefix/metadata
#cp metadata/check_snmp_disk.metadata %buildroot%prefix/metadata/check_snmp_disk.metadata

%clean
rm -rf %buildroot

%files -n monitor-plugin-check_snmp_disk
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_snmp_disk
#%attr(644,root,root) %{prefix}/metadata/check_snmp_disk.metadata

%changelog
* Fri Jul 03 2015 Robin Hagman <robin.hagman@op5.com> 0.0.1
– Initial Packaging
