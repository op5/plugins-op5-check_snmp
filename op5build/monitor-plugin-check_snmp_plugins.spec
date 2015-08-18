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

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: check-devel
BuildRequires: valgrind
BuildRequires: net-snmp-devel
# op5-naemon-devel is needed by check_snmp_procs
BuildRequires: op5-naemon-devel

%description
%{summary}

%package -n monitor-plugin-check_snmp_disk
Group: Applications/System
Summary: Nagios compatible plugins to check disks over SNMP

%description -n monitor-plugin-check_snmp_disk
%{summary}

%package -n monitor-plugin-check_snmp_cpu
Group: Applications/System
Summary: Nagios compatible plugins to check cpu over SNMP

%description -n monitor-plugin-check_snmp_cpu
%{summary}

%package -n monitor-plugin-check_snmp_memory
Group: Applications/System
Summary: Nagios compatible plugins to check memory over SNMP

%description -n monitor-plugin-check_snmp_memory
%{summary}

%package -n monitor-plugin-check_snmp_procs
Group: Applications/System
Summary: Nagios compatible plugins to check procs over SNMP
Requires: op5-naemon

%description -n monitor-plugin-check_snmp_procs
%{summary}

%prep
%setup -q

%build
echo %{version} > .version_number
autoreconf -i
%configure --libexecdir=%{prefix}
make V=1

%install
rm -rf %buildroot
mkdir -p %buildroot%prefix/
%make_install
mkdir -p %buildroot%prefix/metadata
cp op5build/check_snmp_disk.metadata %buildroot%prefix/metadata/check_snmp_disk.metadata
cp op5build/check_snmp_cpu.metadata %buildroot%prefix/metadata/check_snmp_cpu.metadata
cp op5build/check_snmp_memory.metadata %buildroot%prefix/metadata/check_snmp_memory.metadata
cp op5build/check_snmp_procs.metadata %buildroot%prefix/metadata/check_snmp_procs.metadata

%clean
rm -rf %buildroot

%files -n monitor-plugin-check_snmp_disk
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_snmp_disk
%attr(644,root,root) %{prefix}/metadata/check_snmp_disk.metadata

%files -n monitor-plugin-check_snmp_cpu
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_snmp_cpu
%attr(644,root,root) %{prefix}/metadata/check_snmp_cpu.metadata

%files -n monitor-plugin-check_snmp_memory
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_snmp_memory
%attr(644,root,root) %{prefix}/metadata/check_snmp_memory.metadata

%files -n monitor-plugin-check_snmp_procs
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_snmp_procs
%attr(644,root,root) %{prefix}/metadata/check_snmp_procs.metadata

%changelog
* Fri Jul 03 2015 Robin Hagman <robin.hagman@op5.com> 0.0.1
– Initial Packaging