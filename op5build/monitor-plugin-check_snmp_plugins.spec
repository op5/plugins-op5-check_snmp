%define daemon_user monitor
%if 0%{?suse_version}
%define daemon_group www
%else
%define daemon_group apache
%endif

Name: monitor-plugin-check_snmp_plugins
Summary: Nagios compatible plugins to check linux systems over SNMP
Group: Applications/System
Version: %{op5version}
Release: %{op5release}%{?dist}
Prefix: /opt/plugins
License: GPLv2+
Source: %name-%version.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
BuildArch: i386 x86_64
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: check-devel
BuildRequires: valgrind
BuildRequires: net-snmp-devel

%description
%{summary}

%package -n monitor-plugin-check_snmp_disk
Group: Applications/System
Summary: Nagios compatible plugin to check disks over SNMP

%description -n monitor-plugin-check_snmp_disk
%{summary}

%package -n monitor-plugin-check_snmp_cpu
Group: Applications/System
Summary: Nagios compatible plugin to check cpu over SNMP
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_cpu
%{summary}

%package -n monitor-plugin-check_snmp_load_avg
Group: Applications/System
Summary: Nagios compatible plugin to check load average over SNMP
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_load_avg
%{summary}

%package -n monitor-plugin-check_snmp_memory
Group: Applications/System
Summary: Nagios compatible plugin to check memory over SNMP

%description -n monitor-plugin-check_snmp_memory
%{summary}

%package -n monitor-plugin-check_snmp_procs
Group: Applications/System
Summary: Nagios compatible plugin to check procs over SNMP

%description -n monitor-plugin-check_snmp_procs
%{summary}

%prep
%setup -q

%build
echo %{version} > .version_number
autoreconf -i
%configure --libexecdir=%{prefix}
make V=1
make V=1 check

%install
rm -rf %buildroot
mkdir -p %buildroot%prefix/
%make_install
mkdir -p %buildroot%prefix/metadata
mkdir -p %buildroot%{_localstatedir}/check_by_snmp_cpu
cp op5build/check_by_snmp_disk.metadata %buildroot%prefix/metadata/check_by_snmp_disk.metadata
cp op5build/check_by_snmp_cpu.metadata %buildroot%prefix/metadata/check_by_snmp_cpu.metadata
cp op5build/check_by_snmp_load_avg.metadata %buildroot%prefix/metadata/check_by_snmp_load_avg.metadata
cp op5build/check_by_snmp_memory.metadata %buildroot%prefix/metadata/check_by_snmp_memory.metadata
cp op5build/check_by_snmp_procs.metadata %buildroot%prefix/metadata/check_by_snmp_procs.metadata

%clean
rm -rf %buildroot

%files -n monitor-plugin-check_snmp_disk
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_disk
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_disk.metadata

%files -n monitor-plugin-check_snmp_cpu
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_cpu
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_cpu.metadata
%dir %attr(755,%{daemon_user},%{daemon_group}) %{_localstatedir}/check_by_snmp_cpu

%files -n monitor-plugin-check_snmp_load_avg
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_load_avg
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_load_avg.metadata

%files -n monitor-plugin-check_snmp_memory
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_memory
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_memory.metadata

%files -n monitor-plugin-check_snmp_procs
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_procs
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_procs.metadata

%changelog
* Fri Jul 03 2015 Robin Hagman <robin.hagman@op5.com> 0.0.1
– Initial Packaging
