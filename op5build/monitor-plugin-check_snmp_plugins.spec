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
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_disk
%{summary}

%package -n monitor-plugin-check_snmp_disk_io
Group: Applications/System
Summary: Nagios compatible plugin to check disks read/write over SNMP
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_disk_io
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
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_memory
%{summary}

%package -n monitor-plugin-check_snmp_procs
Group: Applications/System
Summary: Nagios compatible plugin to check procs over SNMP
Requires: op5-monitor-user

%description -n monitor-plugin-check_snmp_procs
%{summary}

%package -n monitor-plugin-check_snmp_extend
Group: Applications/System
Summary: Nagios compatible plugin to run plugins over SNMP

%description -n monitor-plugin-check_snmp_extend
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
mkdir -p %buildroot/opt/monitor/op5/pnp/templates.dist
mkdir -p %buildroot%prefix/metadata
mkdir -p %buildroot%{_localstatedir}/check_by_snmp_cpu
mkdir -p %buildroot%{_localstatedir}/check_by_snmp_disk_io
cp op5build/check_by_snmp_disk.metadata %buildroot%prefix/metadata/check_by_snmp_disk.metadata
cp op5build/check_by_snmp_disk_io.metadata %buildroot%prefix/metadata/check_by_snmp_disk_io.metadata
cp op5build/check_by_snmp_cpu.metadata %buildroot%prefix/metadata/check_by_snmp_cpu.metadata
cp op5build/check_by_snmp_load_avg.metadata %buildroot%prefix/metadata/check_by_snmp_load_avg.metadata
cp op5build/check_by_snmp_memory.metadata %buildroot%prefix/metadata/check_by_snmp_memory.metadata
cp op5build/check_by_snmp_procs.metadata %buildroot%prefix/metadata/check_by_snmp_procs.metadata
cp op5build/check_by_snmp_extend.metadata %buildroot%prefix/metadata/check_by_snmp_extend.metadata
cp op5build/pnp/check_by_snmp_cpu.php %buildroot/opt/monitor/op5/pnp/templates.dist/check_by_snmp_cpu.php
cp op5build/pnp/check_by_snmp_memory.php %buildroot/opt/monitor/op5/pnp/templates.dist/check_by_snmp_memory.php
cp op5build/pnp/check_by_snmp_disk.php %buildroot/opt/monitor/op5/pnp/templates.dist/check_by_snmp_disk.php
cp op5build/pnp/check_by_snmp_load_avg.php %buildroot/opt/monitor/op5/pnp/templates.dist/check_by_snmp_load_avg.php
cp op5build/pnp/check_by_snmp_procs.php %buildroot/opt/monitor/op5/pnp/templates.dist/check_by_snmp_procs.php

%clean
rm -rf %buildroot

%files -n monitor-plugin-check_snmp_disk
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_disk
%attr(644,%{daemon_user},%{daemon_group}) /opt/monitor/op5/pnp/templates.dist/check_by_snmp_disk.php
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_disk.metadata

%files -n monitor-plugin-check_snmp_disk_io
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_disk_io
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_disk_io.metadata
%dir %attr(755,%{daemon_user},%{daemon_group}) %{_localstatedir}/check_by_snmp_disk_io

%files -n monitor-plugin-check_snmp_cpu
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_cpu
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_cpu.metadata
%attr(644,%{daemon_user},%{daemon_group}) /opt/monitor/op5/pnp/templates.dist/check_by_snmp_cpu.php
%dir %attr(755,%{daemon_user},%{daemon_group}) %{_localstatedir}/check_by_snmp_cpu

%files -n monitor-plugin-check_snmp_load_avg
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_load_avg
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_load_avg.metadata
%attr(644,%{daemon_user},%{daemon_group}) /opt/monitor/op5/pnp/templates.dist/check_by_snmp_load_avg.php

%files -n monitor-plugin-check_snmp_memory
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_memory
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_memory.metadata
%attr(644,%{daemon_user},%{daemon_group}) /opt/monitor/op5/pnp/templates.dist/check_by_snmp_memory.php

%files -n monitor-plugin-check_snmp_procs
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_procs
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_procs.metadata
%attr(644,%{daemon_user},%{daemon_group}) /opt/monitor/op5/pnp/templates.dist/check_by_snmp_procs.php

%files -n monitor-plugin-check_snmp_extend
%defattr(-,root,root,-)
%attr(755,root,root) %{prefix}/check_by_snmp_extend
%attr(644,root,root) %{prefix}/metadata/check_by_snmp_extend.metadata


%changelog
* Fri Jul 03 2015 Robin Hagman <robin.hagman@op5.com> 0.0.1
– Initial Packaging
