Name:      crash-worker
Summary:    Crash-manager
Version: 0.1.3
Release:    26
Group:      Framework/system
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001:    crash-worker.manifest
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsystemd-journal)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  sys-assert
BuildRequires:  cmake

Requires(post): coreutils
Requires(post): tar
Requires(post): gzip
Requires(post): sys-assert

%description
crash-manager

%prep
%setup -q

%build
cp %{SOURCE1001} .

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS+=" -DTIZEN_ENGINEER_MODE"
%endif
export CFLAGS+=" -Werror"

export CFLAGS+=" -DTIZEN_DEBUG_ENABLE"

%if "%{?tizen_profile_name}" == "wearable"
export CFLAGS+=" -DMICRO_DD"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license
mkdir -p %{buildroot}%{_libdir}/systemd/system/sockets.target.wants
mkdir -p %{buildroot}%{_libdir}/systemd/system/basic.target.wants
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
ln -s ../crash-manager.socket %{buildroot}%{_libdir}/systemd/system/sockets.target.wants/crash-manager.socket
ln -s ../crash-env.service %{buildroot}%{_libdir}/systemd/system/basic.target.wants/crash-env.service
ln -s ../crash-manager.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/crash-manager.service
mkdir -p %{buildroot}/opt/usr/share/crash
mkdir -p %{buildroot}/opt/usr/share/crash/core
mkdir -p %{buildroot}/opt/usr/share/crash/dump
mkdir -p %{buildroot}/opt/usr/share/crash/report

%post
mkdir -p /opt/etc/dump.d
chown root:root /opt/etc/dump.d
chmod 755 /opt/etc/dump.d

mkdir -p /opt/etc/dump.d/module.d
chown root:root /opt/etc/dump.d/module.d
chmod 755 /opt/etc/dump.d/module.d

if [ -f %{_libdir}/rpm-plugins/msm.so ]; then
	find /opt/usr/share/crash -print0 | xargs -0 chsmack -a 'sys-assert::core'
	find /opt/usr/share/crash -type d -print0 | xargs -0 chsmack -t
fi
%postun

%posttrans
#rm -rf /opt/etc/dump.d     #if TIZEN_DEBUG_ENABLE does not exist

%files
%manifest crash-worker.manifest
%defattr(-,system,system,-)
/usr/bin/crash-manager
/etc/crash/crash-manager.conf
/usr/share/license/%{name}
%{_sysconfdir}/smack/accesses.d/crash-worker.efl
%{_libdir}/systemd/system/crash-manager.service
%{_libdir}/systemd/system/multi-user.target.wants/crash-manager.service
%{_libdir}/systemd/system/crash-manager.socket
%{_libdir}/systemd/system/sockets.target.wants/crash-manager.socket
%{_libdir}/systemd/system/crash-env.service
%{_libdir}/systemd/system/basic.target.wants/crash-env.service
/usr/share/dbus-1/system-services/org.tizen.system.crash.service
%attr(775,system,crash) %dir /opt/usr/share/crash
%attr(775,system,crash) %dir /opt/usr/share/crash/dump
%attr(775,system,crash) %dir /opt/usr/share/crash/core
%attr(775,system,crash) %dir /opt/usr/share/crash/report
%attr(0750,system,input)/usr/bin/crashctl
%attr(0744,system,system)/usr/bin/all_log_dump.sh
%attr(0744,system,system)/usr/bin/dump_log.sh
%attr(0744,system,system)/usr/bin/crash_env.sh
%attr(0755,system,system)/usr/bin/dump_systemstate
%attr(0644,system,system)/usr/lib/systemd/system/all_log_dump.service
%attr(0644,system,system)/usr/lib/udev/rules.d/92-all-log-dump.rules
