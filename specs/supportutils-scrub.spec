#
# spec file for package supportutils-scrub
#
# Copyright (c) 2026 SUSE LLC.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/

# SLES 16 / Leap 16.0 (suse_version >= 1600): vendor config goes to /usr/etc
# so /etc remains available for administrator overrides (layered config model).
# SLES 15 / Leap 15.x: traditional /etc path.
# The 0%{?...} guard evaluates to 0 on non-SUSE hosts where suse_version is
# undefined, keeping the macro safe.
%if 0%{?suse_version} >= 1600
%define _conf_dir %{_prefix}/etc/supportutils-scrub
%else
%define _conf_dir %{_sysconfdir}/supportutils-scrub
%endif

# SLE 12 rpmlint does not know the SPDX-2.0 "-only" suffix; use the short form
# there.  All other targets accept GPL-2.0-only.
%if 0%{?suse_version} < 1300
%define _license GPL-2.0
%else
%define _license GPL-2.0-only
%endif

Name:           supportutils-scrub
Version:        1.5
Release:        0
Summary:        Utility to sanitize and remove sensitive data from supportconfig tarballs
License:        %{_license}
Group:          System/Management
Url:            https://github.com/openSUSE/supportutils-scrub
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
Requires:       python3
BuildRequires:  python3
BuildRequires:  python3-pytest

%description
supportutils-scrub masks sensitive information from SUSE supportconfig
tarballs, directories, plain files, and network captures.  It replaces
IPv4/IPv6 addresses, MAC addresses, domain names, hostnames, usernames,
hardware serials, UUIDs, email addresses, passwords, LDAP DNs, and cloud
tokens (AWS/Azure/GCE) consistently across all files in the archive.

Mappings are saved to /var/tmp and can be reused across runs with
--mappings to keep values consistent across multiple supportconfigs.

%prep
%setup -q

%build

%install
rm -rf %{buildroot}

# Directories
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_conf_dir}
mkdir -p %{buildroot}%{_mandir}/man8
mkdir -p %{buildroot}%{_mandir}/man5
mkdir -p %{buildroot}%{_prefix}/lib/supportutils-scrub/supportutils_scrub

# Executable
install -m 0755 bin/supportutils-scrub %{buildroot}%{_sbindir}/supportutils-scrub

# Configuration file
install -m 0644 config/supportutils-scrub.conf \
    %{buildroot}%{_conf_dir}/supportutils-scrub.conf

# Man pages
install -m 0644 man/supportutils-scrub.8 \
    %{buildroot}%{_mandir}/man8/supportutils-scrub.8
gzip -9 %{buildroot}%{_mandir}/man8/supportutils-scrub.8
install -m 0644 man/supportutils-scrub.conf.5 \
    %{buildroot}%{_mandir}/man5/supportutils-scrub.conf.5
gzip -9 %{buildroot}%{_mandir}/man5/supportutils-scrub.conf.5

# Python modules — strip executable bits; the actual entry point is
# %%{_sbindir}/supportutils-scrub (the shim in bin/).
cp -r src/supportutils_scrub/* \
    %{buildroot}%{_prefix}/lib/supportutils-scrub/supportutils_scrub/
find %{buildroot} -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find %{buildroot}%{_prefix}/lib/supportutils-scrub -name "*.py" -exec chmod 0644 {} +

%check
cd %{_builddir}/%{name}-%{version}
PYTHONPATH=src python3 -m pytest tests/ -q

%files
%defattr(-,root,root)
%license LICENSE
%doc README.md
%{_sbindir}/supportutils-scrub
%dir %{_conf_dir}
%if 0%{?suse_version} >= 1600
# /usr/etc files are vendor defaults, not user config — do not mark as %%config.
%{_conf_dir}/supportutils-scrub.conf
%else
%config(noreplace) %{_conf_dir}/supportutils-scrub.conf
%endif
%dir %{_prefix}/lib/supportutils-scrub
%dir %{_prefix}/lib/supportutils-scrub/supportutils_scrub
%dir %{_prefix}/lib/supportutils-scrub/supportutils_scrub/modes
%{_prefix}/lib/supportutils-scrub/supportutils_scrub/*
%{_mandir}/man8/supportutils-scrub.8.gz
%{_mandir}/man5/supportutils-scrub.conf.5.gz

%changelog
* Fri Apr 18 2026 Ronald Pina <rpina@suse.com> - 1.5-0
- Update to version 1.5
  see /usr/share/doc/packages/supportutils-scrub/supportutils-scrub.changes
