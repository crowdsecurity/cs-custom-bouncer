Name:      crowdsec-custom-bouncer
Version:   %(echo $VERSION)
Release:   %(echo $PACKAGE_NUMBER)%{?dist}
Summary:   Custom bouncer for Crowdsec 

License:   MIT
URL:       https://crowdsec.net
Source0:   https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: make
%{?fc33:BuildRequires: systemd-rpm-macros}

Requires: gettext

%define debug_package %{nil}

%description

%define version_number %(echo $VERSION)
%define releasever %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-custom-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -n %{name}-%{version}

%build
BUILD_VERSION=%{local_version} make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
install -m 755 -D %{name} %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/bouncers/%{name}.yaml
install -m 600 -D scripts/_bouncer.sh %{buildroot}/usr/lib/%{name}/_bouncer.sh
BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/bouncers envsubst '$BIN $CFG' < config/%{name}.service | install -m 0644 -D /dev/stdin %{buildroot}%{_unitdir}/%{name}.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
${_bindir}/%{name}
/usr/lib/%{name}/_bouncer.sh
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml

%post -p /usr/bin/sh
systemctl daemon-reload

BOUNCER="%{name}"
BOUNCER_PREFIX="CustomBouncer"

. /usr/lib/%{name}/_bouncer.sh
START=1

if [ "$1" = "1" ]; then
    if need_api_key; then
        if ! set_api_key; then
            START=0
        fi
    fi
fi

%systemd_post %{name}.service

if [ "$START" -eq 0 ]; then
    echo "no api key was generated, you can generate one on your LAPI Server by running 'cscli bouncers add <bouncer_name>' and add it to '/etc/crowdsec/bouncers/$BOUNCER.yaml'" >&2
else
    %if 0%{?fc35}
    systemctl enable "$SERVICE"
    %endif
    systemctl start "$SERVICE"
fi

echo "please enter the binary path in '$CONFIG' and start the bouncer via 'sudo systemctl start $SERVICE'"

%changelog
* Wed Jun 30 2021 Shivam Sandbhor <shivam@crowdsec.net>
- First initial packaging

%preun -p /usr/bin/sh
BOUNCER="%{name}"
. /usr/lib/%{name}/_bouncer.sh

if [ "$1" = "0" ]; then
    systemctl stop "$SERVICE" || echo "cannot stop service"
    systemctl disable "$SERVICE" || echo "cannot disable service"
    delete_bouncer
fi

%postun -p /usr/bin/sh

if [ "$1" == "1" ] ; then
    systemctl restart %{name} || echo "cannot restart service"
fi
