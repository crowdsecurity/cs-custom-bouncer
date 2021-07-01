Name:           crowdsec-custom-bouncer
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:      Custom bouncer for Crowdsec 

License:        MIT
URL:            https://crowdsec.net
Source:         cs-custom-bouncer-%(echo $VERSION).tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  golang >= 1.14
BuildRequires:  make
%{?fc33:BuildRequires: systemd-rpm-macros}

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-custom-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -n cs-custom-bouncer-%{version}

%build
BUILD_VERSION=%{local_version} make
TMP=`mktemp -p /tmp/`
cp config/%{name}.service ${TMP}
BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/ envsubst < ${TMP} > config/%{name}.service
rm ${TMP}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/sbin
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/%{name}/%{name}.yaml 
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
%{_unitdir}/%{name}.service
%config /etc/crowdsec/%{name}/%{name}.yaml 


%post
set -x
systemctl daemon-reload


START=0

systemctl is-active --quiet crowdsec

if [ "$?" -eq "0" ] ; then
    START=1
    echo "cscli/crowdsec is present, generating API key"
    unique=`date +%s`
    API_KEY=`sudo cscli -oraw bouncers add CustomBouncer-${unique}`
    if [ $? -eq 1 ] ; then
        echo "failed to create API token, service won't be started."
        START=0
        API_KEY="<API_KEY>"
    else
        echo "API Key : ${API_KEY}"
    fi
fi

TMP=`mktemp -p /tmp/`
cp /etc/crowdsec/crowdsec-custom-bouncer/crowdsec-custom-bouncer.yaml ${TMP}
API_KEY=${API_KEY} envsubst < ${TMP} > /etc/crowdsec/crowdsec-custom-bouncer/crowdsec-custom-bouncer.yaml
rm ${TMP}

if [ ${START} -eq 0 ] ; then
    echo "no api key was generated, won't start service"
fi

echo "please enter the binary path in '/etc/crowdsec/crowdsec-custom-bouncer/crowdsec-custom-bouncer.yaml' and start the bouncer via 'sudo systemctl start crowdsec-custom-bouncer' "


 
%changelog
* Wed Jun 30 2021 Shivam Sandbhor <shivam@crowdsec.net>
- First initial packaging

%preun
systemctl stop crowdsec-custom-bouncer || echo "cannot stop service"
systemctl disable crowdsec-custom-bouncer || echo "cannot disable service"