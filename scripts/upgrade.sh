#!/bin/sh

set -eu

BOUNCER="crowdsec-custom-bouncer"

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

systemctl stop "$SERVICE"

if ! upgrade_bin; then
    msg err "failed to upgrade $BOUNCER"
    exit 1
fi

systemctl start "$SERVICE" || msg warn "$SERVICE failed to start, please check the systemd logs"

msg succ "$BOUNCER upgraded successfully."
exit 0
#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-custom-bouncer"
BIN_PATH="./crowdsec-custom-bouncer"


upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "crowdsec-custom-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the upgrade script as root or with sudo"
    exit 1
fi

systemctl stop crowdsec-custom-bouncer
upgrade_bin
systemctl start crowdsec-custom-bouncer
echo "crowdsec-custom-bouncer upgraded successfully."
