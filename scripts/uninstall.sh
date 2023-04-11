#!/bin/sh

set -eu

BOUNCER="crowdsec-blocklist-mirror"

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

uninstall() {
    systemctl stop "$SERVICE"
    delete_bouncer
    rm -f "$CONFIG"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    rm -f "/var/log/$BOUNCER.log"
}

uninstall
msg succ "$BOUNCER has been successfully uninstalled"
exit 0
#!/usr/bin/env bash

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-custom-bouncer.service"
LOG_FILE="/var/log/crowdsec-custom-bouncer.log"
CONFIG_DIR="/etc/crowdsec/bouncers"
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-custom-bouncer"

uninstall() {
	systemctl stop crowdsec-custom-bouncer
	rm -f "${CONFIG_DIR}/crowdsec-custom-bouncer.yaml"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-custom-bouncer uninstall successfully"
