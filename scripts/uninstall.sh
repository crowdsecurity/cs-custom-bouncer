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