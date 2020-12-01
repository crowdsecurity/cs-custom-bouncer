#!/usr/bin/env bash

SYSTEMD_PATH_FILE="/etc/systemd/system/cs-custom-bouncer.service"
LOG_FILE="/var/log/cs-custom-bouncer.log"
CONFIG_DIR="/etc/crowdsec/cs-custom-bouncer/"
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"

uninstall() {
	systemctl stop cs-custom-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "cs-custom-bouncer uninstall successfully"