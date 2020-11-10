#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"
BIN_PATH="./cs-custom-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-custom-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-custom-bouncer.service"


gen_apikey() {
    SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
    API_KEY=`cscli bouncers add -n cs-custom-bouncer-${SUFFIX} -o raw`
    API_KEY=${API_KEY} envsubst < ./config/cs-custom-bouncer.yaml > "${CONFIG_DIR}cs-custom-bouncer.yaml"
}

install_custom_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-custom-bouncer.yaml" "${CONFIG_DIR}cs-custom-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-custom-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}


echo "Installing cs-custom-bouncer"
install_custom_bouncer
gen_apikey
echo "cs-custom-bouncer service has been installed!"
