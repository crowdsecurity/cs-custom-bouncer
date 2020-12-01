#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"
BIN_PATH="./cs-custom-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-custom-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-custom-bouncer.service"
API_KEY=""
BINARY_PATH=""

gen_apikey() {
    SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
    API_KEY=`cscli bouncers add cs-custom-bouncer-${SUFFIX} -o raw`
}

gen_binary_path() {
    echo "Absolute path to your custom binary:"
    read BINARY_PATH
    if [[ ${answer} == "" ]]; then
            return
    fi
}

install_custom_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-custom-bouncer.yaml" "${CONFIG_DIR}cs-custom-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-custom-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

gen_config_file() {
    API_KEY=${API_KEY} BINARY_PATH=${BINARY_PATH} envsubst < ./config/cs-custom-bouncer.yaml > "${CONFIG_DIR}cs-custom-bouncer.yaml"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the install script as root or with sudo"
    exit 1
fi
echo "Installing cs-custom-bouncer"
install_custom_bouncer
gen_apikey
gen_binary_path
gen_config_file
systemctl enable cs-firewall-bouncer.service
systemctl start cs-firewall-bouncer.service
echo "cs-custom-bouncer service has been installed!"
