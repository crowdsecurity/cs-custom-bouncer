#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"
BIN_PATH="./cs-custom-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-custom-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-custom-bouncer.service"


check_apikeygen() {
    echo "if you are on a single-machine setup, do you want the wizard to configure your API key ? (Y/n)"
    echo "(note: if you didn't understand the question, 'Y' might be a safe answer)"
    read answer
    if [[ ${answer} == "" ]]; then
            answer="y"
    fi
    if [ "$answer" != "${answer#[Yy]}" ] ;then
            SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
            API_KEY=`cscli bouncers add -n cs-custom-bouncer-${SUFFIX} -o raw`
            API_KEY=${API_KEY} envsubst < ./config/cs-custom-bouncer.yaml > "${CONFIG_DIR}cs-custom-bouncer.yaml"
    else 
        echo "For your bouncer to be functionnal, you need to create an API key and set it in the ${CONFIG_DIR}cs-custom-bouncer.yaml file"
    fi;
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
check_apikeygen
echo "cs-custom-bouncer service has been installed!"
