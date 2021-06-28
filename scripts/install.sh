#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"
BIN_PATH="./cs-custom-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-custom-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-custom-bouncer.service"
API_KEY=""
BINARY_PATH=""

usage() {
      echo "Usage: ./install.sh [options]"
      echo "    -h|--help                              Display this help message."
      echo "    -b|--binary <path>                     Specify the binary path"

      exit 0
}

while [[ $# -gt 0 ]]
do
    key="${1}"
    case ${key} in
    -b|--binary)
        if ! [ -f "${2}" ]; then
            echo "${key} need a path"
            usage
            exit 1
        fi
        BINARY_PATH="$2"
        shift # past argument
        BINARY_PATH=$(readlink -f $BINARY_PATH)
        shift
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)    # unknown option
        echo "Unknown argument ${key}."
        usage
        exit 1
        ;;
    esac
done

gen_apikey() {
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        API_KEY=`cscli bouncers add cs-custom-bouncer-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
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
    echo "Please run the install script as root or with sudo"
    exit 1
fi
echo "Installing cs-custom-bouncer"
install_custom_bouncer
gen_apikey
if ! [ -f "$BINARY_PATH" ]; then
    gen_binary_path
fi
gen_config_file
systemctl enable cs-custom-bouncer.service
if ! [ -f "$BINARY_PATH" ]; then
    echo "$BINARY_PATH doesn't exist, can't start cs-custom-bouncer service."
    echo "Please edit ${CONFIG_DIR}cs-custom-bouncer.yaml with a real binary path and run 'sudo systemctl start cs-custom-bouncer'."
    exit 1
fi

if [ "$READY" = "yes" ]; then
    systemctl start cs-custom-bouncer.service
else
    echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}cs-firewall-bouncer.yaml"
fi

echo "cs-custom-bouncer service has been installed!"
