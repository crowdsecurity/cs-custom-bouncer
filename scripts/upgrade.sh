#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-custom-bouncer"
BIN_PATH="./cs-custom-bouncer"


upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "cs-custom-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the upgrade script as root or with sudo"
    exit 1
fi

systemctl stop cs-custom-bouncer
upgrade_bin
systemctl start cs-custom-bouncer
echo "cs-custom-bouncer upgraded successfully."