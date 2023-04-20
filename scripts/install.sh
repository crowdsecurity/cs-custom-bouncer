#!/bin/sh

set -eu

BOUNCER="crowdsec-custom-bouncer"
BOUNCER_PREFIX="crowdsec-custom-bouncer"

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

API_KEY="<API_KEY>"

gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        unique=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: $API_KEY"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}

gen_config_file() {
    # shellcheck disable=SC2016
    API_KEY=${API_KEY} envsubst '$API_KEY' <"./config/$CONFIG_FILE" | \
        install -D -m 0600 /dev/stdin "$CONFIG"
}

install_bouncer() {
    msg info "Installing $BOUNCER"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0600 "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    systemctl daemon-reload
    gen_apikey
    gen_config_file
    set_local_lapi_url 'CROWDSEC_LAPI_URL'
}

# --------------------------------- #

usage() {
    cat <<EOT >&2
    Usage: $0 [options]
    Options:
      -b, --binary PATH  Path to binary file
      -h, --help         Print this help message
EOT
}

OPTIONS=$(getopt -o hb: --long help,binary: -- "$@")
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  echo "Invalid arguments."
  exit 1
fi
eval set -- "$OPTIONS"
while true; do
  case "$1" in
    -h | --help) usage; exit 0;;
    -b | --binary) BINARY_PATH="$2"; shift 2;;
    --) shift; break;;
    *) break;;
  esac
done

if [ ! -f "$BIN_PATH" ]; then
    msg err "$BIN_PATH not found, exiting."
    exit 1
fi

if [ -e "$BIN_PATH_INSTALLED" ]; then
    msg warn "$BIN_PATH_INSTALLED is already installed. Exiting"
    exit 1
fi

if [ -z "${BINARY_PATH+}" ]; then
    printf '%s' "Path to your custom binary: "
    read -r BINARY_PATH
    # XXX TODO check if path is valid
fi

BINARY_PATH=$(readlink -f "$BINARY_PATH")

install_bouncer

set_config_var_value 'BINARY_PATH' "$BINARY_PATH"

systemctl enable "$SERVICE"
if [ "$READY" = "yes" ]; then
    systemctl start "$SERVICE"
else
    msg warn "service not started. You need to get an API key and configure it in $CONFIG"
fi

msg succ "The $BOUNCER service has been installed!"
exit 0
