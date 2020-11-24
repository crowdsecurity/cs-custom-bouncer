<p align="center">
<img src="https://github.com/crowdsecurity/cs-custom-bouncer/raw/main/docs/assets/crowdsec_custom_logo.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4DA; <a href="#installation/">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>


# cs-custom-bouncer
Crowdsec bouncer written in golang for custom scripts.

cs-custom-bouncer will periodically fetch new and expired/removed decisions from CrowdSec Local API and will pass them as arguments to a custom user script.

## Installation

### With installer

First, download the latest [`cs-custom-bouncer` release](https://github.com/crowdsecurity/cs-custom-bouncer/releases).

```sh
$ tar xzvf cs-custom-bouncer.tgz
$ sudo ./install.sh
```

### From source

Run the following commands:

```bash
git clone https://github.com/crowdsecurity/cs-custom-bouncer.git
cd cs-custom-bouncer/
make release
tar xzvf cs-custom-bouncer.tgz
cd cs-custom-bouncer-v*/
sudo ./install.sh
```

### Start

If your bouncer run on the same machine as your crowdsec local API, you can start the service directly since the `install.sh` took care of the configuration.
```sh
sudo systemctl start cs-custom-bouncer
```

## Usage

The custom binary will be called with the following arguments :

```bash
<my_custom_binary> add <ip> <duration> <reason> <json_object> # to add an IP address
<my_custom_binary> del <ip> <duration> <reason> <json_object> # to del an IP address
```

- `ip` : ip address to block `<ip>/<cidr>`
- `duration`: duration of the remediation in seconds
- `reason` : reason of the decision
- `json_object`: the serialized decision

:warning: don't forget to add execution permissions to your binary/script

### Examples:

```bash
custom_binary.sh add 1.2.3.4/32 3600 "test blacklist"
custom_binary.sh del 1.2.3.4/32 3600 "test blacklist"
```

## Configuration

Before starting the `cs-custom-bouncer` service, please edit the configuration to add your API url and key.
The default configuration file is located under : `/etc/crowdsec/cs-custom-bouncer/`

```sh
$ vim /etc/crowdsec/custom-bouncer/cs-custom-bouncer.yaml
```

```yaml
bin_path: <absolute_path_to_binary>
piddir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: <API_URL>  # when install, default is "localhost:8080"
api_key: <API_KEY>  # Add your API key generated with `cscli bouncers add --name <bouncer_name>`
```

You can then start the service:

```sh
sudo systemctl start cs-custom-bouncer
```
