# cs-custom-bouncer
Crowdsec bouncer written in golang for custom scripts.

cs-custom-bouncer will fetch new and old decisions from a CrowdSec API and then will be given as an argument to a custom binary.

## Installation


### Assisted

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

## Usage

The custom binary must support the following commands:

```bash
<my_custom_binary> add <ip> <duration> <reason> <json_object> # to add an IP address
<my_custom_binary> del <ip> <duration> <reason> <json_object> # to del an IP address
```

- `ip` : ip address to block `<ip>/<cidr>`
- `duration`: duration of the remediation in seconds
- `reason` : reason of the decision
- `json_object`: the serialized decision

:warning: don't forget to add `execution` right to your binary/script

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
bin_path: <path_to_binary>
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