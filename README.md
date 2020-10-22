# cs-custom-bouncer
Crowdsec bouncer written in golang for custom scripts.

cs-custom-bouncer will fetch new and old decisions from a CrowdSec API and then will be given as an argument to a custom binary.

## Installation

First, download the latest [`cs-custom-bouncer` release](https://github.com/crowdsecurity/cs-custom-bouncer/releases).

```sh
$ tar xzvf cs-custom-bouncer.tgz
$ sudo ./install.sh
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