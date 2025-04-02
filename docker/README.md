# Quick reference

CrowdSec bouncer to use custom scripts.

For all the options, refer to the documentation: https://docs.crowdsec.net/u/bouncers/custom/

To use the container image, mount your configuration and the script that will receive decision notifications.


```bash
$ cat config.yaml
bin_path: /custom-script
feed_via_stdin: true # Invokes binary once and feeds incoming decisions to it's stdin.
total_retries: 3
log_mode: stdout
api_url: http://127.0.0.1:8080/
api_key: "......"
$ docker run \
  --network host \
  -v $(pwd)/config.yaml:/crowdsec-custom-bouncer.yaml \
  -v $(pwd)/custom-script:/custom-script crowdsecurity/cs-custom-bouncer:latest
...
```
