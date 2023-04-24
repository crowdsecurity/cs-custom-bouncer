
def test_tls_server(crowdsec, certs_dir, api_key_factory, bouncer, cb_stream_cfg_factory):
    """TLS with server-only certificate"""

    api_key = api_key_factory()

    lapi_env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
        'BOUNCER_KEY_custom': api_key,
    }

    certs = certs_dir(lapi_hostname='lapi')

    volumes = {
        certs: {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(environment=lapi_env, volumes=volumes) as cs:
        cs.wait_for_log("*CrowdSec Local API listening*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)

        port = cs.probe.get_bound_port('8080')
        cfg = cb_stream_cfg_factory()
        cfg['api_url'] = f'https://localhost:{port}'
        cfg['api_key'] = api_key

        with bouncer(cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*auth-api: auth with api key failed*",
                "*tls: failed to verify certificate: x509: certificate signed by unknown authority*",
            ])

        cfg['ca_cert_path'] = (certs / 'ca.crt').as_posix()

        with bouncer(cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ])


def test_tls_mutual(crowdsec, certs_dir, api_key_factory, bouncer, cb_stream_cfg_factory):
    """TLS with two-way bouncer/lapi authentication"""

    lapi_env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    certs = certs_dir(lapi_hostname='lapi')

    volumes = {
        certs: {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(environment=lapi_env, volumes=volumes) as cs:
        cs.wait_for_log("*CrowdSec Local API listening*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)

        port = cs.probe.get_bound_port('8080')
        cfg = cb_stream_cfg_factory()
        cfg['api_url'] = f'https://localhost:{port}'
        cfg['cert_path'] = (certs / 'bouncer.crt').as_posix()
        cfg['key_path'] = (certs / 'bouncer.key').as_posix()
        cfg['ca_cert_path'] = (certs / 'ca.crt').as_posix()

        with bouncer(cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ])
