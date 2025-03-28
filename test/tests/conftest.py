import contextlib

import pytest
from pytest_cs import plugin

# XXX:
# fails with "Argument(s) {'_call'} are declared in the hookimpl but can not be found in the hookspec"
# pytest_exception_interact = plugin.pytest_exception_interact


# provide the name of the bouncer binary to test
@pytest.fixture(scope='session')
def bouncer_under_test():
    return 'crowdsec-custom-bouncer'


# Create a lapi container, register a bouncer and run it with the updated config.
# - Return context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, cb_stream_cfg_factory, api_key_factory, tmp_path_factory, bouncer_binary):
    @contextlib.contextmanager
    def closure(config_lapi=None, config_bouncer=None, api_key=None):
        if config_bouncer is None:
            config_bouncer = {}
        if config_lapi is None:
            config_lapi = {}
        # can be overridden by config_lapi + config_bouncer
        api_key = api_key_factory()
        env = {
            'BOUNCER_KEY_custom': api_key,
        }
        # can be overridden by config_bouncer
        data = tmp_path_factory.mktemp("data") / 'data.txt'
        try:
            env.update(config_lapi)
            with crowdsec(environment=env) as lapi:
                lapi.wait_for_http(8080, '/health')
                port = lapi.probe.get_bound_port('8080')
                cfg = cb_stream_cfg_factory()
                cfg['api_url'] = f'http://localhost:{port}/'
                cfg['api_key'] = api_key
                cfg['bin_args'] = [data.as_posix()]
                cfg.update(config_bouncer)
                with bouncer(cfg) as cb:
                    yield cb, lapi, data
        finally:
            pass

    yield closure


_default_config = {
    'total_retries': 3,
    'update_frequency': '0.1s',
    'log_mode': 'stdout',
    'log_level': 'info',
    'api_url': 'http://localhost:8081/',
    'prometheus': {
        'enabled': False,
    }
}


@pytest.fixture(scope='session')
def cb_cfg_factory():
    def closure(**kw):
        cfg = _default_config.copy()
        cfg |= kw
        return cfg | kw
    yield closure


@pytest.fixture(scope='session')
def cb_stream_cfg_factory(cb_cfg_factory):
    def closure(**kw):
        cfg = {
            'feed_via_stdin': True,
            'bin_path': 'test/custom-stream',
        }
        cfg |= cb_cfg_factory(**kw)
        return cfg
    yield closure


@pytest.fixture(scope='session')
def bouncer_live_cfg():
    def closure(**kw):
        cfg = {
            'feed_via_stdin': False,
            'bin_path': 'test/custom-live',
        }
        cfg |= cb_cfg_factory(**kw)
        return cfg
    yield closure
