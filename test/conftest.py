import contextlib
import os
import pathlib

import pytest

SCRIPT_DIR = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent
cb_binary = PROJECT_ROOT.joinpath("crowdsec-custom-bouncer")
bouncer_binary = cb_binary


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_sessionstart(session):
    if not bouncer_binary.exists() or not os.access(bouncer_binary, os.X_OK):
        raise RuntimeError(f"Bouncer binary not found at {bouncer_binary}. Did you build it?")

    yield


# Create a lapi container, registers a bouncer
# and runs it with the updated config.
# - Returns context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, cb_stream_cfg_factory, api_key_factory, tmp_path_factory):
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
                with bouncer(cb_binary, cfg) as cb:
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
