"""
Full integration test with a real Crowdsec running in Docker
"""

import json
import time

from tests.utils import generate_n_decisions

import pytest


def test_no_lapi(bouncer):
    with bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*connection refused*",
            "*terminating bouncer process*",
        ])
        # TODO: check that the bouncer is not running anymore


def test_no_api_key(crowdsec, lapi, bouncer, bouncer_cfg):
    with crowdsec() as lapi:
        port = lapi.probe.get_bound_port('8080')
        bouncer_cfg['api_url'] = f'http://localhost:{port}'
        del bouncer_cfg['api_key']

        with bouncer(bouncer_cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*unable to configure bouncer: config does not contain LAPI key or certificate*",
            ])
        # TODO: check that the bouncer is not running anymore


def test_bad_api_key(crowdsec, lapi, bouncer, bouncer_cfg):
    with crowdsec() as lapi:
        port = lapi.probe.get_bound_port('8080')
        bouncer_cfg['api_url'] = f'http://localhost:{port}'
        bouncer_cfg['api_key'] = 'badkey'

        with bouncer(bouncer_cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*auth-api: auth with api key failed return nil response, error*",
                # TODO: check bouncer failure "*stream api init failed*"
            ])
            # TODO: check that the bouncer is not running anymore


def test_good_api_key(crowdsec, bouncer, bouncer_cfg, api_key_factory):
    api_key = api_key_factory()
    env = {
        'BOUNCER_KEY_custom': api_key,
    }
    with crowdsec(environment=env) as lapi:
        lapi.wait_for_http(8080, '/health')
        port = lapi.probe.get_bound_port('8080')
        bouncer_cfg['api_url'] = f'http://localhost:{port}'
        bouncer_cfg['api_key'] = api_key

        with bouncer(bouncer_cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
            ])
            # TODO: check that the bouncer can successfully connect
            res = lapi.cont.exec_run('cscli bouncers list -o json')
            assert res.exit_code == 0
            bouncers = json.loads(res.output)
            assert len(bouncers) == 1
            assert bouncers[0]['name'] == 'custom'
            # TODO: assert bouncers[0]['last_pull'] == 'xxx'


def test_good_api_key_nested_context_managers(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        # TODO: check that the bouncer can successfully connect
        res = lapi.cont.exec_run('cscli bouncers list -o json')
        assert res.exit_code == 0
        bouncers = json.loads(res.output)
        assert len(bouncers) == 1
        assert bouncers[0]['name'] == 'custom'
        # TODO: assert bouncers[0]['last_pull'] == 'xxx'


def test_api_key_with_dollar(bouncer_with_lapi):
    """
    Test that we can use a $ in the API key and it's not substituted with an undefined variable
    """
    api_key = 'foo$bar'
    config_lapi = {
        'BOUNCER_KEY_custom': api_key
    }
    config_bouncer = {
        'api_key': api_key
    }
    with bouncer_with_lapi(config_lapi=config_lapi, config_bouncer=config_bouncer) as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        # TODO: check that the bouncer can successfully connect


def test_binary_monitor(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        child = cb.wait_for_child()
        assert child.name() == 'custombinary'
        assert len(cb.children()) == 1

        # Let's kill custombinary and see if it's restarted max_retry times (2)
        cb.halt_children()
        cb.wait_for_child()
        assert len(cb.children()) == 1

        cb.halt_children()
        cb.wait_for_child()
        assert len(cb.children()) == 1

        # This will exceed max_retry and the bouncer would stop
        cb.halt_children()
        with pytest.raises(TimeoutError):
            cb.wait_for_child()
        assert len(cb.children()) == 0

#        assert cb.popen.poll() is not None
        # TODO: check that the bouncer is not running anymore


def test_add_decisions(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])

        for i in range(1, 6):
            res = lapi.cont.exec_run(f'cscli decisions add -i 1.2.3.{i}')
            assert res.exit_code == 0

        time.sleep(0.5)

        with open(data) as f:
            lines = f.readlines()
        assert len(lines) == 5

        for i, line in enumerate(lines, start=1):
            line = json.loads(line)
            del line['duration']
            assert line == {
                'action': 'add',
                'id': i,
                'origin': 'cscli',
                'scenario': "manual 'ban' from 'localhost'",
                'scope': 'Ip',
                'type': 'ban',
                'value': f'1.2.3.{i}'
            }


def test_bin_args(bouncer_with_lapi, tmp_path_factory):
    data = tmp_path_factory.mktemp('data_override') / 'data.txt'
    config_bouncer = {
        'bin_args': [data.as_posix()]
    }

    # ignore the data file returned from the fixture, we have our own
    with bouncer_with_lapi(config_bouncer=config_bouncer) as (cb, lapi, _):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])

        for i in range(1, 6):
            res = lapi.cont.exec_run(f'cscli decisions add -i 1.2.3.{i}')
            assert res.exit_code == 0

        time.sleep(0.5)

        with open(data) as f:
            lines = f.readlines()
        assert len(lines) == 5


def test_cache_retention(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        for i in range(1, 3):
            res = lapi.cont.exec_run(f'cscli decisions add -i 1.2.3.{i}')
            assert res.exit_code == 0
        for i in range(1, 3):
            res = lapi.cont.exec_run(f'cscli decisions add -i 1.2.3.{i}')
            assert res.exit_code == 0
        time.sleep(.5)
        with open(data) as f:
            lines = f.readlines()
        assert len(lines) == 2


def test_delete_decisions(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        for i in range(1, 6):
            res = lapi.cont.exec_run(f'cscli decisions add -i 1.2.3.{i}')
            assert res.exit_code == 0
        time.sleep(0.5)
        for i in range(1, 6):
            res = lapi.cont.exec_run(f'cscli decisions delete --ip 1.2.3.{i}')
            assert res.exit_code == 0
        time.sleep(0.5)
        with open(data) as f:
            lines = f.readlines()
        assert len(lines) == 10
        current_decisions = set()
        for line in lines:
            line = json.loads(line)
            if line['action'] == 'add':
                current_decisions.add(line['id'])
            elif line['action'] == 'del':
                current_decisions.remove(line['id'])
        assert len(current_decisions) == 0
