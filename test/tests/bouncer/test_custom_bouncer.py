import json
import time
from pathlib import Path


def test_no_custom_binary(crowdsec, bouncer, cb_cfg_factory):
    cfg = cb_cfg_factory()
    cfg["bin_path"] = "/does/not/exist"
    with bouncer(cfg) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*unable to load configuration: binary '/does/not/exist' doesn't exist*",
            ]
        )
        cb.proc.wait()
        assert not cb.proc.is_running()


def test_no_api_key(crowdsec, bouncer, cb_stream_cfg_factory):
    cfg = cb_stream_cfg_factory()
    with bouncer(cfg) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*config does not contain LAPI key or certificate*",
            ]
        )
        cb.proc.wait()
        assert not cb.proc.is_running()

    cfg["api_key"] = ""

    with bouncer(cfg) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*config does not contain LAPI key or certificate*",
            ]
        )
        cb.proc.wait()
        assert not cb.proc.is_running()


def test_no_lapi(bouncer, cb_stream_cfg_factory):
    # The bouncer should exit if it can't connect to the LAPI
    cfg = cb_stream_cfg_factory()
    cfg["api_key"] = "not-used"
    with bouncer(cfg) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*connection refused*",
                "*terminating bouncer process*",
                "*process terminated with error: bouncer stream halted*",
            ]
        )


def test_bad_api_key(crowdsec, bouncer, cb_stream_cfg_factory):
    with crowdsec() as lapi:
        port = lapi.probe.get_bound_port("8080")
        cfg = cb_stream_cfg_factory()
        cfg["api_url"] = f"http://localhost:{port}"
        cfg["api_key"] = "badkey"

        with bouncer(cfg) as cb:
            cb.wait_for_lines_fnmatch(
                [
                    "*Using API key auth*",
                    "*Processing new and deleted decisions . . .*",
                    "*auth-api: auth with api key failed return nil response, error*",
                    "*process terminated with error: bouncer stream halted*",
                ]
            )
            cb.proc.wait()
            assert not cb.proc.is_running()


def test_good_api_key(crowdsec, bouncer, cb_stream_cfg_factory, api_key_factory, bouncer_under_test):
    api_key = api_key_factory()
    env = {
        "BOUNCER_KEY_custom": api_key,
    }
    with crowdsec(environment=env) as lapi:
        lapi.wait_for_http(8080, "/health")
        port = lapi.probe.get_bound_port("8080")
        cfg = cb_stream_cfg_factory()
        cfg["api_url"] = f"http://localhost:{port}"
        cfg["api_key"] = api_key

        with bouncer(cfg) as cb:
            # check that the bouncer is attempting to connect
            cb.wait_for_lines_fnmatch(
                [
                    "*Using API key auth*",
                    "*Processing new and deleted decisions . . .*",
                    "*deleting 0 decisions*",
                    "*adding 0 decisions*",
                ]
            )

            # check that the bouncer is registered
            res = lapi.cont.exec_run("cscli bouncers list -o json")
            assert res.exit_code == 0
            bouncers = json.loads(res.output)
            assert len(bouncers) == 1
            assert bouncers[0]["name"] == "custom"
            assert bouncers[0]["auth_type"] == "api-key"
            assert bouncers[0]["type"] == bouncer_under_test

            # check that the bouncer can successfully connect
            # and receive decisions
            time.sleep(1)
            cb.wait_for_lines_fnmatch(
                [
                    "*adding 0 decisions*",
                ]
            )


def test_good_api_key_nested_context_managers(bouncer_with_lapi):
    # like the above test, but with an implicit setup
    # of the lapi and bouncer
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )

        res = lapi.cont.exec_run("cscli bouncers list -o json")
        assert res.exit_code == 0
        bouncers = json.loads(res.output)
        assert len(bouncers) == 1
        assert bouncers[0]["name"] == "custom"


def test_api_key_with_dollar(bouncer_with_lapi):
    """
    Test that we can use a $ in the API key and it's not substituted with an undefined variable
    """
    api_key = "foo$bar"
    config_lapi = {"BOUNCER_KEY_custom": api_key}
    config_bouncer = {"api_key": api_key}
    with bouncer_with_lapi(config_lapi=config_lapi, config_bouncer=config_bouncer) as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )


def test_binary_monitor(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )
        child = cb.wait_for_child(timeout=2)
        assert child.name() == "custom-stream"
        assert len(cb.children()) == 1

        # Let's kill custom-stream and see if it's restarted max_retry times (2)
        cb.halt_children()
        time.sleep(2)
        cb.wait_for_child(timeout=2)
        assert len(cb.children()) == 1
        cb.wait_for_lines_fnmatch(
            [
                "*custom program exited (retry 1/3): signal: killed*",
            ]
        )

        cb.halt_children()
        time.sleep(2)
        cb.wait_for_child(timeout=2)
        assert len(cb.children()) == 1
        cb.wait_for_lines_fnmatch(
            [
                "*custom program exited (retry 2/3): signal: killed*",
            ]
        )

        # This will exceed max_retry and the bouncer will stop
        assert cb.proc.is_running()
        cb.halt_children()
        cb.proc.wait()
        assert not cb.proc.is_running()
        cb.wait_for_lines_fnmatch(
            ["*custom program exited (retry 3/3): signal: killed*", "*maximum retries exceeded for program execution*"]
        )


def test_add_decisions(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )

        for i in range(1, 6):
            res = lapi.cont.exec_run(f"cscli decisions add -i 1.2.3.{i}")
            assert res.exit_code == 0

        time.sleep(1)

        with Path(data).open() as f:
            lines = f.readlines()
        assert len(lines) == 5

        for i, line in enumerate(lines, start=1):
            j = json.loads(line)
            j.pop("duration", None)
            j.pop("uuid", None)
            assert j == {
                "action": "add",
                "id": i,
                "origin": "cscli",
                "scenario": "manual 'ban' from 'localhost'",
                "scope": "Ip",
                "type": "ban",
                "value": f"1.2.3.{i}",
            }


def test_bin_args(bouncer_with_lapi, tmp_path_factory):
    data = tmp_path_factory.mktemp("data_override") / "data.txt"
    config_bouncer = {"bin_args": [data.as_posix()]}

    # ignore the data file returned from the fixture, we have our own
    with bouncer_with_lapi(config_bouncer=config_bouncer) as (cb, lapi, _):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )

        for i in range(1, 6):
            res = lapi.cont.exec_run(f"cscli decisions add -i 1.2.3.{i}")
            assert res.exit_code == 0

        time.sleep(2)

        with Path(data).open() as f:
            lines = f.readlines()
        assert len(lines) == 5


def test_cache_retention(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )
        for i in range(1, 3):
            res = lapi.cont.exec_run(f"cscli decisions add -i 1.2.3.{i}")
            assert res.exit_code == 0
        for i in range(1, 3):
            res = lapi.cont.exec_run(f"cscli decisions add -i 1.2.3.{i}")
            assert res.exit_code == 0
        time.sleep(1)
        with Path(data).open() as f:
            lines = f.readlines()
        assert len(lines) == 2


def test_delete_decisions(bouncer_with_lapi):
    with bouncer_with_lapi() as (cb, lapi, data):
        cb.wait_for_lines_fnmatch(
            [
                "*Using API key auth*",
                "*Processing new and deleted decisions . . .*",
                "*deleting 0 decisions*",
                "*adding 0 decisions*",
            ]
        )
        for i in range(1, 6):
            res = lapi.cont.exec_run(f"cscli decisions add -i 1.2.3.{i}")
            assert res.exit_code == 0
        time.sleep(1)
        for i in range(1, 6):
            res = lapi.cont.exec_run(f"cscli decisions delete --ip 1.2.3.{i}")
            assert res.exit_code == 0
        time.sleep(1)
        with Path(data).open() as f:
            lines = f.readlines()
        assert len(lines) == 10
        current_decisions = set()
        for line in lines:
            j = json.loads(line)
            if j["action"] == "add":
                current_decisions.add(j["id"])
            elif j["action"] == "del":
                current_decisions.remove(j["id"])
        assert len(current_decisions) == 0
