"""
Test with a mocked LAPI and fixtures
"""

import json
import time

from tests.utils import generate_n_decisions
from .conftest import default_config

import pytest

LAPI_CONNECT_TIMEOUT = 1


def test_no_lapi(bouncer):
    with bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*connection refused*",
            "*terminating bouncer process*",
        ])


def test_binary_monitor(lapi, bouncer):
    with lapi(), bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        child = cb.wait_for_child()
        assert child.name() == "custombinary"
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

        assert cb.popen.poll() is not None


def test_add_decisions(lapi, bouncer):
    with lapi() as lp, bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        lp.ds.insert_decisions(generate_n_decisions(5))
        time.sleep(0.5)
        with open("data.txt") as f:
            lines = f.readlines()
        assert len(lines) == 5
        for i, line in enumerate(lines):
            line = json.loads(line)
            assert line["id"] == i
            assert line["action"] == "add"


def test_bin_args(lapi, bouncer, tmp_path_factory):
    data_file = tmp_path_factory.mktemp("data") / "data.txt"
    config = default_config.copy()
    config["bin_args"] = [data_file.as_posix()]

    with lapi() as lp, bouncer(config) as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        lp.ds.insert_decisions(generate_n_decisions(5))
        time.sleep(2)
        with open(data_file) as f:
            lines = f.readlines()
        assert len(lines) == 5


def test_cache_retention(lapi, bouncer):
    with lapi() as lp, bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        decisions = generate_n_decisions(2)
        lp.ds.insert_decisions(decisions)
        lp.ds.insert_decisions(decisions)
        time.sleep(.5)
        with open("data.txt") as f:
            assert len(f.readlines()) == 2


def test_delete_decisions(lapi, bouncer):
    with lapi() as lp, bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        decisions = generate_n_decisions(5)
        lp.ds.insert_decisions(decisions)
        time.sleep(0.5)
        for d in decisions:
            lp.ds.delete_decision_by_id(d["id"])
        time.sleep(0.5)
        with open("data.txt") as f:
            lines = f.readlines()
        assert len(lines) == 10
        current_decisions = set()
        for line in lines:
            line = json.loads(line)
            if line["action"] == "add":
                current_decisions.add(line["id"])
            elif line["action"] == "del":
                current_decisions.remove(line["id"])
        assert len(current_decisions) == 0
