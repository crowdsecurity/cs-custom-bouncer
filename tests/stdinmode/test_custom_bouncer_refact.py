"""
Test with a mocked LAPI and fixtures
"""

import json
import time

from tests.utils import generate_n_decisions

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


def test_cache_retention(lapi, bouncer):
    with lapi() as lp, bouncer() as cb:
        cb.wait_for_lines_fnmatch([
            "*Using API key auth*",
            "*Processing new and deleted decisions . . .*",
        ])
        decisions = generate_n_decisions(2)
        lp.ds.insert_decisions(decisions)
        time.sleep(1)
        lp.ds.insert_decisions(decisions)
        time.sleep(1)
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
        decision_ids = list(map(lambda x: x["id"], decisions))
        time.sleep(0.5)
        list(map(lp.ds.delete_decision_by_id, decision_ids))
        time.sleep(0.5)
        with open("data.txt") as f:
            lines = f.readlines()
        assert len(lines) == 10
        current_decisions = set()
        for i, line in enumerate(lines):
            line = json.loads(line)
            if line["action"] == "add":
                current_decisions.add(line["id"])
            elif line["action"] == "del":
                current_decisions.remove(line["id"])
        assert len(current_decisions) == 0
