"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
# import json
import signal
import subprocess
# import unittest
import time
from pathlib import Path
# from time import sleep
import psutil

import pytest

from tests.mock_lapi import MockLAPI
# from tests.utils import generate_n_decisions

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BOUNCER_BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-custom-bouncer")
CUSTOM_BINARY_PATH = SCRIPT_DIR.joinpath("custombinary")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-custom-bouncer.yaml")

# How long to wait for a child process to spawn
CHILD_SPAWN_TIMEOUT = 1

# How long to fait for the bouncer to fail when there's no LAPI
NO_LAPI_TIMEOUT = 1


class BouncerProc:
    def __init__(self, popen, outpath):
        self.popen = popen
        self.proc = psutil.Process(popen.pid)
        self.outpath = outpath

    def wait_for_child(self, timeout=CHILD_SPAWN_TIMEOUT):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            children = self.proc.children()
            if children:
                return children[0]
            time.sleep(0.1)
        raise TimeoutError("No child process found")

    def halt_children(self):
        for child in self.proc.children():
            child.kill()

    def children(self):
        return self.proc.children()

    def get_output(self):
        return pytest.LineMatcher(self.outpath.read_text().splitlines())


@pytest.fixture(scope='session')
def binary(tmp_path_factory):
    @contextlib.contextmanager
    def closure():
        # create stout and stderr files
        outdir = tmp_path_factory.mktemp("output")
        outpath = outdir / "output.txt"
        with open(outpath, "w") as f:
            cb = subprocess.Popen(
                    [BOUNCER_BINARY_PATH, "-c", CONFIG_PATH],
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    )
        try:
            yield BouncerProc(cb, outpath)
        finally:
            cb.kill()
            cb.wait()
    return closure


@pytest.fixture(scope='session')
def lapi():
    @contextlib.contextmanager
    def closure():
        lapi = MockLAPI()
        lapi.start()
        try:
            yield lapi
        finally:
            lapi.stop()
    return closure


def test_no_lapi(binary):
    with binary() as cb:
        time.sleep(NO_LAPI_TIMEOUT)
        cb.get_output().fnmatch_lines([
            "*connection refused*",
            "*terminating bouncer process*",
        ])


def test_binary_monitor(lapi, binary):
    with lapi() as lp, binary() as cb:
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

        # XXX: do we bother with wait() and poll()?



#    def setUp(self):
#        self.cb = subprocess.Popen([BOUNCER_BINARY_PATH, "-c", CONFIG_PATH])
#        self.lapi = MockLAPI()
#        self.lapi.start()
#        return super().setUp()
#
#    def tearDown(self):
#        self.cb.kill()
#        self.cb.wait()
#        self.lapi.stop()
#
#    def test_binary_monitor(self):
#        sleep(0.5)
#        bouncer_proc = psutil.Process(self.cb.pid)
#
#        def kill_cb_proc():
#            binary_proc = bouncer_proc.children()[0]
#            os.kill(binary_proc.pid, SIGKILL)
#
#        assert len(bouncer_proc.children()) == 1
#        binary_proc = bouncer_proc.children()[0]
#        assert binary_proc.name() == "custombinary"
#
#        # Let's kill binary and see if it's restarted max_retry times (2)
#        kill_cb_proc()
#        sleep(0.5)
#        assert len(bouncer_proc.children()) == 1
#
#        kill_cb_proc()
#        sleep(0.5)
#        assert len(bouncer_proc.children()) == 1
#
#        # This will exceed max_retry and the bouncer would stop
#        kill_cb_proc()
#        self.cb.wait()
#        assert self.cb.poll() is not None
#
#    def test_add_decisions(self):
#        self.lapi.ds.insert_decisions(generate_n_decisions(5))
#        sleep(0.5)
#        with open("data.txt") as f:
#            lines = f.readlines()
#        assert len(lines) == 5
#        for i, line in enumerate(lines):
#            line = json.loads(line)
#            assert line["id"] == i
#            assert line["action"] == "add"
#
#    def test_cache_retention(self):
#        decisions = generate_n_decisions(2)
#        self.lapi.ds.insert_decisions(decisions)
#        sleep(1)
#        self.lapi.ds.insert_decisions(decisions)
#        sleep(1)
#        with open("data.txt") as f:
#            assert len(f.readlines()) == 2
#
#    def test_delete_decisions(self):
#        decisions = generate_n_decisions(5)
#        self.lapi.ds.insert_decisions(decisions)
#        decision_ids = list(map(lambda x: x["id"], decisions))
#        sleep(0.5)
#        list(map(self.lapi.ds.delete_decision_by_id, decision_ids))
#        sleep(0.5)
#        with open("data.txt") as f:
#            lines = f.readlines()
#        assert len(lines) == 10
#        current_decisions = set()
#        for i, line in enumerate(lines):
#            line = json.loads(line)
#            if line["action"] == "add":
#                current_decisions.add(line["id"])
#            elif line["action"] == "del":
#                current_decisions.remove(line["id"])
#        assert len(current_decisions) == 0
