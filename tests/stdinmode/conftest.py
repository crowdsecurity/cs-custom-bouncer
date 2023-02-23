"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
# import json
import subprocess
# import unittest
import time
from pathlib import Path
# from time import sleep
import psutil

import pytest

from pytest_cs import WaiterGenerator

from tests.mock_lapi import MockLAPI
# from tests.utils import generate_n_decisions

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BOUNCER_BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-custom-bouncer")
# CUSTOM_BINARY_PATH = SCRIPT_DIR.joinpath("custombinary")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-custom-bouncer.yaml")

# How long to wait for a child process to spawn
CHILD_SPAWN_TIMEOUT = 1


class ProcessWaiterGenerator(WaiterGenerator):
    def __init__(self, proc):
        self.proc = proc
        super().__init__()

    def context(self):
        return self.proc


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

    def wait_for_lines_fnmatch(proc, s, timeout=5):
        for waiter in ProcessWaiterGenerator(proc):
            with waiter as p:
                p.get_output().fnmatch_lines(s)


@pytest.fixture(scope='session')
def bouncer(tmp_path_factory):
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
