"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
import subprocess
import time
from pathlib import Path
import psutil

import pytest
import yaml

from pytest_cs import WaiterGenerator

from tests.mock_lapi import MockLAPI

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BOUNCER_BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-custom-bouncer")

# How long to wait for a child process to spawn
CHILD_SPAWN_TIMEOUT = 1

default_config = {
    'bin_path': 'tests/stdinmode/custombinary',
    # Invokes binary once and feeds incoming decisions to its stdin.
    'feed_via_stdin': True,
    # number of times to restart binary. relevant if feed_via_stdin=true.
    # Set to -1 for infinite retries.
    'total_retries': 2,
    # ignore IPs banned for triggering scenarios not containing either
    # of provided words, eg ["ssh", "http"]
    'scenarios_containing': [],
    # ignore IPs banned for triggering scenarios
    # containing either of provided words
    'scenarios_not_containing': [],
    'origins': [],
    'piddir': '/var/run/',
    'update_frequency': '0.1s',
    'cache_retention_duration': '10s',
    'daemonize': False,
    'log_mode': 'stdout',
    'log_dir': '/var/log/',
    'log_level': 'debug',
    'api_url': 'http://localhost:8081/',
    'api_key': '1237adaf7a1724ac68a3288828820a67',

    'prometheus': {
        'enabled': False,
        'listen_addr': '127.0.0.1',
        'listen_port': '60602'
    }
}


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
    def closure(config=None):
        if config is None:
            config = default_config
        # create stout and stderr files
        outdir = tmp_path_factory.mktemp("output")
        confpath = outdir / "crowdsec-custom-bouncer.yaml"
        with open(confpath, "w") as f:
            f.write(yaml.dump(config))
        outpath = outdir / "output.txt"
        with open(outpath, "w") as f:
            cb = subprocess.Popen(
                    [BOUNCER_BINARY_PATH, "-c", confpath.as_posix()],
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
