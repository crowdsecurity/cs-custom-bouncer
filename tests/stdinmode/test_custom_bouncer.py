import os
import json
from signal import SIGKILL
import subprocess
import unittest
from pathlib import Path
from time import sleep
import psutil

from tests.mock_lapi import MockLAPI
from tests.utils import generate_n_decisions

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BOUNCER_BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-custom-bouncer")
CUSTOM_BINARY_PATH = SCRIPT_DIR.joinpath("custombinary")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-custom-bouncer.yaml")


class TestCustomBouncer(unittest.TestCase):
    def setUp(self):
        self.cb = subprocess.Popen([BOUNCER_BINARY_PATH, "-c", CONFIG_PATH])
        self.lapi = MockLAPI()
        self.lapi.start()
        return super().setUp()

    def tearDown(self):
        self.cb.kill()
        self.cb.wait()
        self.lapi.stop()

    def test_binary_monitor(self):
        sleep(0.5)
        bouncer_proc = psutil.Process(self.cb.pid)

        def kill_cb_proc():
            binary_proc = bouncer_proc.children()[0]
            os.kill(binary_proc.pid, SIGKILL)

        assert len(bouncer_proc.children()) == 1
        binary_proc = bouncer_proc.children()[0]
        assert binary_proc.name() == "custombinary"

        # Let's kill binary and see if it's restarted max_retry times (2)
        kill_cb_proc()
        sleep(0.5)
        assert len(bouncer_proc.children()) == 1

        kill_cb_proc()
        sleep(0.5)
        assert len(bouncer_proc.children()) == 1

        # This will exceed max_retry and the bouncer would stop
        kill_cb_proc()
        self.cb.wait()
        assert self.cb.poll() is not None

    def test_add_decisions(self):
        self.lapi.ds.insert_decisions(generate_n_decisions(5))
        sleep(0.5)
        with open("data.txt") as f:
            lines = f.readlines()
        assert len(lines) == 5
        for i, line in enumerate(lines):
            line = json.loads(line)
            assert line["id"] == i
            assert line["action"] == "add"

    def test_cache_retention(self):
        decisions = generate_n_decisions(2)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)
        with open("data.txt") as f:
            assert len(f.readlines()) == 2

    def test_delete_decisions(self):
        decisions = generate_n_decisions(5)
        self.lapi.ds.insert_decisions(decisions)
        decision_ids = list(map(lambda x: x["id"], decisions))
        sleep(0.5)
        list(map(self.lapi.ds.delete_decision_by_id, decision_ids))
        sleep(0.5)
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
