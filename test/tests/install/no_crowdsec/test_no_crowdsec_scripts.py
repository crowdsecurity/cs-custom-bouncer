import os
from pathlib import Path

import pexpect
import pytest
import yaml

BOUNCER = "crowdsec-custom-bouncer"
CONFIG = f"/etc/crowdsec/bouncers/{BOUNCER}.yaml"


@pytest.mark.dependency
def test_install_no_crowdsec(project_repo, bouncer_binary, tmp_path, must_be_root):
    c = pexpect.spawn("/usr/bin/sh", ["scripts/install.sh"], cwd=project_repo)

    foo = tmp_path / "foo"
    foo.touch()

    c.expect("Path to your custom binary:")
    c.sendline(foo.as_posix())
    c.expect(f"Installing {BOUNCER}")
    c.expect("WARN.* cscli not found, you will need to generate an api key.")
    c.expect(f"WARN.* service not started. You need to get an API key and configure it in {CONFIG}")
    c.expect(f"The {BOUNCER} service has been installed.")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    with Path(CONFIG).open() as f:
        y = yaml.safe_load(f)
        assert y["api_key"] == "<API_KEY>"
        assert y["bin_path"] == foo.as_posix()

    assert os.path.exists(CONFIG)
    assert os.stat(CONFIG).st_mode & 0o777 == 0o600
    assert os.path.exists(f"/usr/local/bin/{BOUNCER}")
    assert os.stat(f"/usr/local/bin/{BOUNCER}").st_mode & 0o777 == 0o755

    c = pexpect.spawn("/usr/bin/sh", ["scripts/install.sh"], cwd=project_repo)

    c.expect(f"ERR.* /usr/local/bin/{BOUNCER} is already installed. Exiting")


@pytest.mark.dependency(depends=["test_install_no_crowdsec"])
def test_upgrade_no_crowdsec(project_repo, must_be_root):
    os.remove(f"/usr/local/bin/{BOUNCER}")

    c = pexpect.spawn("/usr/bin/sh", ["scripts/upgrade.sh"], cwd=project_repo)

    c.expect(f"{BOUNCER} upgraded successfully")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    assert os.path.exists(f"/usr/local/bin/{BOUNCER}")
    assert os.stat(f"/usr/local/bin/{BOUNCER}").st_mode & 0o777 == 0o755


@pytest.mark.dependency(depends=["test_upgrade_no_crowdsec"])
def test_uninstall_no_crowdsec(project_repo, must_be_root):
    c = pexpect.spawn("/usr/bin/sh", ["scripts/uninstall.sh"], cwd=project_repo)

    c.expect(f"{BOUNCER} has been successfully uninstalled")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    assert not os.path.exists(CONFIG)
    assert not os.path.exists(f"/usr/local/bin/{BOUNCER}")
