import os
import platform
from unittest.mock import ANY, Mock, patch

from click import Command, Context, Group

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.scan import Commit, ScanContext, ScanMode, SecretScanner
from ggshield.scan.repo import cd
from ggshield.scan.scan_context import get_os_info
from tests.unit.conftest import UNCHECKED_SECRET_PATCH


def test_cd_context_manager(tmpdir):
    prev = os.getcwd()
    assert prev != tmpdir
    with cd(tmpdir):
        assert os.getcwd() == tmpdir
    assert os.getcwd() == prev


@patch("pygitguardian.GGClient.multi_content_scan")
def test_request_headers(scan_mock: Mock, client):
    c = Commit()
    c._patch = UNCHECKED_SECRET_PATCH

    with Context(Command("bar"), info_name="bar") as ctx:
        os_name, os_version = get_os_info()
        ctx.parent = Context(Group("foo"), info_name="foo")
        scanner = SecretScanner(
            client=client,
            cache=Cache(),
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path=ctx.command_path,
            ),
            check_api_key=False,
        )
        scanner.scan(c.files)
    scan_mock.assert_called_with(
        ANY,
        {
            "GGShield-Version": __version__,
            "GGShield-Command-Path": "foo bar",
            "GGShield-Command-Id": ANY,
            "GGShield-OS-Name": os_name,
            "GGShield-OS-Version": os_version,
            "GGShield-Python-Version": platform.python_version(),
            "mode": "path",
        },
        ignore_known_secrets=True,
    )
