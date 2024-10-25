import os
import platform
from unittest.mock import ANY, Mock, patch

from click import Command, Context, Group
from pygitguardian.models import MultiScanResult, ScanResult

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.utils.os import cd, get_os_info
from ggshield.verticals.secret import SecretScanner
from tests.unit.conftest import UNCHECKED_SECRET_PATCH


def test_cd_context_manager(tmpdir):
    prev = os.getcwd()
    assert prev != tmpdir
    with cd(tmpdir):
        assert os.getcwd() == tmpdir
    assert os.getcwd() == prev


@patch("pygitguardian.GGClient.multi_content_scan")
def test_request_headers(scan_mock: Mock, client):
    """
    GIVEN a commit to scan
    WHEN SecretScanner.scan() is called on it
    THEN GGClient.multi_content_scan() is called with the correct values for
    `extra_headers`
    """
    c = Commit.from_patch(UNCHECKED_SECRET_PATCH)

    scan_result = ScanResult(policy_break_count=0, policy_breaks=[], policies=[])
    multi_scan_result = MultiScanResult([scan_result])
    multi_scan_result.status_code = 200
    scan_mock.return_value = multi_scan_result

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
            secret_config=SecretConfig(),
        )
        scanner.scan(c.get_files(), scanner_ui=Mock())
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
