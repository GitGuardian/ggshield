import os
from unittest.mock import ANY, Mock, patch

from click import Command, Context, Group

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.core.utils import ScanContext, ScanMode
from ggshield.scan import Commit
from ggshield.scan.repo import cd
from tests.conftest import UNCHECKED_SECRET_PATCH


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
        ctx.parent = Context(Group("foo"), info_name="foo")
        c.scan(
            client=client,
            cache=Cache(),
            matches_ignore={},
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path=ctx.command_path,
            ),
        )
    scan_mock.assert_called_with(
        ANY,
        {
            "GGShield-Version": __version__,
            "GGShield-Command-Path": "foo bar",
            "GGShield-Command-Id": ANY,
            "mode": "path",
        },
    )
