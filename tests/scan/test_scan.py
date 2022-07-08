import os
from unittest.mock import ANY, Mock, patch

from click import Command, Context, Group

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.scan import Commit
from ggshield.scan.repo import cd
from tests.conftest import _SIMPLE_SECRET


def test_cd_context_manager(tmpdir):
    prev = os.getcwd()
    assert prev != tmpdir
    with cd(tmpdir):
        assert os.getcwd() == tmpdir
    assert os.getcwd() == prev


@patch("pygitguardian.GGClient.multi_content_scan")
def test_request_headers(scan_mock: Mock, client):
    c = Commit()
    c._patch = _SIMPLE_SECRET

    with Context(Command("bar"), info_name="bar") as ctx:
        ctx.parent = Context(Group("foo"), info_name="foo")
        c.scan(
            client=client,
            cache=Cache(),
            matches_ignore={},
            mode_header="test",
        )
    scan_mock.assert_called_with(
        ANY,
        {
            "GGShield-Version": __version__,
            "GGShield-Command-Path": "foo bar",
            "mode": "test",
        },
    )
