from os import getcwd
from unittest.mock import patch

from ggshield.dev_scan import cd
from ggshield.scan import Commit
from ggshield.utils import SupportedScanMode
from tests.conftest import _SIMPLE_SECRET


def test_cd_context_manager():
    prev = getcwd()
    with cd("/tmp"):
        assert getcwd() == "/tmp"
    assert getcwd() == prev


@patch("pygitguardian.GGClient.multi_content_scan")
def test_request_headers(scan_mock, client):
    c = Commit()
    c._patch = _SIMPLE_SECRET
    mode = SupportedScanMode.PATH

    c.scan(
        client=client,
        matches_ignore={},
        all_policies=True,
        verbose=False,
        mode_header=mode.value,
    )
    assert {"mode": mode.value} in scan_mock.call_args.args
