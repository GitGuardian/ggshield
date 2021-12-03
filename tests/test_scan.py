import os
from unittest.mock import ANY, Mock, patch

from ggshield.config import Cache
from ggshield.dev_scan import cd
from ggshield.scan import Commit
from ggshield.utils import SupportedScanMode
from tests.conftest import _SIMPLE_SECRET


def test_cd_context_manager():
    prev = os.getcwd()
    target = os.path.realpath("/tmp")
    with cd(target):
        assert os.getcwd() == target
    assert os.getcwd() == prev


@patch("pygitguardian.GGClient.multi_content_scan")
def test_request_headers(scan_mock: Mock, client):
    c = Commit()
    c._patch = _SIMPLE_SECRET
    mode = SupportedScanMode.PATH

    c.scan(
        client=client,
        cache=Cache(),
        matches_ignore={},
        all_policies=True,
        verbose=False,
        mode_header=mode.value,
    )
    scan_mock.assert_called_with(ANY, {"mode": mode.value})
