from pygitguardian.models import Match

from ggshield.core.config.user_config import SecretConfig
from ggshield.verticals.secret import Results, SecretScanCollection
from ggshield.verticals.secret.output.secret_gitlab_webui_output_handler import (
    SecretGitLabWebUIOutputHandler,
    format_secret,
)
from tests.factories import SecretFactory


def test_format_secret():
    secret = SecretFactory(
        matches=[
            Match("AZERTYUIOP", "client_id", line_start=123),
            Match("abcdefghijk", "client_secret", line_start=456),
        ],
    )
    out = format_secret(secret)

    assert secret.detector_display_name in out
    assert "Validity: Valid" in out
    for match in secret.matches:
        assert match.match_type in out
        # match value itself must be obfuscated
        assert match.match not in out


def test_gitlab_web_ui_output_no_secrets():
    """
    GIVEN a content with no secret
    WHEN GitLabWebUIOutputHandler manipulates the corresponding scan
    THEN the error message is empty as expected and the status code is zero
    """
    output_handler = SecretGitLabWebUIOutputHandler(
        secret_config=SecretConfig(), verbose=False
    )
    scan = SecretScanCollection(
        id="scan",
        type="test",
        results=Results(results=[], errors=[]),
    )
    # call output handler
    exit_code = output_handler._get_exit_code(
        SecretScanCollection(
            id="outer_scan",
            type="outer_scan",
            results=Results(results=[], errors=[]),
            scans=[scan],
        )
    )
    error_msg = output_handler._process_scan_impl(scan=scan)

    assert exit_code == 0
    assert error_msg == ""
