from copy import deepcopy

import pytest
from pygitguardian.models import Match, PolicyBreak

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import StringScannable
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from ggshield.verticals.secret.output.secret_gitlab_webui_output_handler import (
    SecretGitLabWebUIOutputHandler,
    format_policy_break,
)
from tests.unit.conftest import _ONE_LINE_AND_MULTILINE_PATCH_CONTENT, TWO_POLICY_BREAKS


def test_format_policy_break():
    policy = PolicyBreak(
        "PayPal",
        "Secrets detection",
        "valid",
        [
            Match("AZERTYUIOP", "client_id", line_start=123),
            Match("abcdefghijk", "client_secret", line_start=456),
        ],
    )
    out = format_policy_break(policy)

    assert policy.break_type in out
    assert "Validity: Valid" in out
    for match in policy.matches:
        assert match.match_type in out
        # match value itself must be obfuscated
        assert match.match not in out


@pytest.mark.parametrize("ignore_known_secrets", [True, False])
def test_gitlab_web_ui_output_no_secrets(ignore_known_secrets):
    """
    GIVEN a content with no secret
    WHEN GitLabWebUIOutputHandler manipulates the corresponding scan
    THEN the error message is empty as expected and the status code is zero
    """
    secret_config = SecretConfig(
        show_secrets=True, ignore_known_secrets=ignore_known_secrets
    )
    output_handler = SecretGitLabWebUIOutputHandler(
        secret_config=secret_config, verbose=False
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


@pytest.mark.parametrize("ignore_known_secrets", [True, False])
@pytest.mark.parametrize(
    "secrets_types",
    ["only_new_secrets", "only_known_secrets", "mixed_secrets"],
)
def test_gitlab_web_ui_output_ignore_known_secrets(secrets_types, ignore_known_secrets):
    """
    GIVEN a content with secrets
    WHEN GitLabWebUIOutputHandler manipulates the corresponding scan
    THEN the error message warns about secrets or about only new secrets depending
    on the ignore_known_secrets parameter
    """
    result: Result = Result(
        StringScannable(content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT, url="leak.txt"),
        scan=deepcopy(TWO_POLICY_BREAKS),  # 2 policy breaks
    )

    all_policy_breaks = result.scan.policy_breaks

    if secrets_types == "only_known_secrets":
        known_policy_breaks = all_policy_breaks
        new_policy_breaks = []
    elif secrets_types == "mixed_secrets":
        # set only first policy break as known
        known_policy_breaks = all_policy_breaks[:1]
        new_policy_breaks = all_policy_breaks[1:]
    else:
        known_policy_breaks = []
        new_policy_breaks = all_policy_breaks

    for index, policy_break in enumerate(known_policy_breaks):
        policy_break.known_secret = True
        policy_break.incident_url = (
            f"https://dashboard.gitguardian.com/workspace/1/incidents/{index}"
        )

    secret_config = SecretConfig(
        show_secrets=True, ignore_known_secrets=ignore_known_secrets
    )
    output_handler = SecretGitLabWebUIOutputHandler(
        secret_config=secret_config, verbose=False
    )
    output = output_handler._process_scan_impl(
        SecretScanCollection(
            id="outer_scan",
            type="outer_scan",
            results=Results(results=[], errors=[]),
            scans=[
                SecretScanCollection(
                    id="scan",
                    type="test",
                    results=Results(
                        results=[result],
                        errors=[],
                    ),
                )
            ],
        )
    )
    if ignore_known_secrets:
        if len(new_policy_breaks):
            assert f"ggshield found {len(new_policy_breaks)} new" in output
        else:
            assert output == ""
    else:
        assert f"ggshield found {len(all_policy_breaks)}" in output
