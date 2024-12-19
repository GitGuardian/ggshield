from copy import deepcopy
from unittest import mock

import click
import pytest

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from ggshield.verticals.secret.output import SecretTextOutputHandler
from ggshield.verticals.secret.output.secret_text_output_handler import (
    format_line_count_break,
)
from ggshield.verticals.secret.secret_scan_collection import group_secrets_by_ignore_sha
from tests.unit.conftest import (
    _MULTI_SECRET_ONE_LINE_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTI_SECRET_TWO_LINES_PATCH,
    _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_MULTILINE_PATCH,
    _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
)


@pytest.mark.parametrize(
    "show_secrets",
    [pytest.param(True, id="show_secrets"), pytest.param(False, id="hide_secrets")],
)
@pytest.mark.parametrize(
    "verbose",
    [pytest.param(True, id="verbose"), pytest.param(False, id="clip_long_lines")],
)
@pytest.mark.parametrize(
    "result_input",
    [
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_SIMPLE_SECRET_PATCH,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_SIMPLE_SECRET_PATCH_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_MULTI_SECRET_ONE_LINE_PATCH,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT",
        ),
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_MULTI_SECRET_TWO_LINES_PATCH,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_SIMPLE_SECRET_MULTILINE_PATCH,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result.from_scan_result(
                StringScannable(
                    content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
                    url="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan_result=_ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
                secret_config=SecretConfig(),
            ),
            id="_ONE_LINE_AND_MULTILINE_PATCH_CONTENT",
        ),
    ],
)
def test_leak_message(result_input, snapshot, show_secrets, verbose):
    # The text output includes the version of the secrets engine, but this version is
    # None until we make an API call. Since this test does not make any API call, set
    # the version to a fake value.
    with mock.patch(
        "ggshield.verticals.secret.output.secret_text_output_handler.VERSIONS"
    ) as VERSIONS:
        VERSIONS.secrets_engine_version = "3.14.159"

        secret_config = SecretConfig(show_secrets=show_secrets)
        output_handler = SecretTextOutputHandler(
            secret_config=secret_config, verbose=verbose
        )

        # _process_scan_impl() modifies its SecretScanCollection arg(!), so make a copy of it
        new_result = deepcopy(result_input)

        output = output_handler._process_scan_impl(
            SecretScanCollection(
                id="scan",
                type="test",
                results=Results(results=[new_result], errors=[]),
                optional_header="> This is an example header",
            )
        )
    # remove colors because color codes are not the same on all OSes. This is required
    # to compare the output with snapshots.
    output = click.unstyle(output)

    snapshot.assert_match(output)

    # all ignore sha should be in the output
    assert all(
        ignore_sha in output
        for ignore_sha in group_secrets_by_ignore_sha(result_input.secrets)
    )


def assert_policies_displayed(output, verbose, ignore_known_secrets, secrets):
    for secret in secrets:
        if not ignore_known_secrets or verbose:
            # All secrets are displayed no matter if they're known or not
            assert f"Secret detected: {secret.break_type}" in output
            if secret.known_secret:
                assert "Known by GitGuardian dashboard: YES" in output
                assert (
                    "https://dashboard.gitguardian.com/workspace/1/incidents/" in output
                )
            else:
                assert "Known by GitGuardian dashboard: NO" in output
                assert "Incident URL: N/A" in output
        else:
            if secret.known_secret:
                assert f"Secret detected: {secret.break_type}" not in output

    if ignore_known_secrets:
        secrets_number = sum(1 for x in secrets if not x.known_secret)
    else:
        secrets_number = len(secrets)

    if secrets_number:
        assert (
            f"{secrets_number} incident{'s' if secrets_number > 1 else ''} detected"
            in output
        )


def assert_warning_is_displayed(
    output: str,
    ignore_known_secrets: bool,
    secrets_types: str,
    known_secrets_number: int,
):
    if ignore_known_secrets and secrets_types in {
        "only_known_secrets",
        "mixed_secrets",
    }:
        plural = (
            "s ignored because they are"
            if known_secrets_number > 1
            else " ignored because it is"
        )
        assert (
            f"Warning: {known_secrets_number} secret{plural} already known by "
            "your GitGuardian dashboard and you used the "
            "`--ignore-known-secrets` option." in output
        )


def assert_no_leak_message_is_diplayed(
    output: str, ignore_known_secrets: bool, secrets_types: str
):
    if secrets_types == "no_secrets":
        assert "No secrets have been found" in output
        assert "No new secrets have been found" not in output
    elif ignore_known_secrets and secrets_types == "only_known_secrets":
        assert "No new secrets have been found" in output
        assert "No secrets have been found" not in output
    else:
        assert "No secrets have been found" not in output
        assert "No new secrets have been found" not in output


def test_format_line_count_break():
    assert format_line_count_break(5) == "\x1b[36m\x1b[22m\x1b[22m  ...\n\x1b[0m"
