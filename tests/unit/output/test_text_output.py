from copy import deepcopy
from unittest import mock

import click
import pytest

from ggshield.core.utils import Filemode
from ggshield.output import TextOutputHandler
from ggshield.output.text.message import (
    _file_info_decoration,
    _file_info_default_decoration,
)
from ggshield.scan import File, Result, Results, ScanCollection
from ggshield.scan.scannable import CommitFile
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
    TWO_POLICY_BREAKS,
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
            Result(
                CommitFile(
                    document=_SIMPLE_SECRET_PATCH,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ),
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                CommitFile(
                    document=_MULTI_SECRET_ONE_LINE_PATCH,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                CommitFile(
                    document=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                CommitFile(
                    document=_MULTI_SECRET_TWO_LINES_PATCH,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                CommitFile(
                    document=_SIMPLE_SECRET_MULTILINE_PATCH,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
            ),
            id="_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                CommitFile(
                    document=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
                    filename="leak.txt",
                    filemode=Filemode.NEW,
                ),
                scan=_ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            ),
            id="_ONE_LINE_AND_MULTILINE_PATCH_CONTENT",
        ),
    ],
)
def test_leak_message(result_input, snapshot, show_secrets, verbose):
    # The text output includes the version of the secrets engine, but this version is
    # None until we make an API call. Since this test does not make any API call, set
    # the version to a fake value.
    with mock.patch("ggshield.output.text.message.VERSIONS") as VERSIONS:
        VERSIONS.secrets_engine_version = "3.14.159"

        output_handler = TextOutputHandler(show_secrets=show_secrets, verbose=verbose)

        # _process_scan_impl() modifies its ScanCollection arg(!), so make a copy of it
        new_result = deepcopy(result_input)

        output = output_handler._process_scan_impl(
            ScanCollection(
                id="scan",
                type="test",
                results=Results(results=[new_result], errors=[]),
                optional_header="> This is an example header",
            )
        )
    # Make output OS-independent, so that it can be safely compared to snapshots
    # regardless of the current OS:
    # - Remove colors because color codes are not the same on all OSes
    # - Replace any custom decoration with the default one
    output = click.unstyle(output).replace(
        _file_info_decoration(), _file_info_default_decoration()
    )

    snapshot.assert_match(output)


def assert_policies_displayed(output, policy_breaks):
    for policy_break in policy_breaks:
        if policy_break.known_secret:
            assert f"Known secret: {policy_break.break_type}" in output
        else:
            assert f"Secret detected: {policy_break.break_type}" in output


def assert_warning_is_displayed(output, warning_is_displayed, known_secrets_number):
    if warning_is_displayed:
        plural = (
            "s ignored because they are"
            if known_secrets_number > 1
            else " ignored because it is"
        )
        assert (
            f"Warning: {known_secrets_number} secret{plural} already known by your GitGuardian"
            f" dashboard and you used the `--ignore-known-secrets` option." in output
        )


def assert_number_of_secrets_is_displayed(output, nb_new_secrets):
    if nb_new_secrets:
        assert (
            f"{nb_new_secrets} incident{'s' if nb_new_secrets > 1 else ''} detected"
            in output
        )


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("ignore_known_secrets", [True, False])
@pytest.mark.parametrize(
    "secrets_types", ["only_new_secrets", "only_known_secrets", "mixed_secrets"]
)
def test_ignore_known_secrets(verbose, ignore_known_secrets, secrets_types):
    """
    GIVEN policy breaks
    WHEN generating text output
    THEN if ignore_known_secrets is used, do not show known secret (unless the verbose mode)
    """
    output_handler = TextOutputHandler(show_secrets=True, verbose=verbose)

    result: Result = Result(
        File(document=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT, filename="leak.txt"),
        scan=deepcopy(TWO_POLICY_BREAKS),  # 2 policy breaks
    )

    all_policy_breaks = result.scan.policy_breaks

    known_policy_breaks = []
    new_policy_breaks = all_policy_breaks

    # add known_secret for the secrets that are known, when the option is, the known_secret field is not returned
    if ignore_known_secrets:
        if secrets_types == "only_known_secrets":
            known_policy_breaks = all_policy_breaks
            new_policy_breaks = []
        elif secrets_types == "mixed_secrets":
            # set only first policy break as known
            known_policy_breaks = all_policy_breaks[:1]
            new_policy_breaks = all_policy_breaks[1:]

    for policy_break in known_policy_breaks:
        policy_break.known_secret = True

    # call output handler
    output = output_handler._process_scan_impl(
        ScanCollection(
            id="outer_scan",
            type="outer_scan",
            results=Results(results=[], errors=[]),
            scans=[
                ScanCollection(
                    id="scan",
                    type="test",
                    results=Results(results=[result], errors=[]),
                    optional_header="> This is an example header",
                )
            ],
        )
    )

    if secrets_types == "only_new_secrets" or not ignore_known_secrets:
        expected_policies_break_displayed = all_policy_breaks
        expected_warning_is_displayed = False
    else:
        expected_warning_is_displayed = True

        if verbose:
            expected_policies_break_displayed = known_policy_breaks
        else:
            if secrets_types == "only_known_secrets":
                # Do not show secrets if there are only known secrets and not in verbose mode
                expected_policies_break_displayed = []
            else:
                expected_policies_break_displayed = new_policy_breaks

    output = click.unstyle(output).replace(
        _file_info_decoration(), _file_info_default_decoration()
    )

    assert_policies_displayed(output, expected_policies_break_displayed)
    assert_warning_is_displayed(
        output, expected_warning_is_displayed, len(known_policy_breaks)
    )
    assert_number_of_secrets_is_displayed(
        output, len(expected_policies_break_displayed)
    )


@pytest.mark.parametrize("ignore_known_secrets", [True, False])
@pytest.mark.parametrize(
    "secrets_types", ["only_new_secrets", "only_known_secrets", "mixed_secrets"]
)
def test_ignore_known_secrets_exit_code(ignore_known_secrets, secrets_types):
    """
    GIVEN policy breaks
    WHEN checking for the exit code
    THEN the exit code is 1 when the new secrets are present, and 0 otherwise
    """
    output_handler = TextOutputHandler(show_secrets=True, verbose=False)

    result: Result = Result(
        File(
            document=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            filename="leak.txt",
        ),
        scan=deepcopy(TWO_POLICY_BREAKS),  # 2 policy breaks
    )

    all_policy_breaks = result.scan.policy_breaks

    known_policy_breaks = []
    new_policy_breaks = all_policy_breaks

    # add known_secret for the secrets that are known, when the option is, the known_secret field is not returned
    if ignore_known_secrets:
        if secrets_types == "only_known_secrets":
            known_policy_breaks = all_policy_breaks
            new_policy_breaks = []
        elif secrets_types == "mixed_secrets":
            # set only first policy break as known
            known_policy_breaks = all_policy_breaks[:1]
            new_policy_breaks = all_policy_breaks[1:]

    for policy_break in known_policy_breaks:
        policy_break.known_secret = True

    # call output handler
    exit_code = output_handler._get_exit_code(
        ScanCollection(
            id="outer_scan",
            type="outer_scan",
            results=Results(results=[], errors=[]),
            scans=[
                ScanCollection(
                    id="scan",
                    type="test",
                    results=Results(results=[result], errors=[]),
                    optional_header="> This is an example header",
                )
            ],
        )
    )

    expected_exit_code = len(new_policy_breaks) > 0

    assert exit_code == expected_exit_code
