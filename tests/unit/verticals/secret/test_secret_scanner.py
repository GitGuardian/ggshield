import platform
from collections import namedtuple
from unittest.mock import ANY, Mock, patch

import click
import pytest
from click import Command, Context, Group
from pygitguardian.models import (
    APITokensResponse,
    Detail,
    Match,
    MultiScanResult,
    PolicyBreak,
    ScanResult,
)

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import (
    ExitCode,
    MissingScopesError,
    QuotaLimitReachedError,
    UnexpectedError,
)
from ggshield.core.scan import (
    Commit,
    DecodeError,
    ScanContext,
    ScanMode,
    Scannable,
    StringScannable,
)
from ggshield.core.scanner_ui.scanner_ui import ScannerUI
from ggshield.utils.git_shell import Filemode
from ggshield.utils.os import get_os_info
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.secret_scanner import handle_scan_chunk_error
from tests.unit.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _SIMPLE_SECRET_TOKEN,
    API_TOKENS_RESPONSE_SCAN_CREATE_INCIDENTS_SCOPES,
    API_TOKENS_RESPONSE_SCAN_SCOPES,
    GG_TEST_TOKEN,
    UNCHECKED_SECRET_PATCH,
    my_vcr,
)


ExpectedScan = namedtuple(
    "expectedScan", ("exit_code", "matches", "first_match", "want")
)
_EXPECT_NO_SECRET = {
    "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
    "filename": "commit://patch/test",
    "filemode": Filemode.NEW,
}


@pytest.mark.parametrize(
    "name,input_patch,expected",
    [
        (
            "multiple_secrets",
            _MULTIPLE_SECRETS_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS, matches=4, first_match="", want=None
            ),
        ),
        (
            "simple_secret",
            UNCHECKED_SECRET_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS,
                matches=1,
                first_match=GG_TEST_TOKEN,
                want=None,
            ),
        ),
        (
            "one_line_and_multiline_patch",
            _ONE_LINE_AND_MULTILINE_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS, matches=1, first_match=None, want=None
            ),
        ),
        (
            "no_secret",
            _NO_SECRET_PATCH,
            ExpectedScan(
                exit_code=0, matches=0, first_match=None, want=_EXPECT_NO_SECRET
            ),
        ),
    ],
    ids=[
        "_MULTIPLE_SECRETS",
        "_SIMPLE_SECRET",
        "_ONE_LINE_AND_MULTILINE_PATCH",
        "_NO_SECRET",
    ],
)
def test_scan_patch(client, cache, name: str, input_patch: str, expected: ExpectedScan):
    commit = Commit.from_patch(input_patch)

    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            secret_config=SecretConfig(),
        )
        results = scanner.scan(commit.get_files(), scanner_ui=Mock())
        for result in results.results:
            if result.secrets:
                assert len(result.secrets[0].matches) == expected.matches
                if expected.first_match:
                    assert result.secrets[0].matches[0].match == expected.first_match
            else:
                assert result.secrets == []

            if expected.want:
                assert result.filename == expected.want["filename"]
                assert result.filemode == expected.want["filemode"]


@pytest.mark.parametrize(
    "unscannable_type",
    [
        "EMPTY",
        "TOO_BIG",
        "BINARY",
        "FILE_NOT_FOUND",
    ],
)
def test_scanner_skips_unscannable_files(client, fs, cache, unscannable_type: str):
    """
    GIVEN a Scannable which is not scannable
    WHEN Scanner.scan() is called on it
    THEN it skips it
    AND the progress callback is called
    """
    mock = Mock(spec=Scannable)
    if unscannable_type == "EMPTY":
        mock.is_longer_than.return_value = False
        mock.content = ""
    elif unscannable_type == "TOO_BIG":
        mock.is_longer_than.return_value = True
    elif unscannable_type == "BINARY":
        mock.is_longer_than.side_effect = DecodeError
    elif unscannable_type == "FILE_NOT_FOUND":
        mock.is_longer_than.side_effect = FileNotFoundError

    scanner_ui = Mock(spec=ScannerUI)

    scanner = SecretScanner(
        client=client,
        cache=cache,
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="external",
        ),
        check_api_key=False,
        secret_config=SecretConfig(),
    )
    scanner.scan([mock], scanner_ui=scanner_ui)

    scanner_ui.on_skipped.assert_called_once()


def test_handle_scan_error_api_key():
    detail = Detail("Invalid GitGuardian API key.")
    detail.status_code = 401
    with pytest.raises(click.UsageError):
        handle_scan_chunk_error(detail, [])


@pytest.mark.parametrize(
    "detail, status_code, chunk",
    [
        pytest.param(
            Detail("Too many documents to scan"),
            400,
            [StringScannable(content="", url="/example") for _ in range(21)],
            id="too many documents",
        ),
        pytest.param(
            Detail(
                "[\"filename:: [ErrorDetail(string='Ensure this field has no more than 256 characters.', code='max_length')]\", '', '', '']"  # noqa
            ),
            400,
            [
                StringScannable(
                    content="still valid", url="/home/user/too/long/file/name"
                ),
                StringScannable(content="", url="valid"),
                StringScannable(content="", url="valid"),
                StringScannable(content="", url="valid"),
            ],
            id="single file exception",
        ),
    ],
)
def test_handle_scan_error(detail, status_code, chunk, capsys, snapshot):
    detail.status_code = status_code
    handle_scan_chunk_error(detail, chunk)
    captured = capsys.readouterr()
    assert captured.err == snapshot


def test_scan_source_uuid_not_found():
    detail = Detail(detail="Source not found.", status_code=400)
    with pytest.raises(UnexpectedError):
        handle_scan_chunk_error(detail, Mock())


def test_handle_scan_quota_limit_reached():
    detail = Detail(detail="Quota limit reached.", status_code=403)
    with pytest.raises(QuotaLimitReachedError):
        handle_scan_chunk_error(detail, Mock())


def test_scan_merge_commit(client, cache):
    """
    GIVEN a merge commit in which a secret was inserted
    WHEN it is scanned
    THEN the secret is found
    """
    commit = Commit.from_patch(
        f"""
commit ca68e177596982fa38f181aa9944340a359748d2
Merge: 2c023f8 502d03c
Author: Aurelien Gateau <aurelien.gateau@gitguardian.com>
Date:   Thu Sep 5 18:39:58 2024 +0200

    Merge branch 'feature'
\0::100644 100644 100644 7601807 5716ca5 8c27e55 MM\0f\0\0diff --cc f
index 7601807,5716ca5..8c27e55
--- a/f
+++ b/f
@@@ -1,1 -1,1 +1,2 @@@
- baz
 -bar
++username=owly
++password={_SIMPLE_SECRET_TOKEN}
"""
    )

    with my_vcr.use_cassette("test_scan_merge_commit"):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            secret_config=SecretConfig(),
        )
        results = scanner.scan(commit.get_files(), scanner_ui=Mock())
        secrets = results.results[0].secrets
        assert len(secrets) == 1

        matches = {m.match_type: m.match for m in secrets[0].matches}
        assert matches["username"] == "owly"
        assert matches["password"] == _SIMPLE_SECRET_TOKEN


@pytest.mark.parametrize(
    "api_response, expected_exception, message",
    [
        (
            Detail(detail="Unexpected response"),
            UnexpectedError,
            "Unexpected response",
        ),
        (
            APITokensResponse.from_dict(API_TOKENS_RESPONSE_SCAN_SCOPES),
            MissingScopesError,
            "Token is missing the required scope incidents:read to perform this operation.",
        ),
    ],
)
def test_with_incident_details_error(
    monkeypatch, client, cache, api_response, expected_exception, message
):
    monkeypatch.setattr(client, "read_metadata", Mock(return_value=None))
    monkeypatch.setattr(client, "api_tokens", Mock(return_value=api_response))
    with pytest.raises(expected_exception) as exc_info:
        SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            check_api_key=True,
            secret_config=SecretConfig(with_incident_details=True),
        )
        assert message in str(exc_info.value)


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
            "scan_options": ANY,
        },
        all_secrets=True,
    )


@pytest.mark.parametrize("ignore_known_secrets", (True, False))
@patch("pygitguardian.GGClient.multi_content_scan")
def test_scan_ignore_known_secrets(scan_mock: Mock, client, ignore_known_secrets):
    """
    GIVEN a call multi_content_scan returning two policy breaks, one known and the other unknown
    WHEN -
    THEN the known policy break is ignored iff ignore_known_secrets is True
    """
    scannable = StringScannable(url="localhost", content="known\nunknown")
    known_secret = PolicyBreak(
        break_type="known",
        policy="Secrets detection",
        detector_name="known",
        detector_group_name="known",
        documentation_url=None,
        validity="valid",
        known_secret=True,
        matches=[
            Match(
                match="known",
                match_type="apikey",
                line_start=0,
                line_end=0,
                index_start=0,
                index_end=1,
            )
        ],
    )
    unknown_secret = PolicyBreak(
        break_type="unknown",
        policy="Secrets detection",
        detector_name="unknown",
        detector_group_name="unknown",
        documentation_url=None,
        validity="valid",
        known_secret=False,
        matches=[
            Match(
                match="unknown",
                match_type="apikey",
                line_start=0,
                line_end=0,
                index_start=0,
                index_end=1,
            )
        ],
    )

    scan_result = ScanResult(
        policy_break_count=1, policy_breaks=[known_secret, unknown_secret], policies=[]
    )
    multi_scan_result = MultiScanResult([scan_result])
    multi_scan_result.status_code = 200
    scan_mock.return_value = multi_scan_result

    scanner = SecretScanner(
        client=client,
        cache=Cache(),
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield",
        ),
        check_api_key=False,
        secret_config=SecretConfig(ignore_known_secrets=ignore_known_secrets),
    )
    results = scanner.scan([scannable], scanner_ui=Mock())

    if ignore_known_secrets:
        assert [
            pbreak.detector_display_name for pbreak in results.results[0].secrets
        ] == ["unknown"]
    else:
        assert [
            pbreak.detector_display_name for pbreak in results.results[0].secrets
        ] == [
            "known",
            "unknown",
        ]


@patch("pygitguardian.GGClient.multi_content_scan")
def test_scan_unexpected_error(scan_mock: Mock, client):
    """
    GIVEN a call multi_content_scan raising an exception
    WHEN calling scanner.scan
    THEN an UnexpectedError is raised
    """
    scannable = StringScannable(url="localhost", content="known\nunknown")

    scan_mock.side_effect = Exception("dummy")

    scanner = SecretScanner(
        client=client,
        cache=Cache(),
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield",
        ),
        check_api_key=False,
        secret_config=SecretConfig(),
    )
    with pytest.raises(UnexpectedError, match="Scanning failed.*"):
        scanner.scan([scannable], scanner_ui=Mock())


@patch("pygitguardian.GGClient.multi_content_scan")
def test_all_secrets_is_used(scan_mock: Mock, client):
    """
    GIVEN one secret ignored in backend, and one not ignored
    WHEN calling scanner.scan with the all_secrets option set to False
    THEN secrets excluded by the backend are ignored
    """
    scannable = StringScannable(url="localhost", content="known\nunknown")
    matches = [
        Match(
            match="known",
            match_type="apikey",
            line_start=0,
            line_end=0,
            index_start=0,
            index_end=1,
        )
    ]
    secret = PolicyBreak(
        break_type="not-excluded",
        policy="Secrets detection",
        detector_name="not-excluded",
        detector_group_name="not-excluded",
        documentation_url=None,
        validity="valid",
        matches=matches,
    )
    excluded_secret = PolicyBreak(
        break_type="excluded",
        policy="Secrets detection",
        detector_name="excluded",
        detector_group_name="excluded",
        documentation_url=None,
        validity="valid",
        matches=matches,
        is_excluded=True,
        exclude_reason="dummy",
    )

    scan_result = ScanResult(
        policy_break_count=1, policy_breaks=[secret, excluded_secret], policies=[]
    )
    multi_scan_result = MultiScanResult([scan_result])
    multi_scan_result.status_code = 200
    scan_mock.return_value = multi_scan_result

    scanner = SecretScanner(
        client=client,
        cache=Cache(),
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield",
        ),
        check_api_key=False,
        secret_config=SecretConfig(),
    )
    results = scanner.scan([scannable], scanner_ui=Mock())
    assert [pbreak.detector_display_name for pbreak in results.results[0].secrets] == [
        "not-excluded"
    ]


@patch("pygitguardian.GGClient.api_tokens")
@patch("pygitguardian.GGClient.scan_and_create_incidents")
def test_source_uuid_is_used(
    scan_and_create_incidents_mock: Mock, api_tokens_mock: Mock, client
):
    """
    GIVEN a source_uuid is provided in the secret config
    WHEN calling scanner.scan
    THEN scan_and_create_incidents is called with the correct source_uuid
    """
    scannable = StringScannable(url="localhost", content="test content")
    source_uuid = "test-source-uuid"

    api_tokens_mock.return_value = APITokensResponse.from_dict(
        API_TOKENS_RESPONSE_SCAN_CREATE_INCIDENTS_SCOPES
    )
    scan_result = ScanResult(policy_break_count=0, policy_breaks=[], policies=[])
    multi_scan_result = MultiScanResult([scan_result])
    multi_scan_result.status_code = 200
    scan_and_create_incidents_mock.return_value = multi_scan_result

    scanner = SecretScanner(
        client=client,
        cache=Cache(),
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield",
        ),
        check_api_key=False,
        secret_config=SecretConfig(source_uuid=source_uuid),
    )
    scanner.scan([scannable], scanner_ui=Mock())

    scan_and_create_incidents_mock.assert_called_once()
    args, _ = scan_and_create_incidents_mock.call_args
    assert args[1] == source_uuid


@pytest.mark.parametrize(
    "api_response, expected_exception, message",
    [
        (
            Detail(detail="Unexpected response"),
            UnexpectedError,
            "Unexpected response",
        ),
        (
            APITokensResponse.from_dict(API_TOKENS_RESPONSE_SCAN_SCOPES),
            MissingScopesError,
            "Token is missing the required scope scan:create_incidents to perform this operation.",
        ),
    ],
)
def test_with_source_uuid_error(
    monkeypatch, client, cache, api_response, expected_exception, message
):
    """
    GIVEN a source_uuid is provided in the secret config
    WHEN creating a SecretScanner with check_api_key=True
    AND the token scope check fails
    THEN a correct error is raised during check_client_api_key
    """
    monkeypatch.setattr(
        client, "read_metadata", Mock(return_value=None)
    )  # Success for API key check
    monkeypatch.setattr(client, "api_tokens", Mock(return_value=api_response))
    with pytest.raises(expected_exception) as exc_info:
        SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            check_api_key=True,  # This will trigger check_client_api_key with source_uuid
            secret_config=SecretConfig(source_uuid="test-uuid"),
        )
        assert message in str(exc_info.value)
