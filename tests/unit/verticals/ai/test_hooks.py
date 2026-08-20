import errno
import json
import os
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set
from unittest.mock import MagicMock, patch

import pytest
from pygitguardian import GGClient
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES, MAXIMUM_PAYLOAD_SIZE
from pygitguardian.models import MCPActivityResponse, MultiScanResult
from pygitguardian.models import ScanResult as ApiScanResult

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan import File, ScanContext, ScanMode, StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.ai.agents import (
    Agent,
    Claude,
    Codex,
    Copilot,
    Cursor,
    Vibe,
    VSCode,
)
from ggshield.verticals.ai.cache import (
    _verdict_cache_path,
    has_clean_verdict,
    verdict_key,
)
from ggshield.verticals.ai.hooks import (
    AIHookScanner,
    _send_desktop_notification,
    build_agent_headers,
    find_filepaths,
    has_already_been_seen,
    parse_hook_input,
)
from ggshield.verticals.ai.mcp import send_mcp_activity
from ggshield.verticals.ai.models import EventType, HookPayload, HookResult, Tool
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.secret_scan_collection import IgnoreKind
from ggshield.verticals.secret.secret_scan_collection import Result as ScanResult
from ggshield.verticals.secret.secret_scan_collection import Results, Secret
from tests.conftest import skipwindows


INSTANCE = "https://api.example.com"
API_KEY = "some-api-key"


def _dummy_payload(event_type: EventType = EventType.OTHER) -> HookPayload:
    return HookPayload(
        event_type=event_type,
        tool=None,
        content="",
        identifier="",
        agent=Cursor(),
        raw={},
    )


@pytest.fixture
def tmp_file(tmp_path: Path) -> Path:
    """Create a temporary file with content."""
    file = tmp_path / "test.txt"
    file.write_text("this is the content")
    return file


def _mock_scanner(
    matches: List[str],
    secret_config: Optional[SecretConfig] = None,
    ignored_secrets_count_by_kind: Optional[Counter] = None,
) -> MagicMock:
    """Create a mock SecretScanner that returns the given Results from scan()."""
    mock = MagicMock(spec=SecretScanner)
    mock.client = MagicMock(spec=GGClient)
    # Annotation-only attributes on GGClient, so spec= does not provide them,
    # and the verdict cache key needs both.
    mock.client.base_uri = INSTANCE
    mock.client.api_key = API_KEY
    # Set in SecretScanner.__init__, so spec= does not provide it either.
    mock.secret_config = secret_config or SecretConfig()

    def scan(scannables, scanner_ui=None, **kwargs):
        # Answers about the first document sent, carrying its url (all a
        # single-payload test needs).
        first = list(scannables)[0]
        return Results(
            results=[
                ScanResult(
                    filename=first.filename,
                    filemode=Filemode.FILE,
                    path=Path("."),
                    url=first.url,
                    secrets=[_make_secret(match) for match in matches],
                    ignored_secrets_count_by_kind=(
                        ignored_secrets_count_by_kind or Counter()
                    ),
                )
            ],
            errors=[],
        )

    mock.scan.side_effect = scan
    return mock


def _make_secret(
    match_str: str = "***",
    known_secret: bool = False,
    incident_url: Optional[str] = None,
):
    """Minimal Secret for tests; _message_from_secrets only uses
    detector_display_name, validity, matches[].match, matches[].match_type,
    known_secret and incident_url."""
    mock_match = MagicMock()
    mock_match.match = match_str
    # get_ignore_sha() hashes "<match>,<match_type>": a MagicMock would hash its
    # repr, unique per instance, and the sha reaches the message.
    mock_match.match_type = "client_secret"
    return Secret(
        detector_display_name="dummy-detector",
        detector_name="dummy-detector",
        detector_group_name=None,
        documentation_url=None,
        validity="valid",
        known_secret=known_secret,
        incident_url=incident_url,
        matches=[mock_match],
        ignore_reason=None,
        diff_kind=None,
        is_vaulted=False,
        vault_type=None,
        vault_name=None,
        vault_path=None,
        vault_path_count=None,
    )


class TestAIHookScannerScanContent:
    """Unit tests for AIHookScanner._scan_content."""

    def test_no_secrets_returns_allow(self):
        """When scanner returns no secrets, result has block=False and nbr_secrets=0."""
        hook_scanner = AIHookScanner(_mock_scanner([]))
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="safe content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is False
        assert result.nbr_secrets == 0
        assert result.message == ""

    def test_with_secrets_returns_block_and_message(self):
        """When scanner returns secrets, result has block=True, nbr_secrets and message set."""
        hook_scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="content with sk-xxx",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is True
        assert result.nbr_secrets == 1
        assert "dummy-detector" in result.message
        assert "secret" in result.message.lower()
        assert "remove the secret from your prompt" in result.message


class TestVerdictCacheShortCircuit:
    """The clean-verdict cache must skip the API call, and only when it is safe to."""

    @staticmethod
    def _payload(
        content: str = "safe content", identifier: str = "id", **kwargs
    ) -> HookPayload:
        return HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content=content,
            identifier=identifier,
            agent=Cursor(),
            raw={},
            **kwargs,
        )

    @staticmethod
    def _key(content: str = "safe content") -> str:
        # A payload with no tool becomes a StringScannable whose filename is the
        # payload identifier.
        return verdict_key(INSTANCE, API_KEY, SecretConfig(), "id", content)

    def test_second_scan_of_identical_content_skips_the_api(self):
        """GIVEN a clean scan WHEN the same content is scanned again THEN no API call."""
        mock_scanner = _mock_scanner([])
        hook_scanner = AIHookScanner(mock_scanner)
        assert hook_scanner._scan_content(self._payload()).block is False
        assert hook_scanner._scan_content(self._payload()).block is False
        mock_scanner.scan.assert_called_once()

    def test_different_content_still_hits_the_api(self):
        """A cached verdict must not leak onto different content."""
        mock_scanner = _mock_scanner([])
        hook_scanner = AIHookScanner(mock_scanner)
        hook_scanner._scan_content(self._payload("safe content"))
        hook_scanner._scan_content(self._payload("other content"))
        assert mock_scanner.scan.call_count == 2

    def test_pre_and_post_tool_use_of_a_read_share_one_api_call(self):
        """Both Read events resolve to the same file, so the second is served locally."""
        mock_scanner = _mock_scanner([])
        hook_scanner = AIHookScanner(mock_scanner)
        pre = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": __file__},
                "cursor_version": "1.2.3",
            }
        )
        post = json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": __file__},
                "tool_response": {"file": {"filePath": __file__}},
                "cursor_version": "1.2.3",
            }
        )
        assert hook_scanner.scan(pre) == 0
        assert hook_scanner.scan(post) == 0
        mock_scanner.scan.assert_called_once()

    def test_scan_with_secrets_is_not_cached(self):
        """A blocking verdict is never remembered as clean."""
        mock_scanner = _mock_scanner(["sk-xxx"])
        hook_scanner = AIHookScanner(mock_scanner)
        assert hook_scanner._scan_content(self._payload("content sk-xxx")).block is True
        assert not has_clean_verdict(self._key("content sk-xxx"))

    def test_degraded_scan_is_not_cached(self):
        """A scan that returned no Result at all is not a verdict, so it is not cached."""
        mock_scanner = _mock_scanner([])
        mock_scanner.scan.side_effect = lambda *args, **kwargs: Results(
            results=[], errors=[]
        )
        hook_scanner = AIHookScanner(mock_scanner)
        assert hook_scanner._scan_content(self._payload()).block is False
        assert not has_clean_verdict(self._key())
        # ... and the next identical payload is scanned again.
        hook_scanner._scan_content(self._payload())
        assert mock_scanner.scan.call_count == 2

    def test_locally_filtered_verdict_is_not_cached(self):
        """The API reported secrets and the local config dropped them: that "clean"
        answer belongs to this config only, so it must not be remembered."""
        mock_scanner = _mock_scanner(
            [],
            ignored_secrets_count_by_kind=Counter({IgnoreKind.IGNORED_DETECTOR: 1}),
        )
        hook_scanner = AIHookScanner(mock_scanner)
        assert hook_scanner._scan_content(self._payload()).block is False
        assert not has_clean_verdict(self._key())
        hook_scanner._scan_content(self._payload())
        assert mock_scanner.scan.call_count == 2

    def test_another_instance_or_token_does_not_reuse_the_verdict(self):
        """Custom detectors and dashboard exclusions are per-workspace."""
        mock_scanner = _mock_scanner([])
        AIHookScanner(mock_scanner)._scan_content(self._payload())
        for attribute, value in (
            ("base_uri", "https://other.example.com"),
            ("api_key", "other-key"),
        ):
            other = _mock_scanner([])
            setattr(other.client, attribute, value)
            AIHookScanner(other)._scan_content(self._payload())
            other.scan.assert_called_once()

    def test_another_secret_config_does_not_reuse_the_verdict(self):
        """filename_only changes the document we send, so the verdict is not reusable."""
        AIHookScanner(_mock_scanner([]))._scan_content(self._payload())
        other = _mock_scanner([], SecretConfig(filename_only=True))
        AIHookScanner(other)._scan_content(self._payload())
        other.scan.assert_called_once()

    def test_same_content_under_another_filename_is_rescanned(self):
        """The filename is part of the document we send, so it is part of the key."""
        mock_scanner = _mock_scanner([])
        hook_scanner = AIHookScanner(mock_scanner)
        hook_scanner._scan_content(self._payload())
        hook_scanner._scan_content(self._payload(identifier="other-id"))
        assert mock_scanner.scan.call_count == 2

    @skipwindows
    def test_untrustworthy_cache_falls_back_to_scanning(self):
        """A world-writable cache is ignored, so the hook scans rather than allows."""
        mock_scanner = _mock_scanner([])
        hook_scanner = AIHookScanner(mock_scanner)
        hook_scanner._scan_content(self._payload())
        _verdict_cache_path().chmod(0o666)
        hook_scanner._scan_content(self._payload())
        assert mock_scanner.scan.call_count == 2


def _scanner_per_document(
    secrets_by_url: Optional[Dict[str, List[str]]] = None,
    skipped_urls: Set[str] = frozenset(),
    ignored_urls: Set[str] = frozenset(),
    reverse: bool = False,
) -> MagicMock:
    """A scanner answering one result per document, keyed by url.

    `skipped_urls` documents get no result at all; `reverse` returns results in
    another order than they were sent.
    """
    secrets_by_url = secrets_by_url or {}
    mock = _mock_scanner([])

    def scan(scannables, scanner_ui=None, **kwargs):
        results = [
            ScanResult(
                filename=scannable.filename,
                filemode=Filemode.FILE,
                path=Path("."),
                url=scannable.url,
                secrets=[
                    _make_secret(match)
                    for match in secrets_by_url.get(scannable.url, [])
                ],
                ignored_secrets_count_by_kind=(
                    Counter({IgnoreKind.IGNORED_DETECTOR: 1})
                    if scannable.url in ignored_urls
                    else Counter()
                ),
            )
            for scannable in scannables
            if scannable.url not in skipped_urls
        ]
        return Results(
            results=list(reversed(results)) if reverse else results, errors=[]
        )

    mock.scan.side_effect = scan
    return mock


def _scanned_urls(mock_scanner: MagicMock, call: int = 0) -> List[str]:
    """The urls of the documents sent to the API on the `call`-th scan."""
    return [scannable.url for scannable in mock_scanner.scan.call_args_list[call][0][0]]


class TestBatchedPayloadScan:
    """Several payloads of one event cost one API call, not one each, and block on
    the payload that holds a secret.
    """

    @staticmethod
    def _payload(identifier: str, content: str = "some content") -> HookPayload:
        return HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content=content,
            identifier=identifier,
            agent=Cursor(),
            raw={},
        )

    @staticmethod
    def _read_payload(path: Path) -> HookPayload:
        return HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="",
            identifier=str(path),
            agent=Cursor(),
            raw={},
        )

    def test_documents_sharing_a_url_are_never_in_the_same_batch(self):
        """GIVEN two payloads whose documents share a url
        WHEN they are scanned
        THEN every batch holds distinct urls, so no document can inherit another's
        verdict from the by_url() lookup."""
        payloads = [self._payload("same-url"), self._payload("same-url")]
        mock_scanner = _scanner_per_document()

        results = AIHookScanner(mock_scanner)._scan_contents(payloads)

        assert len(results) == len(payloads)
        assert mock_scanner.scan.call_count == 2
        for call in mock_scanner.scan.call_args_list:
            urls = [document.url for document in call.args[0]]
            assert len(urls) == len(set(urls))

    def test_a_read_of_an_ignored_path_is_never_scanned(self, tmp_path: Path):
        """GIVEN secret.ignored_paths covering the file a READ names
        WHEN the hook scans the event
        THEN the file is never sent to the API and the read is allowed."""
        file = tmp_path / "fixtures" / "creds.py"
        file.parent.mkdir()
        file.write_text("token = 'xxx'")
        mock_scanner = _scanner_per_document()

        results = AIHookScanner(
            mock_scanner, init_exclusion_regexes(["fixtures/**"])
        )._scan_contents([self._read_payload(file)])

        mock_scanner.scan.assert_not_called()
        assert [result.block for result in results] == [False]

    def test_a_read_outside_the_ignored_paths_is_still_scanned(self, tmp_path: Path):
        """GIVEN secret.ignored_paths that does not cover the file a READ names
        WHEN the hook scans the event
        THEN the file is scanned: an exclusion must not widen past its glob."""
        file = tmp_path / "src" / "creds.py"
        file.parent.mkdir()
        file.write_text("token = 'xxx'")
        mock_scanner = _scanner_per_document()

        AIHookScanner(
            mock_scanner, init_exclusion_regexes(["fixtures/**"])
        )._scan_contents([self._read_payload(file)])

        mock_scanner.scan.assert_called_once()

    def test_an_ignored_path_does_not_exclude_a_command_that_mentions_it(self):
        """GIVEN a BASH payload whose command text contains an excluded path
        WHEN the hook scans it
        THEN it is still scanned: a command is not a file, so a substring match
        must not silence it."""
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.BASH,
            content="cat fixtures/creds.py && export TOKEN=xxx",
            identifier="cat fixtures/creds.py && export TOKEN=xxx",
            agent=Cursor(),
            raw={},
        )
        mock_scanner = _scanner_per_document()

        AIHookScanner(
            mock_scanner, init_exclusion_regexes(["fixtures/**"])
        )._scan_contents([payload])

        mock_scanner.scan.assert_called_once()

    def test_a_prompt_mentioning_files_makes_a_single_api_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """GIVEN a UserPromptSubmit prompt mentioning three files
        WHEN the hook scans it
        THEN the four resulting payloads are sent in one call, all of them."""
        # Relative name from inside tmp_path: an absolute Windows path (@C:/...) trips
        # the @file regex on the drive-letter colon, which this test is not about.
        monkeypatch.chdir(tmp_path)
        files = []
        for index in range(3):
            file = tmp_path / f"file{index}.txt"
            file.write_text(f"content {index}")
            files.append(file)
        mock_scanner = _scanner_per_document()
        prompt = "look at " + " ".join(f"@{file.name}" for file in files)
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
            "cursor_version": "1.2.3",
        }

        assert AIHookScanner(mock_scanner).scan(json.dumps(data)) == 0

        mock_scanner.scan.assert_called_once()
        urls = _scanned_urls(mock_scanner)
        assert len(urls) == 4  # the three files, plus the prompt itself
        for file in files:
            assert any(url.endswith(file.name) for url in urls)

    def test_prompt_mention_and_tool_read_of_one_file_scan_it_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """GIVEN a UserPromptSubmit mentioning @secret.txt (a relative path)
        followed by a PreToolUse Read of the same file by its absolute path,
        both events reporting the same cwd
        WHEN the hook scans them
        THEN the file's path is canonicalized to the same absolute path both
        times, so it shares one verdict-cache key: it is scanned on the prompt
        and the Read is served from the cache -- one API call, not two.

        Without the canonicalization the two events key the cache on different
        filenames (relative vs absolute) and the file is scanned twice.
        """
        # The real hook runs in the agent's cwd, which is why the relative
        # @-mention resolves to a real file; mirror that here.
        monkeypatch.chdir(tmp_path)
        file = tmp_path / "secret.txt"
        file.write_text("clean file content")
        mock_scanner = _scanner_per_document()
        hook_scanner = AIHookScanner(mock_scanner)

        # Cursor reports its cwd as workspace_roots (exercises the override).
        prompt = json.dumps(
            {
                "hook_event_name": "beforeSubmitPrompt",
                "prompt": "please read @secret.txt",
                "workspace_roots": [str(tmp_path)],
                "cursor_version": "1.2.3",
            }
        )
        read = json.dumps(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "read",
                "tool_input": {"file_path": str(file)},
                "workspace_roots": [str(tmp_path)],
                "cursor_version": "1.2.3",
            }
        )

        assert hook_scanner.scan(prompt) == 0
        assert hook_scanner.scan(read) == 0

        # The prompt scanned the file (and the prompt text); the Read added no
        # call because the file's absolute-path key was already cached.
        mock_scanner.scan.assert_called_once()
        absolute = os.path.abspath(os.path.join(str(tmp_path), "secret.txt"))
        key = verdict_key(
            INSTANCE, API_KEY, SecretConfig(), absolute, "clean file content"
        )
        assert has_clean_verdict(key)

    def test_secret_in_the_second_payload_blocks_with_the_same_message(
        self, tmp_path: Path
    ):
        """GIVEN three payloads, the second one holding a secret
        WHEN they are scanned together
        THEN that payload blocks, with the message the per-payload scan gives."""
        files = []
        for index in range(3):
            file = tmp_path / f"file{index}.txt"
            file.write_text(f"content {index}")
            files.append(file)
        payloads = [self._read_payload(file) for file in files]
        secrets = {payloads[1].scannable.url: ["sk-xxx"]}

        result = AIHookScanner(_scanner_per_document(secrets))._scan_payloads(payloads)

        assert result.block is True
        assert result.payload is payloads[1]
        assert result.nbr_secrets == 1
        # The exact wording of the PreToolUse/Read block.
        assert f"Detected 1 secret in {payloads[1].identifier}" in result.message
        assert "The file content was not shown to the agent" in result.message
        # ... and it matches the message a one-payload scan produces.
        alone = AIHookScanner(_scanner_per_document(secrets))._scan_content(payloads[1])
        assert result.message == alone.message

    def test_the_secret_is_attributed_to_the_document_it_was_found_in(self):
        """GIVEN three documents, only the last one holding a secret, and results
        coming back in another order than they were sent
        WHEN they are scanned together
        THEN the block names that document, not one of its siblings."""
        payloads = [self._payload(f"payload-{index}") for index in range(3)]
        mock_scanner = _scanner_per_document({"payload-2": ["sk-xxx"]}, reverse=True)

        results = AIHookScanner(mock_scanner)._scan_contents(payloads)

        assert [result.block for result in results] == [False, False, True]
        assert results[2].payload is payloads[2]

    def test_a_skipped_document_does_not_shift_the_others(self):
        """GIVEN a document the scanner skipped, so it gets no result at all
        WHEN a sibling holds a secret
        THEN the secret is still attributed to the sibling, not to the gap."""
        payloads = [self._payload(f"payload-{index}") for index in range(3)]
        mock_scanner = _scanner_per_document(
            {"payload-2": ["sk-xxx"]}, skipped_urls={"payload-0"}
        )

        results = AIHookScanner(mock_scanner)._scan_contents(payloads)

        assert [result.block for result in results] == [False, False, True]

    def test_a_cached_document_is_left_out_of_the_batch(self):
        """GIVEN a document with a clean verdict already cached
        WHEN it is part of an event with other payloads
        THEN it is not sent, and the others still are."""
        mock_scanner = _scanner_per_document()
        hook_scanner = AIHookScanner(mock_scanner)
        cached = self._payload("cached")
        hook_scanner._scan_content(cached)

        hook_scanner._scan_contents([cached, self._payload("fresh")])

        assert mock_scanner.scan.call_count == 2
        assert _scanned_urls(mock_scanner, call=1) == ["fresh"]

    def test_a_locally_filtered_document_is_not_cached_but_its_sibling_is(self):
        """GIVEN two documents in one batch, one of them with secrets the local
        config filtered out
        WHEN they are scanned
        THEN only the unambiguous one is remembered as clean."""
        payloads = [self._payload("clean"), self._payload("filtered")]
        hook_scanner = AIHookScanner(
            _scanner_per_document(ignored_urls={"filtered"}, reverse=True)
        )

        results = hook_scanner._scan_contents(payloads)

        assert [result.block for result in results] == [False, False]
        key = verdict_key(INSTANCE, API_KEY, SecretConfig(), "clean", "some content")
        assert has_clean_verdict(key)
        filtered_key = verdict_key(
            INSTANCE, API_KEY, SecretConfig(), "filtered", "some content"
        )
        assert not has_clean_verdict(filtered_key)

    def test_a_skipped_document_is_not_cached(self):
        """A document the scan said nothing about has no verdict to remember."""
        payloads = [self._payload("answered"), self._payload("skipped")]
        hook_scanner = AIHookScanner(_scanner_per_document(skipped_urls={"skipped"}))

        hook_scanner._scan_contents(payloads)

        assert has_clean_verdict(
            verdict_key(INSTANCE, API_KEY, SecretConfig(), "answered", "some content")
        )
        assert not has_clean_verdict(
            verdict_key(INSTANCE, API_KEY, SecretConfig(), "skipped", "some content")
        )

    def test_empty_payloads_never_reach_the_api(self):
        """An empty payload costs no API call, batched or not."""
        mock_scanner = _scanner_per_document()
        payloads = [
            self._payload("empty", content=""),
            self._payload("full"),
            self._payload("also-empty", content=""),
        ]

        results = AIHookScanner(mock_scanner)._scan_contents(payloads)

        assert [result.block for result in results] == [False, False, False]
        mock_scanner.scan.assert_called_once()
        assert _scanned_urls(mock_scanner) == ["full"]

    def test_an_unreadable_file_does_not_stop_the_rest_of_the_event(
        self, tmp_path: Path
    ):
        """GIVEN an event holding a secret plus a read of a file that stats but
        cannot be opened
        WHEN the event is scanned
        THEN the unreadable document is dropped and the secret still reaches the
        API, where the read error used to abort the whole event and allow it."""
        locked = tmp_path / "locked.env"
        locked.write_text("TOKEN=abc")
        scanner = _real_secret_scanner()
        scanner.client.base_uri = INSTANCE
        scanner.client.api_key = API_KEY

        def multi_content_scan(documents, *args, **kwargs):
            result = MultiScanResult(
                [
                    ApiScanResult(policy_break_count=0, policy_breaks=[], policies=[])
                    for _ in documents
                ]
            )
            result.status_code = 200
            return result

        scanner.client.multi_content_scan.side_effect = multi_content_scan
        payloads = [self._read_payload(locked), self._payload("prompt")]
        error = PermissionError(errno.EACCES, "Permission denied")

        with patch.object(File, "is_longer_than", side_effect=error):
            results = AIHookScanner(scanner)._scan_contents(payloads)

        assert [result.block for result in results] == [False, False]
        sent = [
            document["filename"]
            for call in scanner.client.multi_content_scan.call_args_list
            for document in call.args[0]
        ]
        assert sent == ["prompt"]

    def test_no_payload_to_scan_makes_no_api_call(self):
        """All payloads empty means nothing to send at all."""
        mock_scanner = _scanner_per_document()
        AIHookScanner(mock_scanner)._scan_contents([self._payload("empty", content="")])
        mock_scanner.scan.assert_not_called()

    def test_more_than_twenty_payloads_are_all_scanned(self):
        """GIVEN more payloads than the API accepts in one call
        WHEN they are scanned
        THEN the scanner chunks them and not a single one is dropped."""
        scanner = _real_secret_scanner()
        scanner.client.base_uri = INSTANCE
        scanner.client.api_key = API_KEY

        def multi_content_scan(documents, *args, **kwargs):
            result = MultiScanResult(
                [
                    ApiScanResult(policy_break_count=0, policy_breaks=[], policies=[])
                    for _ in documents
                ]
            )
            result.status_code = 200
            return result

        scanner.client.multi_content_scan.side_effect = multi_content_scan
        payloads = [self._payload(f"payload-{index}") for index in range(25)]

        assert AIHookScanner(scanner)._scan_payloads(payloads).block is False

        calls = scanner.client.multi_content_scan.call_args_list
        assert len(calls) == 2  # 20 + 5, the API's per-call document limit
        sent = [document["filename"] for call in calls for document in call.args[0]]
        assert sorted(sent) == sorted(payload.identifier for payload in payloads)


class TestHasAlreadyBeenSeen:
    def test_first_call_is_not_duplicate(self):
        assert has_already_been_seen('{"hook_event_name": "PreToolUse"}') is False

    def test_second_identical_call_is_duplicate(self):
        content = '{"hook_event_name": "PreToolUse"}'
        assert has_already_been_seen(content) is False
        assert has_already_been_seen(content) is True

    def test_different_payload_is_not_duplicate(self):
        assert has_already_been_seen('{"prompt": "a"}') is False
        assert has_already_been_seen('{"prompt": "b"}') is False


class TestAIHookScannerScan:
    """Unit tests for the AIHookScanner.scan() method."""

    def test_empty_input_raises(self):
        """Empty or whitespace-only input raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("")
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("   \n  ")

    def test_scan_no_secrets_returns_zero(self):
        """scan() with no secrets returns 0."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "cursor_version": "1.2.3",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0

    def test_scan_duplicate_payload_skips_processing(self):
        """scan() with the same payload as the previous call returns early."""
        mock_scanner = _mock_scanner([])
        scanner = AIHookScanner(mock_scanner)
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "cursor_version": "1.2.3",
        }
        content = json.dumps(data)
        assert scanner.scan(content) == 0
        assert scanner.scan(content) == 0
        mock_scanner.scan.assert_called_once()

    @patch("ggshield.verticals.ai.hooks.AIHookScanner._send_secret_notification")
    def test_scan_post_tool_use_with_secrets_sends_notification(
        self, mock_notify: MagicMock
    ):
        """scan() on POST_TOOL_USE with secrets sends a notification and returns 0 (no block)."""
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "tool_response": {"stdout": "sk-xxx\n"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0
        mock_notify.assert_called_once()
        result = mock_notify.call_args[0][0]
        assert result.nbr_secrets == 1  # nbr_secrets
        assert result.payload.tool == Tool.BASH  # tool

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_scan_post_tool_use_notifier_failure_still_emits_block(
        self, mock_send: MagicMock
    ):
        """GIVEN a PostToolUse leak whose desktop notifier backend crashes
        (e.g. BinaryNotFound on a Homebrew install)
        WHEN scan() runs
        THEN the notifier failure is swallowed and scan() still returns the
        normal block exit code instead of crashing the hook (NHI-1681)."""
        mock_send.side_effect = Exception("BinaryNotFound")
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "tool_response": {"stdout": "sk-xxx\n"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        # Must not raise, and must still reach output_result() (exit 0 for Claude).
        assert scanner.scan(json.dumps(data)) == 0
        mock_send.assert_called_once()

    def test_scan_pre_tool_use_with_secrets_blocks(self):
        """scan() on PRE_TOOL_USE with secrets returns block result."""
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
        }
        code = scanner.scan(json.dumps(data))
        # Claude output_result always returns 0
        assert code == 0

    def test_scan_no_content_returns_allow(self):
        """scan() with no content returns 0 (and doesn't call the API)."""
        mock_scanner = _mock_scanner([])
        scanner = AIHookScanner(mock_scanner)
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "doesn-t-exist"},
            "cursor_version": "1.2.3",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0
        mock_scanner.scan.assert_not_called()

    def test_scan_payloads_refuse_empty_list(self):
        """scan() with empty list of payloads raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError):
            scanner._scan_payloads([])


class TestBuildAgentHeaders:
    """``build_agent_headers`` names the calling AI agent via GGShield-Agent-Name.

    Machine identity (Machine-Id / Machine-Username) is sent on every scan by
    ``ScanContext.get_http_headers`` — only the agent name is hook-specific.
    """

    AGENT_HEADER = "GGShield-Agent-Name"

    def test_returns_only_the_agent_name(self):
        """Just the unprefixed Agent-Name; machine identity is not the hook's job."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"command": "echo hello"},
            "cwd": "/home/alice/project",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        assert build_agent_headers(json.dumps(data)) == {"Agent-Name": "claude-code"}

    def test_agent_name_flows_through_scan_context(self):
        """Fed into ScanContext, the agent name becomes a prefixed header beside mode."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"command": "echo hello"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "s",
        }
        ctx = ScanContext(
            scan_mode=ScanMode.AI_HOOK,
            command_path="ggshield secret scan ai-hook",
            extra_headers=build_agent_headers(json.dumps(data)),
        )
        http_headers = ctx.get_http_headers()
        assert http_headers[self.AGENT_HEADER] == "claude-code"
        assert http_headers["mode"] == ScanMode.AI_HOOK.value

    def test_unrecognized_agent_degrades_to_empty_dict(self):
        """An unrecognized agent yields no headers rather than raising (fail-open)."""
        assert build_agent_headers(json.dumps({"hook_event_name": "PreToolUse"})) == {}

    def test_invalid_json_degrades_to_empty_dict(self):
        """Malformed input yields no headers rather than raising (fail-open)."""
        assert build_agent_headers("not json") == {}


class TestMCPActivity:
    """Unit tests for MCP activity handling."""

    @pytest.mark.parametrize(
        "event_type, tool",
        [
            (EventType.USER_PROMPT, None),
            (EventType.POST_TOOL_USE, Tool.MCP),
            (EventType.PRE_TOOL_USE, Tool.BASH),
            (EventType.OTHER, None),
        ],
    )
    def test_send_mcp_activity_early_returns_for_non_mcp_pre_tool_use(
        self, event_type: EventType, tool: Tool
    ):
        """send_mcp_activity returns allowed=True without calling the API
        when the payload is not an MCP PreToolUse."""
        client = MagicMock(spec=GGClient)
        payload = HookPayload(
            event_type=event_type,
            tool=tool,
            content="some content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = send_mcp_activity(client, payload)
        assert isinstance(result, MCPActivityResponse)
        assert result.allowed is True
        assert result.reason == ""
        client.post.assert_not_called()

    @patch("ggshield.verticals.ai.hooks.send_mcp_activity")
    def test_scan_calls_send_mcp_activity_for_mcp_pre_tool_use(
        self, mock_send_mcp: MagicMock
    ):
        """AIHookScanner.scan() calls send_mcp_activity when the payload is an MCP PreToolUse."""
        mock_send_mcp.return_value = MCPActivityResponse(allowed=True, reason="")
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__some_server__some_tool",
            "tool_input": {"arg": "value"},
            "cursor_version": "2.5.25",
        }
        scanner.scan(json.dumps(data))
        mock_send_mcp.assert_called_once()
        call_payload = mock_send_mcp.call_args[0][1]
        assert call_payload.event_type == EventType.PRE_TOOL_USE
        assert call_payload.tool == Tool.MCP


class TestMCPActivityOverlap:
    """The secret scan and the MCP activity call are two blocking round trips against
    the same API: for an MCP PreToolUse they must run concurrently."""

    def _payload(
        self,
        event_type: EventType = EventType.PRE_TOOL_USE,
        tool: Optional[Tool] = Tool.MCP,
    ) -> HookPayload:
        return HookPayload(
            event_type=event_type,
            tool=tool,
            content="some tool input",
            identifier="mcp__some_server__some_tool",
            agent=MagicMock(),
            raw={},
        )

    @staticmethod
    def _timed(intervals: dict, name: str, duration: float, result: object):
        """Return a callable that sleeps and records the interval it ran over."""

        def _run(*args, **kwargs):
            start = time.monotonic()
            time.sleep(duration)
            intervals[name] = (start, time.monotonic())
            return result

        return _run

    def test_scan_and_activity_run_concurrently(self):
        """Their execution intervals must intersect: if a refactor serialises them
        again, this fails."""
        intervals: dict = {}
        scanner = _mock_scanner([])
        scanner.scan.side_effect = self._timed(
            intervals, "scan", 0.2, scanner.scan.return_value
        )

        with patch(
            "ggshield.verticals.ai.hooks.send_mcp_activity",
            side_effect=self._timed(
                intervals, "mcp", 0.2, MCPActivityResponse(allowed=True, reason="")
            ),
        ):
            result = AIHookScanner(scanner)._scan_payloads([self._payload()])

        assert not result.block
        scan_start, scan_end = intervals["scan"]
        mcp_start, mcp_end = intervals["mcp"]
        assert scan_start < mcp_end and mcp_start < scan_end

    def test_scan_block_wins_over_the_mcp_verdict(self):
        """Same verdict as when the scan short-circuited the activity call."""
        scanner = _mock_scanner(["sk-secret"])
        with patch(
            "ggshield.verticals.ai.hooks.send_mcp_activity",
            return_value=MCPActivityResponse(allowed=False, reason="blocked by policy"),
        ) as mock_send:
            result = AIHookScanner(scanner)._scan_payloads([self._payload()])

        assert result.block
        assert result.nbr_secrets == 1
        assert "blocked by policy" not in result.message
        # Approved behaviour change: the activity is logged even when we block.
        mock_send.assert_called_once()

    def test_mcp_block_returned_when_the_scan_allows(self):
        scanner = _mock_scanner([])
        with patch(
            "ggshield.verticals.ai.hooks.send_mcp_activity",
            return_value=MCPActivityResponse(allowed=False, reason="blocked by policy"),
        ):
            result = AIHookScanner(scanner)._scan_payloads([self._payload()])

        assert result.block
        assert result.message == "blocked by policy"

    def test_api_failure_on_the_worker_thread_fails_open(self):
        """An exception raised while logging the activity must not escape the thread
        and kill the hook."""
        scanner = _mock_scanner([])
        scanner.client.log_mcp_activity.side_effect = RuntimeError("network")
        with patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery"):
            result = AIHookScanner(scanner)._scan_payloads([self._payload()])

        assert not result.block

    @pytest.mark.parametrize(
        ("event_type", "tool"),
        [
            (EventType.PRE_TOOL_USE, Tool.BASH),
            (EventType.PRE_TOOL_USE, None),
            (EventType.POST_TOOL_USE, Tool.MCP),
            (EventType.USER_PROMPT, None),
        ],
    )
    def test_non_mcp_payloads_stay_on_the_serial_path(
        self, event_type: EventType, tool: Optional[Tool]
    ):
        """send_mcp_activity would no-op for these, so they must not pay for a thread."""
        scanner = _mock_scanner([])
        with patch("ggshield.verticals.ai.hooks.send_mcp_activity") as mock_send:
            result = AIHookScanner(scanner)._scan_payloads(
                [self._payload(event_type=event_type, tool=tool)]
            )

        assert not result.block
        mock_send.assert_not_called()

    def test_first_blocking_payload_wins_across_payloads(self):
        """_parse_command can yield several payloads: the first block still wins."""
        allowed = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        blocked = self._payload()
        scanner = _mock_scanner([])
        with patch(
            "ggshield.verticals.ai.hooks.send_mcp_activity",
            return_value=MCPActivityResponse(allowed=False, reason="blocked by policy"),
        ):
            result = AIHookScanner(scanner)._scan_payloads([allowed, blocked])

        assert result.block
        assert result.payload is blocked


class TestMessageFromSecrets:
    """Unit tests for AIHookScanner._message_from_secrets with different payload types."""

    def _payload(
        self,
        event_type: EventType = EventType.PRE_TOOL_USE,
        tool: Optional[Tool] = None,
        identifier: str = "id",
    ) -> HookPayload:
        return HookPayload(
            event_type=event_type,
            tool=tool,
            content="content",
            identifier=identifier,
            agent=Cursor(),
            raw={},
        )

    def test_message_for_user_prompt(self):
        """USER_PROMPT: header/status/remediation talk about the prompt."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in your prompt" in message
        assert "The prompt was not sent to the agent" in message
        assert "remove the secret from your prompt" in message

    def test_message_for_file_mentioned_in_user_prompt(self):
        """USER_PROMPT + Read: a file mentioned in the prompt gets the file wording,
        not the prompt wording, since the secret is in the file."""
        payload = self._payload(
            event_type=EventType.USER_PROMPT,
            tool=Tool.READ,
            identifier="/tmp/config.py",
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in /tmp/config.py" in message
        assert "in your prompt" not in message
        assert "remove the secret from your prompt" not in message

    def test_escape_markdown_adds_hard_breaks(self):
        """escape_markdown turns single newlines into markdown hard breaks
        (two trailing spaces) so agents rendering the message as markdown
        (e.g. Codex) don't collapse them into spaces. Blank-line separations
        are left untouched."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        secrets = [_make_secret("sk-xxx")]
        plain = AIHookScanner._message_from_secrets(secrets, payload)
        markdown = AIHookScanner._message_from_secrets(
            secrets, payload, escape_markdown=True
        )
        assert "  \n" not in plain
        lines = markdown.split("\n")
        for line, next_line in zip(lines, lines[1:]):
            if line and next_line:
                assert line.endswith("  ")
            else:
                assert not line.endswith(" ")
        # Blank-line separations are preserved
        assert markdown.count("\n\n") == plain.count("\n\n")

    def test_message_for_pre_bash_tool(self):
        """PRE_TOOL_USE + Bash: header names the command, nothing ran yet,
        remediation points to a secrets manager."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the command" in message
        assert "was not executed" in message
        assert "secrets manager" in message

    def test_message_for_pre_read_tool(self):
        """PRE_TOOL_USE + Read: header names the file, remediation says to
        avoid sharing it."""
        payload = self._payload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            identifier="/path/to/file",
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "/path/to/file" in message
        assert "avoid sharing this file" in message

    @pytest.mark.parametrize("tool", [Tool.MCP, Tool.OTHER, None])
    def test_message_for_pre_other_tools(self, tool: Optional[Tool]):
        """PRE_TOOL_USE with MCP, an unrecognized tool, or no tool at all
        share the same generic "tool input" wording."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=tool)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the tool input" in message

    def test_other_event_type_falls_back_to_pre_generic_wording(self):
        """An unrecognized event type (EventType.OTHER) falls back to the
        same wording as PRE_TOOL_USE with a non-Bash/Read tool."""
        payload = self._payload(event_type=EventType.OTHER, tool=None)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the tool input" in message
        assert "was not executed" in message

    @pytest.mark.parametrize("tool", [Tool.BASH, Tool.READ, Tool.MCP, Tool.OTHER])
    def test_message_for_post_tool_use_says_leaked(self, tool: Tool):
        """POST_TOOL_USE, regardless of tool: the secret already reached the
        agent, so status says it's compromised and remediation says to revoke
        it (today it is tool-first, which wrongly gives Read/MCP the
        pre-leak "not leaked yet" wording on POST_TOOL_USE)."""
        payload = self._payload(
            event_type=EventType.POST_TOOL_USE, tool=tool, identifier="/path/to/file"
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "Consider it compromised" in message
        assert "revoke the secret" in message

    def test_message_for_post_read_names_the_file(self):
        """POST_TOOL_USE + Read: header names the file, like its PreToolUse
        counterpart, instead of falling back to "in the tool output"."""
        payload = self._payload(
            event_type=EventType.POST_TOOL_USE,
            tool=Tool.READ,
            identifier="/path/to/file",
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "/path/to/file" in message

    def test_message_escapes_markdown(self):
        """When escape_markdown=True, asterisks in matches are replaced with a bullet."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx")], payload, escape_markdown=True
        )
        # The message itself should not contain raw asterisks from matches
        # (the header and bolded validity use ** for bold which is intentional)
        assert "Detected" in message
        assert "•" in message

    def test_message_includes_incident_url_for_known_secret(self):
        """A known secret with an incident_url gets an "Incident URL" line,
        and, on POST_TOOL_USE, a step to resolve the incident."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        secret = _make_secret(
            "sk-xxx",
            known_secret=True,
            incident_url="https://dashboard.gitguardian.com/incidents/1",
        )
        message = AIHookScanner._message_from_secrets([secret], payload)
        assert "Incident URL: https://dashboard.gitguardian.com/incidents/1" in message
        assert (
            "resolve the incident linked above in your GitGuardian dashboard."
            in message
        )

    def test_message_omits_incident_url_for_unknown_secret(self):
        """A secret that isn't a known incident never gets an Incident URL line."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "Incident URL" not in message

    def test_message_omits_resolve_incident_step_before_leak(self):
        """A known secret with an incident_url still gets its Incident URL
        line on PRE_TOOL_USE, but no "resolve the incident" step since
        nothing has leaked yet."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        secret = _make_secret(
            "sk-xxx",
            known_secret=True,
            incident_url="https://dashboard.gitguardian.com/incidents/1",
        )
        message = AIHookScanner._message_from_secrets([secret], payload)
        assert "Incident URL: https://dashboard.gitguardian.com/incidents/1" in message
        assert "resolve the incident" not in message

    def test_resolve_incident_step_is_plural_for_several_known_secrets(self):
        """When more than one secret is a known incident, the remediation
        step uses the plural "incidents"."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets(
            [
                _make_secret(
                    "sk-xxx",
                    known_secret=True,
                    incident_url="https://dashboard.gitguardian.com/incidents/1",
                ),
                _make_secret(
                    "sk-yyy",
                    known_secret=True,
                    incident_url="https://dashboard.gitguardian.com/incidents/2",
                ),
            ],
            payload,
        )
        assert (
            "resolve the incidents linked above in your GitGuardian dashboard."
            in message
        )

    @pytest.mark.parametrize(
        "event_type, tool",
        [
            (EventType.USER_PROMPT, None),
            (EventType.PRE_TOOL_USE, Tool.BASH),
            (EventType.PRE_TOOL_USE, Tool.READ),
            (EventType.PRE_TOOL_USE, Tool.OTHER),
            (EventType.POST_TOOL_USE, Tool.BASH),
            (EventType.POST_TOOL_USE, Tool.READ),
            (EventType.POST_TOOL_USE, Tool.OTHER),
            (EventType.OTHER, None),
        ],
    )
    def test_message_always_ends_with_false_positive_block(
        self, event_type: EventType, tool: Optional[Tool]
    ):
        """Every message ends with the false positive escape hatch, and with the
        `ignored_matches` entry it would write."""
        payload = self._payload(event_type=event_type, tool=tool)
        secret = _make_secret("sk-xxx")
        message = AIHookScanner._message_from_secrets([secret], payload)
        assert "    ggshield secret ignore --last-found" in message
        assert "> If this is a false positive, run:" in message
        assert message.endswith(f"    - match: {secret.get_ignore_sha()}")

    def test_false_positive_block_is_plural_for_several_secrets(self):
        """The false positive block says "these are false positives" when
        several secrets were detected."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx"), _make_secret("sk-yyy")], payload
        )
        assert "> If these are false positives, run:" in message


class TestSendSecretNotification:
    """Unit tests for AIHookScanner._send_secret_notification."""

    def _result(
        self,
        nbr_secrets: int,
        tool: Tool,
        agent: Agent,
        input_command: str = "",
    ) -> HookResult:
        return HookResult(
            block=True,
            message="",
            nbr_secrets=nbr_secrets,
            payload=HookPayload(
                event_type=EventType.PRE_TOOL_USE,
                tool=tool,
                content="",
                identifier="",
                agent=agent,
                raw={"tool_input": {"command": input_command}},
            ),
        )

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_bash_tool(self, mock_send: MagicMock):
        """GIVEN a BASH-tool result
        WHEN a notification is sent
        THEN the message says 'running the command' with the command run."""
        AIHookScanner._send_secret_notification(
            self._result(1, Tool.BASH, Claude(), input_command="ls -la")
        )
        title, message = mock_send.call_args.args
        assert title == "ggshield - Secrets Detected"
        assert "running the command `ls -la`" in message
        assert "Claude Code" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_read_tool(self, mock_send: MagicMock):
        """GIVEN a READ-tool result
        WHEN a notification is sent
        THEN the message says 'reading a file'."""
        AIHookScanner._send_secret_notification(self._result(2, Tool.READ, Cursor()))
        _, message = mock_send.call_args.args
        assert "reading a file" in message
        assert "2" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_other_tool(self, mock_send: MagicMock):
        """GIVEN an OTHER-tool result
        WHEN a notification is sent
        THEN the message says 'using a tool'."""
        AIHookScanner._send_secret_notification(self._result(1, Tool.OTHER, Copilot()))
        _, message = mock_send.call_args.args
        assert "using a tool" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_failure_never_propagates(self, mock_send: MagicMock):
        """GIVEN a notifier backend that raises (e.g. missing binary on brew)
        WHEN a notification is sent
        THEN the exception is swallowed so the hook can still emit its block."""
        mock_send.side_effect = Exception("BinaryNotFound")
        # Must not raise.
        AIHookScanner._send_secret_notification(self._result(1, Tool.BASH, Claude()))


class TestSendDesktopNotification:
    """Unit tests for the per-OS desktop notification backends."""

    @patch("ggshield.verticals.ai.hooks.subprocess.run")
    @patch("ggshield.verticals.ai.hooks.sys")
    def test_macos_uses_native_osascript(
        self, mock_sys: MagicMock, mock_run: MagicMock
    ):
        """GIVEN a macOS host
        WHEN a desktop notification is sent
        THEN it invokes osascript, passing the (attacker-influenced) message
        and title as run-handler arguments rather than interpolating them into
        the AppleScript source (injection- and unicode-safe)."""
        mock_sys.platform = "darwin"
        from ggshield.verticals.ai.hooks import _send_desktop_notification

        # Message with a quote, an accent, an emoji and a tab: none of these
        # can be represented in an AppleScript string literal, so they must be
        # passed as arguments, not baked into the script.
        message = 'ran `café` ❤\ttell app "Finder"'
        _send_desktop_notification("ggshield - Secrets Detected", message)

        args = mock_run.call_args.args[0]
        assert args[0] == "osascript"
        # Uses a run handler reading from argv; the raw strings are the trailing
        # argv items, never embedded in any "-e" script fragment.
        assert "on run argv" in args
        assert message == args[-2]
        assert "ggshield - Secrets Detected" == args[-1]
        script_fragments = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
        assert not any(message in frag for frag in script_fragments)
        # A hook must never hang or read stdin from a notifier subprocess.
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL
        assert mock_run.call_args.kwargs["timeout"] == 10

    @patch("ggshield.verticals.ai.hooks.Notify")
    @patch("ggshield.verticals.ai.hooks.sys")
    def test_non_macos_uses_notifypy(
        self, mock_sys: MagicMock, mock_notify_cls: MagicMock
    ):
        """GIVEN a non-macOS host
        WHEN a desktop notification is sent
        THEN it uses the notifypy backend."""
        mock_sys.platform = "linux"
        from ggshield.verticals.ai.hooks import _send_desktop_notification

        _send_desktop_notification("title", "message")

        instance = mock_notify_cls.return_value
        assert instance.title == "title"
        assert instance.message == "message"
        assert instance.application_name == "ggshield"
        instance.send.assert_called_once()


class TestAIHookScannerParseInput:
    """Unit tests for AIHookparse_hook_input."""

    def test_invalid_json_raises(self):
        """Invalid JSON raises ValueError with parse error."""
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            parse_hook_input("not json {")
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            parse_hook_input("{ missing brace ")

    def test_missing_event_type_raises(self):
        """JSON without event type raises ValueError."""
        with pytest.raises(ValueError):
            parse_hook_input('{"prompt": "hello"}')

    def test_cursor_user_prompt(self):
        """Test Cursor beforeSubmitPrompt (user prompt) parsing."""
        data = {
            "conversation_id": "75fed8a8-2078-4e49-80d2-776b20d441c3",
            "generation_id": "1501ede6-b8ac-43f4-9943-0e218610c5c6",
            "model": "default",
            "prompt": "hello world",
            "attachments": [],
            "hook_event_name": "beforeSubmitPrompt",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "user_email": "user@example.com",
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/75fed8a8/75fed8a8.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert payload.identifier != ""
        assert isinstance(payload.agent, Cursor)

    def test_cursor_pre_tool_use_shell(self):
        """Test Cursor preToolUse with Shell (bash) parsing."""
        data = {
            "conversation_id": "37a17cfc-322c-47ab-88c5-e810f23f4739",
            "generation_id": "049f5b26-326a-4081-82c1-e5c42a63d19e",
            "model": "default",
            "tool_name": "Shell",
            "tool_input": {
                "command": "whoami",
                "cwd": "",
                "timeout": 30000,
            },
            "tool_use_id": "ec1b1027-5b24-4a18-90c7-f8f616d0aeb4",
            "hook_event_name": "preToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/37a17cfc/37a17cfc.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert payload.identifier == "whoami"
        assert isinstance(payload.agent, Cursor)

    def test_cursor_pre_tool_use_read(self, tmp_file: Path):
        """Test Cursor preToolUse with Read (file) parsing."""
        data = {
            "conversation_id": "75fed8a8-2078-4e49-80d2-776b20d441c3",
            "generation_id": "1501ede6-b8ac-43f4-9943-0e218610c5c6",
            "model": "default",
            "tool_name": "Read",
            "tool_input": {"file_path": tmp_file.as_posix()},
            "tool_use_id": "tool_fbfdb104-86a6-4111-a1bf-ce789f93cab",
            "hook_event_name": "preToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/75fed8a8/75fed8a8.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == os.path.abspath(tmp_file)
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Cursor)

    def test_cursor_post_tool_use_shell(self):
        """Test Cursor postToolUse with Shell (simulated cat command result)."""
        data = {
            "conversation_id": "37a17cfc-322c-47ab-88c5-e810f23f4739",
            "generation_id": "049f5b26-326a-4081-82c1-e5c42a63d19e",
            "model": "default",
            "tool_name": "Shell",
            "tool_input": {"command": "whoami", "cwd": "", "timeout": 30000},
            "tool_output": '{"output":"user1","exitCode":0}',
            "duration": 280.475,
            "tool_use_id": "ec1b1027-5b24-4a18-90c7-f8f616d0aeb4",
            "hook_event_name": "postToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user/.cursor/projects/foo/agent-transcripts/37a17cfc/37a17cfc.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, Cursor)

    def test_claude_user_prompt(self):
        """Test Claude Code UserPromptSubmit parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user1/.claude/projects/foo/273ad859-3608-4799-9971-fa15ecb1a65c.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert isinstance(payload.agent, Claude)

    def test_claude_pre_tool_use_bash(self):
        """Test Claude Code PreToolUse with Bash parsing."""
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test postTool hook",
            },
            "tool_use_id": "toolu_01BPMKeZAMCqBtn1xJRNfDJw",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.agent, Claude)

    def test_claude_pre_tool_use_read(self, tmp_file: Path):
        """Test Claude Code PreToolUse with Read parsing."""
        # From raw_hooks_logs: Claude PreToolUse Read
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": tmp_file.as_posix()},
            "tool_use_id": "toolu_01WabtWJpzf1ZJ8GJ3JfQEmq",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == os.path.abspath(tmp_file)
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Claude)

    def test_claude_pre_tool_use_mcp_scans_tool_input(self):
        """PreToolUse for an MCP tool scans the serialized tool_input, so a
        secret in an MCP argument is caught before it reaches the server
        (NHI-1845)."""
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"title": "creds", "body": "token=abc123secret"},
            "tool_use_id": "toolu_01WabtWJpzf1ZJ8GJ3JfQEmq",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.MCP
        assert not payload.empty
        assert "token=abc123secret" in payload.scannable.content
        assert isinstance(payload.agent, Claude)

    def test_claude_post_tool_use_bash(self):
        """Test Claude Code PostToolUse with Bash (simulated cat command result)."""
        # From raw_hooks_logs: Claude PostToolUse Bash - tool_response has stdout
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test postTool hook",
            },
            "tool_response": {
                "stdout": "user1\n",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
                "noOutputExpected": False,
            },
            "tool_use_id": "toolu_01BPMKeZAMCqBtn1xJRNfDJw",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        # Content is json.dumps(tool_response), so the stdout is inside the string
        assert "user1" in payload.content
        assert isinstance(payload.agent, Claude)

    def test_claude_parse_read_files_in_prompt(self):
        """Test parsing "@file_path" mentions from Claude Code prompt."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user1/.claude/projects/foo/273ad859-3608-4799-9971-fa15ecb1a65c.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "read @folder/file.txt and summarize the content.",
        }
        payloads = parse_hook_input(json.dumps(data))
        assert len(payloads) == 2
        payload = payloads[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.tool == Tool.READ
        # The relative @-mention is canonicalized against the event's cwd so it
        # shares a verdict-cache key with the tool's (absolute) read of the file.
        assert payload.identifier == os.path.abspath("/home/user1/foo/folder/file.txt")
        assert payload.content == ""  # empty because inexistent file
        assert isinstance(payload.agent, Claude)

        payload = payloads[1]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "read @folder/file.txt and summarize the content."
        assert payload.tool is None
        assert isinstance(payload.agent, Claude)

    def test_vscode_user_prompt(self):
        """Test VSCode UserPromptSubmit parsing."""
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "UserPromptSubmit",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, VSCode)

    def test_vscode_pre_tool_use_run_in_terminal(self):
        """Test VSCode PreToolUse with run_in_terminal (shell) parsing."""
        # From raw_hooks_logs: Copilot PreToolUse run_in_terminal
        data = {
            "timestamp": "2026-02-26T11:29:05.821Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test preToolUse hook",
                "goal": "whoami to test preToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_use_id": "call_ADJcoVxpnzPtpU6uf0h9wzLR__vscode-1772105116075",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.agent, VSCode)

    def test_vscode_pre_tool_use_read_file(self, tmp_file: Path):
        """Test VSCode PreToolUse with read_file parsing."""
        # From raw_hooks_logs: VSCode PreToolUse read_file (nonexistent path for deterministic test)
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "read_file",
            "tool_input": {
                "filePath": tmp_file.as_posix(),
                "startLine": 1,
                "endLine": 200,
            },
            "tool_use_id": "call_iMFuTGETQ2z23a3xYTqcHBXp__vscode-1772105116078",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == os.path.abspath(tmp_file)
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, VSCode)

    def test_vscode_post_tool_use_run_in_terminal(self):
        """Test VSCode PostToolUse with run_in_terminal (simulated cat result)."""
        # From raw_hooks_logs: Copilot PostToolUse run_in_terminal - tool_response is string
        data = {
            "timestamp": "2026-02-26T11:53:47.392Z",
            "hook_event_name": "PostToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test postToolUse hook",
                "goal": "whoami to test postToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_response": "user1",
            "tool_use_id": "call_f96KUoNCGS8jENVKnlWnSz5Q__vscode-1772105116077",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, VSCode)

    def test_copilot_user_prompt(self):
        """Test Copilot UserPromptSubmit parsing."""
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "UserPromptSubmit",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, Copilot)

    def test_copilot_user_prompt_submitted(self):
        """Test Copilot CLI's own 'userPromptSubmitted' event name parsing.

        Copilot CLI fires the camelCase ``userPromptSubmitted`` event, not the
        VS Code ``UserPromptSubmit``. If it is not mapped, the prompt content is
        never scanned and ggshield wrongly returns ``{"continue": true}``.
        """
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "userPromptSubmitted",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_run_in_terminal(self):
        """Test Copilot PreToolUse with bash parsing."""
        data = {
            "timestamp": "2026-02-26T11:29:05.821Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test preToolUse hook",
                "mode": "sync",
                "initial_wait": 30,
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_read_file(self, tmp_file: Path):
        """Test Copilot PreToolUse with read_file parsing."""
        # From raw_hooks_logs: Copilot PreToolUse read_file (nonexistent path for deterministic test)
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "view",
            "tool_input": {
                "path": tmp_file.as_posix(),
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == os.path.abspath(tmp_file)
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_mcp(self):
        """Test Copilot PreToolUse is correctly overriden to MCP."""
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "server-name-tool-name",
            "tool_input": {
                "arg": "value",
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.MCP
        # Copilot MCP tools are only identified in post_process_payload, after
        # content selection, so the catch-all input scan must cover them.
        assert not payload.empty
        assert "value" in payload.scannable.content
        assert isinstance(payload.agent, Copilot)

    def test_copilot_post_tool_use_run_in_terminal(self):
        """Test Copilot PostToolUse with bash"""
        data = {
            "timestamp": "2026-02-26T11:53:47.392Z",
            "hook_event_name": "PostToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test postToolUse hook",
                "goal": "whoami to test postToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_result": {
                "result_type": "success",
                "text_result_for_llm": "user1\n<exited with exit code 0>",
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, Copilot)

    def test_raises_if_no_agent_recognized(self):
        """Test raises if no agent can be recognized."""
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        with pytest.raises(ValueError, match="Unrecognized agent"):
            parse_hook_input(json.dumps(data))

    def test_codex_user_prompt(self):
        """Test Codex UserPromptSubmit parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "UserPromptSubmit",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "prompt": "hello world",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert isinstance(payload.agent, Codex)

    def test_codex_pre_tool_use_bash(self):
        """Test Codex PreToolUse with Bash parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "Bash",
            "tool_input": {"command": "whoami"},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert isinstance(payload.agent, Codex)

    def test_codex_pre_tool_use_null_transcript_path(self):
        """Codex sends transcript_path as a present-but-null field; detection
        must fall back to turn_id instead of crashing on the None."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": None,
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "Bash",
            "tool_input": {"command": "whoami"},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert isinstance(payload.agent, Codex)

    def test_vibe_pre_tool_bash(self):
        data = {
            "session_id": "session-123",
            "parent_session_id": None,
            "transcript_path": "/home/user/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "pre_tool",
            "tool_name": "bash",
            "tool_call_id": "call-123",
            "tool_input": {"command": "whoami"},
        }

        payload = parse_hook_input(json.dumps(data))[0]

        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert isinstance(payload.agent, Vibe)

    def test_vibe_post_tool_read(self):
        data = {
            "session_id": "session-123",
            "parent_session_id": None,
            "transcript_path": "/home/user/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "post_tool",
            "tool_name": "read_file",
            "tool_call_id": "call-123",
            "tool_input": {"path": "/tmp/secret.txt"},
            "tool_status": "success",
            "tool_output": {"content": "file content"},
            "tool_output_text": "file content",
            "tool_error": None,
            "duration_ms": 42.5,
        }

        payload = parse_hook_input(json.dumps(data))[0]

        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.READ
        # Canonicalized against the event's cwd (see _abs_read_path).
        assert payload.identifier == os.path.abspath("/tmp/secret.txt")
        assert payload.content == '{"content": "file content"}'
        assert isinstance(payload.agent, Vibe)

    def test_vibe_failed_post_tool_scans_output_text(self):
        data = {
            "session_id": "session-123",
            "parent_session_id": None,
            "transcript_path": "/home/user/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "post_tool",
            "tool_name": "bash",
            "tool_call_id": "call-123",
            "tool_input": {"command": "failing-command"},
            "tool_status": "failure",
            "tool_output": None,
            "tool_output_text": "failure output",
            "tool_error": "failed",
            "duration_ms": 42.5,
        }

        payload = parse_hook_input(json.dumps(data))[0]

        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.content == "failure output"
        assert isinstance(payload.agent, Vibe)

    @pytest.mark.parametrize("tool_name", ["bash", "git_bash", "powershell"])
    def test_vibe_shell_tools_are_bash(self, tool_name: str):
        """Every Vibe shell tool is treated as BASH, so the command is parsed for
        file reads instead of being scanned as an opaque tool input."""
        data = {
            "session_id": "session-123",
            "transcript_path": "/home/user/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "pre_tool",
            "tool_name": tool_name,
            "tool_call_id": "call-123",
            "tool_input": {"command": "cat /tmp/secret.txt"},
        }

        payloads = parse_hook_input(json.dumps(data))

        assert payloads[-1].tool == Tool.BASH
        assert payloads[-1].identifier == "cat /tmp/secret.txt"
        # The command references a file, so it is also scanned as a read.
        assert Tool.READ in {payload.tool for payload in payloads}

    def test_vibe_wins_over_claude_when_path_contains_claude(self):
        """Vibe's event names are unambiguous, so they take precedence over
        Claude's transcript_path substring heuristic."""
        data = {
            "session_id": "session-123",
            "transcript_path": "/home/claude/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "pre_tool",
            "tool_name": "bash",
            "tool_call_id": "call-123",
            "tool_input": {"command": "whoami"},
        }

        payload = parse_hook_input(json.dumps(data))[0]

        assert isinstance(payload.agent, Vibe)

    def test_pre_tool_use_read_with_missing_file(self):
        """PRE_TOOL_USE with tool_name 'read' and non-existing file yields empty content."""
        content = json.dumps(
            {
                "hook_event_name": "pretooluse",
                "tool_name": "read",
                "tool_input": {"file_path": "/nonexistent/path"},
                "cursor_version": "1.2.3",
            }
        )
        payload = parse_hook_input(content)[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "/nonexistent/path"
        assert payload.content == ""

    def test_post_tool_use_read_extracts_file_path(self):
        """POST_TOOL_USE with tool_name 'Read' extracts the file path from
        tool_input into the identifier, mirroring the PRE_TOOL_USE Read
        branch, so the block message can name the file instead of falling
        back to a content hash."""
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/nonexistent/path"},
            "tool_response": {"content": "file content"},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "/nonexistent/path"

    def test_pre_tool_use_other_tool(self):
        """PRE_TOOL_USE with unknown tool yields Tool.OTHER and scans its input."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"arg": "value"},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.OTHER
        assert "value" in payload.content

    def test_pre_tool_use_other_tool_empty_input(self):
        """PRE_TOOL_USE with an unknown tool and no input stays empty, so no
        scan API call is made."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.tool == Tool.OTHER
        assert payload.empty

    def test_other_event_type(self):
        """Unknown event type yields EventType.OTHER with empty content."""
        data = {
            "hook_event_name": "SomeOtherEvent",
            "prompt": "hello",
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.OTHER
        assert payload.content == ""
        assert payload.tool is None

    def test_windows_GetContent_parsing(self):
        """The Bash/Get-Content tool use in windows is parsed as file reading."""
        # This case was observed with Codex on Windows.
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "Bash",
            "tool_input": {"command": "Get-Content README.md"},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        # Canonicalized against the event's cwd (see _abs_read_path).
        assert payload.identifier == os.path.abspath("/home/user/project/README.md")

    @staticmethod
    def _bash_hook_input(command: str) -> str:
        return json.dumps(
            {
                "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
                "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
                "cwd": "/home/user/project",
                "hook_event_name": "PreToolUse",
                "turn_id": "turn_123",
                "model": "gpt-5.4",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": "call_123",
            }
        )

    def test_cat_command_yields_file_scannable(self, tmp_path: Path):
        """`cat <existing file>` is still parsed as a file read."""
        target = tmp_path / "code.py"
        target.write_text("secret = 'abc'")
        payloads = parse_hook_input(self._bash_hook_input(f"cat {target}"))
        read = next(p for p in payloads if p.tool == Tool.READ)
        assert read.identifier == str(target)
        assert isinstance(read.scannable, File)

    def test_cat_heredoc_command_is_still_scanned_as_string(self):
        """A `cat > file <<EOF` heredoc must not abort the scan.

        Everything after "cat " used to be treated as a file name, and
        Path.is_file() raised OSError (ENAMETOOLONG) on it, so the command --
        which is precisely a secret being written to a file -- was never
        scanned. Python < 3.13 raises for real here; force the error so the
        regression is covered on every supported version.
        """
        command = "cat > /tmp/script.py <<'EOF'\n" + "x = 1\n" * 2000 + "EOF"
        error = OSError(errno.ENAMETOOLONG, "File name too long")
        with patch.object(Path, "is_file", side_effect=error):
            payloads = parse_hook_input(self._bash_hook_input(command))
            # The bogus "file" payload must not raise, and must be dropped
            # before any API call.
            read = next(p for p in payloads if p.tool == Tool.READ)
            assert isinstance(read.scannable, StringScannable)
            assert read.empty
        bash = payloads[-1]
        assert bash.tool == Tool.BASH
        assert isinstance(bash.scannable, StringScannable)
        assert not bash.empty
        assert bash.scannable.content == command


class TestFlavorOutputResult:
    """Unit tests for Cursor, Claude, Copilot output_result with Result objects.

    Mocks click.echo to capture stdout/stderr and asserts both output and return code.
    """

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_user_prompt_allow(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=False: JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert out["user_message"] == ""

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=True: JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Remove secrets from prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is False
        assert out["user_message"] == "Remove secrets from prompt"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_allow(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=False: permission allow, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.PRE_TOOL_USE))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "allow"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_block(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=True: permission deny, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "deny"
        assert out["user_message"] == "Secrets detected in command"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_post_tool_use(self, mock_echo: MagicMock):
        """Cursor POST_TOOL_USE: empty JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Too late",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        assert json.loads(args[0]) == {}

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_other_block(self, mock_echo: MagicMock):
        """Cursor OTHER event with block: empty JSON, return 2."""
        result = HookResult(
            block=True,
            message="",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Cursor().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_other_allow(self, mock_echo: MagicMock):
        """Cursor OTHER event without block: empty JSON, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.OTHER))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_allow(self, mock_echo: MagicMock):
        """Claude with block=False: JSON continue true to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_block(self, mock_echo: MagicMock):
        """Claude with block=True: JSON continue false and stopReason to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Secrets in file",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert (
            out["hookSpecificOutput"]["permissionDecisionReason"] == "Secrets in file"
        )

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_output_result_allow(self, mock_echo: MagicMock):
        """Copilot with block=False: same as Claude, JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert "stopReason" not in out

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_output_result_block(self, mock_echo: MagicMock):
        """Copilot with block=True: same as Claude, JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Secret in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["decision"] == "block"
        assert out["reason"] == "Secret in tool output"

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_other_result_block(self, mock_echo: MagicMock):
        """Copilot with block=True, other type of event"""
        result = HookResult(
            block=True,
            message="Secret in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Copilot().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert not out["continue"]

    @patch("ggshield.verticals.ai.agents.copilot.click.echo")
    def test_copilot_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Copilot USER_PROMPT block: {"decision": "block"} to stdout, return 0.

        Copilot CLI cancels a prompt before it reaches the model when the hook
        emits ``{"decision": "block"}`` (verified against Copilot CLI 1.0.61).
        The inherited ``{"continue": false}`` is ignored on the prompt event.
        """
        result = HookResult(
            block=True,
            message="Remove secrets from prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["decision"] == "block"
        assert out["reason"] == "Remove secrets from prompt"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_allow(self, mock_echo: MagicMock):
        """Codex with block=False: empty JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.PRE_TOOL_USE))
        code = Codex().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_pre_tool_use_block(self, mock_echo: MagicMock):
        """Codex PRE_TOOL_USE with block=True: permission deny JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False
        out = json.loads(args[0])
        # No systemMessage: Codex already shows the decision reason, setting
        # both would display the message twice.
        assert "systemMessage" not in out
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert (
            out["hookSpecificOutput"]["permissionDecisionReason"]
            == "Secrets detected in command"
        )

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Codex USER_PROMPT with block=True: block decision JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert "systemMessage" not in out
        assert out["decision"] == "block"
        assert out["reason"] == "Secrets detected in prompt"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_post_tool_use_block(self, mock_echo: MagicMock):
        """Codex POST_TOOL_USE with block=True: block decision JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert "systemMessage" not in out
        assert out["decision"] == "block"
        assert out["reason"] == "Secrets detected in tool output"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_other_block(self, mock_echo: MagicMock):
        """Codex unsupported event with block=True writes to stderr and returns 2."""
        result = HookResult(
            block=True,
            message="Unsupported Codex event",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Codex().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("Unsupported Codex event", err=True)

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Claude allow with a warning: continue true plus systemMessage."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Claude().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["continue"] is True
        assert out["systemMessage"] == "could not scan"

    @patch("ggshield.verticals.ai.agents.vscode.click.echo")
    def test_vscode_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """VSCode allow with a warning: continue true plus systemMessage."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = VSCode().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["continue"] is True
        assert out["systemMessage"] == "could not scan"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Codex allow with a warning: systemMessage only, no block fields."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Codex().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out == {"systemMessage": "could not scan"}

    @patch("ggshield.verticals.ai.agents.vibe.click.echo")
    def test_vibe_output_result_allow(self, mock_echo: MagicMock):
        result = HookResult.allow(_dummy_payload(EventType.PRE_TOOL_USE))

        code = Vibe().output_result(result)

        assert code == 0
        mock_echo.assert_not_called()

    @patch("ggshield.verticals.ai.agents.vibe.click.echo")
    def test_vibe_output_result_block(self, mock_echo: MagicMock):
        result = HookResult(
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )

        code = Vibe().output_result(result)

        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out == {
            "decision": "deny",
            "reason": "Secrets detected in command",
        }

    @patch("ggshield.verticals.ai.agents.vibe.click.echo")
    def test_vibe_output_result_allow_with_warning(self, mock_echo: MagicMock):
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )

        code = Vibe().output_result(result)

        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out == {"system_message": "could not scan"}

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Cursor allow with a warning: permission allow plus user_message."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Cursor().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["permission"] == "allow"
        assert out["user_message"] == "could not scan"


@pytest.mark.parametrize(
    "prompt, filepaths",
    [
        ("read @folder/file.txt and summarize the content.", {"folder/file.txt"}),
        (
            "A multi-lineprompt with @file1 \n and @file2 \n and @file3 read.",
            {"file1", "file2", "file3"},
        ),
        ("@filename.txt", {"filename.txt"}),
        ("same @file @file twice", {"file"}),
        ("File can start with a dot: @.env", {".env"}),
        ("File can contain underscores: @my_file.txt", {"my_file.txt"}),
        (
            "Files simply mentioned without @ prefix are not matched: foo.txt bar.txt.",
            set(),
        ),
        ("emails like foo@example.com are not matched.", set()),
        (
            "test @file.multiple.extensions.txt and @file2.txt",
            {"file.multiple.extensions.txt", "file2.txt"},
        ),
        ("files (@folder/foo.txt) can be between parentheses.", {"folder/foo.txt"}),
        ("files @can-contain-hyphens.txt", {"can-contain-hyphens.txt"}),
        (
            'Supports @"file with spaces (and comma, and parentheses) in name".',
            {"file with spaces (and comma, and parentheses) in name"},
        ),
        ('read @"file with \\" in its name.txt"', {'file with \\" in its name.txt'}),
        (
            "Path at the end of a sentence: @file.txt. Another one: @file2.txt.",
            {"file.txt", "file2.txt"},
        ),
        # Edge cases and extra coverage
        ("@ alone or at end: hello @", set()),
        ("@ only: @", set()),
        ('Empty quoted path: @""', set()),
        ("Unquoted path with comma: @a.txt, and @b.txt", {"a.txt", "b.txt"}),
        ("Unquoted path with semicolon: @x; @y", {"x", "y"}),
        ("Paths with underscores: @my_special_file.txt", {"my_special_file.txt"}),
        ("Windows-style path: read @src\\main.py", {"src\\main.py"}),
        (
            'Mixed quoted and unquoted: @config.json and @"big file.txt"',
            {"config.json", "big file.txt"},
        ),
        ("Newline before @: line1\n@file.txt", {"file.txt"}),
        ("VSCode-style path: @file:file.txt", {"file.txt"}),
        ("VSCode-style path with folder: @file:folder/file.txt", {"folder/file.txt"}),
    ],
)
def test_find_filepaths(prompt: str, filepaths: Set[str]):
    """Test filepath regex."""
    assert find_filepaths(prompt) == filepaths, prompt


def _numbered_file(
    directory: Path, nb_lines: int, name: str = "numbered.txt", newline: str = "\n"
) -> Path:
    """A file whose content is `nb_lines` distinguishable lines, "line 1" first.

    Bytes with an explicit terminator, because `write_text` translates "\\n" to
    os.linesep: the fixture would be CRLF on Windows and LF elsewhere, and the
    tests would only ever exercise the host's convention.
    """
    file = directory / name
    file.write_bytes(newline.join(f"line {i}" for i in range(1, nb_lines + 1)).encode())
    return file


def _assert_scanned_lines(payload: HookPayload, file: Path, expected: range) -> None:
    """The scannable holds exactly lines `expected` of `file`, byte for byte.

    Asserted separately so neither can paper over the other: it is a verbatim
    extract (no newline rewriting, no stripped "\\r" — we scan what the agent
    reads, not a normalised lookalike), and it is the right window.
    `splitlines()` here — never in `line_slice`, which must not guess at line
    boundaries — only makes the second check terminator agnostic.
    """
    content = payload.scannable.content
    assert content in file.read_bytes().decode()
    assert content.splitlines() == [f"line {i}" for i in expected]


def _claude_read(file_path: str, event: str = "PreToolUse", **tool_input: int) -> str:
    """A Claude Code Read hook payload, optionally carrying a range."""
    data: dict = {
        "session_id": "3b7ae0c5",
        "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
        "cwd": "/home/user1/foo",
        "hook_event_name": event,
        "tool_name": "Read",
        "tool_input": {"file_path": file_path, **tool_input},
    }
    if event == "PostToolUse":
        # The tool response is not what we scan for a Read: the file on disk is,
        # so that Pre and Post produce the same document.
        data["tool_response"] = {"content": "whatever the agent got back"}
    return json.dumps(data)


def _scanner_finding(needle: str) -> MagicMock:
    """A scanner that reports a secret only if `needle` is in what it is handed."""
    mock = MagicMock(spec=SecretScanner)
    mock.client = MagicMock(spec=GGClient)
    # spec= only provides what the class declares, and the verdict cache key
    # reads all three: base_uri and api_key are annotation-only on GGClient,
    # secret_config is set in SecretScanner.__init__.
    mock.client.base_uri = "https://api.example.com"
    mock.client.api_key = "some-api-key"
    mock.secret_config = SecretConfig()

    def scan(scannables, scanner_ui=None, **kwargs):
        # One answer per document, carrying its url, as the real scanner does.
        return Results(
            results=[
                ScanResult(
                    filename=scannable.filename,
                    filemode=Filemode.FILE,
                    path=Path("."),
                    url=scannable.url,
                    secrets=(
                        [_make_secret(needle)] if needle in scannable.content else []
                    ),
                    ignored_secrets_count_by_kind=Counter(),
                )
                for scannable in scannables
            ],
            errors=[],
        )

    mock.scan.side_effect = scan
    return mock


def _real_secret_scanner() -> SecretScanner:
    """A real SecretScanner with a stubbed client, to exercise the size limits."""
    client = MagicMock()
    client.maximum_payload_size = MAXIMUM_PAYLOAD_SIZE
    client.secret_scan_preferences.maximum_document_size = DOCUMENT_SIZE_THRESHOLD_BYTES
    client.secret_scan_preferences.maximum_documents_per_scan = 20
    return SecretScanner(
        client=client,
        cache=MagicMock(),
        scan_context=ScanContext(
            scan_mode=ScanMode.AI_HOOK, command_path="ggshield secret scan ai-hook"
        ),
        secret_config=SecretConfig(),
        check_api_key=False,
    )


class TestReadRange:
    """A `Tool.READ` must scan the lines the agent is actually reading.

    The part that bites: `SecretScanner._start_scans` silently skips any
    document over `maximum_document_size` (1 MiB), so over-scanning a large
    file ends up scanning nothing and allowing the read, where the slice would
    have scanned fine.

    `line_slice` takes one line of slack on each side, hence the ranges
    asserted below.

    Tests that assert on sliced bytes run against LF and CRLF on every
    platform: line numbering must not depend on the terminator, and a CRLF file
    really does carry "\\r", which the agent's context contains and we must not
    normalise away.
    """

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_claude_offset_and_limit_scans_only_that_window(
        self, tmp_path: Path, newline: str
    ):
        """GIVEN a Claude Read of lines 10-14 THEN only that window is scanned."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        payload = parse_hook_input(_claude_read(file.as_posix(), offset=10, limit=5))[0]
        assert payload.read_range == (10, 14)
        _assert_scanned_lines(payload, file, range(9, 16))

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_claude_offset_only_reads_to_the_end(self, tmp_path: Path, newline: str):
        """An open-ended read must scan to the end, not stop at some assumed cap."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        payload = parse_hook_input(_claude_read(file.as_posix(), offset=500))[0]
        assert payload.read_range == (500, None)
        _assert_scanned_lines(payload, file, range(499, 1001))

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_claude_limit_only_starts_at_the_top(self, tmp_path: Path, newline: str):
        """No offset means "from the first line", not "from nowhere"."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        payload = parse_hook_input(_claude_read(file.as_posix(), limit=5))[0]
        assert payload.read_range == (1, 5)
        _assert_scanned_lines(payload, file, range(1, 7))

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_no_range_still_scans_the_whole_file(self, tmp_path: Path, newline: str):
        """Absent range parameters mean everything: the previous behaviour."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        payload = parse_hook_input(_claude_read(file.as_posix()))[0]
        assert payload.read_range is None
        assert isinstance(payload.scannable, File)
        assert payload.scannable.content == file.read_bytes().decode()

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_secret_inside_the_range_still_blocks_at_pre(
        self, tmp_path: Path, newline: str
    ):
        """The whole point of the Pre hook: a secret about to be read is blocked."""
        file = tmp_path / "conf.txt"
        file.write_bytes(
            newline.join(
                ["padding"] * 20 + ["token=SECRET_IN_RANGE"] + ["padding"] * 500
            ).encode()
        )
        # The secret sits on line 21, the agent reads lines 15 to 25.
        payload = parse_hook_input(_claude_read(file.as_posix(), offset=15, limit=11))[
            0
        ]
        assert payload.event_type == EventType.PRE_TOOL_USE
        result = AIHookScanner(_scanner_finding("SECRET_IN_RANGE"))._scan_content(
            payload
        )
        assert result.block is True
        assert result.nbr_secrets == 1
        # The PreToolUse wording: nothing has reached the agent yet.
        assert "was not shown to the agent" in result.message

    def test_secret_outside_the_range_is_not_reported(self, tmp_path: Path):
        """A secret on a line the agent never reads never enters its context."""
        file = tmp_path / "conf.txt"
        file.write_bytes(
            "\n".join(
                ["padding"] * 400 + ["token=SECRET_OUT_OF_RANGE"] + ["padding"]
            ).encode()
        )
        payload = parse_hook_input(_claude_read(file.as_posix(), offset=1, limit=10))[0]
        scanner = _scanner_finding("SECRET_OUT_OF_RANGE")
        result = AIHookScanner(scanner)._scan_content(payload)
        assert result.block is False
        scanned = scanner.scan.call_args[0][0][0].content
        assert "SECRET_OUT_OF_RANGE" not in scanned

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_pre_and_post_scan_the_same_bytes(self, tmp_path: Path, newline: str):
        """One read must yield one identical document at both events: the
        verdict cache is keyed on (filename, content), and Pre is the only event
        that can block. CRLF included — a terminator handled differently between
        the two would miss every cache hit, or hide a Pre block behind a Post
        entry."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        pre = parse_hook_input(_claude_read(file.as_posix(), offset=10, limit=5))[0]
        post = parse_hook_input(
            _claude_read(file.as_posix(), "PostToolUse", offset=10, limit=5)
        )[0]
        assert pre.event_type == EventType.PRE_TOOL_USE
        assert post.event_type == EventType.POST_TOOL_USE
        assert pre.read_range == post.read_range == (10, 14)
        assert pre.scannable.content == post.scannable.content
        assert pre.scannable.filename == post.scannable.filename

    def test_the_sliced_scannable_is_built_once(self, tmp_path: Path):
        """Slicing reads the file, and `_scan_content` asks twice (`empty`, then
        the scan itself): the second must not re-read it."""
        file = _numbered_file(tmp_path, 1000)
        payload = parse_hook_input(_claude_read(file.as_posix(), offset=10, limit=5))[0]
        assert payload.scannable is payload.scannable

    def test_oversized_file_scans_once_only_a_slice_is_read(self, tmp_path: Path):
        """The headline case: a file too big to be scanned at all is skipped
        outright, while the slice the agent actually reads scans fine."""
        file = _numbered_file(tmp_path, 120_000)
        assert file.stat().st_size > DOCUMENT_SIZE_THRESHOLD_BYTES

        whole = parse_hook_input(_claude_read(file.as_posix()))[0]
        sliced = parse_hook_input(_claude_read(file.as_posix(), offset=1, limit=500))[0]

        scanner = _real_secret_scanner()

        whole_ui = MagicMock()
        assert scanner._start_scans(MagicMock(), [whole.scannable], whole_ui) == {}
        assert whole_ui.on_skipped.called  # nothing was sent to the API at all

        sliced_ui = MagicMock()
        assert scanner._start_scans(MagicMock(), [sliced.scannable], sliced_ui) != {}
        assert not sliced_ui.on_skipped.called

    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_vscode_start_and_end_line(self, tmp_path: Path, newline: str):
        """VS Code's read_file sends startLine/endLine, 1-based and inclusive."""
        file = _numbered_file(tmp_path, 1000, newline=newline)
        data = {
            "session_id": "69cc6a03",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "hook_event_name": "PreToolUse",
            "tool_name": "read_file",
            "tool_input": {
                "filePath": file.as_posix(),
                "startLine": 20,
                "endLine": 24,
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert isinstance(payload.agent, VSCode)
        assert payload.read_range == (20, 24)
        _assert_scanned_lines(payload, file, range(19, 26))

    def test_cursor_falls_back_to_the_whole_file(self, tmp_path: Path):
        """Cursor's Read payload mimics Claude's and may carry a range of its
        own, but we have never seen one: reading Claude's `offset`/`limit` here
        would be a guess, and a wrong guess under-scans. Whole file, as before.
        """
        file = _numbered_file(tmp_path, 1000)
        data = {
            "cursor_version": "2.5.25",
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": file.as_posix(), "offset": 10, "limit": 5},
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert isinstance(payload.agent, Cursor)
        assert payload.read_range is None
        assert payload.scannable.content == file.read_bytes().decode()

    def test_copilot_view_falls_back_to_the_whole_file(self, tmp_path: Path):
        """Every Copilot CLI `view` payload we have carries only `path`, with no
        range parameter to read: whole file, exactly as before."""
        file = _numbered_file(tmp_path, 1000)
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03",
            "tool_name": "view",
            "tool_input": {"path": file.as_posix()},
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert isinstance(payload.agent, Copilot)
        assert payload.read_range is None
        assert payload.scannable.content == file.read_bytes().decode()

    def test_codex_command_read_falls_back_to_the_whole_file(self, tmp_path: Path):
        """The only Codex commands we treat as a read are `cat` and
        `Get-Content`, which read the whole file. A partial read (`sed -n`,
        `head`) stays a Bash payload, never a Tool.READ, so there is no range to
        apply here."""
        file = _numbered_file(tmp_path, 1000)
        data = {
            "turn_id": "t1",
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": f"cat {file.as_posix()}"},
        }
        payloads = parse_hook_input(json.dumps(data))
        read_payload = next(p for p in payloads if p.tool == Tool.READ)
        assert isinstance(read_payload.agent, Codex)
        assert read_payload.read_range is None
        assert read_payload.scannable.content == file.read_bytes().decode()


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", ""])
@patch("ggshield.verticals.ai.hooks.subprocess.run")
def test_no_notification_switch_delivers_nothing(mock_run, monkeypatch, value):
    """GGSHIELD_NO_NOTIFICATION withholds the banner without reaching a backend."""
    monkeypatch.setenv("GGSHIELD_NO_NOTIFICATION", value)
    _send_desktop_notification("ggshield - Secrets Detected", "nothing appears")
    mock_run.assert_not_called()


@pytest.mark.parametrize("value", ["0", "false", "False"])
@patch("ggshield.verticals.ai.hooks.sys.platform", "darwin")
@patch("ggshield.verticals.ai.hooks.subprocess.run")
def test_a_falsy_no_notification_switch_still_notifies(mock_run, monkeypatch, value):
    """The switch reads like every other ggshield boolean: 0 and false are off."""
    monkeypatch.setenv("GGSHIELD_NO_NOTIFICATION", value)
    _send_desktop_notification("ggshield - Secrets Detected", "a banner appears")
    mock_run.assert_called_once()
