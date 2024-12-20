from collections.abc import Iterable

import pytest
from pygitguardian.models import ScanResult

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.filter import get_ignore_sha
from ggshield.core.scan import StringScannable
from ggshield.core.types import IgnoredMatch
from ggshield.verticals.secret import Results
from ggshield.verticals.secret.secret_scan_collection import (
    IgnoreKind,
    IgnoreReason,
    Result,
    compute_ignore_reason,
)
from tests.factories import PolicyBreakFactory, ScannableFactory, ScanResultFactory
from tests.unit.conftest import (
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
)


class MyException(Exception):
    pass


def test_results_from_exception():
    """
    GIVEN an exception
    WHEN creating a Results from it
    THEN it contains the right content
    """
    exc = MyException("Hello")
    results = Results.from_exception(exc)

    assert len(results.errors) == 1
    error = results.errors[0]
    assert error.description == "MyException: Hello"

    assert results.results == []


@pytest.mark.parametrize(
    ("content", "scan_result", "ignores", "final_len"),
    [
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            [],
            _SIMPLE_SECRET_PATCH_SCAN_RESULT.policy_break_count,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-no remove, not all policies",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ["2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93"],
            0,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-remove by sha",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ["368ac3edf9e850d1c0ff9d6c526496f8237ddf91"],
            0,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-remove by plaintext",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            ["1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa"],
            2,
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-remove one by sha",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            [
                "060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e",
                "ce3f9f0362bbe5ab01dfc8ee565e4371",
            ],
            1,
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-remove two by mix",
        ),
    ],
)
def test_create_result_removes_ignored_matches(
    content: str, scan_result: ScanResult, ignores: Iterable, final_len: int
) -> None:
    result = Result.from_scan_result(
        file=StringScannable(url="localhost", content=content),
        scan_result=scan_result,
        secret_config=SecretConfig(
            ignored_matches=[IgnoredMatch(name="", match=x) for x in ignores]
        ),
    )
    assert len(result.secrets) == final_len


@pytest.mark.parametrize("all_secrets", (True, False))
def test_create_result_removes_ignored_matches_bis(all_secrets):
    """
    GIVEN two different policy breaks
    WHEN ignoring the first one
    THEN it is ignored iff all_secrets is false

    Note: this test could replace the one above
    """
    scannable = ScannableFactory()
    policy_breaks = PolicyBreakFactory.create_batch(2, content=scannable.content)

    # ensure policy breaks are different
    if policy_breaks[0].matches[0].match_type == policy_breaks[1].matches[0].match_type:
        policy_breaks[0].matches[0].match_type += "a"

    config = SecretConfig(
        ignored_matches=[
            IgnoredMatch(name="x", match=get_ignore_sha(policy_breaks[0]))
        ],
        all_secrets=all_secrets,
    )
    result = Result.from_scan_result(
        scannable, ScanResultFactory(policy_breaks=policy_breaks), config
    )
    if all_secrets:
        assert len(result.secrets) == 2
        assert result.secrets[0].is_ignored is True
        assert result.secrets[1].is_ignored is False
    else:
        assert len(result.secrets) == 1
        assert result.secrets[0].is_ignored is False
        assert result.ignored_secrets_count_by_kind[IgnoreKind.IGNORED_MATCH] == 1


class TestComputeIgnoreReason:
    def test_ignore_excluded(self):
        """
        GIVEN an policy break excluded from the backend
        WHEN computing the ignore reason
        THEN it contains the original exclusion reason (and is not None)
        """
        policy_break = PolicyBreakFactory(
            is_excluded=True, exclude_reason="BACKEND_REASON"
        )
        assert compute_ignore_reason(policy_break, SecretConfig()) == IgnoreReason(
            IgnoreKind.BACKEND_EXCLUDED, "BACKEND_REASON"
        )

    def test_ignore_ignored_match(self):
        """
        GIVEN an policy break matching an ignored sha in config
        WHEN computing the ignore reason
        THEN it's not None
        """
        policy_break = PolicyBreakFactory()
        config = SecretConfig(
            ignored_matches=[
                IgnoredMatch(name="x", match=get_ignore_sha(policy_break))
            ],
        )
        assert compute_ignore_reason(policy_break, config) is not None

    def test_ignore_ignored_detector(self):
        """
        GIVEN a policy break matching an ignored detector in config
        WHEN computing the ignore reason
        THEN it's not None
        """
        policy_break = PolicyBreakFactory()
        config = SecretConfig(
            ignored_detectors=[policy_break.break_type],
        )
        assert compute_ignore_reason(policy_break, config) is not None

    @pytest.mark.parametrize("ignore_known", (True, False))
    def test_known_secret(self, ignore_known):
        """
        GIVEN a known policy break
        WHEN computing the ignore reason
        THEN it's not None iff ignore_secret is enabled in config
        """
        policy_break = PolicyBreakFactory(known_secret=True)
        config = SecretConfig(ignore_known_secrets=ignore_known)
        assert bool(compute_ignore_reason(policy_break, config)) is ignore_known
