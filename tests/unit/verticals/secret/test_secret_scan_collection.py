from collections.abc import Iterable

import pytest
from pygitguardian.models import ScanResult

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import StringScannable
from ggshield.core.types import IgnoredMatch
from ggshield.verticals.secret import Results
from ggshield.verticals.secret.secret_scan_collection import Result
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
def test_create_result_remove_ignores(
    content: str, scan_result: ScanResult, ignores: Iterable, final_len: int
) -> None:
    result = Result.from_scan_result(
        file=StringScannable(url="localhost", content=content),
        scan_result=scan_result,
        secret_config=SecretConfig(
            ignored_matches=[IgnoredMatch(name="", match=x) for x in ignores]
        ),
    )
    assert len(result.policy_breaks) == final_len


def test_ignore_all_secrets():
    pass
