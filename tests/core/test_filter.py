import copy
import random
import re
from pathlib import Path
from typing import Iterable, List, Set, Union

import pytest
from pygitguardian.models import Match, PolicyBreak, ScanResult
from snapshottest import Snapshot

from ggshield.core.filter import (
    censor_content,
    censor_match,
    get_ignore_sha,
    is_filepath_excluded,
    remove_ignored_from_result,
)
from ggshield.core.types import IgnoredMatch
from tests.conftest import (
    _MULTI_SECRET_ONE_LINE_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTI_SECRET_TWO_LINES_PATCH,
    _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
    _MULTILINE_SECRET,
    _MULTIPLE_SECRETS_PATCH_CONTENT,
    _MULTIPLE_SECRETS_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_MULTILINE_PATCH,
    _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_WITH_FILENAME_PATCH_SCAN_RESULT,
)


_FILTERED_MULTILINE_SECRET = """-----BEGIN RSA PRIVATE KEY-----
+MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******
+****************************************************************
+****************************************************************
+***********+****************************************************
+****************+***********************************************
+**********************+*****************************************
+****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
+-----END RSA PRIVATE KEY-----"""  # noqa


@pytest.mark.parametrize(
    "policy_breaks, duplicates, expected_shas",
    [
        pytest.param(
            _SIMPLE_SECRET_PATCH_SCAN_RESULT.policy_breaks,
            False,
            {"2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93"},
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH_SCAN_RESULT.policy_breaks,
            True,
            {"2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93"},
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-duplicated",
        ),
        pytest.param(
            _MULTIPLE_SECRETS_SCAN_RESULT.policy_breaks,
            False,
            {"41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8"},
            id="_MULTIPLE_SECRETS_SCAN_RESULT",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT.policy_breaks,
            False,
            {
                "530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1",
                "1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa",
                "060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e",
            },
            id="_MULTIPLE_SECRETS_SCAN_RESULT",
        ),
    ],
)
def test_get_ignore_sha(
    policy_breaks: List[PolicyBreak],
    duplicates: bool,
    expected_shas: Set[str],
    snapshot: Snapshot,
) -> None:
    copy_policy_breaks = copy.deepcopy(policy_breaks)
    if duplicates:
        for policy_break in policy_breaks:
            random.shuffle(policy_break.matches)
        copy_policy_breaks.extend(policy_breaks)

    ignore_shas = {get_ignore_sha(policy_break) for policy_break in copy_policy_breaks}
    if duplicates:
        assert len(ignore_shas) == len(copy_policy_breaks) / 2
    assert ignore_shas == expected_shas


@pytest.mark.parametrize(
    "scan_result, ignores, final_len",
    [
        pytest.param(
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            [],
            _SIMPLE_SECRET_PATCH_SCAN_RESULT.policy_break_count,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-no remove, not all policies",
        ),
        pytest.param(
            _SIMPLE_SECRET_WITH_FILENAME_PATCH_SCAN_RESULT,
            [],
            _SIMPLE_SECRET_WITH_FILENAME_PATCH_SCAN_RESULT.policy_break_count - 1,
            id="_SIMPLE_SECRET_PATCH_WITH_FILENAME_SCAN_RESULT-not all policies",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ["2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93"],
            0,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-remove by sha",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ["368ac3edf9e850d1c0ff9d6c526496f8237ddf91"],
            0,
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT-remove by plaintext",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            ["1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa"],
            2,
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-remove one by sha",
        ),
        pytest.param(
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
def test_remove_ignores(
    scan_result: ScanResult, ignores: Iterable, final_len: int
) -> None:
    copy_result = copy.deepcopy(scan_result)
    ignored_matches = [IgnoredMatch(name="", match=x) for x in ignores]
    remove_ignored_from_result(copy_result, ignored_matches)

    assert len(copy_result.policy_breaks) == final_len
    assert copy_result.policy_break_count == final_len


@pytest.mark.parametrize(
    "input_match, expected_value",
    [
        pytest.param(
            Match.SCHEMA.load(
                {
                    "match": "294790898041575",
                    "index_start": 31,
                    "index_end": 46,
                    "type": "client_id",
                }
            ),
            "294*********575",
            id="SIMPLE",
        ),
        pytest.param(
            Match.SCHEMA.load(
                {
                    "match": _MULTILINE_SECRET,
                    "index_start": 31,
                    "index_end": 46,
                    "type": "client_id",
                }
            ),
            _FILTERED_MULTILINE_SECRET,
            id="_MULTILINE_SECRET",
        ),
    ],
)
def test_censor_match(input_match: Match, expected_value: str) -> None:
    value = censor_match(input_match)
    assert len(value) == len(input_match.match)
    assert value == expected_value


@pytest.mark.parametrize(
    "content, policy_breaks",
    [
        pytest.param(
            _MULTIPLE_SECRETS_PATCH_CONTENT,
            _MULTIPLE_SECRETS_SCAN_RESULT.policy_breaks,
            id="_MULTIPLE_SECRETS",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT.policy_breaks,
            id="_ONE_LINE_AND_MULTILINE_PATCH_SCAN_CONTENT",
        ),
        pytest.param(
            _MULTI_SECRET_ONE_LINE_PATCH,
            _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT.policy_breaks,
            id="_MULTI_SECRET_ONE_LINE_PATCH",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_PATCH_SCAN_RESULT.policy_breaks,
            id="_SIMPLE_SECRET_PATCH",
        ),
        pytest.param(
            _SIMPLE_SECRET_MULTILINE_PATCH,
            _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT.policy_breaks,
            id="_SIMPLE_SECRET_MULTILINE_PATCH",
        ),
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_WITH_FILENAME_PATCH_SCAN_RESULT.policy_breaks,
            id="_SIMPLE_SECRET_WITH_FILENAME_PATCH",
        ),
        pytest.param(
            _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
            _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT.policy_breaks,
            id="_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY",
        ),
        pytest.param(
            _MULTI_SECRET_TWO_LINES_PATCH,
            _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT.policy_breaks,
            id="_MULTI_SECRET_TWO_LINES_PATCH",
        ),
    ],
)
def test_censor_content(content: str, policy_breaks: List[PolicyBreak]) -> None:
    copy_policy_breaks = copy.deepcopy(policy_breaks)
    new_content = censor_content(content, copy_policy_breaks)
    assert len(new_content) == len(content)
    for policy_break in policy_breaks:
        for match in policy_break.matches:
            assert match.match not in new_content


@pytest.mark.parametrize(
    "path,regexes,excluded",
    [
        ("foo", {"foo"}, True),
        (Path("dir/foo"), {"foo"}, True),
    ],
)
def test_is_filepath_excluded(
    path: Union[str, Path], regexes: Set[str], excluded: bool
) -> None:
    path = str(path)
    regexes = {re.compile(x) for x in regexes}
    assert is_filepath_excluded(path, regexes) == excluded
