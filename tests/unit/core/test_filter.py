import copy
import random
from typing import List, Set

import pytest
from pygitguardian.models import Match, PolicyBreak

from ggshield.core.filter import censor_match, censor_string, get_ignore_sha
from tests.unit.conftest import (
    _MULTILINE_SECRET,
    _MULTIPLE_SECRETS_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
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
            _MULTIPLE_SECRETS_SCAN_RESULT.policy_breaks,
            True,
            {"41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8"},
            id="_MULTIPLE_SECRETS_SCAN_RESULT-duplicated",
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
    ["text", "expected"],
    (
        ("hello world", "he*** ***ld"),
        ("abcd", "a**d"),
        ("abc", "**c"),
        ("ab", "**"),
        ("a", "*"),
    ),
)
def test_censor_string(text: str, expected: str) -> None:
    censored = censor_string(text)
    assert censored == expected
