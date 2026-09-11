import copy
import random
import re
from typing import List, Set

import pytest
from click import UsageError
from pygitguardian.models import Match, PolicyBreak

from ggshield.core.filter import (
    censor_match,
    censor_string,
    get_ignore_sha,
    is_in_ignored_match_patterns,
    validate_ignored_match_patterns,
)
from tests.factories import build_policy_break
from tests.factory_constants import (
    INVALID_REGEX_PATTERN,
    SOPS_ENCRYPTED_VALUE,
    SOPS_PATTERN,
)
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


class TestIsInIgnoredMatchPatterns:
    def test_without_pattern(self) -> None:
        """
        GIVEN a policy break and no ignore pattern
        WHEN checking whether it is ignored
        THEN it should not be
        """
        policy_break = build_policy_break(SOPS_ENCRYPTED_VALUE)

        assert is_in_ignored_match_patterns(policy_break, []) is False

    def test_matching_pattern(self) -> None:
        """
        GIVEN a policy break whose match is a sops-encrypted value
        WHEN checking it against a pattern for sops-encrypted values
        THEN it should be ignored
        """
        policy_break = build_policy_break(SOPS_ENCRYPTED_VALUE)

        assert is_in_ignored_match_patterns(policy_break, [SOPS_PATTERN]) is True

    def test_non_matching_pattern(self) -> None:
        """
        GIVEN a policy break whose match is a plaintext secret
        WHEN checking it against a pattern for sops-encrypted values
        THEN it should not be ignored
        """
        policy_break = build_policy_break("hunter2")

        assert is_in_ignored_match_patterns(policy_break, [SOPS_PATTERN]) is False

    def test_one_matching_pattern_among_several(self) -> None:
        """
        GIVEN a policy break whose match is a sops-encrypted value
        WHEN checking it against several patterns, one of which matches
        THEN it should be ignored
        """
        policy_break = build_policy_break(SOPS_ENCRYPTED_VALUE)

        assert (
            is_in_ignored_match_patterns(policy_break, ["^vault:", SOPS_PATTERN])
            is True
        )

    def test_one_matching_match_among_several(self) -> None:
        """
        GIVEN a policy break carrying several matches, one of which is sops-encrypted
        WHEN checking it against a pattern for sops-encrypted values
        THEN it should be ignored
        """
        policy_break = build_policy_break("admin", SOPS_ENCRYPTED_VALUE)

        assert is_in_ignored_match_patterns(policy_break, [SOPS_PATTERN]) is True

    def test_unanchored_pattern(self) -> None:
        """
        GIVEN a policy break whose match contains a sops algorithm name
        WHEN checking it against an unanchored pattern
        THEN it should be ignored, the pattern being searched anywhere in the match
        """
        policy_break = build_policy_break(SOPS_ENCRYPTED_VALUE)

        assert is_in_ignored_match_patterns(policy_break, ["AES256_GCM"]) is True


class TestValidateIgnoredMatchPatterns:
    def test_valid_patterns(self) -> None:
        """
        GIVEN patterns which are valid regexes
        WHEN validating them
        THEN it should be accepted
        """
        validate_ignored_match_patterns([SOPS_PATTERN, "^vault:"])

    def test_invalid_pattern(self) -> None:
        """
        GIVEN a pattern which is not a valid regex
        WHEN validating it
        THEN it should raise a usage error naming the pattern
        """
        with pytest.raises(UsageError, match=re.escape(INVALID_REGEX_PATTERN)):
            validate_ignored_match_patterns([INVALID_REGEX_PATTERN])

    def test_empty_pattern(self) -> None:
        """
        GIVEN an empty pattern, which would match every secret
        WHEN validating it
        THEN it should raise a usage error instead of silencing all detection
        """
        with pytest.raises(UsageError, match="should not be empty"):
            validate_ignored_match_patterns([SOPS_PATTERN, ""])
