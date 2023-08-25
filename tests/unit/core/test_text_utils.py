from typing import Optional

import pytest

from ggshield.core.text_utils import clip_long_line, translate_validity


@pytest.mark.parametrize(
    "validity_id, expected",
    [
        ("unknown", "Unknown"),
        (None, "Unknown"),
        ("valid", "Valid"),
        ("unexpected_status", "unexpected_status"),
    ],
)
def test_translate_validity(validity_id: Optional[str], expected: str):
    result = translate_validity(validity_id)
    assert result == expected


@pytest.mark.parametrize(
    "params, want",
    [
        # should not clip anything
        (("123456789", 10, False, False, 0), "123456789"),
        (("123456789", 10, True, False, 0), "123456789"),
        (("123456789", 10, False, True, 0), "123456789"),
        (("123456789", 10, True, True, 0), "123456789"),
        # edge case: should not clip anything
        (("123456789", 9, True, True, 0), "123456789"),
        # edge case: should only clip after
        (("123456789", 8, True, True, 0), "1234567…"),
        # should clip as expected
        (("123456789", 5, False, False, 0), "123456789"),
        (("123456789", 5, True, False, 0), "…6789"),
        (("123456789", 5, False, True, 0), "1234…"),
        (("123456789", 5, True, True, 0), "…456…"),
        (("123456789", 4, True, False, 0), "…789"),
        (("123456789", 4, False, True, 0), "123…"),
        (("123456789", 4, True, True, 0), "…45…"),
        (("123456789", 4, True, True, 6), "…3456…"),
    ],
)
def test_clip_long_line(params, want):
    assert clip_long_line(*params) == want
