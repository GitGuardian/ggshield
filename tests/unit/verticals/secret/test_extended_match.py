from pygitguardian.models import Match

from ggshield.core.lines import Line, get_lines_from_content
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.extended_match import ExtendedMatch
from tests.unit.conftest import _SINGLE_MOVE_PATCH


PLAIN_CONTENT = """/*
01234567890
*/
token=ABCD

# Some more content
# Even more content
"""


def test_from_match_for_plain_content():
    """
    GIVEN some content
    AND a match in it
    WHEN ExtendedMatch.from_match() is called
    THEN it contains the expected values
    """
    lines = get_lines_from_content(PLAIN_CONTENT, Filemode.FILE)
    start = PLAIN_CONTENT.find("A")
    # No + 1 here because in a Match object, index_end points to the last character of
    # the match, not the character after it.
    end = PLAIN_CONTENT.find("D")
    match = Match(match="ABCD", match_type="token", index_start=start, index_end=end)

    ex_match = ExtendedMatch.from_match(match, lines, is_patch=False)

    assert ex_match.line_start == 4
    assert ex_match.line_end == 4
    # ExtendedMatch.from_match() "hijacks" index_start and index_end: they become
    # 0-based *columns*, and index_end points to the character *after* the match :/
    assert ex_match.span.column_index_start == 6
    assert ex_match.span.column_index_end == 10
    assert ex_match.lines_before_secret == [
        Line(content="01234567890", is_patch=False, pre_index=2),
        Line(content="*/", is_patch=False, pre_index=3),
    ]
    assert ex_match.lines_after_secret == [
        Line(content="", is_patch=False, pre_index=5),
        Line(content="# Some more content", is_patch=False, pre_index=6),
    ]
    assert ex_match.lines_with_secret == [
        Line(content="token=ABCD", is_patch=False, pre_index=4),
    ]


def test_from_match_for_a_patch():
    """
    GIVEN a match against a patch
    AND its lines
    WHEN ExtendedMatch.from_match() is called
    THEN it contains the expected values
    """

    # When scanning a patch we send the content after the first "@@" of the patch
    content = _SINGLE_MOVE_PATCH[_SINGLE_MOVE_PATCH.index("@@") :]
    lines = get_lines_from_content(content, Filemode.MODIFY)
    start = 40
    end = 108
    match = Match(
        match=content[start : end + 1],
        match_type="token",
        index_start=start,
        index_end=end,
    )

    ex_match = ExtendedMatch.from_match(match, lines, is_patch=True)

    assert ex_match.line_start == 150
    assert ex_match.line_end == 150
    assert ex_match.span.column_index_start == 11
    assert ex_match.span.column_index_end == 80
    assert ex_match.lines_before_secret == [
        Line(
            content="@@ -150 +150,2 @@",
            is_patch=True,
            pre_index=None,
            post_index=None,
        ),
        Line(
            content="+something",
            is_patch=True,
            pre_index=None,
            post_index=150,
        ),
    ]
    assert ex_match.lines_with_secret == [
        Line(
            content=' sg_key = "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";',
            is_patch=True,
            pre_index=150,
            post_index=151,
        )
    ]
