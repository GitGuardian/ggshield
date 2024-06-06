from pygitguardian.models import Match

from ggshield.core.lines import Line, get_lines_from_content
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.extended_match import ExtendedMatch
from tests.unit.conftest import _SINGLE_MOVE_PATCH


def test_censor_match_for_a_patch():
    """
    GIVEN a match against a patch
    AND its lines
    WHEN ExtendedMatch.from_match()  and ext.censor() are called
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
    len_match = len(ex_match.match)
    ex_match.censor()

    assert len(ex_match.match) == len_match
    assert (
        ex_match.match
        == "SG._Yytrtvlj******************************************-**rRJLGFLBLf0M"
    )
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
            content=' sg_key = "SG._Yytrtvlj******************************************-**rRJLGFLBLf0M";',
            is_patch=True,
            pre_index=150,
            post_index=151,
        )
    ]


PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE = """/*
01234567890
*/
token1=ABCD token2=EFGH

# Some more content
# Even more content
"""


def test_censor_match_for_plain_content_multiple_on_one_line():
    """
    GIVEN some content
    AND a match in it
    WHEN ExtendedMatch.from_match() is called
    THEN it contains the expected values
    """
    lines = get_lines_from_content(PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE, Filemode.FILE)
    start1 = PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE.find("A")
    # No + 1 here because in a Match object, index_end points to the last character of
    # the match, not the character after it.
    end1 = PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE.find("D")
    match1 = Match(match="ABCD", match_type="token", index_start=start1, index_end=end1)
    start2 = PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE.find("E")
    end2 = PLAIN_CONTENT_MUTIPLE_ON_ONE_LINE.find("H")
    match2 = Match(match="EFGH", match_type="token", index_start=start2, index_end=end2)

    ex_match1 = ExtendedMatch.from_match(match1, lines, is_patch=False)
    ex_match2 = ExtendedMatch.from_match(match2, lines, is_patch=False)
    ex_match1.censor()
    ex_match2.censor()

    assert (
        ex_match1.lines_before_secret
        == ex_match2.lines_before_secret
        == [
            Line(
                content="01234567890",
                is_patch=False,
                pre_index=2,
            ),
            Line(content="*/", is_patch=False, pre_index=3),
        ]
    )
    assert (
        ex_match1.lines_after_secret
        == ex_match2.lines_after_secret
        == [
            Line(content="", is_patch=False, pre_index=5),
            Line(content="# Some more content", is_patch=False, pre_index=6),
        ]
    )
    assert (
        ex_match1.lines_with_secret
        == ex_match2.lines_with_secret
        == [
            Line(
                content="token1=A**D token2=E**H",
                is_patch=False,
                pre_index=4,
            ),
        ]
    )
