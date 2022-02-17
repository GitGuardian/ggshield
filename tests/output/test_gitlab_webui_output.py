from pygitguardian.models import Match, PolicyBreak

from ggshield.output.gitlab_webui.gitlab_webui_output_handler import format_policy_break


def test_format_policy_break():
    policy = PolicyBreak(
        "PayPal",
        "Secrets detection",
        "valid",
        [
            Match("AZERTYUIOP", "client_id", line_start=123),
            Match("abcdefghijk", "client_secret", line_start=456),
        ],
    )
    out = format_policy_break(policy)

    assert policy.break_type in out
    assert "Validity: Valid" in out
    for match in policy.matches:
        assert match.match_type in out
        # match value itself must be obfuscated
        assert match.match not in out
