from ggshield.core.text_utils import STYLE, format_text


def remediation_message(
    remediation_steps: str, bypass_message: str, rewrite_git_history: bool = False
) -> str:

    line_start = format_text(">", STYLE["detector_line_start"])

    rewrite_git_history_message = (
        """\n  To prevent having to rewrite git history in the future, setup ggshield as a pre-commit hook:
     https://docs.gitguardian.com/ggshield-docs/integrations/git-hooks/pre-commit\n"""
        if rewrite_git_history
        else ""
    )

    return f"""{line_start} How to remediate

{remediation_steps}
{rewrite_git_history_message}
{line_start} [To apply with caution] If you want to bypass ggshield (false positive or other reason), run:
{bypass_message}"""
