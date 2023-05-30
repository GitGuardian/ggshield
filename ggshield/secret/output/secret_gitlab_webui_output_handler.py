from pygitguardian.models import PolicyBreak

from ggshield.core.filter import censor_match
from ggshield.core.text_utils import pluralize, translate_validity

from ..secret_scan_collection import SecretScanCollection
from .secret_output_handler import SecretOutputHandler


def format_policy_break(policy_break: PolicyBreak) -> str:
    """Returns a string with the policy name, validity and a comma-separated,
    double-quoted, censored version of all `policy_break` matches.

    Looks like this:

    PayPal OAuth2 Keys (Validity: Valid, id="aa*******bb", secret="cc******dd")
    """
    match_str = ", ".join(
        f'{x.match_type}: "{censor_match(x)}"' for x in policy_break.matches
    )
    validity = translate_validity(policy_break.validity)
    return f"{policy_break.break_type} (Validity: {validity}, {match_str})"


class SecretGitLabWebUIOutputHandler(SecretOutputHandler):
    """
    Terse OutputHandler optimized for GitLab Web UI, because GitLab Web UI only shows
    lines starting with GL-HOOK-ERR.

    See https://docs.gitlab.com/ee/administration/server_hooks.html#custom-error-messages
    """

    use_stderr = True

    def __init__(
        self, show_secrets: bool = False, ignore_known_secrets: bool = False
    ) -> None:
        super().__init__(
            show_secrets=show_secrets,
            verbose=False,
            ignore_known_secrets=ignore_known_secrets,
        )

    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        results = list(scan.get_all_results())
        # If no secrets or no new secrets were found
        if not results or (self.ignore_known_secrets and not scan.has_new_secrets):
            return ""

        policy_breaks_to_report = []
        for result in results:
            if not self.ignore_known_secrets:
                # Populate GL-HOOK-ERR with all policy breaks found
                policy_breaks_to_report += result.scan.policy_breaks
            else:
                for policy_break in result.scan.policy_breaks:
                    known = policy_break.known_secret
                    # Populate GL-HOOK-ERR with only new policy breaks
                    if not known:
                        policy_breaks_to_report.append(policy_break)

        # Use a set to ensure we do not report duplicate incidents.
        # (can happen when the secret is present in both the old and the new version of
        # the document)
        formatted_policy_breaks = {
            format_policy_break(x) for x in policy_breaks_to_report
        }
        break_count = len(formatted_policy_breaks)

        if self.ignore_known_secrets:
            summary_str = f"{break_count} new {pluralize('incident', break_count)}"
        else:
            summary_str = f"{break_count} {pluralize('incident', break_count)}"

        # Putting each policy break on its own line would be more readable, but we can't
        # do this because of a bug in GitLab Web IDE which causes newline characters to
        # be shown as "<br>"
        # https://gitlab.com/gitlab-org/gitlab/-/issues/350349
        breaks_str = ", ".join(formatted_policy_breaks)

        return (
            f"GL-HOOK-ERR: ggshield found {summary_str} in these changes: {breaks_str}."
            " The commit has been rejected."
        )
