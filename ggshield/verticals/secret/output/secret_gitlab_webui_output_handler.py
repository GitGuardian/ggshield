from ggshield.core.filter import censor_match
from ggshield.core.text_utils import pluralize, translate_validity

from ..secret_scan_collection import Secret, SecretScanCollection
from .secret_output_handler import SecretOutputHandler


def format_secret(secret: Secret) -> str:
    """Returns a string with the policy name, validity and a comma-separated,
    double-quoted, censored version of all `secret` matches.

    Looks like this:

    PayPal OAuth2 Keys (Validity: Valid, id="aa*******bb", secret="cc******dd")
    """
    match_str = ", ".join(
        f'{x.match_type}: "{censor_match(x)}"' for x in secret.matches
    )
    validity = translate_validity(secret.validity)
    return f"{secret.detector_display_name} (Validity: {validity}, {match_str})"


class SecretGitLabWebUIOutputHandler(SecretOutputHandler):
    """
    Terse OutputHandler optimized for GitLab Web UI, because GitLab Web UI only shows
    lines starting with GL-HOOK-ERR.

    See https://docs.gitlab.com/ee/administration/server_hooks.html#custom-error-messages
    """

    use_stderr = True

    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        results = scan.get_all_results()

        secrets_to_report = [secret for result in results for secret in result.secrets]

        # If no secrets or no new secrets were found
        if len(secrets_to_report) == 0:
            return ""

        # Use a set to ensure we do not report duplicate incidents.
        # (can happen when the secret is present in both the old and the new version of
        # the document)
        formatted_secrets = {format_secret(x) for x in secrets_to_report}
        break_count = len(formatted_secrets)

        if self.ignore_known_secrets:
            summary_str = f"{break_count} new {pluralize('incident', break_count)}"
        else:
            summary_str = f"{break_count} {pluralize('incident', break_count)}"

        # Putting each policy break on its own line would be more readable, but we can't
        # do this because of a bug in GitLab Web IDE which causes newline characters to
        # be shown as "<br>"
        # https://gitlab.com/gitlab-org/gitlab/-/issues/350349
        breaks_str = ", ".join(formatted_secrets)

        return (
            f"GL-HOOK-ERR: ggshield found {summary_str} in these changes: {breaks_str}."
            " The commit has been rejected."
        )
