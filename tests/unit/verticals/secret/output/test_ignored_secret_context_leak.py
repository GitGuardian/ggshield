"""
Regression test: NOT_INTRODUCED secrets must not leak in plaintext
through context lines of adjacent displayed secrets.
"""

import click
from pygitguardian.models import ScanResult

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from ggshield.verticals.secret.output import SecretTextOutputHandler


# ---------------------------------------------------------------------------
# Patch content
# Context line holds an existing secret; the addition line holds a new one.
# The two are adjacent so the context secret lands in lines_before_secret of
# the displayed addition secret.
# ---------------------------------------------------------------------------
_PATCH = '@@ -1,2 +1,3 @@\n SMTP_PASSWORD = "existing_secret_abc123"\n+SMTP_PASSWORD2 = "new_secret_def456"\n'

_EXISTING_SECRET = "existing_secret_abc123"
_NEW_SECRET = "new_secret_def456"

_EXISTING_START = _PATCH.index(_EXISTING_SECRET)
_EXISTING_END = _EXISTING_START + len(_EXISTING_SECRET) - 1
_NEW_START = _PATCH.index(_NEW_SECRET)
_NEW_END = _NEW_START + len(_NEW_SECRET) - 1

# ScanResult with:
#   - policy break 1: diff_kind=context  → will be filtered as NOT_INTRODUCED
#   - policy break 2: diff_kind=addition → displayed in output
_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["Secrets detection"],
        "policy_breaks": [
            {
                "type": "Generic Password",
                "detector_name": "generic_password",
                "detector_group_name": "generic_password",
                "documentation_url": None,
                "policy": "Secrets detection",
                "validity": "no_checker",
                "known_secret": False,
                "incident_url": None,
                "is_excluded": False,
                "is_vaulted": False,
                "diff_kind": "context",
                "matches": [
                    {
                        "match": _EXISTING_SECRET,
                        "index_start": _EXISTING_START,
                        "index_end": _EXISTING_END,
                        "type": "password",
                    }
                ],
            },
            {
                "type": "Generic Password",
                "detector_name": "generic_password",
                "detector_group_name": "generic_password",
                "documentation_url": None,
                "policy": "Secrets detection",
                "validity": "no_checker",
                "known_secret": False,
                "incident_url": None,
                "is_excluded": False,
                "is_vaulted": False,
                "diff_kind": "addition",
                "matches": [
                    {
                        "match": _NEW_SECRET,
                        "index_start": _NEW_START,
                        "index_end": _NEW_END,
                        "type": "password",
                    }
                ],
            },
        ],
        "policy_break_count": 2,
    }
)


def _run_output(show_secrets: bool) -> str:
    result = Result.from_scan_result(
        StringScannable(
            content=_PATCH,
            url="emailService.js",
            filemode=Filemode.MODIFY,
        ),
        scan_result=_SCAN_RESULT,
        secret_config=SecretConfig(),
    )
    handler = SecretTextOutputHandler(
        secret_config=SecretConfig(show_secrets=show_secrets),
        verbose=True,
    )
    raw = handler._process_scan_impl(
        SecretScanCollection(
            id="scan",
            type="commit",
            results=Results(results=[result]),
        )
    )
    return click.unstyle(raw)


def test_ignored_context_secret_not_leaked_in_adjacent_secret_context():
    """
    GIVEN a patch where a context-line secret (NOT_INTRODUCED) is immediately
      above an addition-line secret
    WHEN the text output handler renders the result with show_secrets=False
    THEN the ignored secret's plaintext value must not appear anywhere in the
      output (not even as a context line for the displayed addition secret)
    """
    output = _run_output(show_secrets=False)

    assert (
        _EXISTING_SECRET not in output
    ), f"Ignored secret '{_EXISTING_SECRET}' leaked in plaintext output:\n{output}"
    assert (
        _NEW_SECRET not in output
    ), f"Displayed secret '{_NEW_SECRET}' not censored in output:\n{output}"


def test_show_secrets_reveals_both():
    """
    Sanity check: with show_secrets=True both values appear.
    (The addition secret is shown; the context secret may appear in context.)
    """
    output = _run_output(show_secrets=True)
    assert _NEW_SECRET in output
