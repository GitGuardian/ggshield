import json
import subprocess
from pathlib import Path
from typing import Optional, Union

import pytest
from pygitguardian.models import Match

from ggshield.core.filter import censor_match


PathLike = Union[Path, str]


def run_ggshield(
    *args: str, expected_code: int = 0, cwd: Optional[PathLike] = None
) -> subprocess.CompletedProcess:
    cmd = ("ggshield", *args)
    cwd = None if cwd is None else str(cwd)
    result = subprocess.run(cmd, check=False, text=True, capture_output=True, cwd=cwd)
    assert (
        result.returncode == expected_code
    ), f"""Expected returncode {expected_code}, got {result.returncode}

        == stdout ==

        {result.stdout}

        == stderr ==

        {result.stderr}
        """
    return result


def run_ggshield_scan(
    *args: str, expected_code: int = 0, cwd: Optional[PathLike] = None
) -> subprocess.CompletedProcess:
    args = ("secret", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd)


def run_ggshield_iac_scan(
    *args: str, expected_code: int = 0, cwd: Optional[PathLike] = None
) -> subprocess.CompletedProcess:
    args = ("iac", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd)


def assert_is_valid_json(txt: str) -> None:
    try:
        json.loads(txt)
    except Exception as exc:
        pytest.fail(f"Text is not a valid JSON document:\n---\n{txt}\n---\n{exc}")


def recreate_censored_string(matched_string: str) -> str:
    """Applies ggshield censoring to `matched_string`"""
    match = Match(match=matched_string, match_type="")
    return censor_match(match)


def recreate_censored_content(content: str, matched_string: str) -> str:
    """Applies ggshield censoring to any occurrence of `matched_string` inside
    `content`. Returns the censored string."""
    return content.replace(matched_string, recreate_censored_string(matched_string))
