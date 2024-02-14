import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Union

import pytest
from pygitguardian.models import Match

from ggshield.core.filter import censor_match
from tests.functional.conftest import GGSHIELD_PATH


PathLike = Union[Path, str]


def run_ggshield(
    *args: str,
    expected_code: int = 0,
    cwd: Optional[PathLike] = None,
    env: Optional[Dict] = None,
) -> subprocess.CompletedProcess:
    env = env or dict()
    assert GGSHIELD_PATH is not None
    cmd = (GGSHIELD_PATH, *args)
    cwd = None if cwd is None else str(cwd)
    result = subprocess.run(
        cmd,
        check=False,
        text=True,
        capture_output=True,
        cwd=cwd,
        env={**os.environ, **env},
    )
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
    *args: str,
    expected_code: int = 0,
    cwd: Optional[PathLike] = None,
    env: Optional[Dict] = None,
) -> subprocess.CompletedProcess:
    env = env or dict()
    args = ("secret", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd, env=env)


def run_ggshield_iac_scan(
    *args: str,
    expected_code: int = 0,
    cwd: Optional[PathLike] = None,
    env: Optional[Dict] = None,
) -> subprocess.CompletedProcess:
    env = env or dict()
    args = ("iac", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd, env=env)


def run_ggshield_sca_scan(
    *args: str,
    expected_code: int = 0,
    cwd: Optional[PathLike] = None,
    env: Optional[Dict] = None,
) -> subprocess.CompletedProcess:
    env = env or dict()
    args = ("sca", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd, env=env)


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


# Use this in iac/sca tests until iac/sca hooks are added to the install command
# Meaning they are added to install.py
def create_local_hook(
    hook_dir_path: Path,
    scan_type: str,
    hook_type: str,
    args: Optional[List[str]] = None,
) -> None:
    """Create hook directory (if needed) and pre-commit/pre-push file."""
    hook_dir_path.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir_path / hook_type

    args = args or []

    with hook_path.open("w") as f:
        f.write("#!/usr/bin/env sh\n")
        f.write(f'ggshield {scan_type} scan {hook_type} {" ".join(args)} "$@"\n')
        os.chmod(hook_path, 0o700)
