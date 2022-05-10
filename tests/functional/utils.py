import json
import os
import subprocess
from typing import Optional

import pytest


def run_ggshield(
    *args: str, expected_code: int = 0, cwd: Optional[str] = None
) -> subprocess.CompletedProcess:
    cmd = ["ggshield"]
    if "https_proxy" in os.environ:
        cmd.append("--allow-self-signed")
    cmd.extend(args)
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
    *args: str, expected_code: int = 0, cwd: Optional[str] = None
) -> subprocess.CompletedProcess:
    args = ("secret", "scan", *args)
    return run_ggshield(*args, expected_code=expected_code, cwd=cwd)


def assert_is_valid_json(txt: str) -> None:
    try:
        json.loads(txt)
    except Exception as exc:
        pytest.fail(f"Text is not a valid json document:\n---\n{txt}\n---\n{exc}")
