"""The environment a contract test runs in, and the ggshield binary it runs."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from .sandbox import Sandbox


# Never valid anywhere: the mock never checks it, and the real API rejects it.
FAKE_API_KEY = "ggshield-contract-test-fake-key"

# Variables inherited from the developer's environment. Everything else, in
# particular GITGUARDIAN_*, starts unset.
_INHERITED_VARIABLES = ("PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")


def build_env(
    sandbox: Sandbox,
    mock_url: str,
    extra: Optional[Mapping[str, Optional[str]]] = None,
) -> Dict[str, str]:
    """A clean environment: nothing from the developer's machine leaks in."""
    env = {k: os.environ[k] for k in _INHERITED_VARIABLES if k in os.environ}
    env.update(
        {
            "HOME": str(sandbox.home),
            "USERPROFILE": str(sandbox.home),
            "GG_USER_HOME_DIR": str(sandbox.home),
            "GG_CONFIG_DIR": str(sandbox.config),
            "GG_CACHE_DIR": str(sandbox.cache),
            "GG_DATA_DIR": str(sandbox.data),
            "TMPDIR": str(sandbox.root),
            "TEMP": str(sandbox.root),
            "TMP": str(sandbox.root),
            "GITGUARDIAN_API_KEY": FAKE_API_KEY,
            "GITGUARDIAN_API_URL": mock_url,
            # HasMySecretLeaked too: an HMSL call fails visibly against the mock
            # instead of reaching api.hasmysecretleaked.com. Its JWT request to the
            # SaaS API then also goes to api_url, the mock (config.saas_api_url).
            "GITGUARDIAN_HMSL_URL": mock_url,
            "GITGUARDIAN_DONT_LOAD_ENV": "1",
            "GGSHIELD_NO_KEYRING": "1",
            "GGSHIELD_NO_NOTIFICATION": "1",
            # Not a terminal: no colours, no prompts expected
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    for key, value in (extra or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def ggshield_command(impl: str, rust_bin: str) -> List[str]:
    if impl == "python":
        # Always the Python code, never the Rust dispatcher
        return [sys.executable, "-m", "ggshield"]
    return [rust_bin]


def check_rust_bin(rust_bin: str) -> Optional[str]:
    """Return an error message when the Rust dispatcher can't run the tests."""
    binary = Path(rust_bin)
    if not binary.is_file():
        return (
            f"Rust binary not found: {binary}\n"
            "Build it with `cargo build --release` in rust/, or pass --rust-bin."
        )
    launcher = binary.resolve().parent / (
        "ggshield-py.exe" if os.name == "nt" else "ggshield-py"
    )
    if not launcher.exists():
        return (
            f"{launcher} is missing: the dispatcher hands commands it does not"
            " implement to it.\nFor local runs, copy the virtualenv's `ggshield`"
            f" entry point there, e.g.:\n  cp {Path(sys.executable).parent / 'ggshield'}"
            f" {launcher}"
        )
    return None
