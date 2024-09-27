import os

from ggshield.core import ui


def check_user_requested_skip() -> bool:
    if get_skip_env_var():
        ui.display_warning("Skipping ggshield hook based on SKIP environment variable.")
        return True
    return False


def get_skip_env_var() -> bool:
    """
    When `ggshield` is configured via the [pre-commit
    framework](https://pre-commit.com/) the user has the option to skip
    specific scans by setting the `SKIP` environment variable. When `ggshield`
    is configured directly as a `git` pre-commit hook, though, the user only
    has the option to disable _all_ pre-commit hooks via the `--no-verify`
    command-line option. Here we're "borrowing" the pre-commit framework's
    option so ggshield can be skipped the same way regardless of how it's
    configured.
    """
    skip_env_var = os.getenv("SKIP")
    if skip_env_var is None:
        return False

    return any(p.strip().lower() == "ggshield" for p in skip_env_var.split(","))
