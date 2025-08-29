import os
import re
import shutil
import subprocess as sp
import time
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

import click
from requests import HTTPError

from ggshield.cmd.hmsl.hmsl_common_options import (
    full_hashes_option,
    naming_strategy_option,
)
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import pluralize
from ggshield.verticals.hmsl import get_client
from ggshield.verticals.hmsl.collection import NamingStrategy, collect_list, prepare
from ggshield.verticals.hmsl.output import show_results


# Private key filenames and suffixes from s1ngularity-scanner
PRIVATE_KEYS_FILENAMES = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "certificate.p12",
    "secring.gpg",
    ".gnupg/private-keys-v1.d",
    "private_key.dat",
)
PRIVATE_KEYS_SUFFIXES = (".key", ".pem", ".p12", ".pfx")

# Regex patterns for extracting assigned values from files
assignment_regex = re.compile(
    r"""
    ^\s*
    [a-zA-Z_]\w*
    \s*=\s*
    (?P<value>.{1,5000})
""",
    re.VERBOSE,
)

json_assignment_regex = re.compile(
    r"""
    "[a-zA-Z_]\w*"
    \s*:\s*
    "(?P<value>.{1,5000}?)"
""",
    re.VERBOSE,
)


def remove_quotes(value: str) -> str:
    """Remove surrounding quotes from a value."""
    if len(value) > 1 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]
    return value


def extract_assigned_values(text: str) -> Set[str]:
    """Extract assigned values from text using regex patterns."""
    res = []
    for line in text.splitlines():
        for m in re.finditer(assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value.strip())
            if "#" in pwd_value:
                res.append(pwd_value.split("#")[0].strip())

        for m in re.finditer(json_assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value)

    return {remove_quotes(val) for val in res}


def get_github_token() -> Optional[str]:
    """Get GitHub token from gh CLI if available."""
    if shutil.which("gh"):
        try:
            result = sp.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=sp.DEVNULL,
            )
            if result.returncode == 0 and result.stdout:
                token = result.stdout.strip()
                if re.match(r"^(gho_|ghp_)", token):
                    return token
        except (sp.TimeoutExpired, sp.SubprocessError):
            pass
    return None


def should_skip_directory(dirname: str) -> bool:
    """Determine if a directory should be skipped during traversal."""
    if (
        dirname.startswith(".")
        and dirname not in {".env", ".ssh"}
        and not dirname.startswith(".env")
    ):
        return True
    elif dirname == "node_modules":
        return True
    return False


def get_file_source_info(fpath: Path) -> Optional[str]:
    """Get source info for a file if it should be processed."""
    if fpath.name == ".npmrc":
        return "NPMRC"
    elif fpath.name.startswith(".env") and "example" not in fpath.name:
        return "ENV_FILE"
    elif fpath.name in PRIVATE_KEYS_FILENAMES or any(
        fpath.name.endswith(suffix) for suffix in PRIVATE_KEYS_SUFFIXES
    ):
        return "PRIVATE_KEY"
    return None


class HostSecretGatherer:
    """Handles scanning the local host for secrets."""

    def __init__(self, timeout: int, min_chars: int, verbose: bool = False):
        self.timeout = timeout
        self.min_chars = min_chars
        self.verbose = verbose
        self.home = Path.home()
        self.results: List[Tuple[str, str]] = []
        self.start_time = time.time()
        self.files_processed = 0

    def _show_progress(self, message: str):
        """Show progress message if verbose."""
        if self.verbose:
            elapsed = int(time.time() - self.start_time)
            ui.display_info(f"{message} ({elapsed}s)")

    def gather_environment_variables(self) -> List[Tuple[str, str]]:
        """Collect environment variables."""
        env_vars = []
        for key, value in os.environ.items():
            if len(value) >= self.min_chars:
                env_vars.append((f"ENVIRONMENT_VAR<gg>{key}", value))

        if self.verbose:
            ui.display_info(f"Environment variables: {len(env_vars)} found")
        return env_vars

    def gather_github_token(self) -> List[Tuple[str, str]]:
        """Collect GitHub token if available."""
        gh_token = get_github_token()
        if gh_token and len(gh_token) >= self.min_chars:
            if self.verbose:
                ui.display_info("GitHub token: found")
            return [("GITHUB_TOKEN<gg>gh_auth_token", gh_token)]
        else:
            if self.verbose:
                ui.display_info("GitHub token: not found")
            return []

    def gather_files(self) -> List[Tuple[str, str]]:
        """Gather secrets from files using filesystem walk."""
        file_results = []

        if self.verbose:
            ui.display_info("Starting filesystem scan...")

        try:
            for root, dirs, files in os.walk(self.home):
                current_time = time.time()

                # Check timeout
                if self.timeout > 0 and (current_time - self.start_time) > self.timeout:
                    ui.display_warning(
                        f"Timeout of {self.timeout}s reached after processing "
                        f"{self.files_processed} files"
                    )
                    break

                # Remove unwanted directories
                dirs[:] = [d for d in dirs if not should_skip_directory(d)]

                # Process files in current directory
                for filename in files:
                    fpath = Path(root) / filename
                    source_info = get_file_source_info(fpath)

                    if source_info is None:
                        continue

                    self.files_processed += 1

                    try:
                        text = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception as e:
                        if self.verbose:
                            ui.display_warning(f"Failed reading {fpath}: {e}")
                        continue

                    # For private keys, use the full content
                    if source_info == "PRIVATE_KEY":
                        if len(text.strip()) >= self.min_chars:
                            file_results.append(
                                (f"{source_info}<gg>{fpath}", text.strip())
                            )
                            if self.verbose:
                                ui.display_info(f"Found private key in {fpath}")
                    else:
                        # For other files, extract assigned values
                        values = extract_assigned_values(text)
                        for value in values:
                            if len(value) >= self.min_chars:
                                file_results.append(
                                    (f"{source_info}<gg>{fpath}", value)
                                )

                        if self.verbose and values:
                            ui.display_info(f"Found {len(values)} values in {fpath}")

                    # Check timeout after processing file
                    current_time = time.time()
                    if (
                        self.timeout > 0
                        and (current_time - self.start_time) > self.timeout
                    ):
                        ui.display_warning(
                            f"Timeout of {self.timeout}s reached after processing "
                            f"{self.files_processed} files"
                        )
                        break

        except KeyboardInterrupt:
            ui.display_warning("Scan interrupted by user")

        if self.verbose:
            ui.display_info(
                f"File scan complete: {len(file_results)} values from {self.files_processed} files"
            )

        return file_results

    def gather_all(self) -> List[Tuple[str, str]]:
        """Gather all secrets from the host."""
        all_results = []

        # Collect environment variables
        all_results.extend(self.gather_environment_variables())

        # Collect GitHub token
        all_results.extend(self.gather_github_token())

        # Collect from files
        all_results.extend(self.gather_files())

        return all_results


@click.command()
@click.option(
    "--min-chars",
    type=int,
    default=5,
    help="Minimum character length for values to consider",
    show_default=True,
)
@click.option(
    "--timeout",
    type=int,
    default=0,
    help="Maximum time to spend scanning filesystem (0 for unlimited)",
    show_default=True,
)
@click.option(
    "--max-public-occurrences",
    type=int,
    default=10,
    help="Maximum number of public occurrences for a leak to be reported",
    show_default=True,
)
@add_common_options()
@text_json_format_option
@json_option
@full_hashes_option
@naming_strategy_option
@click.pass_context
def check_host_cmd(
    ctx: click.Context,
    min_chars: int,
    timeout: int,
    max_public_occurrences: int,
    full_hashes: bool,
    naming_strategy: NamingStrategy,
    **kwargs: Any,
) -> int:
    """
    Check if secrets from the local host have leaked.

    This command scans the local environment for potentially leaked secrets by:
    - Collecting environment variables
    - Extracting GitHub token (if gh CLI is available)
    - Scanning configuration files (.env, .npmrc, etc.)
    - Finding private key files

    All processing occurs locally - no secrets are transmitted, only their hashes
    are compared against the GitGuardian database.
    """
    ui.display_info("🔍 Scanning local host for potentially leaked secrets...")
    ui.display_info("🔒 All processing occurs locally, no secrets transmitted")

    if ui.is_verbose():
        timeout_desc = f"{timeout}s" if timeout > 0 else "unlimited"
        ui.display_info(f"Settings: min-chars={min_chars}, timeout={timeout_desc}")

    # Gather secrets from the host
    gatherer = HostSecretGatherer(timeout, min_chars, ui.is_verbose())
    secrets_data = gatherer.gather_all()

    if not secrets_data:
        ui.display_info("No secrets found to check")
        return 0

    ui.display_info(
        f"🔍 Checking {len(secrets_data)} {pluralize('value', len(secrets_data))} "
        f"against public leak database..."
    )

    # Prepare secrets for HMSL
    collected_secrets = collect_list(secrets_data)
    prepared_secrets = prepare(collected_secrets, naming_strategy, full_hashes=True)

    # Use the enhanced check_secrets from hmsl_utils with a custom show_results call

    # Query the API
    ui.display_info("Querying HasMySecretLeaked...")
    ctx_obj = ContextObj.get(ctx)
    client = get_client(ctx_obj.config, hmsl_command_path=ctx.command_path)
    found = []
    error = None
    try:
        found = list(client.check(prepared_secrets.payload, full_hashes=full_hashes))
    except (ValueError, HTTPError) as exception:
        error = exception
    ui.display_info(
        f"{client.quota.remaining} {pluralize('credit', client.quota.remaining)} left for today."
    )

    # Filter by max_public_occurrences
    filtered_secrets = [s for s in found if s.count < max_public_occurrences]
    filtered_count = len(found) - len(filtered_secrets)

    if filtered_count > 0:
        ui.display_info(
            f"ℹ️  Filtered out {filtered_count} leak{'s' if filtered_count > 1 else ''} "
            f"with high public occurrence count (≥{max_public_occurrences})"
        )

    # Use the enhanced show_results with grouping
    show_results(
        secrets=filtered_secrets,
        names=prepared_secrets.mapping,
        json_output=ctx_obj.use_json,
        error=error,
        group_by_source=True,
    )

    if error:
        raise UnexpectedError(str(error))

    return 0
