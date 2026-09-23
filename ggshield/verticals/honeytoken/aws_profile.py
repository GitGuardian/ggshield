"""
On-disk placement of honeytoken AWS credential profiles for
``ggshield honeytoken plant``.

GIM owns *what* (method, filename, profile name); the client owns *where* — both AWS
methods land under ``~/.aws/``. The two methods differ only in the INI section name:

- ``aws_credentials`` → ``[profile_name]`` in the shared **credentials** file.
- ``aws_config_profile`` → ``[profile profile_name]`` in the **config** file (AWS
  mandates the ``profile `` prefix there).

The file is edited in place with ``configupdater`` so the user's other profiles and
comments survive; all reads and writes go through ``secure_file`` (no-follow,
fd-anchored, locked) so the root fan-out is TOCTOU-safe.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Optional, Tuple

from configupdater import ConfigUpdater

from ggshield.verticals.honeytoken import secure_file
from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentMethod,
    HoneytokenCreds,
    PlacementConfig,
)
from ggshield.verticals.honeytoken.placement import ForceRefusal as _ForceRefusal
from ggshield.verticals.honeytoken.placement import (
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.secure_file import SecureFileError


_ACCESS_KEY = "aws_access_key_id"
_SECRET_KEY = "aws_secret_access_key"


class ForceRefusal(_ForceRefusal):
    """A profile holds different credentials than ours."""

    def __init__(self, profile: str, path: Path) -> None:
        super().__init__(
            f"profile [{profile}] in {path} already exists with different credentials "
            "(access key id and/or secret differ from ours) — refusing to overwrite "
            "without --force",
            name=profile,
            path=path,
        )
        self.profile = profile


def aws_path(home: Path, filename: str) -> Path:
    """Compose ``<home>/.aws/<filename>``, re-asserting the backend's safe-charset rule
    (defense in depth: this may run as root) so the path stays directly inside ``.aws``.
    """
    if filename in ("", ".", "..") or "/" in filename or "\\" in filename:
        raise PlacementError(f"invalid honeytoken filename {filename!r}")
    return home / ".aws" / filename


def resolve_placement(
    method: DeploymentMethod, config: PlacementConfig, home: Path
) -> Tuple[Path, str]:
    """Resolve the on-disk path + INI section for a placement. The section format is the
    AWS quirk distinguishing the two methods: the config file needs a ``profile `` prefix
    on named profiles, the credentials file does not."""
    path = aws_path(home, config.filename)
    if method is DeploymentMethod.AWS_CREDENTIALS:
        return path, config.profile_name
    if method is DeploymentMethod.AWS_CONFIG_PROFILE:
        return path, f"profile {config.profile_name}"
    raise PlacementError("unsupported deployment method — client may be out of date")


# --- INI parsing + our-profile decision (shared by both I/O backends) -------------


def _parse_text(text: Optional[str], where: Path) -> ConfigUpdater:
    # configupdater edits in place and keeps comments (configparser wouldn't).
    parser = ConfigUpdater()
    if text:
        # Else configupdater glues our new section onto the last line.
        if not text.endswith("\n"):
            text += "\n"
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            # configupdater parse errors subclass configparser.Error.
            raise PlacementError(
                f"could not parse {where}: not a valid AWS credentials/INI file ({exc})"
            )
    return parser


def _get_value(parser: ConfigUpdater, section: str, key: str) -> Optional[str]:
    sec = parser[section]
    if sec.has_option(key):
        return sec[key].value
    return None


def _decide_write(
    parser: ConfigUpdater,
    section: str,
    creds: HoneytokenCreds,
    force: bool,
    path: Path,
) -> WriteOutcome:
    """Mutate ``parser`` to hold our profile and return the outcome.

    - profile absent → write
    - profile present with the same access key **and** secret → no-op (``ALREADY_CURRENT``)
    - profile present but access key id **and/or** secret differ → refuse unless ``force``
    """
    if parser.has_section(section):
        existing_id = _get_value(parser, section, _ACCESS_KEY)
        existing_secret = _get_value(parser, section, _SECRET_KEY)
        if existing_id == creds.access_token_id and existing_secret == creds.secret_key:
            return WriteOutcome.ALREADY_CURRENT
        if not force:
            raise ForceRefusal(section, path)
    else:
        parser.add_section(section)
    parser[section][_ACCESS_KEY] = creds.access_token_id
    parser[section][_SECRET_KEY] = creds.secret_key
    return WriteOutcome.WROTE


def _decide_remove(
    parser: ConfigUpdater, section: str, expected_access_key_id: Optional[str]
) -> RemoveOutcome:
    """Drop our section if present and (optionally) key-matched; return the outcome.
    ``REMOVED`` means the caller must persist (or unlink) the mutated parser."""
    if not parser.has_section(section):
        return RemoveOutcome.ALREADY_ABSENT
    if expected_access_key_id is not None:
        if _get_value(parser, section, _ACCESS_KEY) != expected_access_key_id:
            return RemoveOutcome.FOREIGN_KEPT
    parser.remove_section(section)
    return RemoveOutcome.REMOVED


# --- public API -------------------------------------------------------------------


def write_aws_profile(
    path: Path, section: str, creds: HoneytokenCreds, force: bool
) -> WriteOutcome:
    """Write/overwrite the (server-named) honeytoken profile, preserving other profiles.

    Rotation is handled upstream by processing ``delete`` before ``write``, so a
    credentials mismatch only trips on a genuine collision the operator should review.
    """
    try:
        secure_file.require_safe_backend()
        if secure_file.FD_HARDENED:
            dir_fd = secure_file.open_dir_fd(path.parent, create=True)
            try:
                parser = _parse_text(secure_file.read_via_fd(dir_fd, path.name), path)
                outcome = _decide_write(parser, section, creds, force, path)
                if outcome is WriteOutcome.WROTE:
                    secure_file.atomic_write_via_fd(dir_fd, path.name, str(parser))
                return outcome
            finally:
                os.close(dir_fd)

        secure_file.reject_symlinked_target(path)
        parser = _parse_text(secure_file.read_path(path), path)
        outcome = _decide_write(parser, section, creds, force, path)
        if outcome is WriteOutcome.WROTE:
            secure_file.atomic_write_path(path, str(parser))
        return outcome
    except SecureFileError as exc:
        raise PlacementError(str(exc))


def remove_aws_profile(
    path: Path, section: str, expected_access_key_id: Optional[str]
) -> RemoveOutcome:
    """Remove the named honeytoken profile, leaving other profiles intact. Remove the
    file only when nothing at all is left (no other profile **and** no comments) rather
    than leave an empty stub.

    When ``expected_access_key_id`` is set, the profile is removed **only if** its
    ``aws_access_key_id`` matches — a profile holding a different key is foreign and is
    left untouched (``FOREIGN_KEPT``). ``None`` removes by name unconditionally.
    """
    try:
        secure_file.require_safe_backend()
        if secure_file.FD_HARDENED:
            try:
                dir_fd = secure_file.open_dir_fd(path.parent, create=False)
            except FileNotFoundError:
                return RemoveOutcome.ALREADY_ABSENT
            try:
                text = secure_file.read_via_fd(dir_fd, path.name)
                if text is None:
                    return RemoveOutcome.ALREADY_ABSENT
                parser = _parse_text(text, path)
                outcome = _decide_remove(parser, section, expected_access_key_id)
                if outcome is not RemoveOutcome.REMOVED:
                    return outcome
                if str(parser).strip():
                    secure_file.atomic_write_via_fd(dir_fd, path.name, str(parser))
                else:
                    secure_file.unlink_via_fd(dir_fd, path.name)
                return outcome
            finally:
                os.close(dir_fd)

        secure_file.reject_symlinked_target(path)
        text = secure_file.read_path(path)
        if text is None:
            return RemoveOutcome.ALREADY_ABSENT
        parser = _parse_text(text, path)
        outcome = _decide_remove(parser, section, expected_access_key_id)
        if outcome is not RemoveOutcome.REMOVED:
            return outcome
        if str(parser).strip():
            secure_file.atomic_write_path(path, str(parser))
        else:
            secure_file.unlink_path(path)
        return outcome
    except SecureFileError as exc:
        raise PlacementError(str(exc))
