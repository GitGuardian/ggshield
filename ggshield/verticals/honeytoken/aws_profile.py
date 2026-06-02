"""
On-disk placement of honeytoken AWS credential profiles for
``ggshield honeytoken plant``.

GIM owns *what* (method, filename, profile name); the client owns *where* — both AWS
methods land under ``~/.aws/``. The two methods differ only in the INI section name:

- ``aws_credentials`` → ``[profile_name]`` in the shared **credentials** file.
- ``aws_config_profile`` → ``[profile profile_name]`` in the **config** file (AWS
  mandates the ``profile `` prefix there).
"""

from __future__ import annotations

import configparser
import enum
import os
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentMethod,
    HoneytokenCreds,
    PlacementConfig,
)


SUPPORTED_METHODS = (
    DeploymentMethod.AWS_CREDENTIALS,
    DeploymentMethod.AWS_CONFIG_PROFILE,
)

_ACCESS_KEY = "aws_access_key_id"
_SECRET_KEY = "aws_secret_access_key"


class WriteOutcome(enum.Enum):
    WROTE = enum.auto()
    ALREADY_CURRENT = enum.auto()


class RemoveOutcome(enum.Enum):
    REMOVED = enum.auto()
    ALREADY_ABSENT = enum.auto()
    FOREIGN_KEPT = enum.auto()


class PlacementError(Exception):
    """The deployment can't be materialized (bad filename or unsupported method)."""


class ForceRefusal(Exception):
    """A profile holds different credentials than ours; refusing to overwrite without
    ``--force``. Carried so the caller can classify it (foreign-collision)."""

    def __init__(self, profile: str, path: Path) -> None:
        super().__init__(
            f"profile [{profile}] in {path} already exists with different credentials "
            "(access key id and/or secret differ from ours) — refusing to overwrite "
            "without --force"
        )
        self.profile = profile
        self.path = path


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


def _load(path: Path) -> configparser.ConfigParser:
    # interpolation=None: AWS secret keys can contain ``%``, which the default
    # interpolation would choke on.
    parser = configparser.ConfigParser(interpolation=None)
    if path.exists():
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError) as exc:
            # A malformed/garbage file is an expected condition, not a crash: surface it
            # as a PlacementError so the caller reports a clean per-deployment failure
            # and leaves the file untouched.
            raise PlacementError(
                f"could not parse {path}: not a valid AWS credentials/INI file ({exc})"
            )
    return parser


def _atomic_write(path: Path, parser: configparser.ConfigParser) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".plant.", suffix=".tmp", dir=str(path.parent))
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            parser.write(handle)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_aws_profile(
    path: Path, section: str, creds: HoneytokenCreds, force: bool
) -> WriteOutcome:
    """Write/overwrite the (server-named) honeytoken profile, preserving other profiles.

    - profile absent → write
    - profile present with the same access key **and** secret → no-op (``ALREADY_CURRENT``)
    - profile present but access key id **and/or** secret differ → refuse unless ``force``
      (rotation is handled upstream by processing ``delete`` before ``write``, so this
      only trips on a genuine collision the operator should review)
    """
    parser = _load(path)
    if parser.has_section(section):
        existing_id = parser.get(section, _ACCESS_KEY, fallback=None)
        existing_secret = parser.get(section, _SECRET_KEY, fallback=None)
        if existing_id == creds.access_token_id and existing_secret == creds.secret_key:
            return WriteOutcome.ALREADY_CURRENT
        if not force:
            raise ForceRefusal(section, path)
    else:
        parser.add_section(section)

    parser.set(section, _ACCESS_KEY, creds.access_token_id)
    parser.set(section, _SECRET_KEY, creds.secret_key)
    _atomic_write(path, parser)
    return WriteOutcome.WROTE


def remove_aws_profile(
    path: Path, section: str, expected_access_key_id: Optional[str]
) -> RemoveOutcome:
    """Remove the named honeytoken profile, leaving other profiles intact. If ours was
    the only one, remove the file rather than leave an empty stub.

    When ``expected_access_key_id`` is set, the profile is removed **only if** its
    ``aws_access_key_id`` matches — a profile holding a different key is foreign and is
    left untouched (``FOREIGN_KEPT``). ``None`` removes by name unconditionally (legacy /
    when the server omitted the token).
    """
    if not path.exists():
        return RemoveOutcome.ALREADY_ABSENT
    parser = _load(path)
    if not parser.has_section(section):
        return RemoveOutcome.ALREADY_ABSENT

    if expected_access_key_id is not None:
        on_disk = parser.get(section, _ACCESS_KEY, fallback=None)
        if on_disk != expected_access_key_id:
            return RemoveOutcome.FOREIGN_KEPT

    parser.remove_section(section)
    if parser.sections():
        _atomic_write(path, parser)
    else:
        # Last section gone — drop the now-empty file rather than leave a stub behind.
        try:
            path.unlink()
        except OSError:
            pass
    return RemoveOutcome.REMOVED
