"""
On-disk placement of honeytoken AWS credential profiles for
``ggshield honeytoken plant``.

GIM owns *what* (method, filename, profile name); the client owns *where* — both AWS
methods land under ``~/.aws/``. The two methods differ only in the INI section name:

- ``aws_credentials`` → ``[profile_name]`` in the shared **credentials** file.
- ``aws_config_profile`` → ``[profile profile_name]`` in the **config** file (AWS
  mandates the ``profile `` prefix there).

Privileged handling runs in the root fan-out: on POSIX we anchor every op to a ``.aws`` fd
opened ``O_NOFOLLOW`` (``dir_fd``/``fchmod``/no-follow), so the fd pins the real inode and a
symlink swapped in after a check (TOCTOU) has no effect. Windows lacks dir fds and uses a
path-based check (no root fan-out there).
"""

from __future__ import annotations

import configparser
import enum
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from configupdater import ConfigUpdater

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

# No-follow, fd-anchored file ops available (POSIX). os.rename (not os.replace) carries
# dir_fd on Linux+macOS and replaces atomically on POSIX.
FD_HARDENED = (
    hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
)


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
        except (configparser.Error, UnicodeDecodeError) as exc:
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


# --- no-follow, fd-anchored backend (POSIX) ---------------------------------------


def open_aws_dir_fd(aws_dir: Path, *, create: bool) -> int:
    """Open ``.aws`` ``O_NOFOLLOW|O_DIRECTORY``, returning an fd that pins the real inode
    (swap-immune) and holds an exclusive advisory lock for the read-modify-write window.
    Symlink/non-dir → ``PlacementError``. ``create`` makes a missing dir 0700; else
    ``FileNotFoundError`` propagates (callers treat absent as a no-op)."""
    import fcntl

    # flock(LOCK_EX) on the fd serializes concurrent `plant` invocations for the whole
    # read-modify-write window; released when the caller closes the fd (or the process
    # dies — no stale lock).
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(aws_dir, flags)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        raise PlacementError(
            f"refusing to use {aws_dir}: not a real directory (symlink?): {exc}"
        )
    # Create the home chain, then `.aws` itself 0700 (the no-follow re-open is the gate).
    os.makedirs(aws_dir.parent, mode=0o700, exist_ok=True)
    try:
        os.mkdir(aws_dir, 0o700)
    except FileExistsError:
        pass
    try:
        fd = os.open(aws_dir, flags)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except OSError as exc:
        raise PlacementError(
            f"refusing to use {aws_dir}: not a real directory (symlink?): {exc}"
        )


def _read_via_fd(dir_fd: int, name: str) -> Optional[str]:
    """Read ``name`` under the pinned dir, no-follow. ``None`` if absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:  # ELOOP → the file itself is a symlink
        raise PlacementError(
            f"refusing to read through symlinked credentials file {name}: {exc}"
        )
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def _atomic_write_via_fd(dir_fd: int, name: str, parser: ConfigUpdater) -> None:
    # Preserve the file's existing mode (new file → 0600).
    try:
        mode = stat.S_IMODE(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        mode = 0o600
    fd = -1
    tmp = None
    for _ in range(8):
        candidate = f".plant.{os.urandom(8).hex()}.tmp"
        try:
            fd = os.open(
                candidate,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            tmp = candidate
            break
        except FileExistsError:
            continue
    if tmp is None:
        raise PlacementError(f"could not create a temp file in {name}'s directory")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            parser.write(handle)
        # Atomic POSIX replace, anchored to the pinned dir on both ends.
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    # Restore the preserved mode via an fd on the final file (no path re-resolution).
    ffd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        os.fchmod(ffd, mode)
    finally:
        os.close(ffd)


# --- path-based fallback (no dir fds / O_NOFOLLOW, e.g. Windows) -------------------


def _reject_symlinked_target(path: Path) -> None:
    """Best-effort pre-check for the path-based (non-POSIX) backend."""
    if path.parent.is_symlink():
        raise PlacementError(f"refusing to use {path.parent}: '.aws' is a symlink")
    if path.is_symlink():
        raise PlacementError(f"refusing to write through symlinked file {path}")


def _load_path(path: Path) -> ConfigUpdater:
    text = path.read_text(encoding="utf-8") if path.exists() else None
    return _parse_text(text, path)


def _atomic_write_path(path: Path, parser: ConfigUpdater) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = 0o600
    fd, tmp = tempfile.mkstemp(prefix=".plant.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            parser.write(handle)
        # Swap first (temp keeps mkstemp's 0600 while holding the secret), then chmod.
        os.replace(tmp, path)
        os.chmod(path, mode)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- public API -------------------------------------------------------------------


def require_safe_backend() -> None:
    """Fail closed on POSIX without dir fds: the only alternative is TOCTOU-prone path
    ops, and POSIX is where the root fan-out makes that exploitable. Windows is exempt.
    """
    if os.name == "posix" and not FD_HARDENED:
        raise PlacementError(
            "this platform lacks the directory file-descriptor support "
            "(O_NOFOLLOW/dir_fd) required to place honeytokens safely — refusing"
        )


def write_aws_profile(
    path: Path, section: str, creds: HoneytokenCreds, force: bool
) -> WriteOutcome:
    """Write/overwrite the (server-named) honeytoken profile, preserving other profiles.

    Rotation is handled upstream by processing ``delete`` before ``write``, so a
    credentials mismatch only trips on a genuine collision the operator should review.
    """
    require_safe_backend()
    if FD_HARDENED:
        dir_fd = open_aws_dir_fd(path.parent, create=True)
        try:
            parser = _parse_text(_read_via_fd(dir_fd, path.name), path)
            outcome = _decide_write(parser, section, creds, force, path)
            if outcome is WriteOutcome.WROTE:
                _atomic_write_via_fd(dir_fd, path.name, parser)
            return outcome
        finally:
            os.close(dir_fd)

    _reject_symlinked_target(path)
    parser = _load_path(path)
    outcome = _decide_write(parser, section, creds, force, path)
    if outcome is WriteOutcome.WROTE:
        _atomic_write_path(path, parser)
    return outcome


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
    require_safe_backend()
    if FD_HARDENED:
        try:
            dir_fd = open_aws_dir_fd(path.parent, create=False)
        except FileNotFoundError:
            return RemoveOutcome.ALREADY_ABSENT
        try:
            text = _read_via_fd(dir_fd, path.name)
            if text is None:
                return RemoveOutcome.ALREADY_ABSENT
            parser = _parse_text(text, path)
            outcome = _decide_remove(parser, section, expected_access_key_id)
            if outcome is not RemoveOutcome.REMOVED:
                return outcome
            if str(parser).strip():
                _atomic_write_via_fd(dir_fd, path.name, parser)
            else:
                try:
                    os.unlink(path.name, dir_fd=dir_fd)
                except OSError:
                    pass
            return RemoveOutcome.REMOVED
        finally:
            os.close(dir_fd)

    _reject_symlinked_target(path)
    if not path.exists():
        return RemoveOutcome.ALREADY_ABSENT
    parser = _load_path(path)
    outcome = _decide_remove(parser, section, expected_access_key_id)
    if outcome is not RemoveOutcome.REMOVED:
        return outcome
    if str(parser).strip():
        _atomic_write_path(path, parser)
    else:
        try:
            path.unlink()
        except OSError:
            pass
    return RemoveOutcome.REMOVED


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
