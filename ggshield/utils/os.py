import json
import logging
import os
import platform
import sys
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Generator, List, Optional, Tuple, Union, overload


logger = logging.getLogger(__name__)


@lru_cache(None)
def get_os_info() -> Tuple[str, str]:
    """
    Returns a tuple of [OS, version]

    OS is always in lowercase
    """
    if sys.platform.lower() == "linux":
        return parse_os_release(Path("/etc/os-release"))
    else:
        return platform.system().lower(), platform.version()


def parse_os_release(os_release_path: Path) -> Tuple[str, str]:
    """
    Extract and return Linux's OS-name and OS-Version
    If extraction fails, we return ('linux', 'unknown')
    """
    error_tuple = "linux", "unknown"

    try:
        with open(os_release_path) as f:
            lines = f.readlines()

        # Build a dictionary from the os-release file contents
        data_dict = {}
        for line in lines:
            if "=" in line:
                key, value = line.split("=")
                key, value = key.strip(), value.strip()
                data_dict[key] = value.strip('"')

        if "ID" not in data_dict:
            return error_tuple

        return data_dict["ID"], data_dict.get("VERSION_ID", "unknown")
    except Exception as exc:
        logger.warning(f"Failed to read Linux OS name and version: {exc}")
        return error_tuple


def is_root() -> bool:
    """Whether the process runs as the POSIX superuser (euid 0).

    Always False where there is no ``geteuid`` (e.g. Windows). Used to decide
    machine-wide behavior, such as planting honeytokens for every user or
    installing git hooks system-wide.
    """
    return hasattr(os, "geteuid") and os.geteuid() == 0


# Per-user locations that root's environment must not impose on another user.
_PER_USER_ENV_VARS = ("GG_USER_HOME_DIR", "VIBE_HOME")


def run_as_user(uid: Optional[int], home: Path, fn: Callable[[], Any]) -> Any:
    """Run ``fn`` as the user ``uid`` and return its JSON-serializable result.

    From root, ``fn`` runs in a forked child holding the user's uid, groups, HOME and
    cwd, so a symlink planted in their home cannot redirect a root write. With no uid,
    or the current one, it runs in-process with HOME pinned to ``home``.
    """
    if uid is None or uid == os.getuid():
        # `sudo` can keep the invoking user's HOME, which would send root's writes
        # into that user's home.
        saved = {var: os.environ.get(var) for var in ("GG_USER_HOME_DIR", "HOME")}
        os.environ["GG_USER_HOME_DIR"] = os.environ["HOME"] = str(home)
        try:
            return fn()
        finally:
            for var, value in saved.items():
                if value is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = value
    # Looked up before the fork: on macOS, directory services are not fork-safe.
    name, gid, groups = _user_credentials(uid)
    # The child moves to the user's home, where a relative argv[0] (the ggshield
    # path written into hooks) would resolve to the wrong file.
    if os.path.dirname(sys.argv[0]):
        sys.argv[0] = os.path.abspath(sys.argv[0])
    sys.stdout.flush()
    sys.stderr.flush()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child, which coverage does not see
        os.close(read_fd)
        try:
            _become_user(uid, name, gid, groups, home)
            reply = {"result": fn()}
        except BaseException as exc:  # noqa: BLE001 - handed to the parent
            reply = {"error": str(exc) or type(exc).__name__}
        try:
            with os.fdopen(write_fd, "w") as out:
                json.dump(reply, out)
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd) as inp:
        output = inp.read()
    _, status = os.waitpid(pid, 0)
    try:
        reply = json.loads(output)
    except ValueError:
        raise RuntimeError(f"the process running as uid {uid} died (status {status})")
    if "error" in reply:
        raise RuntimeError(reply["error"])
    return reply["result"]


def _user_credentials(uid: int) -> Tuple[str, int, List[int]]:
    import pwd

    entry = pwd.getpwuid(uid)
    return entry.pw_name, entry.pw_gid, os.getgrouplist(entry.pw_name, entry.pw_gid)


def _become_user(  # pragma: no cover - child only
    uid: int, name: str, gid: int, groups: List[int], home: Path
) -> None:
    # macOS caps the list at 16 groups; the primary one comes first.
    os.setgroups(groups[: os.sysconf("SC_NGROUPS_MAX")])
    os.setgid(gid)
    os.setuid(uid)
    for var in _PER_USER_ENV_VARS:
        os.environ.pop(var, None)
    os.environ["HOME"] = str(home)
    os.environ["USER"] = os.environ["LOGNAME"] = name
    os.chdir(home)


@contextmanager
def cd(newdir: Union[str, Path]) -> Generator[None, None, None]:
    """
    A context manager to temporarily change the current directory
    """
    prevdir = Path.cwd()
    newdir = Path(newdir).expanduser()
    os.chdir(newdir)
    try:
        yield
    finally:
        os.chdir(prevdir)


@overload
def getenv_int(key: str, default: None = None) -> Optional[int]: ...


@overload
def getenv_int(key: str, default: int) -> int: ...


def getenv_int(key: str, default: Optional[int] = None) -> Optional[int]:
    value = os.getenv(key)
    if value is None:
        return default
    return int(value)


@overload
def getenv_float(key: str, default: None = None) -> Optional[float]: ...


@overload
def getenv_float(key: str, default: float) -> float: ...


def getenv_float(key: str, default: Optional[float] = None) -> Optional[float]:
    value = os.getenv(key)
    if value is None:
        return default
    return float(value)


@overload
def getenv_bool(key: str, default: None = None) -> Optional[bool]: ...


@overload
def getenv_bool(key: str, default: bool) -> bool: ...


def getenv_bool(key: str, default: Optional[bool] = None) -> Optional[bool]:
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() not in {"false", "0"}
