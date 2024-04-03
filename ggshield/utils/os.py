import logging
import os
import platform
import sys
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Optional, Tuple, Union, overload


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


@contextmanager
def cd(newdir: Union[str, Path]) -> Iterator[None]:
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
