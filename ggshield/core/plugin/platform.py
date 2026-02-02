"""
Platform detection utilities for wheel selection.
"""

import platform
import sys
from dataclasses import dataclass
from typing import List


@dataclass
class PlatformInfo:
    """Information about the current platform."""

    os: str
    arch: str
    python_abi: str


def get_platform_info() -> PlatformInfo:
    """Detect current platform for wheel selection."""
    system = platform.system().lower()
    if system == "darwin":
        os_name = "macosx"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "win"
    else:
        os_name = system

    # Detect architecture
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    else:
        arch = machine

    # Detect Python version for ABI
    python_abi = f"cp{sys.version_info.major}{sys.version_info.minor}"

    return PlatformInfo(os=os_name, arch=arch, python_abi=python_abi)


def format_platform_tag(info: PlatformInfo) -> str:
    """Format platform info as a wheel platform tag."""
    return f"{info.os}-{info.arch}"


def get_wheel_platform_tags() -> List[str]:
    """Get list of compatible wheel platform tags for current system."""
    info = get_platform_info()
    tags = [format_platform_tag(info)]

    if info.arch == "arm64":
        tags.append(f"{info.os}-aarch64")
    elif info.arch == "x86_64":
        tags.append(f"{info.os}-amd64")

    return tags
