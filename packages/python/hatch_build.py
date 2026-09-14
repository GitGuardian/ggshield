"""Build hook: vendor the shared provider definitions into the package.

The ``providers/*.yaml`` files at the repository root are the single
cross-language contract (also consumed by the Rust core). Rather than
committing a second copy inside this package, they are copied in at build
time — for wheels, sdists, and editable installs — so the distribution
carries them while the repo keeps exactly one source of truth.

When building from an sdist (which already bundles the copy), the root
``providers/`` directory is absent and the existing files are left in place.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_PACKAGE_PROVIDERS = Path("src", "gitguardian", "providers")


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        source = root.parent.parent / "providers"
        if not source.is_dir():
            # Building from an sdist: the copy is already bundled.
            return
        dest = root / _PACKAGE_PROVIDERS
        dest.mkdir(parents=True, exist_ok=True)
        for yaml_file in sorted(source.glob("*.yaml")):
            shutil.copy2(yaml_file, dest / yaml_file.name)
