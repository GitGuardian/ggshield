"""The console script name the wheel installs.

A platform wheel ships the Rust dispatcher as ``ggshield``, so the Python entry
point moves to ``ggshield-py`` -- the name the dispatcher execs, and the same
two-name layout the standalone bundle uses. The pure wheel keeps ``ggshield`` as
the Python entry point.
"""

import os

from hatchling.metadata.plugin.interface import MetadataHookInterface


class ScriptsMetadataHook(MetadataHookInterface):
    PLUGIN_NAME = "ggshield-scripts"

    def update(self, metadata):
        name = (
            "ggshield-py"
            if os.environ.get("GGSHIELD_BUILD_RUST") == "1"
            else "ggshield"
        )
        metadata["scripts"] = {name: "ggshield.__main__:main"}
