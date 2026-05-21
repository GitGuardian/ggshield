### Fixed

- Plugin installs now enable the canonical `ggshield.plugins` entry point instead of the wheel package name, and local plugin wheels extract into the active runtime cache so mixed root/admin and user executions do not silently lose registered commands.
