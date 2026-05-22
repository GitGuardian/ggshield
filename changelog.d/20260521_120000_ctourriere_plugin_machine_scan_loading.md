### Fixed

- Plugin installs and updates now enable the canonical `ggshield.plugins` entry point instead of the wheel package name, migrating any pre-existing alias row (and preserving its `auto_update` setting), and local plugin wheels extract into the active runtime cache so mixed root/admin and user executions do not silently lose registered commands.
