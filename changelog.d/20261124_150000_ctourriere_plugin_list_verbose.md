### Added

- `ggshield plugin list -v` now shows the plugin directories and enterprise config files ggshield reads, which file decides whether each plugin is enabled, and the manifest and wheel paths of each installed plugin. It also notes that the `version` and `auto_update` values recorded in `enterprise_config.yaml` are not enforced.
- `ggshield machine scan` now explains that the command is provided by the `machine_scan` plugin when that plugin is not installed, not enabled, or failed to load, and points to `ggshield plugin list -v`.
