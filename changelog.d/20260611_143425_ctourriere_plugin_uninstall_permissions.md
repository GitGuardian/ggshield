### Fixed

- `ggshield plugin uninstall` no longer crashes with a raw `PermissionError` when plugin files cannot be removed. Read-only entries are now fixed automatically, and files owned by another user (e.g. residue from a legacy `sudo` install) produce a clear remediation message instead of a traceback.
