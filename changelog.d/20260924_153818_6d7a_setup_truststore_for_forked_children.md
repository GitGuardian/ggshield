### Fixed

- `ggshield secret scan pre-receive` now uses the system trust store in its child process, which no longer inherited it on Python 3.14 (#1508).
- `ggshield secret scan ai-hook` now verifies the instance's TLS certificate against the OS trust store.
