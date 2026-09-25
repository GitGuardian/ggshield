### Fixed

- `ggshield secret scan pre-receive` now uses the system trust store in its child process, which no longer inherited it on Python 3.14 (#1508).
- `ggshield secret scan ai-hook` now verifies the instance's TLS certificate against the OS trust store.
- `ggshield secret scan ai-hook` now honors `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE`, from the environment or `.env`, like the rest of ggshield. A path that does not exist makes the scan fail, as it already does for other commands.
