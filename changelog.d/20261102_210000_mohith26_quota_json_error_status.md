### Added

- `ggshield quota --json` now writes a JSON object with the error `detail` and the HTTP `status_code` to stdout when the API rejects the request, so callers can tell a 403 (for example a token without the Manager access level) from other failures without matching on the message. The error message on stderr and the exit code are unchanged.
