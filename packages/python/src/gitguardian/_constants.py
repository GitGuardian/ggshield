"""Shared constants for the secret-resolution engine."""

from __future__ import annotations

# Text encoding for reading provider definitions and token files.
DEFAULT_ENCODING = "utf-8"

# HTTP client policy.
REQUEST_TIMEOUT_SECONDS = 30.0
# urllib openers also accept file:// and ftp://; a poisoned base URL (e.g.
# $VAULT_ADDR) must not be able to turn a secret read into a local file read.
ALLOWED_URL_SCHEMES = ("http://", "https://")

# Cap on upstream error bodies echoed into our error chain, so a provider (or a
# proxy in front of it) can't spray an arbitrarily large body into our errors.
ERROR_BODY_MAX_CHARS = 256

# Shown in place of a secret value everywhere it is rendered; the reveal
# boundary is Secret.expose().
REDACTION_PLACEHOLDER = "[REDACTED]"

# Fallback user-facing path when the call params lack mount/path.
UNKNOWN_PATH = "<unknown>"

# Field name a scalar (non-object) secret value is exposed under.
SCALAR_FIELD_NAME = "value"
