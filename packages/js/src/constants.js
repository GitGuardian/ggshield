/** Shared constants for the secret-resolution engine. */

/** Text encoding for reading token files and provider definitions. */
export const DEFAULT_ENCODING = "utf-8";

/** HTTP request timeout, in milliseconds. */
export const REQUEST_TIMEOUT_MS = 30_000;

/**
 * `fetch` also accepts file:// and data:// URLs; a poisoned base URL (e.g.
 * $VAULT_ADDR) must not be able to turn a secret read into a local file read.
 */
export const ALLOWED_URL_SCHEMES = ["http://", "https://"];

/**
 * Cap on upstream error bodies echoed into our error chain, so a provider (or
 * a proxy in front of it) can't spray an arbitrarily large body into errors.
 */
export const ERROR_BODY_MAX_CHARS = 256;

/**
 * Shown in place of a secret value everywhere it is rendered; the reveal
 * boundary is {@link import('./secret.js').Secret#expose}.
 */
export const REDACTION_PLACEHOLDER = "[REDACTED]";

/** Fallback user-facing path when the call params lack mount/path. */
export const UNKNOWN_PATH = "<unknown>";

/** Field name a scalar (non-object) secret value is exposed under. */
export const SCALAR_FIELD_NAME = "value";
