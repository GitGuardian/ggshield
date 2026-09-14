/** Auth strategies: resolve a provider token from the environment or a file. */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DEFAULT_ENCODING } from "./constants.js";
import { SecretError } from "./errors.js";

/**
 * @typedef {import('./definition.js').TokenAuth} TokenAuth
 */

/**
 * Headers applying a named auth strategy to an outgoing request.
 *
 * @param {TokenAuth} auth
 * @returns {Record<string, string>}
 */
export function authHeaders(auth) {
  const token = resolveToken(auth);
  const value = auth.scheme === undefined ? token : `${auth.scheme} ${token}`;
  return { [auth.header]: value };
}

/**
 * Resolve a token from `tokenEnv` (preferred) then a token file.
 *
 * @param {TokenAuth} auth
 * @returns {string}
 */
export function resolveToken(auth) {
  const value = process.env[auth.tokenEnv];
  if (value) {
    return value;
  }

  const filePath = tokenFilePath(auth);
  if (filePath !== undefined) {
    const contents = readTokenFile(filePath);
    if (contents) {
      return contents;
    }
  }

  const fileHint = filePath !== undefined ? ` or ${filePath}` : "";
  throw new SecretError(`no token found (set $${auth.tokenEnv}${fileHint})`);
}

/**
 * Read and trim a token file.
 *
 * An empty or absent file just means "no token configured there" (returns
 * `undefined`); any other failure (permissions, a directory, ...) must
 * surface, or the user is sent hunting for a missing token that actually
 * exists.
 *
 * @param {string} filePath
 * @returns {string | undefined}
 */
function readTokenFile(filePath) {
  const resolved = expandUser(filePath);
  try {
    return readFileSync(resolved, DEFAULT_ENCODING).trim();
  } catch (error) {
    if (isNotFound(error)) {
      return undefined;
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new SecretError(`reading token file ${filePath}: ${reason}`);
  }
}

/**
 * `tokenFileEnv`'s environment value if set, else `tokenFile`.
 *
 * @param {TokenAuth} auth
 * @returns {string | undefined}
 */
export function tokenFilePath(auth) {
  if (auth.tokenFileEnv !== undefined) {
    const path = process.env[auth.tokenFileEnv];
    if (path) {
      return path;
    }
  }
  return auth.tokenFile;
}

/**
 * Expand a leading `~` to the user's home directory.
 *
 * Node has no built-in tilde expansion (unlike Python's `Path.expanduser`), so
 * combine `os.homedir()` with the rest of the path ourselves.
 *
 * @param {string} path
 * @returns {string}
 */
function expandUser(path) {
  if (path === "~") {
    return homedir();
  }
  if (path.startsWith("~/")) {
    return join(homedir(), path.slice(2));
  }
  return path;
}

/**
 * Whether an error is a "file not found" (ENOENT) failure.
 *
 * @param {unknown} error
 * @returns {boolean}
 */
function isNotFound(error) {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    /** @type {{ code?: unknown }} */ (error).code === "ENOENT"
  );
}
