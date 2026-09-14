/** HTTP transport — building requests and mapping responses to typed errors. */

import { authHeaders } from "./auth.js";
import { ALLOWED_URL_SCHEMES, ERROR_BODY_MAX_CHARS, REQUEST_TIMEOUT_MS } from "./constants.js";
import {
  AuthenticationError,
  PermissionDeniedError,
  SecretError,
  SecretNotFoundError,
} from "./errors.js";
import { interpolate, interpolatePath } from "./interpolate.js";

/**
 * @typedef {import('./definition.js').ProviderDef} ProviderDef
 */

// Node's stdlib has no named status-code constants (only `http.STATUS_CODES`, a
// code -> message map), so name the few we map here.
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_NOT_FOUND = 404;

/**
 * Build the `fetch` request for a named endpoint.
 *
 * @param {ProviderDef} definition
 * @param {string} endpointName
 * @param {Record<string, string>} params
 * @param {unknown} [body]
 * @returns {{ url: string, init: RequestInit }}
 */
export function buildRequest(definition, endpointName, params, body) {
  const endpoint = definition.endpoints[endpointName];
  if (endpoint === undefined) {
    throw new SecretError(`provider '${definition.name}' has no endpoint '${endpointName}'`);
  }

  const base = interpolate(definition.baseUrl, params);
  // A poisoned base URL (e.g. $VAULT_ADDR) must not be able to turn a secret
  // read into a local file:// read; only http(s) is allowed.
  if (!ALLOWED_URL_SCHEMES.some((scheme) => base.startsWith(scheme))) {
    throw new SecretError(`provider '${definition.name}' base URL must be http(s)`);
  }
  const path = interpolatePath(endpoint.path, params);
  let url = base.replace(/\/+$/, "") + path;
  if (Object.keys(endpoint.query).length > 0) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(endpoint.query)) {
      query.set(key, interpolate(value, params));
    }
    url = `${url}?${query.toString()}`;
  }

  /** @type {Record<string, string>} */
  const headers = authHeaders(definition.auth);
  /** @type {string | undefined} */
  let data;
  if (body !== undefined) {
    data = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  return {
    url,
    init: {
      method: endpoint.method,
      headers,
      body: data,
      // Never follow redirects: a redirect would forward the auth header (e.g.
      // X-Vault-Token) to wherever a compromised server points us.
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    },
  };
}

/**
 * Send a request, returning the body text or mapping non-success statuses to
 * typed errors.
 *
 * @param {string} providerName
 * @param {string} endpointName
 * @param {string} userPath User-facing secret path, for error messages.
 * @param {{ url: string, init: RequestInit }} request
 * @returns {Promise<string>}
 */
export async function sendRequest(providerName, endpointName, userPath, request) {
  let response;
  try {
    response = await fetch(request.url, request.init);
  } catch (error) {
    // Network failure, timeout, or a refused redirect. `fetch` does not reject
    // on HTTP error statuses, so those are handled below.
    const reason = error instanceof Error ? error.message : String(error);
    throw new SecretError(`calling endpoint '${endpointName}': ${reason}`);
  }
  if (response.ok) {
    return response.text();
  }
  // Read the error body as text, not JSON: proxies in front of the provider
  // answer with HTML or empty bodies, and the status must still map to a typed
  // error (404 -> SecretNotFoundError). It is truncated: enough to diagnose
  // (Vault puts the cause in an `errors` array) without echoing arbitrarily
  // large — or request-reflecting — upstream responses.
  let bodyText;
  try {
    bodyText = await response.text();
  } catch {
    bodyText = "<unreadable response body>";
  }
  throw httpError(providerName, response.status, userPath, bodyText, endpointName);
}

/**
 * @param {string} providerName
 * @param {number} status
 * @param {string} userPath
 * @param {string} body
 * @param {string} endpointName
 * @returns {SecretError}
 */
function httpError(providerName, status, userPath, body, endpointName) {
  if (status === HTTP_UNAUTHORIZED) {
    return new AuthenticationError(`authentication failed for provider '${providerName}'`);
  }
  if (status === HTTP_FORBIDDEN) {
    return new PermissionDeniedError(`permission denied for provider '${providerName}'`);
  }
  if (status === HTTP_NOT_FOUND) {
    return new SecretNotFoundError(`secret not found at ${userPath}`);
  }
  return new SecretError(
    `${providerName} endpoint '${endpointName}' returned ${status}: ` +
      truncate(body, ERROR_BODY_MAX_CHARS),
  );
}

/**
 * Truncate to at most `maxChars` characters, marking elision.
 *
 * @param {string} value
 * @param {number} maxChars
 * @returns {string}
 */
export function truncate(value, maxChars) {
  if (value.length <= maxChars) {
    return value;
  }
  return `${value.slice(0, maxChars)}… (${value.length} chars total)`;
}
