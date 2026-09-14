/**
 * Provider definitions and the strict parser for `providers/<name>.yaml`.
 *
 * The YAML files are the cross-language provider contract; parsing is strict
 * (unknown keys are rejected) to stay consistent across implementations.
 * Definitions are converted to JS at build time by
 * `scripts/generate-providers.mjs` — the runtime imports the generated module
 * (see `providers.js`) and never parses YAML. This module deliberately does
 * not import the generated file, so the generator can use
 * {@link parseProviderDef} before that file exists.
 */

import { SecretError } from "./errors.js";

/**
 * A supported secret-manager backend. Each member's value is the name of a
 * bundled provider definition (`providers/<name>.yaml`).
 *
 * @readonly
 * @enum {string}
 */
export const Provider = Object.freeze({
  ONEPASSWORD: "onepassword",
  VAULT: "vault",
});

/** Every supported provider name. @type {readonly string[]} */
export const PROVIDERS = Object.freeze(Object.values(Provider));

/** The HTTP methods an endpoint may use. @type {readonly string[]} */
const METHODS = Object.freeze(["DELETE", "GET", "POST", "PUT"]);

/**
 * @typedef {object} TokenAuth
 * @property {string} tokenEnv Environment variable holding the token.
 * @property {string} [tokenFileEnv] Environment variable holding a token file path.
 * @property {string} [tokenFile] Default token file path.
 * @property {string} header Header the token is sent in.
 * @property {string} [scheme] Authentication scheme prepended to the token.
 */

/**
 * @typedef {object} Endpoint
 * @property {string} method HTTP method (one of {@link METHODS}).
 * @property {string} path URL path template, with `${name}` placeholders.
 * @property {Record<string, string>} query Query-string template parameters.
 * @property {string | null} secret Dot-path to the secret in the JSON response.
 */

/**
 * @typedef {object} ProviderDef
 * @property {string} name
 * @property {string} description
 * @property {string} baseUrl
 * @property {TokenAuth} auth
 * @property {Record<string, Endpoint>} endpoints
 */

/**
 * Parse a provider definition from a raw (YAML-parsed) object, rejecting
 * unknown keys. Used at build time by the generator and by tests; the runtime
 * uses the generated definitions directly.
 *
 * @param {unknown} raw
 * @returns {ProviderDef}
 */
export function parseProviderDef(raw) {
  try {
    if (!isRecord(raw)) {
      throw new Error("not a mapping");
    }
    const leftovers = { ...raw };
    const def = {
      name: takeString(leftovers, "name"),
      description: String(pop(leftovers, "description") ?? ""),
      baseUrl: takeString(leftovers, "base_url"),
      auth: parseAuth(pop(leftovers, "auth")),
      endpoints: parseEndpoints(pop(leftovers, "endpoints")),
    };
    noLeftovers(leftovers, "provider definition");
    return def;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new SecretError(`parsing provider definition: ${reason}`);
  }
}

/**
 * @param {unknown} raw
 * @returns {TokenAuth}
 */
function parseAuth(raw) {
  if (!isRecord(raw)) {
    throw new Error("'auth' must be a mapping");
  }
  const leftovers = { ...raw };
  const strategy = pop(leftovers, "strategy");
  if (strategy !== "token") {
    throw new Error(`unknown auth strategy '${String(strategy)}'`);
  }
  /** @type {TokenAuth} */
  const auth = {
    tokenEnv: takeString(leftovers, "token_env"),
    header: String(pop(leftovers, "header") ?? "Authorization"),
  };
  const tokenFileEnv = pop(leftovers, "token_file_env");
  if (tokenFileEnv != null) {
    auth.tokenFileEnv = String(tokenFileEnv);
  }
  const tokenFile = pop(leftovers, "token_file");
  if (tokenFile != null) {
    auth.tokenFile = String(tokenFile);
  }
  const scheme = pop(leftovers, "scheme");
  if (scheme != null) {
    if (typeof scheme !== "string") {
      throw new Error("'scheme' must be a string");
    }
    auth.scheme = scheme;
  }
  noLeftovers(leftovers, "auth");
  return auth;
}

/**
 * @param {unknown} raw
 * @returns {Record<string, Endpoint>}
 */
function parseEndpoints(raw) {
  if (raw === undefined || raw === null) {
    return {};
  }
  if (!isRecord(raw)) {
    throw new Error("'endpoints' must be a mapping");
  }
  /** @type {Record<string, Endpoint>} */
  const endpoints = {};
  for (const [name, endpoint] of Object.entries(raw)) {
    endpoints[name] = parseEndpoint(endpoint);
  }
  return endpoints;
}

/**
 * @param {unknown} raw
 * @returns {Endpoint}
 */
function parseEndpoint(raw) {
  if (!isRecord(raw)) {
    throw new Error("endpoint must be a mapping");
  }
  const leftovers = { ...raw };
  const method = takeString(leftovers, "method");
  if (!METHODS.includes(method)) {
    throw new Error(`unknown endpoint method '${method}'`);
  }
  /** @type {Record<string, string>} */
  const query = {};
  const rawQuery = pop(leftovers, "query");
  if (rawQuery != null) {
    if (!isRecord(rawQuery)) {
      throw new Error("'query' must be a mapping");
    }
    for (const [key, value] of Object.entries(rawQuery)) {
      query[key] = String(value);
    }
  }
  const secret = pop(leftovers, "secret");
  /** @type {Endpoint} */
  const endpoint = {
    method,
    path: takeString(leftovers, "path"),
    query,
    secret: secret == null ? null : String(secret),
  };
  noLeftovers(leftovers, "endpoint");
  return endpoint;
}

/**
 * Pop a required string key, erroring if it is absent or not a string.
 *
 * @param {Record<string, unknown>} raw
 * @param {string} key
 * @returns {string}
 */
function takeString(raw, key) {
  const value = pop(raw, key);
  if (typeof value !== "string") {
    throw new Error(`'${key}' must be a string`);
  }
  return value;
}

/**
 * Read and remove a key from a mutable object.
 *
 * @param {Record<string, unknown>} raw
 * @param {string} key
 * @returns {unknown}
 */
function pop(raw, key) {
  const value = raw[key];
  delete raw[key];
  return value;
}

/**
 * Throw if any keys remain unconsumed.
 *
 * @param {Record<string, unknown>} raw
 * @param {string} context
 * @returns {void}
 */
function noLeftovers(raw, context) {
  const keys = Object.keys(raw);
  if (keys.length > 0) {
    throw new Error(`unknown ${context} keys: ${keys.join(", ")}`);
  }
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
