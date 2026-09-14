/** `${NAME}` template interpolation for base URLs and endpoint paths. */

import { SecretError } from "./errors.js";

/**
 * Substitute `${NAME}` placeholders, resolving from params then env.
 *
 * @param {string} template
 * @param {Record<string, string>} params
 * @returns {string}
 */
export function interpolate(template, params) {
  return interpolateWith(template, params, (_key, value) => value);
}

/**
 * {@link interpolate} for URL path templates.
 *
 * Substituted values are percent-encoded (template literals are trusted and
 * left as-is). Only Vault's `${path}` preserves `/` for nested secret paths;
 * every other placeholder is one path segment.
 *
 * @param {string} template
 * @param {Record<string, string>} params
 * @returns {string}
 */
export function interpolatePath(template, params) {
  return interpolateWith(template, params, (key, value) => encodePathValue(value, key === "path"));
}

/**
 * Percent-encode a path value against RFC 3986 unreserved (`A-Za-z0-9-._~`),
 * optionally keeping `/` literal.
 *
 * `encodeURIComponent` differs twice: it encodes `/` (we want it literal) and
 * leaves `!*'()` unescaped (we want them encoded), so both are corrected.
 *
 * @param {string} value
 * @param {boolean} preserveSlash
 * @returns {string}
 */
function encodePathValue(value, preserveSlash) {
  const encoded = value
    .split(preserveSlash ? "/" : "\0")
    .map((segment) =>
      encodeURIComponent(segment).replace(
        /[!*'()]/g,
        (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
      ),
    )
    .join("/");
  return encoded;
}

/**
 * @param {string} template
 * @param {Record<string, string>} params
 * @param {(key: string, value: string) => string} encode
 * @returns {string}
 */
function interpolateWith(template, params, encode) {
  /** @type {string[]} */
  const out = [];
  let rest = template;
  let start = rest.indexOf("${");
  while (start !== -1) {
    out.push(rest.slice(0, start));
    const after = rest.slice(start + 2);
    const end = after.indexOf("}");
    if (end === -1) {
      throw new SecretError(`unterminated '\${' in template '${template}'`);
    }
    const key = after.slice(0, end);
    const paramValue = params[key];
    let value;
    if (paramValue !== undefined) {
      value = paramValue;
    } else {
      const envValue = process.env[key];
      if (envValue === undefined) {
        throw new SecretError(`no value for '\${${key}}' (param or environment)`);
      }
      value = envValue;
    }
    out.push(encode(key, value));
    rest = after.slice(end + 1);
    start = rest.indexOf("${");
  }
  out.push(rest);
  return out.join("");
}
