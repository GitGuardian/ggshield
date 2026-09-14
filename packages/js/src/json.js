/** Helpers for extracting secret fields from a provider's JSON response. */

import { SCALAR_FIELD_NAME } from "./constants.js";

/**
 * Turn the extracted secret value into a map of field -> value.
 *
 * A JSON object becomes one entry per key, a 1Password-style field array uses
 * each field's label/title/name/ID, and a scalar becomes one `value` entry.
 *
 * @param {unknown} value
 * @returns {Record<string, string>}
 */
export function secretFields(value) {
  if (isObject(value)) {
    /** @type {Record<string, string>} */
    const fields = {};
    for (const [key, item] of Object.entries(value)) {
      fields[key] = scalarToString(item);
    }
    return fields;
  }
  if (Array.isArray(value)) {
    /** @type {Record<string, string>} */
    const fields = {};
    for (const item of value) {
      if (!isObject(item)) {
        continue;
      }
      const key = ["label", "title", "name", "id"]
        .map((name) => item[name])
        .find((candidate) => typeof candidate === "string");
      if (typeof key === "string" && "value" in item) {
        fields[key] = scalarToString(item.value);
      }
    }
    return fields;
  }
  return { [SCALAR_FIELD_NAME]: scalarToString(value) };
}

/**
 * A JSON scalar as a plain string (no quotes); other shapes as compact JSON.
 *
 * @param {unknown} value
 * @returns {string}
 */
function scalarToString(value) {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

/**
 * Walk a dotted path (e.g. `data.data`) into parsed JSON.
 *
 * Dots are always separators: keys containing a `.` cannot be addressed.
 * Returns `undefined` when any segment is missing.
 *
 * @param {unknown} value
 * @param {string} path
 * @returns {unknown}
 */
export function dotPath(value, path) {
  let current = value;
  for (const segment of path.split(".")) {
    if (!isObject(current) || !(segment in current)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

/**
 * Whether `value` is a plain JSON object (not null, not an array).
 *
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
