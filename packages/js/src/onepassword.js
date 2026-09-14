/** 1Password Connect path resolution and item field helpers. */

import { missingFieldsError, SecretError, SecretNotFoundError } from "./errors.js";

/**
 * @param {string} path
 * @returns {[string, string]}
 */
export function parseOnepasswordPath(path) {
  const separator = path.indexOf("/");
  const vault = separator === -1 ? "" : path.slice(0, separator);
  const item = separator === -1 ? "" : path.slice(separator + 1);
  if (!vault || !item || item.includes("/")) {
    throw new SecretError(`path '${path}' must be '<vault>/<item>', e.g. dev/myapp`);
  }
  return [vault, item];
}

/**
 * @param {unknown} values
 * @param {{ kind: string, query: string, nameKey: string, path: string }} options
 * @returns {string | null}
 */
export function resolveOnepasswordId(values, { kind, query, nameKey, path }) {
  if (!Array.isArray(values)) {
    throw new SecretError("1Password Connect list response was not an array");
  }
  const matches = [];
  for (const value of values) {
    if (!isRecord(value) || typeof value.id !== "string") {
      continue;
    }
    const name = typeof value[nameKey] === "string" ? value[nameKey] : "";
    if (value.id === query || name === query) {
      matches.push({ id: value.id, name });
    }
  }
  if (matches.length === 0) {
    if (kind === "vault") {
      throw new SecretNotFoundError(`secret not found at ${path}`);
    }
    return null;
  }
  const [match] = matches;
  if (matches.length === 1 && match !== undefined) {
    return match.id;
  }
  const descriptions = matches.map(({ id, name }) => (name ? `${name} (${id})` : id)).join(", ");
  throw new SecretError(
    `more than one 1Password ${kind} matches '${query}'; specify its ID: ${descriptions}`,
  );
}

/**
 * @param {Record<string, string>} fields
 * @returns {Array<Record<string, string>>}
 */
export function onepasswordItemFields(fields) {
  return Object.entries(fields).map(([label, value]) => ({
    label,
    type: "CONCEALED",
    value,
  }));
}

/**
 * @param {Record<string, unknown>} item
 * @param {Record<string, string>} updates
 */
export function mergeOnepasswordItemFields(item, updates) {
  const fields = itemFieldArray(item);
  for (const [key, value] of Object.entries(updates)) {
    const field = fields.find((candidate) => fieldMatches(candidate, key));
    if (field === undefined) {
      fields.push({ label: key, type: "CONCEALED", value });
    } else {
      field.value = value;
    }
  }
}

/**
 * @param {Record<string, unknown>} item
 * @param {Record<string, string>} fields
 */
export function replaceOnepasswordItemFields(item, fields) {
  item.fields = onepasswordItemFields(fields);
}

/**
 * @param {Record<string, unknown>} item
 * @param {readonly string[]} keys
 */
export function removeOnepasswordItemFields(item, keys) {
  const fields = itemFieldArray(item);
  const missing = keys.filter((key) => !fields.some((field) => fieldMatches(field, key)));
  if (missing.length > 0) {
    throw missingFieldsError(missing);
  }
  item.fields = fields.filter((field) => !keys.some((key) => fieldMatches(field, key)));
}

/**
 * @param {Record<string, unknown>} item
 * @returns {Array<Record<string, unknown>>}
 */
function itemFieldArray(item) {
  if (!Array.isArray(item.fields) || !item.fields.every(isRecord)) {
    throw new SecretError("1Password item response did not contain a fields array");
  }
  return item.fields;
}

/**
 * @param {Record<string, unknown>} field
 * @param {string} key
 */
function fieldMatches(field, key) {
  return field.label === key || field.title === key || field.id === key;
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
