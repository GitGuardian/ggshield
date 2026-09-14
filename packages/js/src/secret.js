/** The redacted-by-default secret value wrapper. */

import { REDACTION_PLACEHOLDER } from "./constants.js";

/**
 * A secret value, redacted by default.
 *
 * Every stringification path — template literals, `String()`, `console.log`
 * (`util.inspect`) and `JSON.stringify` — shows `[REDACTED]`; call
 * {@link Secret#expose} to read the real value at the point of use.
 */
export class Secret {
  /** @type {string} */
  #value;

  /** @param {string} value */
  constructor(value) {
    this.#value = value;
  }

  /**
   * Return the secret value as a plain string.
   *
   * This is the explicit reveal boundary — keep the returned string's
   * lifetime short and never log it.
   *
   * @returns {string}
   */
  expose() {
    return this.#value;
  }

  /**
   * Redact in string coercion (template literals, `String()`, concatenation).
   *
   * @returns {string}
   */
  toString() {
    return REDACTION_PLACEHOLDER;
  }

  /**
   * Redact in `JSON.stringify` — without this the private field is skipped but
   * an enclosing object would still serialize `{}`; more importantly, a naive
   * `toJSON` returning the value would leak it, so redact explicitly.
   *
   * @returns {string}
   */
  toJSON() {
    return REDACTION_PLACEHOLDER;
  }

  /**
   * Redact in `console.log` / `util.inspect`.
   *
   * @returns {string}
   */
  [Symbol.for("nodejs.util.inspect.custom")]() {
    return `Secret(${REDACTION_PLACEHOLDER})`;
  }
}
