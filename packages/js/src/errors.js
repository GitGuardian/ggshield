/**
 * Error hierarchy for secret-store failures.
 *
 * The `SecretError` taxonomy is shared across the GitGuardian SDKs and CLI so
 * the same failures are reported the same way everywhere.
 */

/** Base error for all secret-store failures. */
export class SecretError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "SecretError";
  }
}

/** No secret exists at the requested path. */
export class SecretNotFoundError extends SecretError {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "SecretNotFoundError";
  }
}

/** The provider rejected our credentials. */
export class AuthenticationError extends SecretError {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "AuthenticationError";
  }
}

/** The provider refused access to the requested secret. */
export class PermissionDeniedError extends SecretError {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "PermissionDeniedError";
  }
}

/** The secret exists but does not contain the requested field(s). */
export class FieldNotFoundError extends SecretError {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "FieldNotFoundError";
  }
}

/** The provider does not support this operation. */
export class UnsupportedOperationError extends SecretError {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "UnsupportedOperationError";
  }
}

/**
 * Build the error for fields absent from a secret, deduplicated.
 *
 * @param {readonly string[]} fields
 * @returns {FieldNotFoundError}
 */
export function missingFieldsError(fields) {
  const unique = [...new Set(fields)];
  if (unique.length === 1) {
    return new FieldNotFoundError(`field not found in secret: ${unique[0]}`);
  }
  return new FieldNotFoundError(`fields not found in secret: ${unique.join(", ")}`);
}
