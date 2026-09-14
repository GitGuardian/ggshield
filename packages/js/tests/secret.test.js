/** Tests for the redaction wrapper and the error taxonomy. */

import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";

import {
  AuthenticationError,
  FieldNotFoundError,
  PermissionDeniedError,
  Secret,
  SecretError,
  SecretNotFoundError,
  UnsupportedOperationError,
} from "../src/index.js";

test("secret hides the value but expose reveals it", () => {
  const secret = new Secret("value-from-provider");

  assert.equal(secret.expose(), "value-from-provider");
  // String coercion / template literals / inspect / JSON all show the stamp.
  assert.ok(!`logged: ${secret}`.includes("value-from-provider"));
  assert.ok(!inspect(secret).includes("value-from-provider"));
  assert.ok(!JSON.stringify({ secret }).includes("value-from-provider"));
  assert.equal(String(secret), "[REDACTED]");
  assert.equal(inspect(secret), "Secret([REDACTED])");
  assert.equal(JSON.stringify(secret), '"[REDACTED]"');
});

test("exception hierarchy", () => {
  for (const Subclass of [
    SecretNotFoundError,
    AuthenticationError,
    PermissionDeniedError,
    FieldNotFoundError,
    UnsupportedOperationError,
  ]) {
    assert.ok(new Subclass("x") instanceof SecretError);
  }
  assert.ok(new SecretError("x") instanceof Error);
});
