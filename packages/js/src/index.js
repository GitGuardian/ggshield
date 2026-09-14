/**
 * GitGuardian secrets SDK — read secrets straight into memory.
 *
 * The high-level entry point is {@link SecretStore}: build one for a
 * {@link Provider}, then read secrets directly from your application code:
 *
 * ```js
 * import { Provider, SecretStore } from 'gitguardian';
 *
 * const store = new SecretStore(Provider.VAULT);
 * const stripe = await store.getSecret('secret/myapp', 'STRIPE_KEY');
 * charge({ apiKey: stripe.expose() });
 * ```
 *
 * Providers are declared as data in `providers/<name>.yaml` and exposed as the
 * {@link Provider} enum. Resolved secret values are returned as {@link Secret}
 * so they are not accidentally leaked through `toString()`, logging,
 * template literals, or `JSON.stringify` — callers must opt in with `expose()`
 * to read them.
 *
 * @module gitguardian
 */

export { Provider } from "./definition.js";
export {
  AuthenticationError,
  FieldNotFoundError,
  PermissionDeniedError,
  SecretError,
  SecretNotFoundError,
  UnsupportedOperationError,
} from "./errors.js";
export { Secret } from "./secret.js";
export { SecretStore } from "./store.js";
