/** Runtime access to the build-time-generated provider definitions. */

import { PROVIDER_DEFINITIONS } from "./providers.generated.js";
import { SecretError } from "./errors.js";

/**
 * The bundled definition for a provider.
 *
 * @param {string} provider A {@link import('./definition.js').Provider} value.
 * @returns {import('./definition.js').ProviderDef}
 */
export function providerDefinition(provider) {
  const definition = PROVIDER_DEFINITIONS[provider];
  if (definition === undefined) {
    throw new SecretError(`unknown provider '${provider}'`);
  }
  return definition;
}
