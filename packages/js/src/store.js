/**
 * The secret-resolution engine.
 *
 * Behavior stays in parity with the other GitGuardian SDKs and the CLI: same
 * provider contract, env-override precedence, KV v2 check-and-set writes,
 * no-redirect policy, and error taxonomy — so a change to secret-resolution
 * semantics must land everywhere. Request building and transport live in
 * `http.js`; template interpolation in `interpolate.js`.
 *
 * The API is async, since `fetch` is.
 */

import { UNKNOWN_PATH } from "./constants.js";
import {
  FieldNotFoundError,
  missingFieldsError,
  SecretError,
  SecretNotFoundError,
  UnsupportedOperationError,
} from "./errors.js";
import { buildRequest, sendRequest } from "./http.js";
import { dotPath, secretFields } from "./json.js";
import {
  isRecord,
  mergeOnepasswordItemFields,
  onepasswordItemFields,
  parseOnepasswordPath,
  removeOnepasswordItemFields,
  replaceOnepasswordItemFields,
  resolveOnepasswordId,
} from "./onepassword.js";
import { providerDefinition } from "./providers.js";
import { Secret } from "./secret.js";

/**
 * @typedef {import('./definition.js').ProviderDef} ProviderDef
 */

/**
 * A live client for one provider — the main SDK entry point.
 *
 * Building a store is cheap and opens no connection; network round-trips
 * happen in {@link SecretStore#getSecret} / {@link SecretStore#getSecrets}.
 *
 * With `envOverride` enabled (the default), an environment variable named like
 * a secret field replaces the provider's value, so the same code runs on a
 * developer machine (fetching from the provider) and on a server where the
 * platform already injects the secret as an environment variable. Disable it
 * when a poisoned environment must not be able to substitute secrets.
 */
export class SecretStore {
  /** @type {ProviderDef} */
  #definition;
  /** @type {boolean} */
  #envOverride;

  /**
   * @param {string} provider A {@link import('./definition.js').Provider} value.
   * @param {object} [options]
   * @param {boolean} [options.envOverride] Default `true`.
   */
  constructor(provider, { envOverride = true } = {}) {
    this.#definition = providerDefinition(provider);
    this.#envOverride = envOverride;
  }

  /**
   * Fetch a single `field` of the secret at `path`.
   *
   * With env override enabled (the default), an environment variable named
   * `field` short-circuits the lookup entirely — no provider access, no
   * network.
   *
   * @param {string} path
   * @param {string} field
   * @returns {Promise<Secret>}
   */
  async getSecret(path, field) {
    if (this.#envOverride) {
      const override = envOverrideValue(field);
      if (override !== undefined) {
        return new Secret(override);
      }
    }
    const fields = await this.#getFields(path);
    const value = fields[field];
    if (value === undefined) {
      throw new FieldNotFoundError(`field not found in secret: ${field}`);
    }
    return new Secret(value);
  }

  /**
   * Fetch every field of the secret at `path`.
   *
   * With env override enabled (the default), an environment variable named
   * like a field replaces that field's value. The field *names* still come
   * from the provider, so this call always fetches.
   *
   * @param {string} path
   * @returns {Promise<Record<string, Secret>>}
   */
  async getSecrets(path) {
    const fields = await this.#getFields(path);
    /** @type {Record<string, Secret>} */
    const secrets = {};
    for (const [name, value] of Object.entries(fields)) {
      secrets[name] = new Secret(value);
    }
    return secrets;
  }

  /**
   * Create or update fields in the secret at `path`.
   *
   * @param {string} path
   * @param {Record<string, string>} fields
   * @returns {Promise<void>}
   */
  async setSecrets(path, fields) {
    if (Object.keys(fields).length === 0) {
      throw new SecretError("cannot set a secret with no fields");
    }
    if (this.#definition.name === "onepassword") {
      await this.#setOnepasswordSecrets(path, fields);
      return;
    }
    const params = readParams(path);
    this.#requireVault("writing secrets");
    const existing = await this.#readVaultSecretVersion(params);
    // Version 0 means "create only if still absent", so a secret created
    // between our read and write fails the CAS check too.
    const [merged, version] = existing ?? [{}, 0];
    Object.assign(merged, fields);
    await this.#writeVaultSecrets(params, merged, version);
  }

  /**
   * Replace the secret at `path` with exactly `fields`.
   *
   * @param {string} path
   * @param {Record<string, string>} fields
   * @returns {Promise<void>}
   */
  async replaceSecrets(path, fields) {
    if (Object.keys(fields).length === 0) {
      throw new SecretError("cannot set a secret with no fields");
    }
    if (this.#definition.name === "onepassword") {
      const [params] = await this.#onepasswordTarget(path, false);
      const item = await this.#onepasswordItem(params);
      replaceOnepasswordItemFields(item, fields);
      await this.#send("write_secret", params, item);
      return;
    }
    const params = readParams(path);
    this.#requireVault("writing secrets");
    const existing = await this.#readVaultSecretVersion(params);
    await this.#writeVaultSecrets(params, fields, existing?.[1] ?? 0);
  }

  /**
   * Delete a whole secret, or selected fields when `keys` is given.
   *
   * @param {string} path
   * @param {readonly string[]} [keys]
   * @returns {Promise<void>}
   */
  async deleteSecrets(path, keys = []) {
    if (this.#definition.name === "onepassword") {
      await this.#deleteOnepasswordSecrets(path, keys);
      return;
    }
    const params = readParams(path);
    this.#requireVault("deleting secrets");
    if (keys.length === 0) {
      await this.#send("delete_secret", params);
      return;
    }

    const existing = await this.#readVaultSecretVersion(params);
    if (existing === null) {
      throw missingFieldsError(keys);
    }
    const [fields, version] = existing;
    const missing = keys.filter((key) => !(key in fields));
    if (missing.length > 0) {
      throw missingFieldsError(missing);
    }

    for (const key of keys) {
      delete fields[key];
    }
    if (Object.keys(fields).length === 0) {
      await this.#send("delete_secret", params);
    } else {
      await this.#writeVaultSecrets(params, fields, version);
    }
  }

  /**
   * @param {string} path
   * @returns {Promise<Record<string, string>>}
   */
  async #getFields(path) {
    const params =
      this.#definition.name === "onepassword"
        ? (await this.#onepasswordTarget(path, false))[0]
        : readParams(path);
    const fields = await this.#fetch("read_secret", params);
    if (this.#envOverride) {
      for (const key of Object.keys(fields)) {
        const override = envOverrideValue(key);
        if (override !== undefined) {
          fields[key] = override;
        }
      }
    }
    return fields;
  }

  /**
   * @param {string} path
   * @param {boolean} allowMissingItem
   * @returns {Promise<[Record<string, string>, boolean]>}
   */
  async #onepasswordTarget(path, allowMissingItem) {
    const [vault, item] = parseOnepasswordPath(path);
    /** @type {Record<string, string>} */
    const params = { vault, item };
    const vaults = await this.#fetchValue("list_vaults", params);
    const vaultId = resolveOnepasswordId(vaults, {
      kind: "vault",
      query: vault,
      nameKey: "name",
      path,
    });
    if (vaultId === null) {
      throw new SecretError("1Password vault unexpectedly missing");
    }
    params.vault_id = vaultId;

    const items = await this.#fetchValue("list_items", params);
    const itemId = resolveOnepasswordId(items, {
      kind: "item",
      query: item,
      nameKey: "title",
      path,
    });
    if (itemId !== null) {
      params.item_id = itemId;
      return [params, true];
    }
    if (allowMissingItem) {
      return [params, false];
    }
    throw new SecretNotFoundError(`secret not found at ${path}`);
  }

  /**
   * @param {Record<string, string>} params
   * @returns {Promise<Record<string, unknown>>}
   */
  async #onepasswordItem(params) {
    const item = await this.#fetchValue("read_secret", params);
    if (!isRecord(item)) {
      throw new SecretError("1Password item response was not an object");
    }
    return item;
  }

  /**
   * @param {string} path
   * @param {Record<string, string>} updates
   */
  async #setOnepasswordSecrets(path, updates) {
    const [params, itemExists] = await this.#onepasswordTarget(path, true);
    if (itemExists) {
      const item = await this.#onepasswordItem(params);
      mergeOnepasswordItemFields(item, updates);
      await this.#send("write_secret", params, item);
      return;
    }
    await this.#send("create_secret", params, {
      vault: { id: params.vault_id },
      title: params.item,
      category: "SECURE_NOTE",
      fields: onepasswordItemFields(updates),
    });
  }

  /**
   * @param {string} path
   * @param {readonly string[]} keys
   */
  async #deleteOnepasswordSecrets(path, keys) {
    const [params] = await this.#onepasswordTarget(path, false);
    if (keys.length === 0) {
      await this.#send("delete_secret", params);
      return;
    }
    const item = await this.#onepasswordItem(params);
    removeOnepasswordItemFields(item, keys);
    if (Array.isArray(item.fields) && item.fields.length === 0) {
      await this.#send("delete_secret", params);
    } else {
      await this.#send("write_secret", params, item);
    }
  }

  /**
   * @param {string} operation
   * @returns {void}
   */
  #requireVault(operation) {
    // TODO: drive writes/deletes from the provider definition once a second
    // writable backend lands (mirrors the same TODO in core).
    if (this.#definition.name !== "vault") {
      throw new UnsupportedOperationError(
        `provider '${this.#definition.name}' does not support ${operation}`,
      );
    }
  }

  /**
   * Fetch an endpoint and extract its declared secret into a field map.
   *
   * @param {string} endpointName
   * @param {Record<string, string>} params
   * @returns {Promise<Record<string, string>>}
   */
  async #fetch(endpointName, params) {
    const body = await this.#fetchValue(endpointName, params);
    const endpoint = this.#definition.endpoints[endpointName];
    const secretPath = endpoint?.secret ?? null;
    if (secretPath === null) {
      throw new SecretError(`endpoint '${endpointName}' does not expose a secret`);
    }
    const secret = dotPath(body, secretPath);
    if (secret == null) {
      throw new SecretError(`secret path '${secretPath}' not found in response`);
    }
    return secretFields(secret);
  }

  /**
   * Call an endpoint and parse its JSON response.
   *
   * @param {string} endpointName
   * @param {Record<string, string>} params
   * @param {unknown} [body]
   * @returns {Promise<unknown>}
   */
  async #fetchValue(endpointName, params, body) {
    const raw = await this.#send(endpointName, params, body);
    try {
      return JSON.parse(raw);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new SecretError(`parsing JSON response: ${reason}`);
    }
  }

  /**
   * Send a request to an endpoint, returning the raw body text.
   *
   * @param {string} endpointName
   * @param {Record<string, string>} params
   * @param {unknown} [body]
   * @returns {Promise<string>}
   */
  #send(endpointName, params, body) {
    const request = buildRequest(this.#definition, endpointName, params, body);
    return sendRequest(this.#definition.name, endpointName, userPath(params), request);
  }

  /**
   * Fields and KV v2 version of the secret, or `null` when absent.
   *
   * The version feeds Vault's check-and-set option so read-modify-write
   * callers fail on concurrent writes instead of silently overwriting them.
   *
   * @param {Record<string, string>} params
   * @returns {Promise<[Record<string, string>, number] | null>}
   */
  async #readVaultSecretVersion(params) {
    let body;
    try {
      body = await this.#fetchValue("read_secret", params);
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        return null;
      }
      throw error;
    }
    // KV v2 response layout; this helper is only reached for vault.
    const data = dotPath(body, "data.data");
    if (data == null) {
      throw new SecretError("secret path 'data.data' not found in response");
    }
    const version = dotPath(body, "data.metadata.version");
    if (typeof version !== "number" || !Number.isInteger(version)) {
      throw new SecretError("no 'data.metadata.version' in KV v2 read response");
    }
    return [secretFields(data), version];
  }

  /**
   * @param {Record<string, string>} params
   * @param {Record<string, string>} fields
   * @param {number} casVersion
   * @returns {Promise<void>}
   */
  async #writeVaultSecrets(params, fields, casVersion) {
    // check-and-set: reject the write if the secret is no longer at the
    // version our merge was based on, instead of dropping the fields a
    // concurrent writer just added.
    const body = { data: { ...fields }, options: { cas: casVersion } };
    await this.#send("write_secret", params, body);
  }
}

/**
 * Map a user-facing secret path to the read endpoint's parameters.
 *
 * Vault paths are `<mount>/<secret path>`, mirroring `vault kv get`.
 *
 * @param {string} path
 * @returns {Record<string, string>}
 */
export function readParams(path) {
  const separator = path.indexOf("/");
  if (separator === -1) {
    throw new SecretError(`path '${path}' must be '<mount>/<path>', e.g. secret/myapp`);
  }
  return { mount: path.slice(0, separator), path: path.slice(separator + 1) };
}

/**
 * The value of the environment variable named `field`, if non-empty.
 *
 * @param {string} field
 * @returns {string | undefined}
 */
function envOverrideValue(field) {
  return process.env[field] || undefined;
}

/**
 * @param {Record<string, string>} params
 * @returns {string}
 */
function userPath(params) {
  if ("mount" in params && "path" in params) {
    return `${params.mount}/${params.path}`;
  }
  if ("vault" in params && "item" in params) {
    return `${params.vault}/${params.item}`;
  }
  return UNKNOWN_PATH;
}
