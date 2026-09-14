/**
 * Offline smoke tests for the public SDK surface.
 *
 * These run without a secret-manager server: the env-override path never
 * touches the network, and the provider-access tests stub `fetch` so the
 * transport fails deterministically, regardless of what is (or isn't) listening
 * on the local machine.
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";

import { Provider, Secret, SecretError, SecretStore } from "../src/index.js";

const VAULT_ADDR = "https://vault.example";

/** Replace the global `fetch` with one that always fails at the transport layer. */
function stubFailingFetch() {
  mock.method(globalThis, "fetch", () => Promise.reject(new TypeError("fetch failed")));
}

/**
 * @param {unknown[]} responses
 * @returns {Array<{ url: string, init?: RequestInit }>}
 */
function stubJsonResponses(responses) {
  /** @type {Array<{ url: string, init?: RequestInit }>} */
  const requests = [];
  /**
   * @param {string | URL | Request} url
   * @param {RequestInit} [init]
   */
  function handler(url, init) {
    requests.push({ url: String(url), init });
    return Promise.resolve(
      new Response(JSON.stringify(responses.shift()), {
        headers: { "Content-Type": "application/json" },
      }),
    );
  }
  mock.method(globalThis, "fetch", handler);
  return requests;
}

/** @type {NodeJS.ProcessEnv} */
let savedEnv;

beforeEach(() => {
  savedEnv = { ...process.env };
});

afterEach(() => {
  mock.restoreAll();
  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  Object.assign(process.env, savedEnv);
});

test("env override short-circuits the provider", async () => {
  // No VAULT_ADDR configured: the lookup must return before any provider
  // access happens.
  delete process.env.VAULT_ADDR;
  process.env.SMOKE_TEST_FIELD = "value-from-env";

  const store = new SecretStore(Provider.VAULT);
  const secret = await store.getSecret("secret/does-not-matter", "SMOKE_TEST_FIELD");

  assert.ok(secret instanceof Secret);
  assert.equal(secret.expose(), "value-from-env");
});

test("secret is redacted by default", async () => {
  process.env.SMOKE_TEST_FIELD = "value-from-env";
  const secret = await new SecretStore(Provider.VAULT).getSecret("secret/x", "SMOKE_TEST_FIELD");

  assert.ok(!String(secret).includes("value-from-env"));
  assert.ok(!`logged: ${secret}`.includes("value-from-env"));
});

test("env override can be disabled", async () => {
  process.env.VAULT_ADDR = VAULT_ADDR;
  process.env.VAULT_TOKEN = "fake-token";
  process.env.SMOKE_TEST_FIELD = "value-from-env";
  stubFailingFetch();

  const store = new SecretStore(Provider.VAULT, { envOverride: false });
  await assert.rejects(store.getSecret("secret/myapp", "SMOKE_TEST_FIELD"), SecretError);
});

test("provider failure raises a SecretError", async () => {
  process.env.VAULT_ADDR = VAULT_ADDR;
  process.env.VAULT_TOKEN = "fake-token";
  stubFailingFetch();

  const store = new SecretStore(Provider.VAULT);
  await assert.rejects(store.getSecrets("secret/myapp"), (error) => {
    assert.ok(error instanceof SecretError);
    assert.match(error.message, /read_secret/);
    return true;
  });
});

test("non-http base URLs are rejected", async () => {
  // A poisoned VAULT_ADDR must not be able to turn a secret read into a local
  // file:// read; it is rejected while building the request, before any fetch.
  process.env.VAULT_ADDR = "file:///etc/passwd";
  process.env.VAULT_TOKEN = "fake-token";

  const store = new SecretStore(Provider.VAULT, { envOverride: false });
  await assert.rejects(store.getSecrets("secret/myapp"), /must be http/);
});

test("setSecrets rejects empty fields", async () => {
  // Guarded before any provider access, so no server is needed.
  await assert.rejects(
    new SecretStore(Provider.VAULT).setSecrets("secret/myapp", {}),
    /cannot set a secret with no fields/,
  );
});

test("writes reach the provider and surface failures", async () => {
  // The write path is otherwise exercised end-to-end against a throwaway vault
  // dev-server (see AGENTS.md); here we only assert it reaches the transport and
  // maps a failure to SecretError.
  process.env.VAULT_ADDR = VAULT_ADDR;
  process.env.VAULT_TOKEN = "fake-token";
  stubFailingFetch();
  const store = new SecretStore(Provider.VAULT);

  await assert.rejects(store.setSecrets("secret/myapp", { API_KEY: "fake" }), SecretError);
  await assert.rejects(store.deleteSecrets("secret/myapp"), SecretError);
});

test("onepassword reads an item by vault and item name", async () => {
  process.env.OP_CONNECT_HOST = "https://connect.example";
  process.env.OP_CONNECT_TOKEN = "fake-connect-token";
  const responses = [
    [{ id: "vault-id", name: "dev" }],
    [{ id: "item-id", title: "myapp" }],
    {
      fields: [{ id: "api", label: "API_KEY", value: "fake-value" }],
    },
  ];
  const requests = stubJsonResponses(responses);

  const fields = await new SecretStore(Provider.ONEPASSWORD, {
    envOverride: false,
  }).getSecrets("dev/myapp");

  assert.equal(fields.API_KEY?.expose(), "fake-value");
  assert.deepEqual(
    requests.map(({ init }) => init?.method),
    ["GET", "GET", "GET"],
  );
  assert.ok(requests[2]?.url.endsWith("/v1/vaults/vault-id/items/item-id"));
  assert.ok(
    requests.every(
      ({ init }) => new Headers(init?.headers).get("Authorization") === "Bearer fake-connect-token",
    ),
  );
});

test("onepassword creates a missing item", async () => {
  process.env.OP_CONNECT_HOST = "https://connect.example";
  process.env.OP_CONNECT_TOKEN = "fake-connect-token";
  const responses = [[{ id: "vault-id", name: "dev" }], [], { id: "created-item" }];
  const requests = stubJsonResponses(responses);

  await new SecretStore(Provider.ONEPASSWORD).setSecrets("dev/myapp", {
    API_KEY: "fake-value",
  });

  const request = requests[2];
  assert.ok(request);
  assert.equal(request.init?.method, "POST");
  assert.ok(request.url.endsWith("/v1/vaults/vault-id/items"));
  assert.deepEqual(JSON.parse(String(request.init?.body)), {
    vault: { id: "vault-id" },
    title: "myapp",
    category: "SECURE_NOTE",
    fields: [
      {
        label: "API_KEY",
        type: "CONCEALED",
        value: "fake-value",
      },
    ],
  });
});
