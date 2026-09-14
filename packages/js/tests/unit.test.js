/** Unit tests for the engine internals, mirroring packages/core's Rust tests. */

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { authHeaders, resolveToken, tokenFilePath } from "../src/auth.js";
import { truncate } from "../src/http.js";
import { interpolate, interpolatePath } from "../src/interpolate.js";
import { dotPath, secretFields } from "../src/json.js";
import {
  mergeOnepasswordItemFields,
  parseOnepasswordPath,
  removeOnepasswordItemFields,
  resolveOnepasswordId,
} from "../src/onepassword.js";
import { readParams } from "../src/store.js";

/** @type {NodeJS.ProcessEnv} */
let savedEnv;

beforeEach(() => {
  savedEnv = { ...process.env };
});

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  Object.assign(process.env, savedEnv);
});

test("interpolate resolves params then env", () => {
  process.env.GG_TEST_INTERP = "from-env";
  assert.equal(
    interpolate("${mount}/${GG_TEST_INTERP}", { mount: "from-params" }),
    "from-params/from-env",
  );
  delete process.env.GG_TEST_UNSET_INTERP;
  assert.throws(() => interpolate("${GG_TEST_UNSET_INTERP}", {}), /no value for/);
  assert.throws(() => interpolate("${oops", {}), /unterminated/);
});

test("interpolatePath percent-encodes values but keeps slashes", () => {
  assert.equal(interpolatePath("/v1/${path}", { path: "a/b#c?d %e" }), "/v1/a/b%23c%3Fd%20%25e");
  assert.equal(interpolatePath("/v1/${item_id}", { item_id: "item/id" }), "/v1/item%2Fid");
  // Template literals are trusted and left as-is.
  assert.equal(interpolatePath("/v1/data?x=1", {}), "/v1/data?x=1");
});

test("readParams splits mount and path", () => {
  assert.deepEqual(readParams("secret/myapp/db"), { mount: "secret", path: "myapp/db" });
  assert.throws(() => readParams("no-slash"), /must be '<mount>\/<path>'/);
});

test("resolveToken prefers env then file", () => {
  const dir = mkdtempSync(join(tmpdir(), "gg-"));
  const tokenFile = join(dir, "token");
  writeFileSync(tokenFile, "  s.abc123\n");
  const auth = { tokenEnv: "GG_TEST_TOKEN", tokenFile, header: "X-Vault-Token" };

  process.env.GG_TEST_TOKEN = "from-env";
  assert.equal(resolveToken(auth), "from-env");

  delete process.env.GG_TEST_TOKEN;
  assert.equal(resolveToken(auth), "s.abc123");
});

test("resolveToken treats a missing file as no token", () => {
  delete process.env.GG_TEST_TOKEN;
  const auth = {
    tokenEnv: "GG_TEST_TOKEN",
    tokenFile: "/definitely/missing/token",
    header: "X-Vault-Token",
  };
  assert.throws(() => resolveToken(auth), /no token found/);
});

test("resolveToken surfaces unreadable token files", () => {
  delete process.env.GG_TEST_TOKEN;
  // A directory is unreadable-as-a-file without being NotFound.
  const dir = mkdtempSync(join(tmpdir(), "gg-"));
  const auth = { tokenEnv: "GG_TEST_TOKEN", tokenFile: dir, header: "X-Vault-Token" };
  assert.throws(() => resolveToken(auth), /reading token file/);
});

test("tokenFilePath prefers env then default", () => {
  const auth = {
    tokenEnv: "T",
    tokenFileEnv: "GG_TEST_TOKEN_PATH",
    tokenFile: "~/.vault-token",
    header: "X-Vault-Token",
  };
  delete process.env.GG_TEST_TOKEN_PATH;
  assert.equal(tokenFilePath(auth), "~/.vault-token");
  process.env.GG_TEST_TOKEN_PATH = "/custom/token";
  assert.equal(tokenFilePath(auth), "/custom/token");
});

test("authHeaders prepends the scheme", () => {
  process.env.GG_TEST_TOKEN = "fake-token";
  const auth = {
    tokenEnv: "GG_TEST_TOKEN",
    header: "Authorization",
    scheme: "Bearer",
  };
  assert.deepEqual(authHeaders(auth), { Authorization: "Bearer fake-token" });
});

test("secretFields splits objects and wraps scalars", () => {
  assert.deepEqual(secretFields({ A: "1", B: 2, C: true }), {
    A: "1",
    B: "2",
    C: "true",
  });
  assert.deepEqual(secretFields("flat"), { value: "flat" });
  assert.deepEqual(
    secretFields([{ id: "account", label: "ACCOUNT", value: "fake-user" }, { id: "empty" }]),
    { ACCOUNT: "fake-user" },
  );
});

test("onepassword path resolution and field updates", () => {
  assert.deepEqual(parseOnepasswordPath("dev/myapp"), ["dev", "myapp"]);
  assert.throws(() => parseOnepasswordPath("dev/team/myapp"), /<vault>\/<item>/);
  assert.equal(
    resolveOnepasswordId([{ id: "vault-id", name: "dev" }], {
      kind: "vault",
      query: "dev",
      nameKey: "name",
      path: "dev/myapp",
    }),
    "vault-id",
  );
  const item = {
    fields: [{ id: "api", label: "API_KEY", value: "old" }],
  };
  mergeOnepasswordItemFields(item, {
    API_KEY: "new",
    DB_URL: "fake://db",
  });
  const [apiField] = item.fields;
  assert.ok(apiField);
  assert.equal(apiField.value, "new");
  removeOnepasswordItemFields(item, ["API_KEY"]);
  assert.deepEqual(
    item.fields.map((field) => field.label),
    ["DB_URL"],
  );
});

test("dotPath walks nested objects", () => {
  const body = { data: { data: { K: "V" } } };
  assert.deepEqual(dotPath(body, "data.data"), { K: "V" });
  assert.equal(dotPath(body, "data.missing"), undefined);
});

test("truncate marks elision", () => {
  assert.equal(truncate("short", 10), "short");
  assert.equal(truncate("x".repeat(300), 4), "xxxx… (300 chars total)");
});
