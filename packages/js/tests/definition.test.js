/** Tests for provider definitions and their build-time generation. */

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import { parseProviderDef, Provider, PROVIDERS } from "../src/definition.js";
import { providerDefinition } from "../src/providers.js";
import { PROVIDER_DEFINITIONS } from "../src/providers.generated.js";

const REPO_PROVIDERS = new URL("../../../providers/", import.meta.url);

test("every provider has a loadable definition", () => {
  for (const provider of PROVIDERS) {
    assert.equal(providerDefinition(provider).name, provider);
  }
});

test("generated definitions match the repo contract", (t) => {
  // providers/*.yaml (repo root) is the single source; the generated module is
  // built from it at install/build time. Guards that it is a faithful
  // conversion of the source (regenerate with `pnpm run generate:providers`).
  if (!existsSync(REPO_PROVIDERS)) {
    t.skip("not running from the repository checkout");
    return;
  }
  const files = readdirSync(REPO_PROVIDERS).filter((name) => name.endsWith(".yaml"));
  assert.ok(files.length > 0, "expected at least one provider YAML");
  for (const file of files) {
    const text = readFileSync(new URL(file, REPO_PROVIDERS), "utf8");
    const def = parseProviderDef(parseYaml(text));
    assert.deepStrictEqual(
      PROVIDER_DEFINITIONS[def.name],
      def,
      `${file} not reflected in the generated module; run pnpm run generate:providers`,
    );
  }
});

test("unknown definition keys are rejected", () => {
  assert.throws(
    () =>
      parseProviderDef({
        name: "x",
        base_url: "y",
        auth: { strategy: "token", token_env: "T" },
        bogus: 1,
      }),
    /unknown provider definition keys/,
  );
});

test("provider enum identity", () => {
  assert.equal(Provider.ONEPASSWORD, Provider.ONEPASSWORD);
  assert.equal(Provider.VAULT, Provider.VAULT);
  assert.equal({ [Provider.ONEPASSWORD]: "ok" }[Provider.ONEPASSWORD], "ok");
  assert.equal({ [Provider.VAULT]: "ok" }[Provider.VAULT], "ok");
});
