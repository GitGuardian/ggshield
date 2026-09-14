# GitGuardian JavaScript SDK

Read secrets from your secret manager straight into application memory,
without writing them to disk or the process environment.

Distributed on npm as `gitguardian`:

```bash
npm install gitguardian
```

```js
import { Provider, SecretStore } from "gitguardian";

const store = new SecretStore(Provider.VAULT);

// One field of one secret. Paths mirror `vault kv get`: <mount>/<path>.
const stripe = await store.getSecret("secret/myapp", "STRIPE_KEY");
charge({ apiKey: stripe.expose() });

// Every field of a secret, as Record<string, Secret>.
for (const [name, value] of Object.entries(await store.getSecrets("secret/myapp"))) {
  // ...
}
```

Secret values come back wrapped in `Secret`: `String()`, template literals,
`console.log` and `JSON.stringify` all show `[REDACTED]`; the real value is only
revealed by an explicit `expose()` call at the point of use.

The API is asynchronous — reads and writes return promises — because the
underlying HTTP calls are. HTTP goes through the platform `fetch` and never
follows redirects, so auth headers cannot be forwarded to a host the provider
didn't answer from. Requires Node.js 20+.

## Environment override

By default, an environment variable named like a secret field takes precedence
over the provider's value — `getSecret('secret/myapp', 'STRIPE_KEY')` returns
`$STRIPE_KEY` without any provider access when that variable is set. The same
code therefore works on a developer machine (fetching from the provider) and on
a platform that already injects the secret as an environment variable. Disable
it with `new SecretStore(Provider.VAULT, { envOverride: false })`.

## Configuration

Providers are configured the same way as the `gitguardian` CLI. For Vault:
`VAULT_ADDR`, and a token from `$VAULT_TOKEN` or `~/.vault-token` (written by
`vault login`).

For 1Password, deploy a
[Connect server](https://www.1password.dev/connect/get-started), then set
`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`. Paths are `<vault>/<item>` and accept
either exact names or IDs:

```js
const store = new SecretStore(Provider.ONEPASSWORD);
const secrets = await store.getSecrets("Engineering/myapp");
```

## Errors

All failures throw `SecretError`; specific cases throw its subclasses
`SecretNotFoundError`, `AuthenticationError`, `PermissionDeniedError`,
`FieldNotFoundError`, and `UnsupportedOperationError`.

## Types

The package is written in JavaScript with JSDoc type annotations, type-checked
with tsgo (`@typescript/native-preview`), and ships generated `.d.ts`
declarations, so it type-checks and offers full editor completion in both
JavaScript and TypeScript projects — while consumers can still step into the
readable `.js` source in `node_modules`.

## Developing

This package is a JavaScript port of the `packages/core` engine; both interpret
the same declarative provider definitions. The repository's `providers/*.yaml`
files are the single source of truth: they are converted into
`src/providers.generated.js` at build time (the `prepare`/`prepack` scripts) —
so that module is generated, not committed (it is gitignored), and the package
never carries a second copy — and behavior changes must land in both
implementations. `pnpm install` regenerates it; `pnpm run generate:providers`
does so on demand.

This package is the sole member of the repo-root pnpm workspace, so the scripts
below run from the **repository root** (no `cd` needed):

```bash
pnpm install              # installs the SDK; also generates src/providers.generated.js
pnpm run ci               # test + fmt:check + lint + check + build + knip, in parallel
pnpm test                 # node:test, offline, no Vault needed
pnpm run fmt:check        # formatting (oxfmt)
pnpm run lint             # linting (oxlint)
pnpm run check            # type checking (tsgo, checkJs)
pnpm run build            # emit .d.ts declarations to dist/
pnpm run knip             # unused files, dependencies, and exports
```

Write operations (`setSecrets`, `replaceSecrets`, `deleteSecrets`) can be
smoke-tested against a throwaway provider as described in `AGENTS.md`.
