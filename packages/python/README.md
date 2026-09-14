# GitGuardian Python SDK

Read secrets from your secret manager straight into application memory,
without writing them to disk or the process environment.

Distributed on PyPI as `gitguardian`:

```bash
pip install gitguardian
```

```python
from gitguardian import Provider, SecretStore

store = SecretStore(Provider.VAULT)

# One field of one secret. Paths mirror `vault kv get`: <mount>/<path>.
stripe = store.get_secret("secret/myapp", "STRIPE_KEY")
charge(api_key=stripe.expose())

# Every field of a secret, as dict[str, Secret].
for name, value in store.get_secrets("secret/myapp").items():
    ...
```

Secret values come back wrapped in `Secret`: `repr()`, `str()`, f-strings and
logging all show `[REDACTED]`; the real value is only exposed by an explicit
`expose()` call at the point of use.

Pure Python (3.10+), fully typed, one dependency (`pyyaml`). HTTP goes through
the standard library and never follows redirects, so auth headers cannot be
forwarded to a host the provider didn't answer from.

## Environment override

By default, an environment variable named like a secret field takes precedence
over the provider's value — `get_secret("secret/myapp", "STRIPE_KEY")` returns
`$STRIPE_KEY` without any provider access when that variable is set. The same
code therefore works on a developer machine (fetching from the provider) and
on a platform that already injects the secret as an environment variable.
Disable it with `SecretStore(Provider.VAULT, env_override=False)`.

## Configuration

Providers are configured the same way as the `gitguardian` CLI. For Vault:
`VAULT_ADDR`, and a token from `$VAULT_TOKEN` or `~/.vault-token` (written by
`vault login`).

For 1Password, deploy a
[Connect server](https://www.1password.dev/connect/get-started), then set
`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`. Paths are `<vault>/<item>` and accept
either exact names or IDs:

```python
store = SecretStore(Provider.ONEPASSWORD)
secrets = store.get_secrets("Engineering/myapp")
```

## Errors

All failures raise `SecretError`; specific cases raise its subclasses
`SecretNotFoundError`, `AuthenticationError`, `PermissionDeniedError`,
`FieldNotFoundError`, and `UnsupportedOperationError`.

## Developing

This package is a Python port of the `packages/core` engine; both interpret
the same declarative provider definitions. The repository's `providers/*.yaml`
files are the single source of truth: they are vendored into
`src/gitguardian/providers/` at build time (`hatch_build.py`) — so that
directory is generated, not committed — and behavior changes must land in both
implementations.

```bash
cd packages/python
uv sync
uv run pytest              # offline, no Vault needed
uv run ruff format .       # formatting
uv run ruff check --fix .  # linting (incl. bandit security rules)
uv run ty check            # type checking
```

Write operations (`set_secrets`, `replace_secrets`, `delete_secrets`) can be
smoke-tested against a throwaway provider as described in `AGENTS.md`.
