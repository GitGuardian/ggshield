# Hashicorp Vault

The `ggshield check-secret-manager hashicorp-vault` command interacts with Hashicorp Vault instances.

## Tests using cassettes

Like other tests, a lot of the tests for ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client
are using cassettes recorded using [VCR.py](https://github.com/kevin1024/vcrpy) to replay network interactions.

To generate these cassettes, a local Hashicorp Vault instance in dev mode is used by running the official Vault docker image.
The server is populated with test data:

- a `secret_v1` kv mount (version 1)
- a `secret` kv mount (version 2)
  These two mounts are populated with some file and directories (same data for both)

The server has two tokens:

- `my_vault_token` is a root token with all rights
- `restricted_token` is a token with the `default` policy.
  It cannot read the kv mounts (if you want to test error handling for example).

These vault tokens do not use the `hvs.<random_characters>` pattern on purpose to avoid
triggering ggshield.

### Running the server

The script handling the server is `scripts/hmsl/hashicorp_vault.py`:

- to start the server: `python scripts/hmsl/hashicorp_vault.py start`.
- to stop the server: `python scripts/hmsl/hashicorp_vault.py stop`

The server runs on the default Vault port (8200).

You can then use the tokens above to interact with the server API.

The web UI is enabled and can be reached on http://127.0.0.1:8200.

If you want to use the CLI, it's available directly in the container:

- Run `docker exec -it hashicorp-vault-ggshield sh` to get a shell inside the container
- Call the vault CLI as normal (no need to login). For example `vault token lookup`.

### Using the server in tests

The server can be used in tests like in `tests/unit/verticals/hmsl/secret_manager/hashicorp_vault/test_api_client.py`.

The stable test data mean that the cassettes can be deleted and recreated without issues.
