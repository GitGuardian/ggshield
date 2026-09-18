//! The provider definitions that ship with the binary.
//!
//! `${NAME}` in a `base_url` is resolved from the environment; `${name}` in an
//! endpoint path is filled from the requested secret path and percent-encoded
//! (see `store::interpolate_path`). The invariants a definition has to hold —
//! absolute paths, balanced placeholders, non-empty names — are asserted by
//! the tests at the bottom of this file, over every provider at once.

use crate::definition::{Auth, Endpoint, Method, ProviderDef};

/// HashiCorp Vault's KV v2 secrets engine.
///
/// `mount` and `path` are derived from the requested secret path
/// (`secret/myapp/db` -> mount `secret`, path `myapp/db`), and the KV v2 API
/// nests the secret data under `.data.data`.
///
/// Token auth: prefer `$VAULT_TOKEN`, fall back to `~/.vault-token` (written by
/// `vault login`), which is the precedence the official Vault CLI uses. Other
/// Vault auth methods (AppRole, OIDC, ...) all end in a token, so they can be
/// added later as further coded strategies.
pub(crate) const VAULT: ProviderDef = ProviderDef {
    name: "vault",
    description: "HashiCorp Vault KV v2 secrets engine",
    base_url: "${VAULT_ADDR}",
    auth: Auth::Token {
        token_env: "VAULT_TOKEN",
        token_file_env: Some("VAULT_TOKEN_FILE_PATH"),
        token_file: Some("~/.vault-token"),
        header: "X-Vault-Token",
        scheme: None,
    },
    endpoints: &[
        (
            "read_secret",
            Endpoint {
                method: Method::Get,
                path: "/v1/${mount}/data/${path}",
                query: &[],
                secret: Some("data.data"),
            },
        ),
        (
            // The request body is built by `store`, as {"data": {field: value}}.
            "write_secret",
            Endpoint {
                method: Method::Post,
                path: "/v1/${mount}/data/${path}",
                query: &[],
                secret: None,
            },
        ),
        (
            // The latest version only, mirroring `vault kv delete`.
            "delete_secret",
            Endpoint {
                method: Method::Delete,
                path: "/v1/${mount}/data/${path}",
                query: &[],
                secret: None,
            },
        ),
    ],
};

/// 1Password items through a Connect server.
pub(crate) const ONEPASSWORD: ProviderDef = ProviderDef {
    name: "onepassword",
    description: "1Password items through a Connect server",
    base_url: "${OP_CONNECT_HOST}",
    auth: Auth::Token {
        token_env: "OP_CONNECT_TOKEN",
        token_file_env: None,
        token_file: None,
        header: "Authorization",
        scheme: Some("Bearer"),
    },
    endpoints: &[
        (
            "list_vaults",
            Endpoint {
                method: Method::Get,
                path: "/v1/vaults",
                query: &[],
                secret: None,
            },
        ),
        (
            "list_items",
            Endpoint {
                method: Method::Get,
                path: "/v1/vaults/${vault_id}/items",
                query: &[],
                secret: None,
            },
        ),
        (
            "read_secret",
            Endpoint {
                method: Method::Get,
                path: "/v1/vaults/${vault_id}/items/${item_id}",
                query: &[],
                secret: Some("fields"),
            },
        ),
        (
            "create_secret",
            Endpoint {
                method: Method::Post,
                path: "/v1/vaults/${vault_id}/items",
                query: &[],
                secret: None,
            },
        ),
        (
            "write_secret",
            Endpoint {
                method: Method::Put,
                path: "/v1/vaults/${vault_id}/items/${item_id}",
                query: &[],
                secret: None,
            },
        ),
        (
            "delete_secret",
            Endpoint {
                method: Method::Delete,
                path: "/v1/vaults/${vault_id}/items/${item_id}",
                query: &[],
                secret: None,
            },
        ),
    ],
};

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a test is
// for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::provider::Provider;

    /// What the build script used to check on every build, now checked once
    /// over every definition that exists.
    fn definitions() -> Vec<&'static ProviderDef> {
        Provider::ALL
            .iter()
            .filter_map(|provider| provider.definition())
            .collect()
    }

    fn placeholders(value: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let mut rest = value;
        while let Some(start) = rest.find("${") {
            let after = &rest[start + 2..];
            let end = after
                .find('}')
                .unwrap_or_else(|| panic!("unterminated placeholder in {value}"));
            names.push(&after[..end]);
            rest = &after[end + 1..];
        }
        assert!(!rest.contains('}'), "unmatched closing brace in {value}");
        names
    }

    #[test]
    fn every_definition_names_itself_and_a_base_url() {
        for definition in definitions() {
            assert!(!definition.name.is_empty());
            assert!(!definition.description.is_empty());
            assert!(!definition.base_url.is_empty());
            for name in placeholders(definition.base_url) {
                assert!(!name.is_empty(), "{}", definition.name);
            }
        }
    }

    /// The provider's name is how the CLI, the error messages and `Provider`
    /// itself refer to it; a definition naming itself something else would
    /// report a provider the user cannot select.
    #[test]
    fn a_definition_agrees_with_the_provider_that_returns_it() {
        for provider in Provider::ALL {
            if let Some(definition) = provider.definition() {
                assert_eq!(definition.name, provider.as_str());
            }
        }
    }

    #[test]
    fn endpoint_paths_are_absolute_and_their_placeholders_balanced() {
        for definition in definitions() {
            for (name, endpoint) in definition.endpoints {
                assert!(
                    endpoint.path.starts_with('/'),
                    "{}: endpoint '{name}' path must start with '/'",
                    definition.name
                );
                for placeholder in placeholders(endpoint.path) {
                    assert!(!placeholder.is_empty(), "{}: {name}", definition.name);
                }
            }
        }
    }

    #[test]
    fn endpoint_names_are_unique_within_a_provider() {
        for definition in definitions() {
            let mut names: Vec<_> = definition.endpoints.iter().map(|(name, _)| *name).collect();
            names.sort_unstable();
            let count = names.len();
            names.dedup();
            assert_eq!(
                count,
                names.len(),
                "{}: duplicate endpoint",
                definition.name
            );
        }
    }

    #[test]
    fn token_auth_names_an_environment_variable_and_a_header() {
        for definition in definitions() {
            let Auth::Token {
                token_env, header, ..
            } = &definition.auth;
            assert!(!token_env.is_empty(), "{}", definition.name);
            assert!(!header.is_empty(), "{}", definition.name);
        }
    }
}
