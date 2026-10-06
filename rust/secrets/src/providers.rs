//! Bundled provider definitions.
//!
//! `${NAME}` in a `base_url` comes from the environment; `${name}` in an
//! endpoint path is filled from the secret path (see `store::interpolate_path`).

use crate::definition::{Auth, Endpoint, Method, ProviderDef};

/// `secret/myapp/db` maps to mount `secret`, path `myapp/db`.
pub(crate) const VAULT: ProviderDef = ProviderDef {
    name: "vault",
    description: "HashiCorp Vault KV v2 secrets engine",
    base_url: "${VAULT_ADDR}",
    auth: Auth::Token {
        token_env: "VAULT_TOKEN",
        token_file_env: Some("VAULT_TOKEN_FILE_PATH"),
        token_file: Some("~/.vault-token"),
        header: "X-Vault-Token",
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
            "write_secret",
            Endpoint {
                method: Method::Post,
                path: "/v1/${mount}/data/${path}",
                query: &[],
                secret: None,
            },
        ),
        (
            // What `vault kv` asks to tell a KV v2 mount from a v1 one.
            "mount_info",
            Endpoint {
                method: Method::Get,
                path: "/v1/sys/internal/ui/mounts/${mount}/${path}",
                query: &[],
                secret: None,
            },
        ),
        (
            // Latest version only, mirroring `vault kv delete`.
            "delete_secret",
            Endpoint {
                method: Method::Delete,
                path: "/v1/${mount}/data/${path}",
                query: &[],
                secret: None,
            },
        ),
        (
            "delete_versions",
            Endpoint {
                method: Method::Post,
                path: "/v1/${mount}/delete/${path}",
                query: &[],
                secret: None,
            },
        ),
    ],
};

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::provider::Provider;

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
