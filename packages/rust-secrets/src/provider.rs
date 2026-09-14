use serde::{Deserialize, Serialize};

use crate::definition::{Auth, ProviderDef};

/// A supported secret-manager backend.
///
/// Most variants are backed by a bundled provider definition
/// (`providers/<name>.yaml`); [`Provider::ALL`] lists every supported backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
// Keep the CLI names aligned with the serde names (clap defaults to
// kebab-case, which would diverge for multi-word providers).
#[cfg_attr(feature = "clap", clap(rename_all = "snake_case"))]
pub enum Provider {
    /// Dotenv files encrypted with a device-local key. Has no YAML
    /// definition: it makes no HTTP calls and has no base URL or token.
    File,
    Onepassword,
    Vault,
}

impl Provider {
    /// Every supported provider.
    pub const ALL: &'static [Provider] = &[Provider::File, Provider::Onepassword, Provider::Vault];

    /// The canonical lowercase name (matches the `name` in the YAML).
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::File => "file",
            Provider::Onepassword => "onepassword",
            Provider::Vault => "vault",
        }
    }

    /// The bundled YAML definition for this provider, if it has one.
    ///
    /// `None` for backends that are not HTTP APIs: a definition must declare a
    /// base URL and an auth strategy, neither of which a local file has.
    pub(crate) fn definition(self) -> Option<&'static str> {
        match self {
            Provider::File => None,
            Provider::Onepassword => Some(include_str!("../../../providers/onepassword.yaml")),
            Provider::Vault => Some(include_str!("../../../providers/vault.yaml")),
        }
    }
}

/// Environment variables that carry a provider's bootstrap credentials.
///
/// These are what `gitguardian` itself authenticates with, and `gitguardian run`
/// removes them from the child's environment: leaving `VAULT_TOKEN` there would
/// hand every child the key to the whole store.
///
/// # What this does not cover
///
/// Only the variables the definitions name (`token_env`, `token_file_env`).
/// Scrubbing them does **not** make the child unable to authenticate, because a
/// token can also sit in a file at a well-known path — `token_file`'s default,
/// `~/.vault-token`, which `vault login` writes and this crate's own auth falls
/// back to. A child that reads that file has the same access `gitguardian` does,
/// and no environment variable exists to remove to stop it.
///
/// So this is defence in depth, not a boundary: it stops a task runner from
/// picking a token out of its environment, and nothing more. Sandboxing the
/// child's filesystem is the only thing that would make it one, and that is not
/// something this crate does.
pub fn credential_env_vars() -> Vec<String> {
    let mut names = Vec::new();
    for provider in Provider::ALL {
        let Some(yaml) = provider.definition() else {
            continue;
        };
        // A definition that fails to parse is a build-time error (build.rs
        // validates every bundled file), so there is nothing to report here.
        let Ok(definition) = ProviderDef::from_yaml(yaml) else {
            continue;
        };
        let Auth::Token {
            token_env,
            token_file_env,
            ..
        } = definition.auth;
        names.push(token_env);
        names.extend(token_file_env);
    }
    names.sort();
    names.dedup();
    names
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn credential_env_vars_covers_every_http_provider() {
        let names = credential_env_vars();
        assert!(names.contains(&"VAULT_TOKEN".to_string()), "{names:?}");
        assert!(
            names.contains(&"VAULT_TOKEN_FILE_PATH".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"OP_CONNECT_TOKEN".to_string()), "{names:?}");
    }

    #[test]
    fn the_file_provider_has_no_definition_and_no_credentials() {
        assert!(Provider::File.definition().is_none());
        assert!(Provider::ALL.contains(&Provider::File));
    }
}
