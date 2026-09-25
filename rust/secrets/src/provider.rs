use serde::{Deserialize, Serialize};

use crate::definition::{Auth, ProviderDef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
// Match serde's names; clap's kebab-case default diverges for multi-word providers.
#[cfg_attr(feature = "clap", clap(rename_all = "snake_case"))]
pub enum Provider {
    /// Dotenv files encrypted with a device-local key.
    File,
    Vault,
}

impl Provider {
    pub const ALL: &'static [Provider] = &[Provider::File, Provider::Vault];

    pub fn as_str(self) -> &'static str {
        match self {
            Provider::File => "file",
            Provider::Vault => "vault",
        }
    }

    /// `None` for backends that are not HTTP APIs.
    pub(crate) fn definition(self) -> Option<&'static ProviderDef> {
        match self {
            Provider::File => None,
            Provider::Vault => Some(&crate::providers::VAULT),
        }
    }
}

/// Env vars carrying provider credentials, for `run` to scrub from the child.
///
/// Defence in depth only: a child can still read `~/.vault-token` directly.
pub fn credential_env_vars() -> Vec<String> {
    let mut names = Vec::new();
    for provider in Provider::ALL {
        let Some(definition) = provider.definition() else {
            continue;
        };
        let Auth::Token {
            token_env,
            token_file_env,
            ..
        } = definition.auth;
        names.push(token_env.to_string());
        names.extend(token_file_env.map(str::to_string));
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
// A failed unwrap in a test is the assertion failing.
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
    }

    #[test]
    fn the_file_provider_has_no_definition_and_no_credentials() {
        assert!(Provider::File.definition().is_none());
        assert!(Provider::ALL.contains(&Provider::File));
    }
}
