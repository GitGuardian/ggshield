use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A provider definition, (de)serialized from `providers/<name>.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub base_url: String,
    pub auth: Auth,
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
}

/// How to authenticate against a provider. The `strategy` field selects the
/// variant; the remaining fields are that strategy's parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
pub enum Auth {
    /// Send a token in a header. The token is read from the `token_env`
    /// environment variable if set, otherwise from a token file whose path is
    /// `token_file_env`'s value (if set) or `token_file`.
    Token {
        token_env: String,
        #[serde(default)]
        token_file_env: Option<String>,
        #[serde(default)]
        token_file: Option<String>,
        #[serde(default = "default_token_header")]
        header: String,
        #[serde(default)]
        scheme: Option<String>,
    },
}

fn default_token_header() -> String {
    "Authorization".to_string()
}

/// The HTTP method used to call an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Delete,
    Get,
    Post,
    Put,
}

/// A single named API call used to fetch secrets from the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub method: Method,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    /// Dot-path to the secret in the JSON response. The value there is either a
    /// map of field -> value, or a scalar (exposed as the `value` field).
    /// Dots are always separators: keys that themselves contain a `.` cannot
    /// be addressed.
    #[serde(default)]
    pub secret: Option<String>,
}

impl ProviderDef {
    /// Parse a provider definition from YAML.
    pub fn from_yaml(src: &str) -> Result<Self> {
        serde_yaml_ng::from_str(src).context("parsing provider definition")
    }
}
