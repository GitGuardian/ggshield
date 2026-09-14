use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

// Every provider that *has* a YAML definition. `file` is deliberately absent:
// it is a local backend with no base URL and no auth strategy, so there is
// nothing for a definition to describe and nothing here to validate.
const SUPPORTED_PROVIDERS: &[&str] = &["onepassword", "vault"];

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let providers_dir = manifest_dir.join("../../providers");

    println!("cargo:rerun-if-changed={}", providers_dir.display());

    let entries = fs::read_dir(&providers_dir).unwrap_or_else(|err| {
        panic!(
            "failed to read provider definitions from {}: {err}",
            providers_dir.display()
        )
    });

    let mut providers = Vec::new();
    for entry in entries {
        let path = entry.expect("reading the providers directory").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        println!("cargo:rerun-if-changed={}", path.display());
        providers.push(validate_provider(&path));
    }

    providers.sort();
    if providers != SUPPORTED_PROVIDERS {
        panic!(
            "provider YAML files must match supported providers {:?}; found {:?}",
            SUPPORTED_PROVIDERS, providers
        );
    }
}

fn validate_provider(path: &Path) -> String {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let provider: ProviderDef = serde_yaml_ng::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    validate_name("provider name", &provider.name);
    validate_name("provider description", &provider.description);
    validate_name("provider base_url", &provider.base_url);
    validate_placeholders("base_url", &provider.base_url);
    validate_auth(&provider.auth);

    let file_name = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("a *.yaml path has a UTF-8 stem");
    if provider.name != file_name {
        panic!(
            "{} declares provider name '{}' but filename is '{}.yaml'",
            path.display(),
            provider.name,
            file_name
        );
    }

    if !SUPPORTED_PROVIDERS.contains(&provider.name.as_str()) {
        panic!(
            "{} declares unsupported provider '{}'; update Provider and build.rs together",
            path.display(),
            provider.name
        );
    }

    let read_secret = provider
        .endpoints
        .get("read_secret")
        .unwrap_or_else(|| panic!("{} must define a read_secret endpoint", path.display()));

    if provider.endpoints.is_empty() {
        panic!("{} must define at least one endpoint", path.display());
    }

    for (name, endpoint) in &provider.endpoints {
        validate_name("endpoint name", name);
        validate_endpoint(name, endpoint);
    }

    if read_secret
        .secret
        .as_deref()
        .is_none_or(|secret| secret.trim().is_empty())
    {
        panic!(
            "{} read_secret endpoint must declare a secret path",
            path.display()
        );
    }

    provider.name
}

fn validate_auth(auth: &Auth) {
    match auth {
        Auth::Token {
            token_env,
            token_file_env,
            token_file,
            header,
            scheme,
        } => {
            validate_name("token_env", token_env);
            validate_name("auth header", header);
            if let Some(token_file_env) = token_file_env {
                validate_name("token_file_env", token_file_env);
            }
            if let Some(token_file) = token_file {
                validate_name("token_file", token_file);
            }
            if let Some(scheme) = scheme {
                validate_name("auth scheme", scheme);
            }
        }
    }
}

fn validate_endpoint(name: &str, endpoint: &Endpoint) {
    match endpoint.method {
        Method::Delete => {}
        Method::Get => {}
        Method::Post => {}
        Method::Put => {}
    }

    if !endpoint.path.starts_with('/') {
        panic!("endpoint '{name}' path must start with '/'");
    }
    validate_placeholders(&format!("endpoint '{name}' path"), &endpoint.path);
    if let Some(secret) = &endpoint.secret {
        validate_dot_path(&format!("endpoint '{name}' secret"), secret);
    }

    for (key, value) in &endpoint.query {
        validate_name(&format!("endpoint '{name}' query key"), key);
        validate_name(&format!("endpoint '{name}' query value"), value);
        validate_placeholders(&format!("endpoint '{name}' query '{key}'"), value);
    }
}

fn validate_name(kind: &str, value: &str) {
    if value.trim().is_empty() {
        panic!("{kind} must not be empty");
    }
}

fn validate_dot_path(kind: &str, value: &str) {
    validate_name(kind, value);
    if value.split('.').any(str::is_empty) {
        panic!("{kind} must not contain empty dot-path segments");
    }
}

fn validate_placeholders(kind: &str, value: &str) {
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .unwrap_or_else(|| panic!("{kind} contains an unterminated placeholder: {value}"));
        let name = &after[..end];
        validate_name(&format!("{kind} placeholder name"), name);
        rest = &after[end + 1..];
    }
    if rest.contains('}') {
        panic!("{kind} contains an unmatched closing brace: {value}");
    }
}

// Keep the serde attributes below aligned with src/definition.rs: a YAML
// file the runtime parser accepts must never fail to *parse* here. Stricter
// requirements (non-empty description, ...) belong in the validate_* checks
// above, where the panic message says what is actually wrong.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDef {
    name: String,
    #[serde(default)]
    description: String,
    base_url: String,
    auth: Auth,
    #[serde(default)]
    endpoints: BTreeMap<String, Endpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
enum Auth {
    Token {
        token_env: String,
        token_file_env: Option<String>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Method {
    Delete,
    Get,
    Post,
    Put,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    method: Method,
    path: String,
    #[serde(default)]
    query: BTreeMap<String, String>,
    secret: Option<String>,
}
