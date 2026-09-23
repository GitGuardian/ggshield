use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::auth::apply_auth;
use crate::definition::{Method, ProviderDef};
use crate::error::SecretError;
use crate::file::{DeleteOutcome, DeletePlan, EncryptOutcome, FileBackend, ReadWarnings};
use crate::json::{dot_path, secret_fields};
use crate::provider::Provider;

/// A client for one provider; the main SDK entry point.
#[derive(Debug, Clone)]
pub struct SecretStore {
    backend: Backend,
    env_override: bool,
}

#[derive(Debug, Clone)]
enum Backend {
    /// Boxed: this variant is an order of magnitude larger than `File`.
    Http(Box<Http>),
    File(FileBackend),
}

#[derive(Debug, Clone)]
struct Http {
    definition: &'static ProviderDef,
    agent: ureq::Agent,
}

impl SecretStore {
    pub fn builder(provider: Provider) -> SecretStoreBuilder {
        SecretStoreBuilder {
            provider,
            env_override: None,
            file_encrypt: true,
            project_path_is_default: false,
        }
    }

    /// Every field of the secret at `path`; an unreadable field is an error.
    ///
    /// Use [`get_secrets_with_warnings`](SecretStore::get_secrets_with_warnings)
    /// to get the readable fields plus a report of the rest.
    pub fn get_secrets(&self, path: &str) -> Result<BTreeMap<String, SecretString>> {
        let (fields, warnings) = self.get_secrets_with_warnings(path)?;
        ensure!(
            warnings.unreadable.is_empty(),
            "{path}: {} of its fields could not be read, so this is not every field of the \
             secret: {}",
            warnings.unreadable.len(),
            warnings.unreadable.join("; ")
        );
        Ok(fields)
    }

    /// A caller injecting the result into a child process must treat
    /// [`ReadWarnings::unreadable`] as fatal.
    pub fn get_secrets_with_warnings(
        &self,
        path: &str,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        let (mut fields, warnings) = match &self.backend {
            Backend::Http(http) => (http.get_secrets(path)?, ReadWarnings::default()),
            Backend::File(file) => file.get_secrets(path)?,
        };
        if self.env_override {
            for (key, value) in fields.iter_mut() {
                if let Some(env_value) = env_override_value(key) {
                    *value = env_value;
                }
            }
        }
        Ok((fields, warnings))
    }

    /// With env override on (the default), an env var named `field` wins
    /// without contacting the provider.
    pub fn get_secret(&self, path: &str, field: &str) -> Result<SecretString> {
        if self.env_override
            && let Some(value) = env_override_value(field)
        {
            return Ok(value);
        }
        // An unreadable entry elsewhere must not fail this field, and a
        // plaintext field must not need the keyring.
        if let Backend::File(file) = &self.backend {
            return file.get_secret(path, field);
        }
        let mut fields = self.get_secrets(path)?;
        fields.remove(field).ok_or_else(|| {
            SecretError::FieldNotFound {
                field: field.to_string(),
            }
            .into()
        })
    }

    /// For the file provider: the named file only, with no decryption.
    pub fn field_names(&self, path: &str) -> Result<Vec<String>> {
        match &self.backend {
            Backend::Http(http) => match http.get_secrets(path) {
                Ok(fields) => Ok(fields.into_keys().collect()),
                Err(error) if SecretError::is_secret_not_found(&error) => Ok(Vec::new()),
                Err(error) => Err(error),
            },
            Backend::File(file) => file.field_names(path),
        }
    }

    /// Every field one file sets, with no other scope merged in.
    pub fn get_secrets_from_file(
        &self,
        path: &str,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        match &self.backend {
            Backend::File(file) => file.get_secrets_from_file(path),
            Backend::Http(_) => self.get_secrets_with_warnings(path),
        }
    }

    /// The scope each `file`-provider field came from; empty for other providers.
    pub fn field_scopes(&self, path: &str) -> Result<BTreeMap<String, String>> {
        match &self.backend {
            Backend::File(file) => file.field_scopes(path),
            Backend::Http(_) => Ok(BTreeMap::new()),
        }
    }

    pub fn set_secrets(&self, path: &str, fields: &BTreeMap<String, SecretString>) -> Result<()> {
        self.set_secrets_with_warnings(path, fields, None).map(drop)
    }

    /// `expected_existing` is what the user confirmed overwriting; the `file`
    /// provider refuses the write if another name appeared since. HTTP ignores it.
    pub fn set_secrets_with_warnings(
        &self,
        path: &str,
        fields: &BTreeMap<String, SecretString>,
        expected_existing: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<Vec<String>> {
        ensure!(!fields.is_empty(), "cannot set a secret with no fields");
        match &self.backend {
            Backend::Http(http) => http.set_secrets(path, fields).map(|()| Vec::new()),
            Backend::File(file) => file.set_secrets(path, fields, expected_existing),
        }
    }

    /// `file` provider only. `dry_run` reports without writing, so a
    /// confirmation prompt comes from the same code as the write.
    pub fn encrypt_in_place(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
        dry_run: bool,
    ) -> Result<EncryptOutcome> {
        match &self.backend {
            Backend::File(file) => file.encrypt_in_place(path, only, dry_run),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.to_string(),
                operation: "encrypting values in place",
            }
            .into()),
        }
    }

    /// Delete a whole secret, or only `keys` when non-empty.
    ///
    /// A caller that confirms with the user first should use
    /// [`plan_delete`](Self::plan_delete) and [`delete_planned`](Self::delete_planned).
    pub fn delete_secrets(&self, path: &str, keys: &[String]) -> Result<DeleteOutcome> {
        match &self.backend {
            Backend::Http(http) => http.delete_secrets(path, keys).map(|()| DeleteOutcome {
                removed: keys.to_vec(),
                warnings: Vec::new(),
            }),
            Backend::File(file) => {
                let only = (!keys.is_empty()).then(|| keys.iter().cloned().collect());
                let plan = file.plan_delete(path, only.as_ref())?;
                file.delete_planned(path, &plan)
            }
        }
    }

    /// File provider only. `None` for `only` means every variable; nothing is written.
    pub fn plan_delete(&self, path: &str, only: Option<&BTreeSet<String>>) -> Result<DeletePlan> {
        match &self.backend {
            Backend::File(file) => file.plan_delete(path, only),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.to_string(),
                operation: "planning a delete",
            }
            .into()),
        }
    }

    /// File provider only. Refuses if the file changed since the plan was made.
    pub fn delete_planned(&self, path: &str, plan: &DeletePlan) -> Result<DeleteOutcome> {
        match &self.backend {
            Backend::File(file) => file.delete_planned(path, plan),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.to_string(),
                operation: "planning a delete",
            }
            .into()),
        }
    }
}

impl Http {
    fn get_secrets(&self, path: &str) -> Result<BTreeMap<String, SecretString>> {
        let params = self.read_params(path)?;
        self.fetch("read_secret", &params)
    }

    fn set_secrets(&self, path: &str, fields: &BTreeMap<String, SecretString>) -> Result<()> {
        match self.definition.name {
            "vault" => {
                let params = self.read_params(path)?;
                self.set_vault_secrets(&params, fields)
            }
            name => Err(SecretError::UnsupportedOperation {
                provider: name.to_string(),
                operation: "writing secrets",
            }
            .into()),
        }
    }

    fn delete_secrets(&self, path: &str, keys: &[String]) -> Result<()> {
        match self.definition.name {
            "vault" => {
                let params = self.read_params(path)?;
                self.delete_vault_secrets(&params, keys)
            }
            name => Err(SecretError::UnsupportedOperation {
                provider: name.to_string(),
                operation: "deleting secrets",
            }
            .into()),
        }
    }

    // TODO: drive this from the provider definition once a backend has
    // different path conventions.
    fn read_params(&self, path: &str) -> Result<BTreeMap<String, String>> {
        let (mount, secret_path) = path.split_once('/').with_context(|| {
            format!("path '{path}' must be '<mount>/<path>', e.g. secret/myapp")
        })?;
        Ok(BTreeMap::from([
            ("mount".to_string(), mount.to_string()),
            ("path".to_string(), secret_path.to_string()),
        ]))
    }

    fn fetch(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, SecretString>> {
        let body = self.fetch_value(endpoint_name, params)?;
        let secret_path = self
            .definition
            .endpoint(endpoint_name)
            .and_then(|endpoint| endpoint.secret)
            .with_context(|| format!("endpoint '{endpoint_name}' does not expose a secret"))?;
        let secret = dot_path(&body, secret_path)
            .with_context(|| format!("secret path '{secret_path}' not found in response"))?;
        Ok(secret_fields(secret))
    }

    fn fetch_value(&self, endpoint_name: &str, params: &BTreeMap<String, String>) -> Result<Value> {
        let request = self.request(endpoint_name, params)?;
        let mut response = self.send(endpoint_name, params, request, String::new())?;
        response
            .body_mut()
            .read_json()
            .context("parsing JSON response")
    }

    /// The version feeds Vault's check-and-set, so concurrent writes fail
    /// instead of being silently overwritten.
    fn read_vault_secret_version(
        &self,
        params: &BTreeMap<String, String>,
    ) -> Result<Option<(BTreeMap<String, SecretString>, u64)>> {
        let body = match self.fetch_value("read_secret", params) {
            Ok(body) => body,
            Err(error) if SecretError::is_secret_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let fields = dot_path(&body, "data.data")
            .map(secret_fields)
            .context("secret path 'data.data' not found in response")?;
        let version = dot_path(&body, "data.metadata.version")
            .and_then(Value::as_u64)
            .context("no 'data.metadata.version' in KV v2 read response")?;
        Ok(Some((fields, version)))
    }

    // A soft delete keeps `current_version` in metadata; only a never-written
    // secret takes CAS 0, which still fails if one is created concurrently.
    fn read_vault_current_version(&self, params: &BTreeMap<String, String>) -> Result<u64> {
        let body = match self.fetch_value("read_metadata", params) {
            Ok(body) => body,
            Err(error) if SecretError::is_secret_not_found(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        dot_path(&body, "data.current_version")
            .and_then(Value::as_u64)
            .context("no 'data.current_version' in KV v2 metadata response")
    }

    fn set_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        fields: &BTreeMap<String, SecretString>,
    ) -> Result<()> {
        let (mut merged, version) = match self.read_vault_secret_version(params)? {
            Some(current) => current,
            None => (BTreeMap::new(), self.read_vault_current_version(params)?),
        };
        for (key, value) in fields {
            merged.insert(key.clone(), value.clone());
        }
        self.write_vault_secrets(params, &merged, version)
    }

    fn delete_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        keys: &[String],
    ) -> Result<()> {
        if keys.is_empty() {
            return self.send_empty("delete_secret", params);
        }

        let Some((mut existing, version)) = self.read_vault_secret_version(params)? else {
            return Err(SecretError::missing_fields(keys).into());
        };
        let missing = keys
            .iter()
            .filter(|key| !existing.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(SecretError::missing_fields(&missing).into());
        }

        for key in keys {
            existing.remove(key);
        }
        if existing.is_empty() {
            self.send_empty("delete_secret", params)
        } else {
            self.write_vault_secrets(params, &existing, version)
        }
    }

    fn write_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        fields: &BTreeMap<String, SecretString>,
        cas_version: u64,
    ) -> Result<()> {
        let data = fields
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    Value::String(value.expose_secret().to_string()),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let body = serde_json::json!({ "data": data, "options": { "cas": cas_version } });
        self.send_json("write_secret", params, &body)
    }

    fn send_json(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
        body: &Value,
    ) -> Result<()> {
        let request = self
            .request(endpoint_name, params)?
            .header("Content-Type", "application/json");
        let body = serde_json::to_string(body).context("serialising request body")?;
        self.send(endpoint_name, params, request, body)?;
        Ok(())
    }

    fn send_empty(&self, endpoint_name: &str, params: &BTreeMap<String, String>) -> Result<()> {
        let request = self.request(endpoint_name, params)?;
        self.send(endpoint_name, params, request, String::new())?;
        Ok(())
    }

    fn request(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
    ) -> Result<ureq::http::request::Builder> {
        let endpoint = self.definition.endpoint(endpoint_name).with_context(|| {
            format!(
                "provider '{}' has no endpoint '{endpoint_name}'",
                self.definition.name
            )
        })?;

        let base = interpolate(self.definition.base_url, params)?;
        let path = interpolate_path(endpoint.path, params)?;
        let mut url = format!("{}{}", base.trim_end_matches('/'), path);
        if !endpoint.query.is_empty() {
            let mut pairs = Vec::with_capacity(endpoint.query.len());
            for (key, value) in endpoint.query {
                let value = interpolate(value, params)?;
                pairs.push(format!("{}={}", encode_query(key), encode_query(&value)));
            }
            url.push('?');
            url.push_str(&pairs.join("&"));
        }
        let method = match endpoint.method {
            Method::Delete => "DELETE",
            Method::Get => "GET",
            Method::Post => "POST",
        };
        let request = ureq::http::Request::builder().method(method).uri(&url);
        apply_auth(request, &self.definition.auth)
    }

    fn send(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
        request: ureq::http::request::Builder,
        body: String,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let request = request
            .body(body)
            .with_context(|| format!("building the request for endpoint '{endpoint_name}'"))?;
        let mut response = self
            .agent
            .run(request)
            .with_context(|| format!("calling endpoint '{endpoint_name}'"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        // Text, not JSON: proxies answer with HTML or empty bodies, and the
        // status must still map to a typed error.
        let body = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "<unreadable response body>".to_string());
        Err(self.http_error(status, &user_path(params), body, endpoint_name))
    }

    fn http_error(
        &self,
        status: ureq::http::StatusCode,
        user_path: &str,
        body: String,
        endpoint_name: &str,
    ) -> anyhow::Error {
        match status.as_u16() {
            401 => SecretError::AuthenticationFailed {
                provider: self.definition.name.to_string(),
            }
            .into(),
            403 => SecretError::PermissionDenied {
                provider: self.definition.name.to_string(),
            }
            .into(),
            404 => SecretError::SecretNotFound {
                path: user_path.to_string(),
            }
            .into(),
            _ => anyhow::anyhow!(
                "{} endpoint '{endpoint_name}' returned {status}: {}",
                self.definition.name,
                truncate(&body, 256)
            ),
        }
    }
}

pub struct SecretStoreBuilder {
    provider: Provider,
    /// `None` means unset: the `file` backend accepts the default but not an explicit `true`.
    env_override: Option<bool>,
    file_encrypt: bool,
    project_path_is_default: bool,
}

impl SecretStoreBuilder {
    /// Whether an env var named like a field overrides the provider (default: `true`).
    ///
    /// `env_override(true)` is rejected for the `file` provider.
    pub fn env_override(mut self, enabled: bool) -> Self {
        self.env_override = Some(enabled);
        self
    }

    /// For the `file` provider: whether written values are encrypted (default: `true`).
    pub fn file_encrypt(mut self, enabled: bool) -> Self {
        self.file_encrypt = enabled;
        self
    }

    /// For the `file` provider: the caller defaulted the project path rather than taking it from
    /// the user, so a directory there (a virtualenv named `.env`) reads as no project file
    /// instead of failing the read (default: `false`).
    pub fn project_path_is_default(mut self, defaulted: bool) -> Self {
        self.project_path_is_default = defaulted;
        self
    }

    /// Opens no connection; network calls happen on first read.
    pub fn build(self) -> Result<SecretStore> {
        let Some(definition) = self.provider.definition() else {
            ensure!(
                self.env_override != Some(true),
                "env_override(true) is not supported by the 'file' provider: it reads dotenv \
                 files, and an environment variable named like a field would shadow the value \
                 the file holds. Leave it at the default or pass env_override(false)"
            );
            return Ok(SecretStore {
                backend: Backend::File(FileBackend::new(
                    self.file_encrypt,
                    self.project_path_is_default,
                )),
                env_override: false,
            });
        };

        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            // A redirect would carry the auth header to wherever the server points.
            .max_redirects(0)
            // Otherwise 4xx/5xx become transport errors and 404 -> SecretNotFound never runs.
            .http_status_as_error(false)
            .build();
        let agent = ureq::Agent::new_with_config(config);

        Ok(SecretStore {
            backend: Backend::Http(Box::new(Http { definition, agent })),
            env_override: self.env_override.unwrap_or(true),
        })
    }
}

fn env_override_value(field: &str) -> Option<SecretString> {
    match std::env::var(field) {
        Ok(value) if !value.is_empty() => Some(SecretString::from(value)),
        _ => None,
    }
}

/// Resolves `${NAME}` from `params`, then the environment.
fn interpolate(template: &str, params: &BTreeMap<String, String>) -> Result<String> {
    interpolate_with(template, params, |_, value| value.to_string())
}

fn encode_query(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

/// Everything but RFC 3986 unreserved characters.
const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
const NESTED_PATH_ENCODE_SET: &percent_encoding::AsciiSet = &PATH_SEGMENT_ENCODE_SET.remove(b'/');

/// Only `${path}` keeps `/`, for nested Vault secret paths; every other value is one segment.
fn interpolate_path(template: &str, params: &BTreeMap<String, String>) -> Result<String> {
    interpolate_with(template, params, |key, value| {
        let encode_set = if key == "path" {
            NESTED_PATH_ENCODE_SET
        } else {
            PATH_SEGMENT_ENCODE_SET
        };
        percent_encoding::utf8_percent_encode(value, encode_set).to_string()
    })
}

fn interpolate_with(
    template: &str,
    params: &BTreeMap<String, String>,
    encode: impl Fn(&str, &str) -> String,
) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .with_context(|| format!("unterminated '${{' in template '{template}'"))?;
        let key = &after[..end];
        let value = match params.get(key) {
            Some(value) => value.clone(),
            None => std::env::var(key)
                .with_context(|| format!("no value for '${{{key}}}' (param or environment)"))?,
        };
        out.push_str(&encode(key, &value));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn truncate(value: &str, max: usize) -> String {
    match value.char_indices().nth(max) {
        Some((index, _)) => format!(
            "{}… ({} chars total)",
            &value[..index],
            value.chars().count()
        ),
        None => value.to_string(),
    }
}

fn user_path(params: &BTreeMap<String, String>) -> String {
    match (params.get("mount"), params.get("path")) {
        (Some(mount), Some(path)) => format!("{mount}/{path}"),
        _ => match (params.get("vault"), params.get("item")) {
            (Some(vault), Some(item)) => format!("{vault}/{item}"),
            _ => "<unknown>".to_string(),
        },
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::definition::{Auth, Method};

    #[test]
    fn env_override_true_is_refused_for_the_file_provider() {
        let error = SecretStore::builder(Provider::File)
            .env_override(true)
            .build()
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("env_override(true)"), "{message}");
        assert!(message.contains("file"), "{message}");
    }

    #[test]
    fn the_file_provider_builds_with_the_default_and_with_an_explicit_false() {
        assert!(SecretStore::builder(Provider::File).build().is_ok());
        assert!(
            SecretStore::builder(Provider::File)
                .env_override(false)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn a_remote_provider_still_defaults_to_env_override() {
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        assert!(store.env_override);
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    impl SecretStore {
        fn http(&self) -> &Http {
            match &self.backend {
                Backend::Http(http) => http,
                Backend::File(_) => panic!("expected an HTTP store"),
            }
        }
    }

    #[test]
    fn parses_the_vault_provider() {
        let provider = Provider::Vault.definition().unwrap();
        assert_eq!(provider.name, "vault");
        let Auth::Token {
            token_env, header, ..
        } = &provider.auth;
        assert_eq!(*token_env, "VAULT_TOKEN");
        assert_eq!(*header, "X-Vault-Token");
        let endpoint = provider
            .endpoint("read_secret")
            .expect("read_secret endpoint");
        assert_eq!(endpoint.method, Method::Get);
        assert_eq!(endpoint.secret, Some("data.data"));
        let write_endpoint = provider
            .endpoint("write_secret")
            .expect("write_secret endpoint");
        assert_eq!(write_endpoint.method, Method::Post);
        assert!(write_endpoint.secret.is_none());
        let delete_endpoint = provider
            .endpoint("delete_secret")
            .expect("delete_secret endpoint");
        assert_eq!(delete_endpoint.method, Method::Delete);
        assert!(delete_endpoint.secret.is_none());
    }

    #[test]
    fn builder_loads_the_provider_definition() {
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        assert_eq!(store.http().definition.name, "vault");
    }

    #[test]
    fn read_params_splits_mount_from_path() {
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        let params = store.http().read_params("secret/myapp/db").unwrap();
        assert_eq!(params.get("mount").map(String::as_str), Some("secret"));
        assert_eq!(params.get("path").map(String::as_str), Some("myapp/db"));
        assert!(store.http().read_params("nomount").is_err());
    }

    #[test]
    fn interpolates_params_then_env() {
        let out = interpolate(
            "/v1/${mount}/data/${path}",
            &params(&[("mount", "secret"), ("path", "a/b")]),
        )
        .unwrap();
        assert_eq!(out, "/v1/secret/data/a/b");
    }

    #[test]
    fn interpolate_path_encodes_values_but_keeps_segment_separators() {
        let out = interpolate_path(
            "/v1/${mount}/data/${path}",
            &params(&[("mount", "secret"), ("path", "app#prod x/y?z%0")]),
        )
        .unwrap();
        assert_eq!(out, "/v1/secret/data/app%23prod%20x/y%3Fz%250");
    }

    #[test]
    fn interpolate_path_leaves_template_literals_alone() {
        let out = interpolate_path("/v1/data?raw", &params(&[])).unwrap();
        assert_eq!(out, "/v1/data?raw");
    }

    #[test]
    fn get_secrets_refuses_a_partial_read_that_with_warnings_reports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        // Another tool's marker: unreadable without touching the keyring.
        std::fs::write(&path, "GOOD=readable\nBAD=encrypted:dotenvx-blob\n").unwrap();
        let path = path.to_str().unwrap();

        let store = SecretStore::builder(Provider::File)
            .env_override(false)
            .build()
            .unwrap();

        let error = store
            .get_secrets(path)
            .expect_err("a field that could not be read was dropped in silence");
        let message = format!("{error:#}");
        assert!(message.contains("BAD"), "{message}");
        assert!(message.contains("not every field"), "{message}");

        let (fields, warnings) = store.get_secrets_with_warnings(path).unwrap();
        assert_eq!(
            fields.get("GOOD").map(|value| value.expose_secret()),
            Some("readable")
        );
        assert!(
            warnings.unreadable.iter().any(|line| line.contains("BAD")),
            "{warnings:?}"
        );
    }

    #[test]
    fn interpolation_reports_missing_keys() {
        let error = interpolate("${definitely_unset_xyz}", &params(&[])).unwrap_err();
        assert!(error.to_string().contains("definitely_unset_xyz"));
    }

    #[test]
    fn env_override_value_requires_set_and_non_empty() {
        assert!(env_override_value("GG_TEST_UNSET_OVERRIDE").is_none());
        // SAFETY: uniquely-named vars, removed below; no other test reads them.
        unsafe { std::env::set_var("GG_TEST_EMPTY_OVERRIDE", "") };
        assert!(env_override_value("GG_TEST_EMPTY_OVERRIDE").is_none());
        unsafe { std::env::set_var("GG_TEST_SET_OVERRIDE", "from-env") };
        assert_eq!(
            env_override_value("GG_TEST_SET_OVERRIDE")
                .unwrap()
                .expose_secret(),
            "from-env"
        );
        unsafe { std::env::remove_var("GG_TEST_EMPTY_OVERRIDE") };
        unsafe { std::env::remove_var("GG_TEST_SET_OVERRIDE") };
    }

    #[test]
    fn get_secret_short_circuits_on_env_override_without_network() {
        // SAFETY: uniquely-named var, removed below; no other test reads it.
        unsafe { std::env::set_var("GG_TEST_SHORTCIRCUIT_FIELD", "local-value") };
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        let value = store
            .get_secret("secret/whatever", "GG_TEST_SHORTCIRCUIT_FIELD")
            .unwrap();
        assert_eq!(value.expose_secret(), "local-value");
        unsafe { std::env::remove_var("GG_TEST_SHORTCIRCUIT_FIELD") };

        // Dead local port, so the provider call fails fast and stays hermetic.
        // SAFETY: no other test reads VAULT_ADDR; restored below.
        let previous_addr = std::env::var("VAULT_ADDR").ok();
        unsafe { std::env::set_var("VAULT_ADDR", "http://127.0.0.1:9") };
        let store = SecretStore::builder(Provider::Vault)
            .env_override(false)
            .build()
            .unwrap();
        assert!(
            store
                .get_secret("secret/whatever", "GG_TEST_SHORTCIRCUIT_FIELD")
                .is_err()
        );
        match previous_addr {
            // SAFETY: see above.
            Some(addr) => unsafe { std::env::set_var("VAULT_ADDR", addr) },
            None => unsafe { std::env::remove_var("VAULT_ADDR") },
        }
    }

    static TEST_VAULT: ProviderDef = ProviderDef {
        auth: Auth::Token {
            token_env: "GG_TEST_CAS_VAULT_TOKEN",
            token_file_env: None,
            token_file: None,
            header: "X-Vault-Token",
        },
        ..crate::providers::VAULT
    };

    /// Answers one request per connection with each canned response and sends back each request.
    fn serve(responses: Vec<(u16, &'static str)>) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{BufRead, BufReader, Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();
                request.push_str(&String::from_utf8(request_body).unwrap());
                sender.send(request).unwrap();
                write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (addr, receiver)
    }

    #[test]
    fn set_after_a_soft_delete_uses_the_metadata_current_version_as_cas() {
        let (addr, server) = serve(vec![
            (404, r#"{"errors":[]}"#),
            (200, r#"{"data":{"current_version":3}}"#),
            (200, r#"{"data":{"version":4}}"#),
        ]);
        // SAFETY: uniquely-named var, removed below; no other test reads it.
        unsafe { std::env::set_var("GG_TEST_CAS_VAULT_TOKEN", "token") };
        let http = Http {
            definition: &TEST_VAULT,
            agent: ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    .http_status_as_error(false)
                    .build(),
            ),
        };
        let fields = BTreeMap::from([("KEY".to_string(), SecretString::from("value"))]);
        http.set_vault_secrets(
            &params(&[("VAULT_ADDR", &addr), ("mount", "secret"), ("path", "app")]),
            &fields,
        )
        .unwrap();
        unsafe { std::env::remove_var("GG_TEST_CAS_VAULT_TOKEN") };

        let received: Vec<_> = server.try_iter().collect();
        assert!(received[0].starts_with("GET /v1/secret/data/app "));
        assert!(received[1].starts_with("GET /v1/secret/metadata/app "));
        assert!(received[2].starts_with("POST /v1/secret/data/app "));
        assert!(received[2].contains(r#""cas":3"#), "{}", received[2]);
    }

    #[test]
    fn truncate_caps_long_strings_on_char_boundaries() {
        assert_eq!(truncate("short", 256), "short");
        let long = "é".repeat(300);
        let cut = truncate(&long, 256);
        assert!(cut.starts_with(&"é".repeat(256)));
        assert!(cut.contains("300 chars total"));
    }

    #[test]
    fn missing_fields_error_is_pluralized_and_deduplicated() {
        assert_eq!(
            SecretError::missing_fields(&["VAR".to_string()]).to_string(),
            "field not found in secret: VAR"
        );
        assert_eq!(
            SecretError::missing_fields(&[
                "VAR".to_string(),
                "STRIPE".to_string(),
                "VAR".to_string()
            ])
            .to_string(),
            "fields not found in secret: VAR, STRIPE"
        );
    }
}
