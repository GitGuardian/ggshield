use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
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

/// Raw, so a write keeps the JSON type of every field it does not touch.
type VaultFields = serde_json::Map<String, Value>;

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
    /// instead of being silently overwritten. With no live version the fields
    /// are `None`: a soft-deleted secret's 404 still names its version, and a
    /// never-written one takes CAS 0.
    fn read_vault_secret(
        &self,
        params: &BTreeMap<String, String>,
    ) -> Result<(Option<VaultFields>, u64)> {
        let request = self.request("read_secret", params)?;
        let mut response = self.run("read_secret", request, String::new())?;
        if response.status() == ureq::http::StatusCode::NOT_FOUND {
            let version = response
                .body_mut()
                .read_json::<Value>()
                .ok()
                .and_then(|body| dot_path(&body, "data.metadata.version")?.as_u64())
                .unwrap_or(0);
            return Ok((None, version));
        }
        if !response.status().is_success() {
            return Err(self.error_response("read_secret", params, response));
        }
        let body: Value = response
            .body_mut()
            .read_json()
            .context("parsing JSON response")?;
        let version = dot_path(&body, "data.metadata.version")
            .and_then(Value::as_u64)
            .with_context(|| {
                format!(
                    "the read of {} has no 'data.metadata.version', so '{}' is not a KV v2 \
                     mount; only KV v2 is supported",
                    user_path(params),
                    params.get("mount").map_or("", String::as_str)
                )
            })?;
        let fields = dot_path(&body, "data.data")
            .and_then(Value::as_object)
            .cloned()
            .context("no 'data.data' object in KV v2 read response")?;
        Ok((Some(fields), version))
    }

    /// On a KV v1 mount the `data/` paths are ordinary secret names, so a write
    /// would land beside the secret instead of failing.
    fn ensure_vault_kv_v2(&self, params: &BTreeMap<String, String>) -> Result<()> {
        let body = match self.fetch_value("mount_info", params) {
            Ok(body) => body,
            // Older Vaults lack the endpoint and some policies deny it; the
            // read's metadata check still catches an existing v1 secret.
            Err(error) if is_denied_or_missing(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let mount = dot_path(&body, "data.path")
            .and_then(Value::as_str)
            .or_else(|| params.get("mount").map(String::as_str))
            .unwrap_or_default()
            .trim_end_matches('/');
        let engine = dot_path(&body, "data.type").and_then(Value::as_str);
        let version = dot_path(&body, "data.options.version").and_then(Value::as_str);
        match (engine, version) {
            (Some("kv"), Some("2")) | (None, _) => Ok(()),
            (Some("kv" | "generic"), _) => bail!(
                "the Vault mount '{mount}' is KV version 1; only KV v2 is supported \
                 (`vault kv enable-versioning {mount}` upgrades it)"
            ),
            (Some(engine), _) => {
                bail!("the Vault mount '{mount}' is a '{engine}' secrets engine, not KV v2")
            }
        }
    }

    fn set_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        fields: &BTreeMap<String, SecretString>,
    ) -> Result<()> {
        self.ensure_vault_kv_v2(params)?;
        let (current, version) = self.read_vault_secret(params)?;
        let mut merged = current.unwrap_or_default();
        for (key, value) in fields {
            merged.insert(
                key.clone(),
                Value::String(value.expose_secret().to_string()),
            );
        }
        self.write_vault_secrets(params, merged, version)
    }

    fn delete_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        keys: &[String],
    ) -> Result<()> {
        self.ensure_vault_kv_v2(params)?;
        if keys.is_empty() {
            return self.send_empty("delete_secret", params);
        }

        let (Some(mut existing), version) = self.read_vault_secret(params)? else {
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
            // The version read, not the latest: a write since then must survive.
            let body = serde_json::json!({ "versions": [version] });
            self.send_json("delete_versions", params, &body)
        } else {
            self.write_vault_secrets(params, existing, version)
        }
    }

    fn write_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        fields: VaultFields,
        cas_version: u64,
    ) -> Result<()> {
        let body = serde_json::json!({ "data": fields, "options": { "cas": cas_version } });
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
        let response = self.run(endpoint_name, request, body)?;
        if response.status().is_success() {
            return Ok(response);
        }
        Err(self.error_response(endpoint_name, params, response))
    }

    fn run(
        &self,
        endpoint_name: &str,
        request: ureq::http::request::Builder,
        body: String,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let request = request
            .body(body)
            .with_context(|| format!("building the request for endpoint '{endpoint_name}'"))?;
        self.agent
            .run(request)
            .with_context(|| format!("calling endpoint '{endpoint_name}'"))
    }

    fn error_response(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
        mut response: ureq::http::Response<ureq::Body>,
    ) -> anyhow::Error {
        // Text, not JSON: proxies answer with HTML or empty bodies, and the
        // status must still map to a typed error.
        let body = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "<unreadable response body>".to_string());
        self.http_error(response.status(), &user_path(params), body, endpoint_name)
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

fn is_denied_or_missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<SecretError>(),
            Some(SecretError::PermissionDenied { .. } | SecretError::SecretNotFound { .. })
        )
    })
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

    fn test_http() -> Http {
        // SAFETY: uniquely-named var, only ever set to this value; no other test reads it.
        unsafe { std::env::set_var("GG_TEST_CAS_VAULT_TOKEN", "token") };
        Http {
            definition: &TEST_VAULT,
            agent: ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    .http_status_as_error(false)
                    .build(),
            ),
        }
    }

    fn secret_params(addr: &str) -> BTreeMap<String, String> {
        params(&[("VAULT_ADDR", addr), ("mount", "secret"), ("path", "app")])
    }

    fn one_field(key: &str, value: &str) -> BTreeMap<String, SecretString> {
        BTreeMap::from([(key.to_string(), SecretString::from(value))])
    }

    /// `serve` records headers then body, and no header holds a `{`.
    fn request_body(request: &str) -> Value {
        serde_json::from_str(&request[request.find('{').unwrap()..]).unwrap()
    }

    const KV_V2_MOUNT: &str =
        r#"{"data":{"path":"secret/","type":"kv","options":{"version":"2"}}}"#;

    fn serve_kv2(
        mut responses: Vec<(u16, &'static str)>,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        responses.insert(0, (200, KV_V2_MOUNT));
        serve(responses)
    }

    /// The requests after the mount preflight `serve_kv2` answers.
    fn after_preflight(server: &std::sync::mpsc::Receiver<String>) -> Vec<String> {
        let mut received: Vec<_> = server.try_iter().collect();
        assert!(
            received[0].starts_with("GET /v1/sys/internal/ui/mounts/secret/app "),
            "{}",
            received[0]
        );
        received.remove(0);
        received
    }

    #[test]
    fn a_write_to_a_kv_v1_mount_is_refused_before_touching_it() {
        for mount in [
            r#"{"data":{"path":"secret/","type":"kv","options":null}}"#,
            r#"{"data":{"path":"secret/","type":"kv","options":{"version":"1"}}}"#,
        ] {
            let (addr, server) = serve(vec![(200, mount)]);
            let error = test_http()
                .set_vault_secrets(&secret_params(&addr), &one_field("KEY", "value"))
                .unwrap_err();
            assert!(format!("{error:#}").contains("KV version 1"), "{error:#}");
            assert_eq!(server.try_iter().count(), 1);
        }

        let (addr, server) = serve(vec![(
            200,
            r#"{"data":{"path":"secret/","type":"transit","options":null}}"#,
        )]);
        let error = test_http()
            .delete_vault_secrets(&secret_params(&addr), &[])
            .unwrap_err();
        assert!(format!("{error:#}").contains("'transit'"), "{error:#}");
        assert_eq!(server.try_iter().count(), 1);
    }

    #[test]
    fn a_denied_mount_preflight_falls_back_to_the_read_metadata_check() {
        let (addr, server) = serve(vec![
            (403, r#"{"errors":["permission denied"]}"#),
            (200, r#"{"data":{"KEY":"v1-shaped"}}"#),
        ]);
        let error = test_http()
            .set_vault_secrets(&secret_params(&addr), &one_field("KEY", "value"))
            .unwrap_err();
        assert!(format!("{error:#}").contains("not a KV v2"), "{error:#}");
        assert_eq!(server.try_iter().count(), 2, "nothing was written");
    }

    #[test]
    fn set_keeps_the_json_type_of_the_fields_it_does_not_touch() {
        let (addr, server) = serve_kv2(vec![
            (
                200,
                r#"{"data":{"data":{"port":5432,"tls":true,"opts":{"a":1}},"metadata":{"version":2}}}"#,
            ),
            (200, r#"{"data":{"version":3}}"#),
        ]);
        test_http()
            .set_vault_secrets(&secret_params(&addr), &one_field("NEW", "x"))
            .unwrap();

        let received = after_preflight(&server);
        let body = request_body(&received[1]);
        assert_eq!(
            body["data"],
            serde_json::json!({"port": 5432, "tls": true, "opts": {"a": 1}, "NEW": "x"})
        );
        assert_eq!(body["options"]["cas"], 2);
    }

    #[test]
    fn set_after_a_soft_delete_takes_the_cas_version_from_the_404_body() {
        let (addr, server) = serve_kv2(vec![
            (
                404,
                r#"{"data":{"data":null,"metadata":{"version":3,"deletion_time":"2026-01-01T00:00:00Z"}}}"#,
            ),
            (200, r#"{"data":{"version":4}}"#),
        ]);
        test_http()
            .set_vault_secrets(&secret_params(&addr), &one_field("KEY", "value"))
            .unwrap();

        let received = after_preflight(&server);
        assert_eq!(received.len(), 2, "no metadata read: {received:?}");
        assert!(received[0].starts_with("GET /v1/secret/data/app "));
        assert!(received[1].starts_with("POST /v1/secret/data/app "));
        let body = request_body(&received[1]);
        assert_eq!(body["data"], serde_json::json!({"KEY": "value"}));
        assert_eq!(body["options"]["cas"], 3);
    }

    #[test]
    fn set_of_a_never_written_secret_uses_cas_zero() {
        let (addr, server) = serve_kv2(vec![
            (404, r#"{"errors":[]}"#),
            (200, r#"{"data":{"version":1}}"#),
        ]);
        test_http()
            .set_vault_secrets(&secret_params(&addr), &one_field("KEY", "value"))
            .unwrap();

        let received = after_preflight(&server);
        assert_eq!(received.len(), 2, "{received:?}");
        assert_eq!(request_body(&received[1])["options"]["cas"], 0);
    }

    #[test]
    fn unsetting_the_last_field_soft_deletes_only_the_version_read() {
        let (addr, server) = serve_kv2(vec![
            (
                200,
                r#"{"data":{"data":{"ONLY":"x"},"metadata":{"version":5}}}"#,
            ),
            (204, ""),
        ]);
        test_http()
            .delete_vault_secrets(&secret_params(&addr), &["ONLY".to_string()])
            .unwrap();

        let received = after_preflight(&server);
        assert!(
            received[1].starts_with("POST /v1/secret/delete/app "),
            "{}",
            received[1]
        );
        assert_eq!(
            request_body(&received[1]),
            serde_json::json!({"versions": [5]})
        );
    }

    #[test]
    fn unsetting_some_fields_rewrites_the_rest_with_cas() {
        let (addr, server) = serve_kv2(vec![
            (
                200,
                r#"{"data":{"data":{"A":"x","B":7},"metadata":{"version":5}}}"#,
            ),
            (200, r#"{"data":{"version":6}}"#),
        ]);
        test_http()
            .delete_vault_secrets(&secret_params(&addr), &["A".to_string()])
            .unwrap();

        let received = after_preflight(&server);
        assert!(received[1].starts_with("POST /v1/secret/data/app "));
        let body = request_body(&received[1]);
        assert_eq!(body["data"], serde_json::json!({"B": 7}));
        assert_eq!(body["options"]["cas"], 5);
    }

    #[test]
    fn a_denied_read_fails_the_set_instead_of_writing() {
        let (addr, server) = serve_kv2(vec![(403, r#"{"errors":["permission denied"]}"#)]);
        let error = test_http()
            .set_vault_secrets(&secret_params(&addr), &one_field("KEY", "value"))
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SecretError>(),
                Some(SecretError::PermissionDenied { .. })
            ),
            "{error:#}"
        );
        assert_eq!(after_preflight(&server).len(), 1);
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
