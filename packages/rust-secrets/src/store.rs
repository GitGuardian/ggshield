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

mod onepassword;

/// A live client for one provider — the main SDK entry point.
///
/// Construct it with [`SecretStore::builder`], then read secrets with
/// [`get_secret`](SecretStore::get_secret) / [`get_secrets`](SecretStore::get_secrets).
#[derive(Debug, Clone)]
pub struct SecretStore {
    backend: Backend,
    env_override: bool,
}

/// How a provider is actually reached.
///
/// Two consumers, one crate: an enum rather than a public async trait, so the
/// dispatch stays visible in one place instead of behind a vtable.
#[derive(Debug, Clone)]
enum Backend {
    /// A remote HTTP API described by a provider definition.
    ///
    /// Boxed: the ureq agent and the parsed definition make this variant an
    /// order of magnitude larger than the file one, and every `SecretStore`
    /// would carry that footprint.
    Http(Box<Http>),
    /// Local dotenv files, encrypted with a device-local key.
    File(FileBackend),
}

/// An HTTP provider: its definition and the client that calls it.
#[derive(Debug, Clone)]
struct Http {
    definition: ProviderDef,
    agent: ureq::Agent,
}

impl SecretStore {
    /// Start building a store for the given [`Provider`].
    pub fn builder(provider: Provider) -> SecretStoreBuilder {
        SecretStoreBuilder {
            provider,
            env_override: None,
            file_encrypt: true,
        }
    }

    /// Fetch every field of the secret at `path`.
    ///
    /// With env override enabled (the default), an environment variable named
    /// like a field replaces that field's value. The field *names* still come
    /// from the provider, so this call always fetches.
    ///
    /// # Why a field that cannot be read is an error here
    ///
    /// This call promises *every* field, and it has no channel to say otherwise:
    /// a caller handed `Ok({GOOD})` for a file that also names `BAD` cannot tell
    /// an unreadable `BAD` from a field nobody ever set. Silently returning the
    /// readable half is how `run` came to inject a partial environment, and how
    /// the shell hook came to make a secret vanish — the same defect twice,
    /// because the convenient API let it be ignored. A caller that genuinely
    /// wants the readable half asks for it by name, with
    /// [`get_secrets_with_warnings`](SecretStore::get_secrets_with_warnings),
    /// and then has [`ReadWarnings::unreadable`] in its hands to report.
    ///
    /// File advisories ([`ReadWarnings::advisories`]) are *not* fatal: they are
    /// heuristics that lose no field of their own, and are dropped here.
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

    /// Fetch every field of the secret at `path`, with a report of what could
    /// not be read.
    ///
    /// Only the `file` provider produces warnings today: a dotenv file can hold
    /// an entry encrypted on another machine, or one another tool wrote, and
    /// failing the whole read over it would take every unrelated value in the
    /// file down too. The warnings name the field and the reason, never a value,
    /// and are meant to be shown to the user — a field that is missing because
    /// it could not be read must never look like a field that was never set.
    ///
    /// Warnings, not errors, are returned so this crate does no I/O of its own;
    /// the caller decides where they go. A caller that *injects* the result into
    /// a child process must treat [`ReadWarnings::unreadable`] as fatal; see its
    /// documentation.
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

    /// Fetch a single `field` of the secret at `path`.
    ///
    /// With env override enabled (the default), an environment variable named
    /// `field` short-circuits the lookup entirely — no provider access, no
    /// network. This lets the same code run on a developer machine (fetching
    /// from the provider) and on a server where the platform already exposes
    /// the secret as an environment variable.
    pub fn get_secret(&self, path: &str, field: &str) -> Result<SecretString> {
        if self.env_override
            && let Some(value) = env_override_value(field)
        {
            return Ok(value);
        }
        // The file backend resolves one field without touching the others: an
        // unreadable entry elsewhere in the file is not this field's problem,
        // and a plaintext field must not need the keyring.
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

    /// The names of the fields the secret at `path` already has.
    ///
    /// Used to warn before an overwrite. For the file provider this reads only
    /// the named file — no other scope, no decryption, no keyring access.
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

    /// Which scope each field of a `file`-provider secret came from, keyed by
    /// field name ("user", "repo" or "project").
    ///
    /// Empty for every other provider: a remote secret is one document, so
    /// there is no merge to explain.
    pub fn field_scopes(&self, path: &str) -> Result<BTreeMap<String, String>> {
        match &self.backend {
            Backend::File(file) => file.field_scopes(path),
            Backend::Http(_) => Ok(BTreeMap::new()),
        }
    }

    /// Create or update fields in the secret at `path`.
    pub fn set_secrets(&self, path: &str, fields: &BTreeMap<String, SecretString>) -> Result<()> {
        self.set_secrets_with_warnings(path, fields, None).map(drop)
    }

    /// [`set_secrets`](Self::set_secrets), with any warning the write raised.
    ///
    /// The `file` provider can notice that the document it just wrote to was
    /// already misparsed — a stray quote elsewhere in the file — which is worth
    /// telling the user without failing a write that is itself fine.
    ///
    /// `expected_existing` is the set of field names the caller has already told
    /// the user would be overwritten, or `None` when it asked nothing. The
    /// `file` provider re-checks it under the write lock and refuses the write
    /// if some other name being set has appeared meanwhile, so a confirmation
    /// cannot be applied to a file that changed after it was given. The HTTP
    /// providers have no such check yet: their writes are per-field, so there is
    /// no locked window to re-check it in.
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

    /// Encrypt the plaintext values of the dotenv file at `path`, in place.
    ///
    /// Only the `file` provider has values sitting in a file to encrypt; for
    /// anything else the provider already holds the secret and there is nothing
    /// local to convert.
    ///
    /// Comments, ordering and quoting survive, values that are already encrypted
    /// are left byte-for-byte alone, and the whole pass is one locked
    /// read-modify-write.
    /// With `dry_run`, reports what would change and writes nothing — so a
    /// confirmation prompt is built by the same code that does the work, and the
    /// two cannot drift apart.
    pub fn encrypt_in_place(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
        dry_run: bool,
    ) -> Result<EncryptOutcome> {
        match &self.backend {
            Backend::File(file) => file.encrypt_in_place(path, only, dry_run),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.clone(),
                operation: "encrypting values in place",
            }
            .into()),
        }
    }

    /// Delete a whole secret, or selected fields when `keys` is non-empty.
    ///
    /// The file provider is the exception to the empty-`keys` case: it removes
    /// named variables from a dotenv file, preserving comments and ordering,
    /// and refuses an empty `keys` rather than reading it as "empty the file".
    /// It plans and writes in one call here, which is right for a caller with
    /// no confirmation step; a caller that asks the user first wants
    /// [`plan_delete`](Self::plan_delete) and
    /// [`delete_planned`](Self::delete_planned) instead, so the write can
    /// refuse a file that changed while the question was on screen.
    ///
    /// Returns the outcome rather than `()` so the file provider's warnings —
    /// a name that was assigned more than once, a comment that was kept — reach
    /// the caller. Discarding them silently would hide the fact that more lines
    /// than requested were touched.
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

    /// What a delete would remove from a dotenv file, and the state of the file
    /// it was decided against. File provider only.
    ///
    /// `only` names the variables to remove; `None` means every variable the
    /// file sets. Nothing is written, and everything that should stop a delete
    /// is reported here — before the caller puts a question to the user.
    pub fn plan_delete(&self, path: &str, only: Option<&BTreeSet<String>>) -> Result<DeletePlan> {
        match &self.backend {
            Backend::File(file) => file.plan_delete(path, only),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.clone(),
                operation: "planning a delete",
            }
            .into()),
        }
    }

    /// Carry out a [`DeletePlan`]. File provider only.
    ///
    /// Refuses if the file changed since the plan was made, so an answer the
    /// user gave about one file is never applied to another.
    pub fn delete_planned(&self, path: &str, plan: &DeletePlan) -> Result<DeleteOutcome> {
        match &self.backend {
            Backend::File(file) => file.delete_planned(path, plan),
            Backend::Http(http) => Err(SecretError::UnsupportedOperation {
                provider: http.definition.name.clone(),
                operation: "planning a delete",
            }
            .into()),
        }
    }
}

impl Http {
    fn get_secrets(&self, path: &str) -> Result<BTreeMap<String, SecretString>> {
        match self.definition.name.as_str() {
            "onepassword" => self.get_onepassword_secrets(path),
            _ => {
                let params = self.read_params(path)?;
                self.fetch("read_secret", &params)
            }
        }
    }

    fn set_secrets(&self, path: &str, fields: &BTreeMap<String, SecretString>) -> Result<()> {
        match self.definition.name.as_str() {
            "onepassword" => self.set_onepassword_secrets(path, fields),
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
        match self.definition.name.as_str() {
            "onepassword" => self.delete_onepassword_secrets(path, keys),
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

    /// Map a user-facing secret path to the read endpoint's parameters.
    ///
    /// Vault paths are `<mount>/<secret path>`, mirroring `vault kv get`.
    // TODO: drive this from the provider definition once we add backends with
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

    /// Call `endpoint_name` with the given call-time `params` and return the
    /// secret fields it exposes.
    ///
    /// `${NAME}` placeholders in the base URL, path and query are resolved
    /// against `params` first, then the process environment — so `${path}`
    /// comes from the caller while `${VAULT_ADDR}` comes from the environment.
    fn fetch(
        &self,
        endpoint_name: &str,
        params: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, SecretString>> {
        let body = self.fetch_value(endpoint_name, params)?;
        let secret_path = self
            .definition
            .endpoints
            .get(endpoint_name)
            .and_then(|endpoint| endpoint.secret.as_deref())
            .with_context(|| format!("endpoint '{endpoint_name}' does not expose a secret"))?;
        let secret = dot_path(&body, secret_path)
            .with_context(|| format!("secret path '{secret_path}' not found in response"))?;
        Ok(secret_fields(secret))
    }

    /// Call `endpoint_name` and return the status-checked JSON response body.
    fn fetch_value(&self, endpoint_name: &str, params: &BTreeMap<String, String>) -> Result<Value> {
        let request = self.request(endpoint_name, params)?;
        let mut response = self.send(endpoint_name, params, request, String::new())?;
        response
            .body_mut()
            .read_json()
            .context("parsing JSON response")
    }

    /// Fields and KV v2 version of the secret at `params`, or `None` when the
    /// secret does not exist. The version feeds Vault's check-and-set option
    /// so read-modify-write callers fail on concurrent writes instead of
    /// silently overwriting them.
    fn read_vault_secret_version(
        &self,
        params: &BTreeMap<String, String>,
    ) -> Result<Option<(BTreeMap<String, SecretString>, u64)>> {
        let body = match self.fetch_value("read_secret", params) {
            Ok(body) => body,
            Err(error) if SecretError::is_secret_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        // KV v2 response layout; this helper is only reached for vault.
        let fields = dot_path(&body, "data.data")
            .map(secret_fields)
            .context("secret path 'data.data' not found in response")?;
        let version = dot_path(&body, "data.metadata.version")
            .and_then(Value::as_u64)
            .context("no 'data.metadata.version' in KV v2 read response")?;
        Ok(Some((fields, version)))
    }

    fn set_vault_secrets(
        &self,
        params: &BTreeMap<String, String>,
        fields: &BTreeMap<String, SecretString>,
    ) -> Result<()> {
        // Version 0 means "create only if still absent", so a secret created
        // between our read and write fails the CAS check too.
        let (mut merged, version) = self.read_vault_secret_version(params)?.unwrap_or_default();
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
        // check-and-set: reject the write if the secret is no longer at the
        // version our merge was based on, instead of dropping the fields a
        // concurrent writer just added.
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
        let endpoint = self
            .definition
            .endpoints
            .get(endpoint_name)
            .with_context(|| {
                format!(
                    "provider '{}' has no endpoint '{endpoint_name}'",
                    self.definition.name
                )
            })?;

        let base = interpolate(&self.definition.base_url, params)?;
        let path = interpolate_path(&endpoint.path, params)?;
        let mut url = format!("{}{}", base.trim_end_matches('/'), path);
        if !endpoint.query.is_empty() {
            let mut pairs = Vec::with_capacity(endpoint.query.len());
            for (key, value) in &endpoint.query {
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
            Method::Put => "PUT",
        };
        let request = ureq::http::Request::builder().method(method).uri(&url);
        apply_auth(request, &self.definition.auth)
    }

    /// Send the request, mapping non-success statuses to typed errors.
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
        // Read the error body as text, not JSON: proxies in front of the
        // provider answer with HTML or empty bodies, and the status must
        // still map to a typed error (404 -> SecretNotFound). http_error
        // truncates it: enough to diagnose (Vault puts the cause in an
        // `errors` array) without echoing arbitrarily large — or
        // request-reflecting — upstream responses into our error chain.
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
                provider: self.definition.name.clone(),
            }
            .into(),
            403 => SecretError::PermissionDenied {
                provider: self.definition.name.clone(),
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

/// Builder for [`SecretStore`]. Optional configuration (namespace, address or
/// token overrides, ...) will be added here as chained methods.
pub struct SecretStoreBuilder {
    provider: Provider,
    /// `None` until a caller says: the default and an explicit choice have to be
    /// told apart, because the `file` backend can honour only one of them.
    env_override: Option<bool>,
    file_encrypt: bool,
}

impl SecretStoreBuilder {
    /// Whether an environment variable named like a secret field overrides the
    /// provider's value (default: `true`).
    ///
    /// Disable to always read from the provider, e.g. when a poisoned
    /// environment must not be able to substitute secrets.
    ///
    /// Not supported by the `file` provider, which always reads the file: with
    /// the override on, `get` would echo the ambient environment back instead
    /// of what the file holds. Leaving it at the default is fine there;
    /// `env_override(true)` is rejected by [`build`](Self::build) rather than
    /// silently doing the opposite of what was asked.
    pub fn env_override(mut self, enabled: bool) -> Self {
        self.env_override = Some(enabled);
        self
    }

    /// For the `file` provider: whether written values are encrypted
    /// (default: `true`). Disable to store readable plaintext.
    pub fn file_encrypt(mut self, enabled: bool) -> Self {
        self.file_encrypt = enabled;
        self
    }

    /// Build the store: load the provider definition and a lazy HTTP client.
    ///
    /// This is synchronous and opens no connection — like `connect_lazy_with`,
    /// the network round-trips happen later in `get_secret`/`get_secrets`.
    pub fn build(self) -> Result<SecretStore> {
        let Some(yaml) = self.provider.definition() else {
            // An explicit opt-in cannot be honoured here, and quietly doing the
            // opposite is worse than refusing: a caller who asked for the
            // environment to win would get provider values and never know.
            ensure!(
                self.env_override != Some(true),
                "env_override(true) is not supported by the 'file' provider: it reads dotenv \
                 files, and an environment variable named like a field would shadow the value \
                 the file holds. Leave it at the default or pass env_override(false)"
            );
            return Ok(SecretStore {
                backend: Backend::File(FileBackend::new(self.file_encrypt)),
                env_override: false,
            });
        };
        let definition = ProviderDef::from_yaml(yaml)?;

        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            // Never follow redirects: a redirect would carry a custom auth
            // header like X-Vault-Token to wherever a compromised server
            // points us. Secret managers don't redirect in normal operation;
            // fail loudly if one does.
            .max_redirects(0)
            // Without this ureq turns every 4xx/5xx into a transport error,
            // and the status mapping below (404 -> SecretNotFound) would
            // never run.
            .http_status_as_error(false)
            .build();
        let agent = ureq::Agent::new_with_config(config);

        Ok(SecretStore {
            backend: Backend::Http(Box::new(Http { definition, agent })),
            // Overriding from the environment is the documented default for a
            // remote provider.
            env_override: self.env_override.unwrap_or(true),
        })
    }
}

/// The value of the environment variable named `field`, if set and non-empty.
fn env_override_value(field: &str) -> Option<SecretString> {
    match std::env::var(field) {
        Ok(value) if !value.is_empty() => Some(SecretString::from(value)),
        _ => None,
    }
}

/// Substitute `${NAME}` placeholders, resolving each from `params` then env.
fn interpolate(template: &str, params: &BTreeMap<String, String>) -> Result<String> {
    interpolate_with(template, params, |_, value| value.to_string())
}

/// Percent-encode a query-string key or value.
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

/// [`interpolate`] for URL path templates: substituted values are
/// percent-encoded (template literals are trusted and left as-is). Only
/// Vault's `${path}` preserves `/` for nested secret paths; every other
/// placeholder is one path segment.
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

/// Truncate to at most `max` characters, marking elision.
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
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use secrecy::ExposeSecret;

    use super::*;
    use crate::definition::{Auth, Method};

    static NEXT_TOKEN_FILE: AtomicU64 = AtomicU64::new(0);

    /// Finding 16: an explicit `env_override(true)` on the file provider used to
    /// be silently turned into `false`, giving the caller the opposite of what
    /// it asked for with no way to notice.
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

    /// Finding 16: the *default* must keep working, though — refusing that
    /// would break every caller that never mentions the setting.
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

    /// And a remote provider still defaults to overriding from the environment.
    #[test]
    fn a_remote_provider_still_defaults_to_env_override() {
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        assert!(store.env_override);
    }

    struct TestTokenFile(PathBuf);

    impl Drop for TestTokenFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    impl SecretStore {
        /// The HTTP backend, for tests that poke at the definition directly.
        fn http(&self) -> &Http {
            match &self.backend {
                Backend::Http(http) => http,
                Backend::File(_) => panic!("expected an HTTP store"),
            }
        }

        fn http_mut(&mut self) -> &mut Http {
            match &mut self.backend {
                Backend::Http(http) => http,
                Backend::File(_) => panic!("expected an HTTP store"),
            }
        }
    }

    fn onepassword_store(base_url: String) -> (SecretStore, TestTokenFile) {
        let token_path = std::env::temp_dir().join(format!(
            "gg-onepassword-connect-token-{}-{}",
            std::process::id(),
            NEXT_TOKEN_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&token_path, "fake-connect-token").unwrap();
        let token_file = TestTokenFile(token_path);
        let mut store = SecretStore::builder(Provider::Onepassword)
            .env_override(false)
            .build()
            .unwrap();
        store.http_mut().definition.base_url = base_url;
        store.http_mut().definition.auth = Auth::Token {
            token_env: "GG_TEST_UNSET_CONNECT_TOKEN".to_string(),
            token_file_env: None,
            token_file: Some(token_file.0.to_string_lossy().into_owned()),
            header: "Authorization".to_string(),
            scheme: Some("Bearer".to_string()),
        };
        (store, token_file)
    }

    #[test]
    fn every_http_provider_has_a_loadable_definition() {
        for &provider in Provider::ALL {
            // The file provider is local, so it has no definition to load.
            let Some(yaml) = provider.definition() else {
                assert_eq!(provider, Provider::File);
                continue;
            };
            let definition = ProviderDef::from_yaml(yaml)
                .unwrap_or_else(|err| panic!("{provider} definition should parse: {err}"));
            assert_eq!(
                definition.name,
                provider.as_str(),
                "{provider} name mismatch"
            );
        }
    }

    #[test]
    fn parses_the_vault_provider() {
        let provider = ProviderDef::from_yaml(Provider::Vault.definition().unwrap()).unwrap();
        assert_eq!(provider.name, "vault");
        let Auth::Token {
            token_env, header, ..
        } = &provider.auth;
        assert_eq!(token_env, "VAULT_TOKEN");
        assert_eq!(header, "X-Vault-Token");
        let endpoint = provider
            .endpoints
            .get("read_secret")
            .expect("read_secret endpoint");
        assert_eq!(endpoint.method, Method::Get);
        assert_eq!(endpoint.secret.as_deref(), Some("data.data"));
        let write_endpoint = provider
            .endpoints
            .get("write_secret")
            .expect("write_secret endpoint");
        assert_eq!(write_endpoint.method, Method::Post);
        assert!(write_endpoint.secret.is_none());
        let delete_endpoint = provider
            .endpoints
            .get("delete_secret")
            .expect("delete_secret endpoint");
        assert_eq!(delete_endpoint.method, Method::Delete);
        assert!(delete_endpoint.secret.is_none());
    }

    #[test]
    fn parses_the_onepassword_connect_provider() {
        let provider = ProviderDef::from_yaml(Provider::Onepassword.definition().unwrap()).unwrap();
        assert_eq!(provider.name, "onepassword");
        let Auth::Token {
            token_env,
            header,
            scheme,
            ..
        } = &provider.auth;
        assert_eq!(token_env, "OP_CONNECT_TOKEN");
        assert_eq!(header, "Authorization");
        assert_eq!(scheme.as_deref(), Some("Bearer"));
        assert_eq!(provider.endpoints["write_secret"].method, Method::Put);
    }

    #[test]
    fn onepassword_requests_use_bearer_auth_and_encoded_ids() {
        let (store, _token_file) = onepassword_store("https://connect.example".to_string());
        let params = BTreeMap::from([
            ("vault_id".to_string(), "vault id".to_string()),
            ("item_id".to_string(), "item/id".to_string()),
        ]);
        let request = store
            .http()
            .request("read_secret", &params)
            .unwrap()
            .body(String::new())
            .unwrap();
        assert_eq!(
            request.uri(),
            "https://connect.example/v1/vaults/vault%20id/items/item%2Fid"
        );
        assert_eq!(
            request.headers()["Authorization"],
            "Bearer fake-connect-token"
        );
    }

    #[test]
    fn onepassword_connect_reads_an_item_by_vault_and_item_name() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let responses = [
                ("GET /v1/vaults ", r#"[{"id":"vault-id","name":"dev"}]"#),
                (
                    "GET /v1/vaults/vault-id/items ",
                    r#"[{"id":"item-id","title":"myapp"}]"#,
                ),
                (
                    "GET /v1/vaults/vault-id/items/item-id ",
                    r#"{"fields":[{"id":"api","label":"API_KEY","value":"fake-value"}]}"#,
                ),
            ];
            for (expected_request, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 4096];
                let count = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..count]);
                assert!(request.starts_with(expected_request), "{request}");
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fake-connect-token"),
                    "{request}"
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });

        let (store, _token_file) = onepassword_store(format!("http://{address}"));
        let fields = store.get_secrets("dev/myapp").unwrap();
        assert_eq!(fields["API_KEY"].expose_secret(), "fake-value");
        server.join().unwrap();
    }

    #[test]
    fn provider_def_roundtrips_through_yaml() {
        let provider = ProviderDef::from_yaml(Provider::Vault.definition().unwrap()).unwrap();
        let yaml = serde_yaml_ng::to_string(&provider).unwrap();
        let again = ProviderDef::from_yaml(&yaml).unwrap();
        assert_eq!(again.name, provider.name);
        assert_eq!(again.endpoints.len(), provider.endpoints.len());
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

    /// Finding 2b: `get_secrets` promises *every* field and has no channel to
    /// say otherwise, so returning the readable half handed the caller
    /// `Ok({GOOD})` for a file that also names `BAD` — indistinguishable from a
    /// field nobody ever set. That convenience is how `run` came to inject a
    /// partial environment and how the shell hook came to make a secret vanish:
    /// the same defect twice, because the API let it be ignored.
    #[test]
    fn get_secrets_refuses_a_partial_read_that_with_warnings_reports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        // Another tool's marker: unreadable without any keyring being involved.
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

        // The caller that asks for the readable half by name still gets it, and
        // gets the warning in its hands.
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
        // base_url's ${VAULT_ADDR} is deliberately unresolvable: if the env
        // override didn't short-circuit before fetching, this would error.
        // SAFETY: uniquely-named var, removed below; no other test reads it.
        unsafe { std::env::set_var("GG_TEST_SHORTCIRCUIT_FIELD", "local-value") };
        let store = SecretStore::builder(Provider::Vault).build().unwrap();
        let value = store
            .get_secret("secret/whatever", "GG_TEST_SHORTCIRCUIT_FIELD")
            .unwrap();
        assert_eq!(value.expose_secret(), "local-value");
        unsafe { std::env::remove_var("GG_TEST_SHORTCIRCUIT_FIELD") };

        // With override disabled, the same call must consult the provider.
        // Point VAULT_ADDR at a dead local port so the test stays hermetic:
        // the fetch fails fast instead of reaching a real server.
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
