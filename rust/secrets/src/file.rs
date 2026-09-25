//! The `file` provider: dotenv files encrypted value by value with a device-local key.
//!
//! Scopes, most specific winning per variable: system (`/etc/gitguardian/secrets.env`), user
//! (`<config dir>/gitguardian/secrets.env`), repo (`<common git dir>/gitguardian/secrets.env`) and
//! project (`./.env` or `--path`). The system scope is world-readable and plaintext only: a sealed
//! value there would be readable only by the user whose keyring sealed it.
//!
//! Key material is zeroized; plaintext values are not, they live in ordinary `String`s.

pub(crate) mod atomic;
pub(crate) mod crypto;
pub(crate) mod envelope;
pub(crate) mod keystore;
mod ownership;
mod repo;
pub mod trust;
#[cfg(windows)]
mod win_security;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use secrecy::{ExposeSecret, SecretString};

use crate::dotenv::{Document, QuoteProblem, is_valid_key};
use crate::error::SecretError;
use crypto::Cipher;
use envelope::{ValueKind, classify};

/// The project-scope file when `--path` is not given.
pub const DEFAULT_PROJECT_PATH: &str = ".env";

const USER_SCOPE_DIR: &str = "gitguardian";
const USER_SCOPE_FILE: &str = "secrets.env";
const KEYSET_LOCK_FILE: &str = "keyset.lock";

/// The repo-scope file for the repository containing `directory`, shared by all its worktrees.
pub fn repo_scope_path(directory: &Path) -> Option<PathBuf> {
    repo::scope_path(directory)
}

/// The system-scope file. Never created by this crate: writing it needs administrator
/// privileges.
pub fn system_scope_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(
            PathBuf::from("/etc")
                .join(USER_SCOPE_DIR)
                .join(USER_SCOPE_FILE),
        )
    }
    #[cfg(windows)]
    {
        let root = std::env::var_os("ProgramData")?;
        Some(
            PathBuf::from(root)
                .join(USER_SCOPE_DIR)
                .join(USER_SCOPE_FILE),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

pub fn user_scope_path() -> Result<PathBuf> {
    Ok(config_root()?.join(USER_SCOPE_DIR).join(USER_SCOPE_FILE))
}

/// `~/Library/Application Support` on Apple platforms, where `config_dir` is
/// `~/Library/Preferences`, which belongs to the defaults system.
fn config_root() -> Result<PathBuf> {
    use etcetera::BaseStrategy as _;

    let strategy = etcetera::base_strategy::choose_native_strategy()
        .context("locating the user configuration directory")?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Ok(strategy.data_dir())
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        Ok(strategy.config_dir())
    }
}

/// Derived from the OS user's passwd home, not `$HOME`: the keyring entry is per OS user, so an
/// environment-derived lock lets two environments each mint a master key and lose one.
fn keyset_lock_path() -> Result<PathBuf> {
    let root = match os_user_home() {
        Some(home) => config_root_under(&home),
        // No passwd entry (some minimal containers): fall back to the environment.
        None => config_root()?,
    };
    Ok(root.join(USER_SCOPE_DIR).join(KEYSET_LOCK_FILE))
}

fn config_root_under(home: &Path) -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        home.join("Library").join("Application Support")
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        home.join(".config")
    }
}

/// Home directory from the password database, deliberately not `$HOME`.
#[cfg(unix)]
fn os_user_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsString};
    use std::os::unix::ffi::OsStringExt;

    let mut buffer = vec![0u8; 1024];
    loop {
        // SAFETY: getpwuid_r writes only into buffers that outlive the call.
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let code = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if code == libc::ERANGE && buffer.len() < 1 << 16 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if code != 0 || found.is_null() || passwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: `found` is non-null, so `pw_dir` is a NUL-terminated string inside live `buffer`.
        let home = unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes().to_vec();
        let home = PathBuf::from(OsString::from_vec(home));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(not(unix))]
fn os_user_home() -> Option<PathBuf> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    System,
    Global,
    Local,
    Project,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::System => "system",
            Scope::Global => "global",
            Scope::Local => "local",
            Scope::Project => "project",
        })
    }
}

struct Layer {
    scope: Scope,
    path: PathBuf,
    document: Document,
}

#[derive(Clone)]
enum Encryption {
    Device,
    Plaintext,
    /// Tests only: exercises the encrypted path without the OS keyring.
    #[cfg(test)]
    Fixed(Arc<dyn Cipher + Send + Sync>),
    /// Tests only: a `Device` stand-in would reach the developer's real keychain.
    #[cfg(test)]
    Unavailable,
}

#[derive(Clone)]
pub(crate) struct FileBackend {
    encryption: Encryption,
    /// `None` when the platform has no usable config directory.
    user_path: Option<PathBuf>,
    system_path: Option<PathBuf>,
    /// The project path was not chosen by the caller, so a directory there is no project file.
    project_path_is_default: bool,
}

// No cipher or key material.
impl std::fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackend")
            .field("user_path", &self.user_path)
            .field("system_path", &self.system_path)
            .field(
                "encryption",
                &match self.encryption {
                    Encryption::Device => "device",
                    Encryption::Plaintext => "plaintext",
                    #[cfg(test)]
                    Encryption::Fixed(_) => "fixed",
                    #[cfg(test)]
                    Encryption::Unavailable => "unavailable",
                },
            )
            .finish()
    }
}

impl FileBackend {
    pub(crate) fn new(encrypt: bool, project_path_is_default: bool) -> Self {
        FileBackend {
            encryption: if encrypt {
                Encryption::Device
            } else {
                Encryption::Plaintext
            },
            user_path: user_scope_path().ok(),
            system_path: system_scope_path(),
            project_path_is_default,
        }
    }

    /// The cipher used to seal new values, or `None` when writing plaintext.
    fn write_cipher(&self) -> Result<Option<Arc<dyn Cipher + Send + Sync>>> {
        match &self.encryption {
            Encryption::Device => Ok(Some(Arc::new(keystore::load_or_create()?))),
            Encryption::Plaintext => Ok(None),
            #[cfg(test)]
            Encryption::Fixed(cipher) => Ok(Some(cipher.clone())),
            #[cfg(test)]
            Encryption::Unavailable => bail!("no keyset on this device (test)"),
        }
    }

    /// `None` on a dry run with no device key yet: minting the key is not undone by answering
    /// `n`.
    fn encrypt_cipher(&self, dry_run: bool) -> Result<Option<Arc<dyn Cipher + Send + Sync>>> {
        if !dry_run {
            return Ok(Some(self.write_cipher()?.context(
                "encrypting in place needs a cipher; this backend writes plaintext",
            )?));
        }
        match &self.encryption {
            Encryption::Device => {
                Ok(keystore::load()?
                    .map(|keyset| Arc::new(keyset) as Arc<dyn Cipher + Send + Sync>))
            }
            Encryption::Plaintext => {
                bail!("encrypting in place needs a cipher; this backend writes plaintext")
            }
            #[cfg(test)]
            Encryption::Fixed(cipher) => Ok(Some(cipher.clone())),
            #[cfg(test)]
            Encryption::Unavailable => bail!("no keyset on this device (test)"),
        }
    }

    /// Called only for encrypted values, so plaintext reads never touch the keyring.
    fn read_cipher(&self) -> Result<Arc<dyn Cipher + Send + Sync>> {
        #[cfg(test)]
        match &self.encryption {
            Encryption::Fixed(cipher) => return Ok(cipher.clone()),
            Encryption::Unavailable => bail!(
                "this device has no gitguardian encryption key (test stand-in for a missing \
                 keyring)"
            ),
            _ => {}
        }
        let keyset = keystore::load()?.with_context(|| {
            format!(
                "this device has no gitguardian encryption key (OS keyring service '{}', account \
                 '{}'), so encrypted values cannot be read here; they were written on another \
                 machine or the key has been removed",
                keystore::KEYRING_SERVICE,
                keystore::KEYRING_ACCOUNT
            )
        })?;
        Ok(Arc::new(keyset))
    }

    /// Every value visible at `project_path`, with per-entry failures in [`ReadWarnings`] rather
    /// than failing the whole read. A file where nothing could be read is still an error.
    pub(crate) fn get_secrets(
        &self,
        project_path: &str,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        let (layers, skipped) = self.layers(Path::new(project_path))?;
        self.resolve(project_path, layers, skipped)
    }

    /// Every value in one file, with no other scope merged in.
    pub(crate) fn get_secrets_from_file(
        &self,
        path: &str,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        let layers = match atomic::read_to_string(Path::new(path))? {
            Some(contents) => vec![Layer {
                scope: Scope::Project,
                document: Document::parse(&contents),
                path: PathBuf::from(path),
            }],
            None => Vec::new(),
        };
        self.resolve(path, layers, Vec::new())
    }

    fn resolve(
        &self,
        project_path: &str,
        layers: Vec<Layer>,
        skipped: Vec<String>,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        if layers.is_empty() {
            return Err(not_found(project_path, &skipped));
        }
        // A stray quote loses variables at parse time, so reads must report it too.
        let advisories = skipped
            .into_iter()
            .chain(layers.iter().flat_map(|layer| {
                layer
                    .document
                    .quote_problems()
                    .into_iter()
                    .map(|problem| format!("{}: {problem}", layer.path.display()))
            }))
            .collect();
        let (fields, unreadable) = self.decrypt(&merge(&layers))?;
        Ok((
            fields,
            ReadWarnings {
                unreadable,
                advisories,
            },
        ))
    }

    /// Which scope each visible field's value came from; decrypts nothing.
    pub(crate) fn field_scopes(&self, project_path: &str) -> Result<BTreeMap<String, String>> {
        let (layers, _) = self.layers(Path::new(project_path))?;
        Ok(merge(&layers)
            .into_iter()
            .map(|(field, resolved)| (field.to_string(), resolved.scope.to_string()))
            .collect())
    }

    /// One value; decrypts only that field, so an unrelated unreadable entry cannot fail it.
    pub(crate) fn get_secret(&self, project_path: &str, field: &str) -> Result<SecretString> {
        let (layers, skipped) = self.layers(Path::new(project_path))?;
        if layers.is_empty() {
            return Err(not_found(project_path, &skipped));
        }
        let merged = merge(&layers);
        let Some(resolved) = merged.get(field) else {
            // A stray quote can swallow a field. Name every layer with a problem: there is no
            // telling which one was meant to define it.
            let problems = layers
                .iter()
                .filter_map(|layer| {
                    layer.document.quote_problem().map(|problem| {
                        format!(
                            "{} ({} scope): {problem}",
                            layer.path.display(),
                            layer.scope
                        )
                    })
                })
                .collect::<Vec<_>>();
            let mut error: anyhow::Error = SecretError::FieldNotFound {
                field: field.to_string(),
            }
            .into();
            if !skipped.is_empty() {
                error = error.context(skipped.join("; "));
            }
            if problems.is_empty() {
                return Err(error);
            }
            return Err(error.context(format!(
                "'{field}' may be defined but invisible: a stray quote swallows the variables \
                 around it. {}",
                problems.join("; ")
            )));
        };
        let mut cipher = None;
        self.open(field, resolved, &mut cipher)
    }

    /// Names defined in `project_path` alone; never decrypts, so it is safe before `set` writes.
    pub(crate) fn field_names(&self, project_path: &str) -> Result<Vec<String>> {
        let Some(contents) = atomic::read_to_string(Path::new(project_path))? else {
            return Ok(Vec::new());
        };
        let document = Document::parse(&contents);
        let mut names = document
            .entries()
            .map(|entry| entry.key().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Create or update `fields` at `path`; every value is encrypted before anything is written.
    ///
    /// `expected_existing` is the set of names the user was told would be overwritten; any other
    /// existing name means the file changed since the prompt, and the write is refused.
    pub(crate) fn set_secrets(
        &self,
        path: &str,
        fields: &BTreeMap<String, SecretString>,
        expected_existing: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        for key in fields.keys() {
            if !is_valid_key(key) {
                bail!("'{key}' is not a valid environment variable name");
            }
        }

        if self.is_system_path(path) && !matches!(self.encryption, Encryption::Plaintext) {
            bail!("{}", SEALED_SYSTEM_VALUE);
        }
        let cipher = self.write_cipher()?;
        if cipher.is_none() {
            // An encrypted value becomes a marker, so only plaintext can be misread as a reference.
            for (key, value) in fields {
                reject_unstorable_plaintext(key, value.expose_secret())?;
            }
        }

        let mut locked = atomic::LockedFile::open_as(Path::new(path), self.visibility_of(path))?;
        let contents = locked.read()?;
        let mut document = Document::parse(&contents);
        if let Some(expected) = expected_existing {
            confirm_still_current(path, &document, fields, expected)?;
        }
        match document.quote_problem() {
            // A new quoted value would pair with the stray quote.
            Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
                "{path}: {problem}. Writing to this file would let that quote pair with one of \
                 ours, silently swallowing the variables in between — no bytes are lost, but \
                 values disappear. Fix line {} first",
                problem.line()
            ),
            // Writing the same name would append a second assignment and leave the broken line's
            // plaintext on disk.
            Some(problem @ QuoteProblem::TrailingAfterQuote { .. }) => bail!(
                "{path}: {problem}. Refusing to write to a file with a line whose value is \
                 partly outside its quotes; fix line {} first",
                problem.line()
            ),
            // A heuristic that must not block a legitimate multi-line value.
            Some(problem @ QuoteProblem::SwallowedAssignment { .. }) => {
                warnings.push(format!("{path}: {problem}"));
            }
            None => {}
        }

        let mut rendered = Vec::with_capacity(fields.len());
        for (key, value) in fields {
            let text = match &cipher {
                Some(cipher) => cipher
                    .encrypt(key, value.expose_secret().as_bytes())
                    .with_context(|| format!("encrypting '{key}'"))?
                    .to_marker(),
                None => value.expose_secret().to_string(),
            };
            rendered.push((key, text));
        }
        for (key, text) in rendered {
            // Say so: the user was told one field would be overwritten.
            let duplicates = document.assignment_count(key);
            if duplicates > 1 {
                warnings.push(format!(
                    "{path}: '{key}' is assigned {duplicates} times; every assignment was \
                     replaced, so no earlier value is left behind"
                ));
            }
            document.upsert(key, &text);
        }
        warnings.extend(locked.replace(&document.to_string())?);
        Ok(warnings)
    }

    /// Encrypt the plaintext values at `path` in place, under one lock so a concurrent `set` cannot
    /// land mid-pass. Existing references are left byte-for-byte alone, spending no fresh nonce.
    pub(crate) fn encrypt_in_place(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
        dry_run: bool,
    ) -> Result<EncryptOutcome> {
        // `LockedFile::open` creates the file and minting the device key is irreversible, so a
        // missing file short-circuits first.
        if std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(EncryptOutcome::default());
        }
        if self.is_system_path(path) {
            bail!("{}", SEALED_SYSTEM_VALUE);
        }

        let mut locked = atomic::LockedFile::open(Path::new(path))?;
        let contents = locked.read()?;
        let mut document = Document::parse(&contents);
        let mut outcome = EncryptOutcome::default();
        match document.quote_problem() {
            Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
                "{path}: {problem}. Refusing to rewrite a file whose meaning is already \
                 ambiguous; fix line {} first",
                problem.line()
            ),
            Some(problem @ QuoteProblem::TrailingAfterQuote { .. }) => bail!(
                "{path}: {problem}. Refusing to rewrite a file with a line whose value is partly \
                 outside its quotes — sealing the quoted half would leave the rest of it on disk \
                 in cleartext; fix line {} first",
                problem.line()
            ),
            Some(problem @ QuoteProblem::SwallowedAssignment { .. }) => {
                outcome.warnings.push(format!("{path}: {problem}"));
            }
            None => {}
        }

        // Loaded lazily: minting the device key must not happen for a pass with nothing to seal.
        let mut cipher: Option<Arc<dyn Cipher + Send + Sync>> = None;
        let mut cipher_loaded = false;
        let changed = document.map_values(|key, value| -> Result<Option<String>> {
            if only.is_some_and(|only| !only.contains(key)) {
                return Ok(None);
            }
            match classify(value) {
                // An empty value holds no secret; sealing it device-locks a placeholder. `set`
                // refuses empty values too.
                Ok(ValueKind::Plain) if value.is_empty() => {
                    if only.is_some() {
                        outcome
                            .warnings
                            .push(format!("left '{key}' alone: it has no value to encrypt"));
                    }
                    Ok(None)
                }
                Ok(ValueKind::Plain) => {
                    outcome.encrypted.push(key.to_string());
                    if !cipher_loaded {
                        cipher = self.encrypt_cipher(dry_run)?;
                        cipher_loaded = true;
                    }
                    // Dry run with no keyset yet: naming the value is all the preview needs.
                    let Some(cipher) = &cipher else {
                        return Ok(None);
                    };
                    let marker = cipher
                        .encrypt(key, value.as_bytes())
                        .with_context(|| format!("encrypting '{key}'"))?
                        .to_marker();
                    Ok(Some(marker))
                }
                Ok(ValueKind::Encrypted(_)) => {
                    outcome.already_encrypted.push(key.to_string());
                    Ok(None)
                }
                // Encrypting another tool's marker would bury a value we cannot read.
                Err(error) => {
                    outcome
                        .warnings
                        .push(format!("left '{key}' alone: {error}"));
                    Ok(None)
                }
            }
        })?;

        if changed > 0 && !dry_run {
            outcome
                .warnings
                .extend(locked.replace(&document.to_string())?);
        }
        Ok(outcome)
    }

    /// Plan a delete against an unlocked read, so the confirmation prompt never holds the lock.
    /// The plan records the file's digest; [`Self::delete_planned`] refuses if it changed since.
    pub(crate) fn plan_delete(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<DeletePlan> {
        // Checked explicitly: "sets nothing" for a mistyped `--path` implies the secrets were
        // already gone.
        let Some(contents) = atomic::read_to_string(Path::new(path))? else {
            bail!("{path} does not exist, so there is nothing to delete");
        };
        let document = Document::parse(&contents);
        fatal_quote_problem(path, &document)?;

        let present = document
            .entries()
            .map(|entry| entry.key())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(only) = only {
            // After the quote check: a stray quote hides assignments, so "does not set" would
            // mislead.
            let unknown = only
                .iter()
                .filter(|key| !present.contains(key.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            ensure!(
                unknown.is_empty(),
                "{path} does not set {}",
                unknown.join(", ")
            );
        }

        // Deduplicated, so a repeated name does not look like a concurrent writer.
        let targets: Vec<String> = match only {
            Some(only) => only.iter().cloned().collect(),
            None => present.iter().map(|key| key.to_string()).collect(),
        };
        for target in targets.iter() {
            refuse_enclosed_assignments(path, &document, target.as_str())?;
        }

        Ok(DeletePlan {
            targets,
            digest: digest_of(&contents),
        })
    }

    /// Carry out a [`DeletePlan`] by removing lines, so comments, order and other values survive.
    ///
    /// Never decrypts: removing a teammate's device-local marker must work without their key.
    pub(crate) fn delete_planned(&self, path: &str, plan: &DeletePlan) -> Result<DeleteOutcome> {
        ensure!(
            !plan.targets.is_empty(),
            "no fields were named to delete from {path}; this provider removes named variables, \
             never a whole file"
        );

        let mut locked = atomic::LockedFile::open_as(Path::new(path), self.visibility_of(path))?;
        let contents = locked.read()?;

        // Any change invalidates the plan: a `set` since the prompt would otherwise have its
        // unconfirmed ciphertext destroyed.
        ensure!(
            digest_of(&contents) == plan.digest,
            "{path} changed since the delete was prepared, so nothing was removed. Re-run to see \
             what would be deleted now"
        );

        let mut document = Document::parse(&contents);
        let mut outcome = DeleteOutcome::default();
        // Re-checked under the lock so the guarantee does not rest on the digest alone.
        fatal_quote_problem(path, &document)?;

        for key in &plan.targets {
            refuse_enclosed_assignments(path, &document, key)?;
            let removed = document.remove(key);
            if !removed.any() {
                // Already gone, which is what was asked for.
                outcome
                    .warnings
                    .push(format!("{path} no longer set '{key}'; nothing to remove"));
                continue;
            }
            outcome.removed.push(key.clone());
            if removed.assignments > 1 {
                outcome.warnings.push(format!(
                    "{path}: '{key}' was assigned {} times; every assignment was removed",
                    removed.assignments
                ));
            }
            for comment in removed.kept_comments {
                outcome.warnings.push(format!(
                    "{path}: kept the comment that followed '{key}' as a line of its own: \
                     {comment}"
                ));
            }
        }

        if outcome.removed.is_empty() {
            // Still sweep stale temporaries, which `replace` would otherwise have collected.
            outcome
                .warnings
                .extend(atomic::collect_stale_temporaries(Path::new(path)));
            return Ok(outcome);
        }
        outcome
            .warnings
            .extend(locked.replace(&document.to_string())?);
        Ok(outcome)
    }

    fn is_system_path(&self, path: &str) -> bool {
        self.system_path.as_deref() == Some(Path::new(path))
    }

    fn visibility_of(&self, path: &str) -> atomic::Visibility {
        if self.is_system_path(path) {
            atomic::Visibility::Shared
        } else {
            atomic::Visibility::Private
        }
    }

    /// The scope files that exist, least specific first, and why any were skipped.
    fn layers(&self, project_path: &Path) -> Result<(Vec<Layer>, Vec<String>)> {
        let mut layers = Vec::new();
        let mut skipped = Vec::new();
        if let Some(system_path) = self.system_path.as_deref()
            && system_path != project_path
            && let Some(contents) = read_implicit_layer(Scope::System, system_path, &mut skipped)?
        {
            layers.push(Layer {
                scope: Scope::System,
                document: Document::parse(&contents),
                path: system_path.to_path_buf(),
            });
        }
        if let Some(user_path) = self.user_path.as_deref()
            && user_path != project_path
            && let Some(contents) = read_implicit_layer(Scope::Global, user_path, &mut skipped)?
        {
            layers.push(Layer {
                scope: Scope::Global,
                document: Document::parse(&contents),
                path: user_path.to_path_buf(),
            });
        }
        // Resolved per call: one store can be asked about files in different repositories.
        if let Some(repo_path) = repo::scope_path(project_directory(project_path))
            && repo_path != project_path
            && self.user_path.as_deref() != Some(repo_path.as_path())
            && let Some(contents) = read_implicit_layer(Scope::Local, &repo_path, &mut skipped)?
        {
            layers.push(Layer {
                scope: Scope::Local,
                document: Document::parse(&contents),
                path: repo_path,
            });
        }
        let default_is_a_directory = self.project_path_is_default
            && std::fs::symlink_metadata(project_path).is_ok_and(|metadata| metadata.is_dir());
        if !default_is_a_directory && let Some(contents) = atomic::read_to_string(project_path)? {
            layers.push(Layer {
                scope: Scope::Project,
                document: Document::parse(&contents),
                path: project_path.to_path_buf(),
            });
        }
        Ok((layers, skipped))
    }
}

/// Refused before the keyring is touched, so no device key is minted for nothing.
const SEALED_SYSTEM_VALUE: &str = "the system scope is shared by every user of this machine, and \
     an encrypted value there could be read only by the user whose keyring sealed it. Store it \
     with --plain, or use --global for a value only you need";

/// A scope file the user did not name: one they cannot read is skipped, not fatal, so a
/// root-only `/etc/gitguardian` cannot break every other user's reads.
fn read_implicit_layer(
    scope: Scope,
    path: &Path,
    skipped: &mut Vec<String>,
) -> Result<Option<String>> {
    let contents = match atomic::read_to_string(path) {
        Err(error) if is_permission_denied(&error) => {
            skipped.push(format!(
                "skipped the {scope} scope file {}: permission denied",
                path.display()
            ));
            return Ok(None);
        }
        other => other?,
    };
    // Every user's reads merge the system scope, so any user who could write it could set
    // variables for all of them (on Windows, anyone may create folders in ProgramData).
    if scope == Scope::System
        && contents.is_some()
        && let Some(reason) = std::iter::once(path)
            .chain(path.parent())
            .find_map(ownership::untrusted_writer)
    {
        skipped.push(format!(
            "skipped the system scope file {}: {reason}",
            path.display()
        ));
        return Ok(None);
    }
    Ok(contents)
}

fn is_permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

fn not_found(path: &str, skipped: &[String]) -> anyhow::Error {
    let error: anyhow::Error = SecretError::SecretNotFound {
        path: path.to_string(),
    }
    .into();
    if skipped.is_empty() {
        error
    } else {
        error.context(skipped.join("; "))
    }
}

/// A bare `.env` has no parent component, which means the current directory.
fn project_directory(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// What a bulk read could not do.
#[derive(Debug, Default)]
pub struct ReadWarnings {
    /// Fields whose value could not be read, named but never valued. A caller injecting into a
    /// child's environment must refuse on these.
    pub unreadable: Vec<String>,
    /// Heuristic remarks about the files that lost no field; worth showing, never failing over.
    pub advisories: Vec<String>,
}

impl ReadWarnings {
    /// Every message, unreadable fields first.
    pub fn messages(&self) -> impl Iterator<Item = &str> {
        self.unreadable
            .iter()
            .chain(self.advisories.iter())
            .map(String::as_str)
    }
}

/// Refuse a write if a name being set appeared after the user confirmed the overwrites.
fn confirm_still_current(
    path: &str,
    document: &Document,
    fields: &BTreeMap<String, SecretString>,
    expected: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let surprises = fields
        .keys()
        .filter(|key| document.entry(key).is_some() && !expected.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        surprises.is_empty(),
        "{path} gained {} since the overwrite check, so this write was never confirmed; \
         re-run to see what would be replaced",
        surprises.join(", ")
    );
    Ok(())
}

/// A delete that has been decided but not yet carried out, pinned to the file's digest.
#[derive(Debug)]
pub struct DeletePlan {
    /// The names that will be removed, deduplicated.
    pub targets: Vec<String>,
    digest: String,
}

#[derive(Debug, Default)]
pub struct DeleteOutcome {
    /// Empty means the file was left alone.
    pub removed: Vec<String>,
    /// Never contains a value.
    pub warnings: Vec<String>,
}

/// Refuse a document whose quoting is ambiguous enough that a rewrite changes unnamed variables.
fn fatal_quote_problem(path: &str, document: &Document) -> Result<()> {
    match document.quote_problem() {
        // Removing a line moves what an unterminated quote swallows.
        Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
            "{path}: {problem}. Refusing to rewrite a file whose meaning is already ambiguous; \
             fix line {} first",
            problem.line()
        ),
        Some(problem @ QuoteProblem::TrailingAfterQuote { .. }) => bail!(
            "{path}: {problem}. Refusing to rewrite a file with a line whose value is partly \
             outside its quotes; fix line {} first",
            problem.line()
        ),
        // Not fatal alone: `refuse_enclosed_assignments` decides per entry being removed.
        Some(QuoteProblem::SwallowedAssignment { .. }) | None => Ok(()),
    }
}

/// Refuse to remove an entry whose value swallowed later assignments: removing it destroys them.
///
/// Independent of the `SwallowedAssignment` heuristic, which misses short names.
fn refuse_enclosed_assignments(path: &str, document: &Document, key: &str) -> Result<()> {
    for entry in document.entries().filter(|entry| entry.key() == key) {
        let enclosed = entry.enclosed_assignments();
        ensure!(
            enclosed.is_empty(),
            "{path}: the value of '{key}' spans several lines and has what reads as an \
             assignment to {} inside it, so a stray quote has probably swallowed {}. Removing \
             '{key}' would delete {} too, with no way to recover {}; fix the quoting first",
            enclosed.join(", "),
            if enclosed.len() == 1 {
                "a variable"
            } else {
                "variables"
            },
            if enclosed.len() == 1 { "it" } else { "them" },
            if enclosed.len() == 1 { "it" } else { "them" },
        );
    }
    Ok(())
}

/// Must be cryptographic: it gates whether a prepared delete may still be written.
fn digest_of(contents: &str) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(contents.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Default)]
pub struct EncryptOutcome {
    pub encrypted: Vec<String>,
    pub already_encrypted: Vec<String>,
    /// Names left alone, and why. Never contains a value.
    pub warnings: Vec<String>,
}

struct Resolved<'a> {
    /// Unquoted: a marker may be written `KEY="gitguardian:..."`.
    value: String,
    scope: Scope,
    path: &'a Path,
}

/// Flatten the layers, most specific last.
///
/// Every user-scope value is injected into every command in every repository, so the user-scope
/// file is ambient authority; a future declared-only filter belongs here.
fn merge<'a>(layers: &'a [Layer]) -> BTreeMap<&'a str, Resolved<'a>> {
    let mut merged = BTreeMap::new();
    for layer in layers {
        for entry in layer.document.entries() {
            merged.insert(
                entry.key(),
                Resolved {
                    value: entry.value(),
                    scope: layer.scope,
                    path: &layer.path,
                },
            );
        }
    }
    merged
}

impl FileBackend {
    /// Decrypt per key, loading the cipher only if needed; errors only when nothing could be read.
    fn decrypt(
        &self,
        merged: &BTreeMap<&str, Resolved<'_>>,
    ) -> Result<(BTreeMap<String, SecretString>, Vec<String>)> {
        let mut cipher: Option<Arc<dyn Cipher + Send + Sync>> = None;
        let mut fields = BTreeMap::new();
        let mut unreadable = Vec::new();
        let mut first_error: Option<anyhow::Error> = None;
        for (key, resolved) in merged {
            match self.open(key, resolved, &mut cipher) {
                Ok(value) => {
                    fields.insert((*key).to_string(), value);
                }
                Err(error) => {
                    unreadable.push(format!("{error:#}"));
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if fields.is_empty()
            && let Some(error) = first_error
        {
            return Err(error);
        }
        Ok((fields, unreadable))
    }

    fn open(
        &self,
        key: &str,
        resolved: &Resolved<'_>,
        cipher: &mut Option<Arc<dyn Cipher + Send + Sync>>,
    ) -> Result<SecretString> {
        let source = || {
            format!(
                "reading '{key}' from the {} scope file {}",
                resolved.scope,
                resolved.path.display()
            )
        };
        match classify(&resolved.value).with_context(source)? {
            ValueKind::Plain => Ok(SecretString::from(resolved.value.clone())),
            ValueKind::Encrypted(envelope) => {
                if cipher.is_none() {
                    // Per-key context, so a missing keyring names the value it could not open.
                    *cipher = Some(self.read_cipher().with_context(source)?);
                }
                let cipher = cipher.as_ref().expect("the cipher was just loaded");
                let plaintext = cipher.decrypt(key, &envelope).with_context(source)?;
                // Not `String::from_utf8`: its error would hold an unzeroized copy of the secret.
                let text = std::str::from_utf8(&plaintext)
                    .map_err(|_| anyhow::anyhow!("'{key}' does not decrypt to text"))?;
                Ok(SecretString::from(text.to_owned()))
            }
        }
    }
}

/// Refuse a `--plain` value that would be read back as a reference. Names the field, never the
/// value.
fn reject_unstorable_plaintext(key: &str, value: &str) -> Result<()> {
    if matches!(classify(value), Ok(ValueKind::Plain)) {
        return Ok(());
    }
    bail!(
        "the value for '{key}' would be read back as a secret reference rather than as the \
         text you typed, because it starts with a marker prefix ('{}', 'encrypted:' or \
         'varlock('). Store it encrypted (without --plain), or change the value",
        envelope::MARKER_PREFIX
    )
}

#[cfg(test)]
// A failed unwrap is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;

    use super::crypto::test_cipher::TestCipher;
    use super::*;

    const FAKE_VALUE: &str = "fake-placeholder-value";

    struct Fixture {
        directory: tempfile::TempDir,
        backend: FileBackend,
    }

    impl Fixture {
        /// Deterministic cipher and scope files in a tempdir; the real keyring is never touched.
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let user_path = directory.path().join("user-secrets.env");
            Fixture {
                backend: FileBackend {
                    encryption: Encryption::Fixed(Arc::new(TestCipher::new(0x5a))),
                    user_path: Some(user_path),
                    // A real /etc file would make these tests machine-dependent.
                    system_path: Some(directory.path().join("system-secrets.env")),
                    project_path_is_default: false,
                },
                directory,
            }
        }

        fn plaintext(mut self) -> Self {
            self.backend.encryption = Encryption::Plaintext;
            self
        }

        /// A device whose keyring never held the key.
        fn without_a_key(mut self) -> Self {
            self.backend.encryption = Encryption::Unavailable;
            self
        }

        fn project_path(&self) -> String {
            self.directory
                .path()
                .join(".env")
                .to_string_lossy()
                .into_owned()
        }

        fn write_project(&self, contents: &str) {
            std::fs::write(self.directory.path().join(".env"), contents).unwrap();
        }

        /// Make the directory a git checkout and write its repo-scope file.
        fn write_repo(&self, contents: &str) {
            let store = self.directory.path().join(".git").join("gitguardian");
            std::fs::create_dir_all(&store).unwrap();
            std::fs::write(store.join("secrets.env"), contents).unwrap();
        }

        fn write_system(&self, contents: &str) {
            std::fs::write(self.backend.system_path.as_ref().unwrap(), contents).unwrap();
        }

        fn write_user(&self, contents: &str) {
            std::fs::write(self.backend.user_path.as_ref().unwrap(), contents).unwrap();
        }

        fn read_project(&self) -> String {
            std::fs::read_to_string(self.directory.path().join(".env")).unwrap()
        }

        fn set(&self, pairs: &[(&str, &str)]) -> Result<Vec<String>> {
            let fields = pairs
                .iter()
                .map(|(key, value)| (key.to_string(), SecretString::from(value.to_string())))
                .collect();
            self.backend
                .set_secrets(&self.project_path(), &fields, None)
        }

        fn get(&self) -> Result<BTreeMap<String, SecretString>> {
            self.get_reporting().map(|(fields, _)| fields)
        }

        fn get_reporting(&self) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
            self.backend.get_secrets(&self.project_path())
        }

        fn get_field(&self, field: &str) -> Result<SecretString> {
            self.backend.get_secret(&self.project_path(), field)
        }

        /// Plan and carry out a delete, as a caller with no prompt would.
        fn delete(&self, keys: &[&str]) -> Result<DeleteOutcome> {
            let plan = self.plan(keys)?;
            self.backend.delete_planned(&self.project_path(), &plan)
        }

        fn plan(&self, keys: &[&str]) -> Result<DeletePlan> {
            let only = (!keys.is_empty()).then(|| {
                keys.iter()
                    .map(|key| key.to_string())
                    .collect::<BTreeSet<_>>()
            });
            self.backend
                .plan_delete(&self.project_path(), only.as_ref())
        }
    }

    fn value(fields: &BTreeMap<String, SecretString>, key: &str) -> String {
        fields
            .get(key)
            .unwrap_or_else(|| panic!("no field '{key}'"))
            .expose_secret()
            .to_string()
    }

    #[test]
    fn the_user_scope_file_lives_under_the_config_directory() {
        let path = user_scope_path().unwrap();
        assert!(path.ends_with("gitguardian/secrets.env"), "{path:?}");
    }

    /// The keyset lock is per OS user, not per environment, since the keyring entry is.
    #[cfg(unix)]
    #[test]
    fn the_keyset_lock_is_scoped_to_the_os_user_not_to_the_environment() {
        let home = os_user_home().expect("this test needs a passwd entry");
        let lock = keyset_lock_path().unwrap();
        assert!(lock.starts_with(&home), "{lock:?} is not under {home:?}");
        assert!(lock.ends_with("gitguardian/keyset.lock"), "{lock:?}");
        assert_ne!(lock.parent(), None);
    }

    #[test]
    fn set_then_get_round_trips_an_encrypted_value() {
        let fixture = Fixture::new();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();

        let contents = fixture.read_project();
        assert!(contents.starts_with("API_KEY=gitguardian:"), "{contents}");
        assert!(!contents.contains(FAKE_VALUE), "{contents}");

        assert_eq!(value(&fixture.get().unwrap(), "API_KEY"), FAKE_VALUE);
    }

    #[test]
    fn plain_mode_writes_a_readable_value() {
        let fixture = Fixture::new().plaintext();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        assert_eq!(fixture.read_project(), format!("API_KEY={FAKE_VALUE}\n"));
        assert_eq!(value(&fixture.get().unwrap(), "API_KEY"), FAKE_VALUE);
    }

    #[test]
    fn plaintext_and_encrypted_entries_live_side_by_side() {
        let fixture = Fixture::new();
        fixture.write_project("# app config\nDEBUG=true\n");
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();

        let fields = fixture.get().unwrap();
        assert_eq!(value(&fields, "DEBUG"), "true");
        assert_eq!(value(&fields, "API_KEY"), FAKE_VALUE);
        assert!(
            fixture
                .read_project()
                .starts_with("# app config\nDEBUG=true\n")
        );
    }

    #[test]
    fn writing_preserves_comments_order_and_untouched_ciphertext() {
        let fixture = Fixture::new();
        fixture.set(&[("FIRST", "one"), ("SECOND", "two")]).unwrap();
        let before = fixture.read_project();
        let first_line = before.lines().next().unwrap().to_string();

        fixture.write_project(&format!("# keep me\n{before}\n# trailing\n"));
        fixture.set(&[("SECOND", "changed")]).unwrap();

        let after = fixture.read_project();
        assert!(after.starts_with("# keep me\n"), "{after}");
        assert!(after.contains("# trailing\n"), "{after}");
        // FIRST was not re-encrypted: its ciphertext is byte-for-byte intact.
        assert!(after.contains(&first_line), "{after}");
        assert_eq!(value(&fixture.get().unwrap(), "SECOND"), "changed");
        assert_eq!(value(&fixture.get().unwrap(), "FIRST"), "one");
    }

    #[test]
    fn the_project_scope_wins_over_the_user_scope() {
        let fixture = Fixture::new();
        fixture.write_user("SHARED=from-user\nONLY_USER=user-only\n");
        fixture.write_project("SHARED=from-project\n");

        let fields = fixture.get().unwrap();
        assert_eq!(value(&fields, "SHARED"), "from-project");
        assert_eq!(value(&fields, "ONLY_USER"), "user-only");
    }

    #[test]
    fn a_user_scope_value_resolves_with_no_project_file_at_all() {
        let fixture = Fixture::new();
        fixture.write_user("ONLY_USER=user-only\n");
        assert_eq!(value(&fixture.get().unwrap(), "ONLY_USER"), "user-only");
    }

    #[test]
    fn nothing_anywhere_is_a_secret_not_found() {
        let fixture = Fixture::new();
        let error = fixture.get().unwrap_err();
        assert!(SecretError::is_secret_not_found(&error), "{error:#}");
    }

    #[test]
    fn field_names_ignore_the_user_scope_and_never_decrypt() {
        let fixture = Fixture::new();
        fixture.write_user("ONLY_USER=user-only\n");
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        assert_eq!(
            fixture
                .backend
                .field_names(&fixture.project_path())
                .unwrap(),
            vec!["API_KEY".to_string()]
        );
    }

    #[test]
    fn a_value_moved_to_another_variable_fails_to_decrypt() {
        let fixture = Fixture::new();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        let marker = fixture
            .read_project()
            .trim()
            .strip_prefix("API_KEY=")
            .unwrap()
            .to_string();
        fixture.write_project(&format!("OTHER_KEY={marker}\n"));

        let error = fixture.get().unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("OTHER_KEY"), "{message}");
        assert!(!message.contains(FAKE_VALUE), "{message}");
    }

    #[test]
    fn a_tampered_value_fails_without_leaking_anything() {
        let fixture = Fixture::new();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        let contents = fixture.read_project();
        // Flip a byte of the base64 payload.
        let tampered = contents.replace("gitguardian:", "gitguardian:A");
        fixture.write_project(&tampered);

        let error = fixture.get().unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.contains(FAKE_VALUE), "{message}");
        assert!(message.contains("API_KEY"), "{message}");
    }

    #[test]
    fn a_dotenvx_file_says_so() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY=encrypted:BASE64BLOB\n");
        let error = fixture.get().unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("dotenvx"), "{message}");
        assert!(message.contains("API_KEY"), "{message}");
    }

    #[test]
    fn a_varlock_file_says_so() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY=varlock(something)\n");
        assert!(format!("{:#}", fixture.get().unwrap_err()).contains("varlock"));
    }

    #[test]
    fn an_unknown_ref_kind_is_reported_as_such() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY=gitguardian:vault:secret/app\n");
        let message = format!("{:#}", fixture.get().unwrap_err());
        assert!(message.contains("held elsewhere"), "{message}");
        assert!(message.contains("Upgrade the CLI"), "{message}");
        // The field is named; the kind, a fragment of the value, is not.
        assert!(message.contains("API_KEY"), "{message}");
        assert!(!message.contains("vault"), "{message}");
    }

    #[test]
    fn an_invalid_variable_name_is_refused_before_anything_is_written() {
        let fixture = Fixture::new();
        let fields = BTreeMap::from([("not a name".to_string(), SecretString::from("x"))]);
        let error = fixture
            .backend
            .set_secrets(&fixture.project_path(), &fields, None)
            .unwrap_err();
        assert!(format!("{error:#}").contains("not a valid environment variable name"));
        assert!(!fixture.directory.path().join(".env").exists());
    }

    #[test]
    fn error_messages_name_the_file_a_value_came_from() {
        let fixture = Fixture::new();
        fixture.write_user("API_KEY=encrypted:BASE64BLOB\n");
        let message = format!("{:#}", fixture.get().unwrap_err());
        assert!(message.contains("global scope"), "{message}");
        assert!(message.contains("user-secrets.env"), "{message}");
    }

    #[test]
    fn a_multiline_value_survives_the_round_trip() {
        let fixture = Fixture::new().plaintext();
        fixture
            .set(&[("PRIVATE_KEY", "line one\nline two\n")])
            .unwrap();
        assert_eq!(
            value(&fixture.get().unwrap(), "PRIVATE_KEY"),
            "line one\nline two\n"
        );
    }

    #[test]
    fn one_unreadable_entry_does_not_hide_the_readable_ones() {
        let fixture = Fixture::new();
        fixture.write_project("DEBUG=true\nBAD=gitguardian:!!!not-base64!!!\nPORT=8080\n");

        let (fields, warnings) = fixture.get_reporting().unwrap();
        assert_eq!(value(&fields, "DEBUG"), "true");
        assert_eq!(value(&fields, "PORT"), "8080");
        assert!(!fields.contains_key("BAD"));

        assert_eq!(warnings.unreadable.len(), 1, "{warnings:?}");
        assert!(warnings.unreadable[0].contains("BAD"), "{warnings:?}");
    }

    /// Resolving one field opens nothing else, so an unreadable neighbour cannot fail it.
    #[test]
    fn a_readable_field_resolves_past_an_unreadable_one() {
        let (fixture, cipher) = counting_fixture();
        assert_eq!(fixture.get_field("DEBUG").unwrap().expose_secret(), "true");
        assert_eq!(cipher.decrypts(), 0, "an unrelated value was decrypted");
        assert!(fixture.get_field("BAD").is_err());
        assert_eq!(
            fixture.get_field("SEALED").unwrap().expose_secret(),
            FAKE_VALUE
        );
        assert_eq!(cipher.decrypts(), 1, "only the field asked for was opened");
    }

    /// Counts decrypts, to assert that resolving one field opened nothing else.
    struct CountingCipher {
        inner: TestCipher,
        decrypts: std::sync::atomic::AtomicUsize,
    }

    impl CountingCipher {
        fn new(pad: u8) -> Self {
            CountingCipher {
                inner: TestCipher::new(pad),
                decrypts: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn decrypts(&self) -> usize {
            self.decrypts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Cipher for CountingCipher {
        fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<super::envelope::Envelope> {
            self.inner.encrypt(key_name, plaintext)
        }

        fn decrypt(
            &self,
            key_name: &str,
            envelope: &super::envelope::Envelope,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            self.decrypts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.decrypt(key_name, envelope)
        }
    }

    /// One plaintext, one sealed and one unopenable entry, over a counting cipher.
    fn counting_fixture() -> (Fixture, Arc<CountingCipher>) {
        let sealing = Fixture::new();
        sealing.set(&[("SEALED", FAKE_VALUE)]).unwrap();
        let sealed = sealing.read_project();

        let cipher = Arc::new(CountingCipher::new(0x5a));
        let fixture = Fixture {
            backend: FileBackend {
                encryption: Encryption::Fixed(cipher.clone()),
                user_path: sealing.backend.user_path.clone(),
                system_path: sealing.backend.system_path.clone(),
                project_path_is_default: false,
            },
            directory: sealing.directory,
        };
        fixture.write_project(&format!(
            "DEBUG=true\n{sealed}BAD=gitguardian:!!!not-base64!!!\n"
        ));
        (fixture, cipher)
    }

    #[test]
    fn asking_for_the_unreadable_field_itself_fails() {
        let fixture = Fixture::new();
        fixture.write_project("DEBUG=true\nBAD=gitguardian:!!!not-base64!!!\n");
        let error = fixture.get_field("BAD").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("BAD"), "{message}");
        assert!(message.contains("envelope"), "{message}");
    }

    #[test]
    fn a_missing_keyset_is_reported_per_key_by_name() {
        let fixture = Fixture::new();
        fixture
            .set(&[("ALPHA", FAKE_VALUE), ("BETA", FAKE_VALUE)])
            .unwrap();
        fixture.write_project(&format!("PLAIN=kept\n{}", fixture.read_project()));

        let blind = FileBackend {
            encryption: Encryption::Unavailable,
            user_path: fixture.backend.user_path.clone(),
            system_path: fixture.backend.system_path.clone(),
            project_path_is_default: false,
        };
        let (fields, warnings) = blind.get_secrets(&fixture.project_path()).unwrap();

        assert_eq!(
            value(&fields, "PLAIN"),
            "kept",
            "plaintext must still resolve"
        );
        // Unreadable, not advisories: an injecting caller must see two variables are missing.
        assert_eq!(warnings.unreadable.len(), 2, "{warnings:?}");
        assert!(warnings.advisories.is_empty(), "{warnings:?}");
        assert!(
            warnings.unreadable.iter().any(|w| w.contains("ALPHA")),
            "no warning named ALPHA: {warnings:?}"
        );
        assert!(
            warnings.unreadable.iter().any(|w| w.contains("BETA")),
            "no warning named BETA: {warnings:?}"
        );
    }

    #[test]
    fn a_bad_user_scope_entry_does_not_break_an_unrelated_project() {
        let fixture = Fixture::new();
        fixture.write_user("BROKEN=gitguardian:!!!not-base64!!!\nSHARED=from-user\n");
        fixture.write_project("DEBUG=true\n");

        let (fields, warnings) = fixture.get_reporting().unwrap();
        assert_eq!(value(&fields, "DEBUG"), "true");
        assert_eq!(value(&fields, "SHARED"), "from-user");
        assert!(
            warnings
                .unreadable
                .iter()
                .any(|warning| warning.contains("BROKEN")),
            "{warnings:?}"
        );
    }

    /// A counting cipher proves no other entry was opened, which a `Fixed` one could not.
    #[test]
    fn reading_a_plaintext_field_ignores_other_entries_entirely() {
        let (fixture, cipher) = counting_fixture();
        // A foreign marker that would error if classified.
        fixture.write_project(&format!(
            "FOREIGN=encrypted:BASE64BLOB\n{}",
            fixture.read_project()
        ));
        assert_eq!(fixture.get_field("DEBUG").unwrap().expose_secret(), "true");
        assert_eq!(
            cipher.decrypts(),
            0,
            "resolving a plaintext field opened another entry"
        );
    }

    #[test]
    fn a_file_with_no_readable_value_is_an_error() {
        let fixture = Fixture::new();
        fixture.write_project("BAD=gitguardian:!!!not-base64!!!\n");
        let error = fixture.get().unwrap_err();
        assert!(format!("{error:#}").contains("BAD"), "{error:#}");
    }

    /// The error names the field and never the value.
    #[test]
    fn a_plaintext_value_that_looks_like_a_reference_is_refused() {
        for value in [
            "encrypted:whatever",
            "varlock(something)",
            "gitguardian:QUJDREVGRw",
            "gitguardian:vault:secret/app",
        ] {
            let fixture = Fixture::new().plaintext();
            let error = fixture.set(&[("TOKEN", value)]).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("TOKEN"), "{message}");
            assert!(!message.contains(value), "the value leaked: {message}");
            assert!(
                !fixture.directory.path().join(".env").exists(),
                "nothing should have been written for {value}"
            );
        }
    }

    /// It becomes a marker, so it reads back correctly.
    #[test]
    fn an_encrypted_value_may_look_like_anything() {
        let fixture = Fixture::new();
        fixture.set(&[("TOKEN", "encrypted:whatever")]).unwrap();
        assert_eq!(
            value(&fixture.get().unwrap(), "TOKEN"),
            "encrypted:whatever"
        );
    }

    #[test]
    fn writing_to_a_file_with_an_unterminated_quote_is_refused() {
        let fixture = Fixture::new().plaintext();
        fixture.write_project("NOTE=\"oops\nAPI_KEY=abc\n");
        let error = fixture.set(&[("GREETING", "hello world")]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("quote"), "{message}");
        assert_eq!(fixture.read_project(), "NOTE=\"oops\nAPI_KEY=abc\n");
        assert_eq!(value(&fixture.get().unwrap(), "API_KEY"), "abc");
    }

    #[test]
    fn appending_a_spaced_value_keeps_the_other_variables() {
        let fixture = Fixture::new().plaintext();
        fixture.write_project("NOTE=\"fine\"\nAPI_KEY=abc\n");
        fixture.set(&[("GREETING", "hello world")]).unwrap();

        let fields = fixture.get().unwrap();
        assert_eq!(value(&fields, "NOTE"), "fine");
        assert_eq!(value(&fields, "API_KEY"), "abc");
        assert_eq!(value(&fields, "GREETING"), "hello world");
    }

    /// A shell would expand it in a file people `source`.
    #[test]
    fn a_shell_active_plaintext_value_is_quoted_and_round_trips() {
        for dangerous in ["p$aw0rd", "$(touch /tmp/pwned)", "`id`", "a;b"] {
            let fixture = Fixture::new().plaintext();
            fixture.set(&[("TOKEN", dangerous)]).unwrap();
            let contents = fixture.read_project();
            assert!(
                !contents.contains(&format!("TOKEN={dangerous}")),
                "written bare: {contents:?}"
            );
            assert_eq!(value(&fixture.get().unwrap(), "TOKEN"), dangerous);
        }
    }

    fn encrypt_all(fixture: &Fixture) -> EncryptOutcome {
        fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), None, false)
            .unwrap()
    }

    /// A value the CLI cannot prompt for can be written to the file and encrypted from there.
    #[test]
    fn a_multiline_value_can_be_encrypted_in_place() {
        let fixture = Fixture::new();
        let pem = "-----BEGIN PRIVATE KEY-----\nfake-line-two\n-----END PRIVATE KEY-----";
        fixture.write_project(&format!("PRIVATE_KEY=\"{pem}\"\n"));

        let outcome = encrypt_all(&fixture);
        assert_eq!(outcome.encrypted, vec!["PRIVATE_KEY".to_string()]);
        assert!(!fixture.read_project().contains("fake-line-two"));
        assert_eq!(value(&fixture.get().unwrap(), "PRIVATE_KEY"), pem);
    }

    /// Comments, ordering and quoting must survive, exactly as for `set`.
    #[test]
    fn encrypting_in_place_preserves_the_document() {
        let fixture = Fixture::new();
        fixture
            .write_project("# header\nPORT=3000   # trailing note\n\nURL='http://x/y'\n# tail\n");
        encrypt_all(&fixture);

        let after = fixture.read_project();
        assert!(after.starts_with("# header\n"), "{after}");
        assert!(after.contains("# trailing note"), "{after}");
        assert!(after.contains("# tail\n"), "{after}");
        assert!(after.contains("URL='gitguardian:"), "{after}");
        let fields = fixture.get().unwrap();
        assert_eq!(value(&fields, "PORT"), "3000");
        assert_eq!(value(&fields, "URL"), "http://x/y");
    }

    /// A fresh nonce for an unchanged value is churn in a committed file.
    #[test]
    fn encrypting_in_place_is_idempotent() {
        let fixture = Fixture::new();
        fixture.write_project("A=one\nB=two\n");
        assert_eq!(encrypt_all(&fixture).encrypted.len(), 2);
        let after_first = fixture.read_project();

        let second = encrypt_all(&fixture);
        assert!(second.encrypted.is_empty(), "{second:?}");
        assert_eq!(second.already_encrypted.len(), 2);
        assert_eq!(fixture.read_project(), after_first, "ciphertext churned");
    }

    /// Encrypting only the winning assignment would leave the other in plaintext.
    #[test]
    fn a_duplicated_key_is_encrypted_at_every_assignment() {
        let fixture = Fixture::new();
        fixture.write_project("A=first\nA=second\n");
        assert_eq!(encrypt_all(&fixture).encrypted.len(), 2);

        let after = fixture.read_project();
        assert!(!after.contains("first"), "{after}");
        assert!(!after.contains("second"), "{after}");
        assert_eq!(after.matches("gitguardian:").count(), 2, "{after}");
        assert_eq!(value(&fixture.get().unwrap(), "A"), "second");
    }

    #[test]
    fn only_the_named_variables_are_encrypted() {
        let fixture = Fixture::new();
        fixture.write_project("KEEP=readable\nSEAL=secret\n");
        let only = std::collections::BTreeSet::from(["SEAL".to_string()]);
        let outcome = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), Some(&only), false)
            .unwrap();

        assert_eq!(outcome.encrypted, vec!["SEAL".to_string()]);
        let after = fixture.read_project();
        assert!(after.contains("KEEP=readable"), "{after}");
        assert!(!after.contains("secret"), "{after}");
    }

    #[test]
    fn a_foreign_marker_is_left_alone_and_reported() {
        let fixture = Fixture::new();
        fixture.write_project("MINE=plain\nTHEIRS=encrypted:dotenvx-blob\n");
        let outcome = encrypt_all(&fixture);

        assert_eq!(outcome.encrypted, vec!["MINE".to_string()]);
        assert_eq!(outcome.warnings.len(), 1, "{outcome:?}");
        assert!(outcome.warnings[0].contains("THEIRS"), "{outcome:?}");
        assert!(
            fixture
                .read_project()
                .contains("THEIRS=encrypted:dotenvx-blob"),
            "the foreign value must be byte-for-byte intact"
        );
    }

    #[test]
    fn a_dry_run_writes_nothing() {
        let fixture = Fixture::new();
        fixture.write_project("A=one\n");
        let before = fixture.read_project();
        let outcome = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), None, true)
            .unwrap();

        assert_eq!(outcome.encrypted, vec!["A".to_string()], "still reported");
        assert_eq!(fixture.read_project(), before, "the file must be untouched");
    }

    #[test]
    fn encrypting_a_file_with_an_unterminated_quote_is_refused() {
        let fixture = Fixture::new();
        fixture.write_project("NOTE=\"oops\nA=1\n");
        let before = fixture.read_project();
        let error = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), None, false)
            .unwrap_err();
        assert!(format!("{error:#}").contains("line 1"), "{error:#}");
        assert_eq!(fixture.read_project(), before);
    }

    #[test]
    fn a_plaintext_backend_cannot_encrypt_in_place() {
        let fixture = Fixture::new().plaintext();
        fixture.write_project("A=one\n");
        let error = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), None, false)
            .unwrap_err();
        assert!(format!("{error:#}").contains("cipher"), "{error:#}");
    }

    #[test]
    fn a_pass_with_nothing_to_encrypt_never_asks_for_a_cipher() {
        // `Unavailable` bails if asked for a cipher.
        let fixture = Fixture::new();
        let blind = FileBackend {
            encryption: Encryption::Unavailable,
            user_path: fixture.backend.user_path.clone(),
            system_path: fixture.backend.system_path.clone(),
            project_path_is_default: false,
        };
        fixture.write_project("FOREIGN=encrypted:dotenvx\nEMPTY=\n");
        let before = fixture.read_project();

        let outcome = blind
            .encrypt_in_place(&fixture.project_path(), None, false)
            .expect("a pass with nothing to encrypt must not need a cipher");
        assert!(outcome.encrypted.is_empty(), "{outcome:?}");
        assert_eq!(fixture.read_project(), before);

        let plain = Fixture::new().plaintext();
        plain.write_project("FOREIGN=encrypted:dotenvx\n");
        let outcome = plain
            .backend
            .encrypt_in_place(&plain.project_path(), None, false)
            .expect("no cipher is needed when nothing is plaintext");
        assert!(outcome.encrypted.is_empty(), "{outcome:?}");
    }

    /// Sealing an empty value would device-lock a placeholder.
    #[test]
    fn encrypting_skips_empty_values() {
        let fixture = Fixture::new();
        let source = "API_KEY= # get this from the dashboard\nREAL=secret-ish\n";
        fixture.write_project(source);

        let outcome = encrypt_all(&fixture);
        assert_eq!(outcome.encrypted, vec!["REAL".to_string()]);
        let after = fixture.read_project();
        assert!(
            after.starts_with("API_KEY= # get this from the dashboard\n"),
            "{after}"
        );
        assert!(after.contains("REAL=gitguardian:"), "{after}");

        let fixture = Fixture::new();
        fixture.write_project("API_KEY=\n");
        let only = std::collections::BTreeSet::from(["API_KEY".to_string()]);
        let outcome = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), Some(&only), false)
            .unwrap();
        assert!(outcome.encrypted.is_empty(), "{outcome:?}");
        assert!(
            outcome.warnings.iter().any(|w| w.contains("no value")),
            "{outcome:?}"
        );
    }

    /// Sealing the quoted half would leave the rest on disk in cleartext.
    #[test]
    fn a_value_that_is_partly_outside_its_quotes_blocks_both_writers() {
        let fixture = Fixture::new();
        let source = "API_KEY='super'password\nPORT=80\n";
        fixture.write_project(source);

        let error = fixture
            .backend
            .encrypt_in_place(&fixture.project_path(), None, false)
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("outside its quotes"), "{message}");
        assert_eq!(fixture.read_project(), source, "the file was rewritten");

        let error = fixture.set(&[("OTHER", "value")]).unwrap_err();
        assert!(format!("{error:#}").contains("line 1"), "{error:#}");
        assert_eq!(fixture.read_project(), source, "the file was rewritten");

        let (fields, warnings) = fixture.get_reporting().unwrap();
        assert!(!fields.contains_key("API_KEY"), "{fields:?}");
        assert!(
            warnings
                .advisories
                .iter()
                .any(|warning| warning.contains("API_KEY")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_field_that_appears_after_the_overwrite_check_is_not_silently_replaced() {
        let fixture = Fixture::new();
        // At prompt time the file had no API_KEY.
        let confirmed = std::collections::BTreeSet::new();
        // Another process adds it in the meantime.
        fixture.write_project("API_KEY=written-by-someone-else\n");

        let fields = BTreeMap::from([(
            "API_KEY".to_string(),
            SecretString::from(FAKE_VALUE.to_string()),
        )]);
        let error = fixture
            .backend
            .set_secrets(&fixture.project_path(), &fields, Some(&confirmed))
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("API_KEY"), "{message}");
        assert!(message.contains("never confirmed"), "{message}");
        assert_eq!(
            fixture.read_project(),
            "API_KEY=written-by-someone-else\n",
            "the other process's value was replaced anyway"
        );

        // Having been shown the name, the same write goes through.
        let confirmed = std::collections::BTreeSet::from(["API_KEY".to_string()]);
        fixture
            .backend
            .set_secrets(&fixture.project_path(), &fields, Some(&confirmed))
            .unwrap();
        assert_eq!(value(&fixture.get().unwrap(), "API_KEY"), FAKE_VALUE);
    }

    #[test]
    fn the_field_not_found_hint_names_every_file_that_could_be_hiding_it() {
        let fixture = Fixture::new();
        fixture.write_user("USER_NOTE=\"oops\nUSER_KEY=abc\nUSER_END=\"fine\n");
        fixture.write_project("NOTE=\"oops\nAPI_KEY=abc\nEND=\"fine\n");

        let error = fixture.get_field("NEVER_SET").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("field not found"), "{message}");
        assert!(
            message.contains("may be defined but invisible"),
            "{message}"
        );
        assert!(message.contains("user-secrets.env"), "{message}");
        assert!(message.contains("global scope"), "{message}");
        assert!(message.contains("project scope"), "{message}");
    }

    #[test]
    fn debug_output_shows_no_secrets() {
        let fixture = Fixture::new();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        let debug = format!("{:?}", fixture.backend);
        assert!(!debug.contains(FAKE_VALUE), "{debug}");
    }

    #[test]
    fn delete_removes_the_line_and_leaves_the_document_alone() {
        let fixture = Fixture::new();
        fixture.write_project("# keep me\nPORT=3000\n\nGONE=bye\nKEEP=here\n");

        let outcome = fixture.delete(&["GONE"]).unwrap();
        assert_eq!(outcome.removed, ["GONE"]);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            fixture.read_project(),
            "# keep me\nPORT=3000\n\nKEEP=here\n"
        );
    }

    /// Otherwise the file could only be fixed on the machine that wrote it.
    #[test]
    fn delete_does_not_need_the_key_the_value_was_sealed_with() {
        let fixture = Fixture::new();
        fixture.set(&[("THEIRS", FAKE_VALUE)]).unwrap();
        let sealed = fixture.read_project();
        assert!(sealed.contains("gitguardian:"), "{sealed}");

        let fixture = fixture.without_a_key();
        assert!(fixture.get_field("THEIRS").is_err());

        fixture.delete(&["THEIRS"]).unwrap();
        assert_eq!(fixture.read_project(), "");
    }

    #[test]
    fn delete_refuses_to_empty_a_file() {
        let fixture = Fixture::new();
        fixture.write_project("KEEP=here\n");

        let plan = DeletePlan {
            targets: Vec::new(),
            digest: String::new(),
        };
        let error = fixture
            .backend
            .delete_planned(&fixture.project_path(), &plan)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("never a whole file"),
            "{error:#}"
        );
        assert_eq!(fixture.read_project(), "KEEP=here\n");
    }

    /// A `set` between plan and write must not have its new ciphertext deleted.
    #[test]
    fn delete_refuses_a_file_that_changed_since_the_plan() {
        let fixture = Fixture::new();
        fixture.write_project("TOKEN=old\nKEEP=here\n");
        let plan = fixture.plan(&["TOKEN"]).unwrap();

        // The value under the same name is replaced while the prompt waits.
        fixture.write_project("TOKEN=freshly-rotated\nKEEP=here\n");

        let error = fixture
            .backend
            .delete_planned(&fixture.project_path(), &plan)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("changed since the delete was prepared"),
            "{error:#}"
        );
        assert_eq!(
            fixture.read_project(),
            "TOKEN=freshly-rotated\nKEEP=here\n",
            "the never-confirmed value was deleted"
        );
    }

    /// The plan is refused outright rather than partly applied.
    #[test]
    fn delete_refuses_a_file_that_gained_a_variable_since_the_plan() {
        let fixture = Fixture::new();
        fixture.write_project("TOKEN=old\n");
        let plan = fixture.plan(&["TOKEN"]).unwrap();
        fixture.write_project("TOKEN=old\nAPPENDED=by-another-process\n");

        assert!(
            fixture
                .backend
                .delete_planned(&fixture.project_path(), &plan)
                .is_err()
        );
        assert_eq!(
            fixture.read_project(),
            "TOKEN=old\nAPPENDED=by-another-process\n"
        );
    }

    #[test]
    fn delete_says_when_a_name_was_assigned_more_than_once() {
        let fixture = Fixture::new();
        fixture.write_project("DUP=one\nKEEP=here\nDUP=two\n");

        let outcome = fixture.delete(&["DUP"]).unwrap();
        assert_eq!(outcome.removed, ["DUP"]);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert!(
            outcome.warnings[0].contains("assigned 2 times"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(fixture.read_project(), "KEEP=here\n");
    }

    #[test]
    fn delete_deduplicates_a_repeated_name() {
        let fixture = Fixture::new();
        fixture.write_project("A_KEY=1\nB_KEY=2\n");

        let outcome = fixture.delete(&["A_KEY", "A_KEY"]).unwrap();
        assert_eq!(outcome.removed, ["A_KEY"]);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fixture.read_project(), "B_KEY=2\n");
    }

    /// The note beside the value is text the user wrote and did not name.
    #[test]
    fn delete_keeps_an_inline_comment_and_says_so() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY=abc # obtain from the break-glass owner\nKEEP=1\n");

        let outcome = fixture.delete(&["API_KEY"]).unwrap();
        assert_eq!(outcome.removed, ["API_KEY"]);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert!(
            outcome.warnings[0].contains("kept the comment that followed 'API_KEY'"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            fixture.read_project(),
            "# obtain from the break-glass owner\nKEEP=1\n"
        );
    }

    /// Removing it would silently destroy the swallowed variables.
    #[test]
    fn delete_refuses_an_entry_that_swallowed_other_assignments() {
        let fixture = Fixture::new();
        let original = "A=\"oops\nB=keepme\nc=fine\"\nD=keep\n";
        fixture.write_project(original);

        let error = fixture.delete(&["A"]).unwrap_err();
        let message = format!("{error:#}");
        // Including the one-character and lowercase names the heuristic misses.
        assert!(message.contains("'A'"), "{message}");
        assert!(message.contains("B, c"), "{message}");
        assert!(message.contains("fix the quoting first"), "{message}");
        assert_eq!(fixture.read_project(), original, "the file was rewritten");
    }

    #[test]
    fn delete_all_refuses_a_file_with_a_swallowed_assignment() {
        let fixture = Fixture::new();
        let original = "A=\"oops\nB=keepme\"\nD=keep\n";
        fixture.write_project(original);

        assert!(fixture.delete(&[]).is_err());
        assert_eq!(fixture.read_project(), original);
    }

    /// A PEM key is one multi-line entry and must stay deletable.
    #[test]
    fn delete_removes_a_multiline_value_that_is_not_a_swallowed_assignment() {
        let fixture = Fixture::new();
        fixture.write_project(
            "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw==\n-----END PRIVATE KEY-----\"\nKEEP=1\n",
        );

        let outcome = fixture.delete(&["PRIVATE_KEY"]).unwrap();
        assert_eq!(outcome.removed, ["PRIVATE_KEY"]);
        assert_eq!(fixture.read_project(), "KEEP=1\n");
    }

    /// Removing a line moves what the stray quote swallows.
    #[test]
    fn delete_refuses_a_file_whose_quoting_is_already_ambiguous() {
        let fixture = Fixture::new();
        let original = "BROKEN=\"oops\nTARGET=gone\nEND=\"fine\n";
        fixture.write_project(original);

        let error = fixture.delete(&["TARGET"]).unwrap_err();
        assert!(format!("{error:#}").contains("fix line"), "{error:#}");
        assert_eq!(fixture.read_project(), original);
    }

    #[test]
    fn a_hidden_assignment_is_reported_as_a_quote_problem_not_as_a_missing_name() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY='super'password\nKEEP=1\n");

        let error = fixture.plan(&["API_KEY"]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("fix line 1"), "{message}");
        assert!(!message.contains("does not set"), "{message}");
    }

    #[test]
    fn delete_never_touches_the_user_scope_file() {
        let fixture = Fixture::new();
        fixture.write_user("USER_ONLY=theirs\n");
        fixture.write_project("KEEP=here\n");

        let error = fixture.plan(&["USER_ONLY"]).unwrap_err();
        assert!(
            format!("{error:#}").contains("does not set USER_ONLY"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.backend.user_path.as_ref().unwrap()).unwrap(),
            "USER_ONLY=theirs\n"
        );
    }

    /// `LockedFile::open` creates what it opens, so the missing file must be caught first.
    #[test]
    fn delete_on_a_missing_file_says_so_and_creates_nothing() {
        let fixture = Fixture::new();

        for keys in [&["ANY"][..], &[][..]] {
            let error = fixture.plan(keys).unwrap_err();
            assert!(format!("{error:#}").contains("does not exist"), "{error:#}");
        }
        assert!(!fixture.directory.path().join(".env").exists());
    }
    #[test]
    fn a_repo_value_is_visible_from_a_checkout_that_does_not_define_it() {
        let fixture = Fixture::new().plaintext();
        fixture.write_repo("SHARED=from-repo\n");
        fixture.write_project("LOCAL=from-project\n");

        let fields = fixture
            .backend
            .get_secrets(&fixture.project_path())
            .unwrap()
            .0;
        assert_eq!(fields["SHARED"].expose_secret(), "from-repo");
        assert_eq!(fields["LOCAL"].expose_secret(), "from-project");
    }

    #[test]
    fn a_project_file_overrides_the_repo_one_variable_at_a_time() {
        // A worktree overrides one variable and keeps the rest the repository holds.
        let fixture = Fixture::new().plaintext();
        fixture.write_repo("API_URL=https://shared\nTOKEN=shared-token\n");
        fixture.write_project("API_URL=https://this-branch\n");

        let fields = fixture
            .backend
            .get_secrets(&fixture.project_path())
            .unwrap()
            .0;
        assert_eq!(fields["API_URL"].expose_secret(), "https://this-branch");
        assert_eq!(fields["TOKEN"].expose_secret(), "shared-token");
    }

    #[test]
    fn the_repo_scope_sits_between_user_and_project() {
        let fixture = Fixture::new().plaintext();
        fixture.write_user("V=from-user\nONLY_USER=u\n");
        fixture.write_repo("V=from-repo\nONLY_REPO=r\n");
        fixture.write_project("V=from-project\n");

        let fields = fixture
            .backend
            .get_secrets(&fixture.project_path())
            .unwrap()
            .0;
        assert_eq!(fields["V"].expose_secret(), "from-project");
        assert_eq!(fields["ONLY_REPO"].expose_secret(), "r");
        assert_eq!(fields["ONLY_USER"].expose_secret(), "u");
    }
    #[test]
    fn the_system_scope_is_the_least_specific_of_the_four() {
        let fixture = Fixture::new().plaintext();
        fixture.write_system("V=from-system\nONLY_SYSTEM=s\n");
        fixture.write_user("V=from-user\n");
        fixture.write_repo("V=from-repo\n");
        fixture.write_project("V=from-project\n");

        let fields = fixture
            .backend
            .get_secrets(&fixture.project_path())
            .unwrap()
            .0;
        assert_eq!(fields["V"].expose_secret(), "from-project");
        assert_eq!(fields["ONLY_SYSTEM"].expose_secret(), "s");
    }

    #[test]
    fn a_system_value_reaches_a_directory_with_no_files_of_its_own() {
        let fixture = Fixture::new().plaintext();
        fixture.write_system("SHARED=from-system\n");

        let fields = fixture
            .backend
            .get_secrets(&fixture.project_path())
            .unwrap()
            .0;
        assert_eq!(fields["SHARED"].expose_secret(), "from-system");
    }

    /// What `get --global` asks: what this file sets, not what a command would see.
    fn system_path(fixture: &Fixture) -> String {
        fixture
            .backend
            .system_path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretString> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), SecretString::from(value.to_string())))
            .collect()
    }

    #[test]
    fn a_sealed_value_is_refused_in_the_system_scope() {
        let fixture = Fixture::new();
        let error = fixture
            .backend
            .set_secrets(
                &system_path(&fixture),
                &fields(&[("API_KEY", FAKE_VALUE)]),
                None,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("--plain"), "{error:#}");
        assert!(!fixture.backend.system_path.as_ref().unwrap().exists());

        fixture.write_system("API_KEY=plain\n");
        let error = fixture
            .backend
            .encrypt_in_place(&system_path(&fixture), None, false)
            .unwrap_err();
        assert!(format!("{error:#}").contains("--plain"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn a_plaintext_system_value_is_written_readable_by_everyone() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new().plaintext();
        let store = fixture.directory.path().join("etc-gitguardian");
        let path = store.join("secrets.env");
        fixture.backend.system_path = Some(path.clone());
        fixture
            .backend
            .set_secrets(path.to_str().unwrap(), &fields(&[("PORT", "80")]), None)
            .unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store), 0o755);
        assert_eq!(mode(&path), 0o644);
    }

    /// Root's `/etc/gitguardian` at 0700 must not break every other user's reads.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_system_scope_is_skipped_with_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        // Root reads it regardless.
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let mut fixture = Fixture::new();
        let store = fixture.directory.path().join("etc-gitguardian");
        std::fs::create_dir(&store).unwrap();
        std::fs::write(store.join("secrets.env"), "SYSTEM=1\n").unwrap();
        fixture.backend.system_path = Some(store.join("secrets.env"));
        fixture.write_project("PROJECT=1\n");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = fixture.get_reporting();
        let field = fixture.get_field("PROJECT");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();

        let (fields, warnings) = result.unwrap();
        assert_eq!(value(&fields, "PROJECT"), "1");
        assert!(!fields.contains_key("SYSTEM"));
        assert!(
            warnings
                .advisories
                .iter()
                .any(|line| line.contains("skipped the system scope file")),
            "{warnings:?}"
        );
        assert!(warnings.unreadable.is_empty(), "{warnings:?}");
        assert_eq!(field.unwrap().expose_secret(), "1");
    }

    /// Another user who can write the system scope could set variables for everyone.
    #[cfg(unix)]
    #[test]
    fn a_system_scope_others_can_write_is_skipped_with_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new().plaintext();
        let store = fixture.directory.path().join("etc-gitguardian");
        std::fs::create_dir(&store).unwrap();
        let path = store.join("secrets.env");
        std::fs::write(&path, "PLANTED=1\n").unwrap();
        fixture.backend.system_path = Some(path.clone());
        fixture.write_project("PROJECT=1\n");

        for (file_mode, directory_mode) in [(0o664, 0o755), (0o644, 0o777)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(file_mode)).unwrap();
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(directory_mode))
                .unwrap();
            let (fields, warnings) = fixture.get_reporting().unwrap();
            assert!(
                !fields.contains_key("PLANTED"),
                "{file_mode:o}/{directory_mode:o}"
            );
            assert!(
                warnings
                    .advisories
                    .iter()
                    .any(|line| line.contains("writable by users other than its owner")),
                "{warnings:?}"
            );
        }

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(value(&fixture.get().unwrap(), "PLANTED"), "1");
    }

    /// A file the user named is still an error when they cannot read it.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_project_file_is_still_an_error() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let fixture = Fixture::new();
        fixture.write_project("PROJECT=1\n");
        let path = fixture.directory.path().join(".env");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = fixture.get_reporting();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn reading_one_file_merges_nothing_else_in() {
        let fixture = Fixture::new().plaintext();
        fixture.write_user("V=from-user\nONLY_USER=u\n");
        fixture.write_project("V=from-project\n");

        let user_path = fixture.backend.user_path.clone().unwrap();
        let fields = fixture
            .backend
            .get_secrets_from_file(user_path.to_str().unwrap())
            .unwrap()
            .0;
        assert_eq!(fields["V"].expose_secret(), "from-user");
        assert_eq!(fields.len(), 2, "{fields:?}");
    }
}
