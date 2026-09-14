//! The `file` provider: secrets kept in dotenv files, encrypted value by
//! value with a device-local key.
//!
//! Three scopes, resolved like git config — most specific wins, variable by
//! variable:
//!
//! | scope   | file                                          |
//! |---------|-----------------------------------------------|
//! | user    | `<config dir>/gitguardian/secrets.env`        |
//! | repo    | `<common git dir>/gitguardian/secrets.env`    |
//! | project | `./.env`, or whatever `--path` names           |
//!
//! The merge is per variable, not per file: the repo scope holds what every
//! worktree of a repository shares, and a `.env` beside a particular checkout
//! overrides only the names it sets. A branch pointing at a different backend
//! is one line in one file, not a copy of the whole set.
//!
//! There is no machine scope, and the repo scope is the only git awareness in
//! this crate: see [`repo`] for what it does and does not read.
//!
//! # What is zeroized, and what is not
//!
//! A stated limit, so nobody reads the care taken in one place as a guarantee
//! about the other.
//!
//! **Key material is zeroized.** The keyring blob is read into a `Zeroizing`
//! buffer, [`crypto::Keyset::to_bytes`] reserves its exact capacity so no
//! reallocation leaves a copy behind, and decrypted ciphertext is handled
//! without ever moving the bytes into a `FromUtf8Error` (see
//! [`FileBackend::open`]).
//!
//! **Plaintext values are not.** They live in ordinary `String`s from the moment
//! a file is read to the moment a command prints or injects them:
//! `LockedFile::read` returns the whole file as a `String`, `Entry::value`
//! returns another, `Resolved::value` another, and `Document::to_string` builds
//! the replacement document as one more. Under `set --plain`, and for every
//! plaintext entry of a mixed file, a secret therefore sits in several heap
//! allocations that are dropped without being wiped, and the shell hook
//! accumulates every value for a directory into one `String` before printing it.
//!
//! This is a deliberate limit rather than an oversight, and the reason is that
//! closing it is not local: it means a value type that is zeroized *and*
//! byte-range-editable threaded through the whole document model, replacing
//! `String` in [`crate::dotenv`] as well as here. The exposure it would buy back
//! is a copy in this process's own heap — readable by a debugger attached to
//! this process, or in a core dump. It is worth doing; it is not worth doing
//! halfway, because a half-migrated path reads as a guarantee that is not there.
//! Until then: the process is short-lived, and the file the value came from is
//! on the same disk.

pub(crate) mod atomic;
pub(crate) mod crypto;
pub(crate) mod envelope;
pub(crate) mod keystore;
mod repo;
pub mod trust;

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

/// Directory holding the user-scope file, under the platform's config
/// directory: `~/.config` (XDG) on Linux, `~/Library/Application Support` on
/// macOS, the roaming app-data folder on Windows.
const USER_SCOPE_DIR: &str = "gitguardian";
const USER_SCOPE_FILE: &str = "secrets.env";
/// Lock file beside it, guarding this user's keyring writes.
const KEYSET_LOCK_FILE: &str = "keyset.lock";

/// The repo-scope file for the repository containing `directory`, or `None`
/// when it is not in one.
///
/// One store per repository, shared by all its worktrees; see [`repo`].
pub fn repo_scope_path(directory: &Path) -> Option<PathBuf> {
    repo::scope_path(directory)
}

/// The user-scope file for this machine's current user.
pub fn user_scope_path() -> Result<PathBuf> {
    Ok(config_root()?.join(USER_SCOPE_DIR).join(USER_SCOPE_FILE))
}

/// The per-user directory an application keeps its own files in.
///
/// On Apple platforms that is `~/Library/Application Support`: the strategy's
/// `config_dir` is `~/Library/Preferences`, which belongs to the defaults
/// system, not to files an application writes itself. Elsewhere it is the
/// usual config directory — `$XDG_CONFIG_HOME` (default `~/.config`) on Linux,
/// the roaming app-data folder on Windows.
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

/// Lock file serialising this user's OS-keyring writes.
///
/// In the gitguardian directory under the config root, which is where the
/// user-scope file lives too — but derived from the **operating system user**,
/// not from `$HOME`/`$XDG_CONFIG_HOME`.
///
/// That distinction is the whole point. The thing this lock protects is one
/// keyring entry, `(gitguardian, file:keyset)`, and the credential store scopes
/// that entry by login user: there is exactly one of it per OS user, whatever
/// the environment says. A lock path taken from the environment is therefore a
/// lock on the wrong thing — two commands run by the same user under
/// `XDG_CONFIG_HOME=/a` and `/b` take *different* locks over *one* keyring
/// entry, both find it empty, both mint a master key, and the second store
/// replaces the first. The value the first one had already encrypted is then
/// unreadable for good, which is the exact loss [`keystore`]'s lock exists to
/// prevent.
///
/// The passwd entry's home directory is the OS user's own answer to "where do
/// your files live", so in the ordinary case — where `$HOME` is that same
/// directory — this is the path it always was. It only diverges when the
/// environment has been redirected, which is precisely when it must.
fn keyset_lock_path() -> Result<PathBuf> {
    let root = match os_user_home() {
        Some(home) => config_root_under(&home),
        // No passwd entry (a uid with no user, some minimal containers): fall
        // back to the environment rather than refusing to encrypt at all. The
        // two are the same directory whenever the environment is honest.
        None => config_root()?,
    };
    Ok(root.join(USER_SCOPE_DIR).join(KEYSET_LOCK_FILE))
}

/// The per-user application directory under an explicit home directory.
///
/// The same layout [`config_root`] picks, with the home directory supplied
/// instead of read from the environment.
fn config_root_under(home: &Path) -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        home.join("Library").join("Application Support")
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        // The XDG default for `$XDG_CONFIG_HOME`.
        home.join(".config")
    }
}

/// The current OS user's home directory according to the password database.
///
/// Deliberately not `$HOME`: see [`keyset_lock_path`]. `None` when the user has
/// no passwd entry, or on a platform with no password database.
#[cfg(unix)]
fn os_user_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsString};
    use std::os::unix::ffi::OsStringExt;

    let mut buffer = vec![0u8; 1024];
    loop {
        // SAFETY: `getpwuid_r` writes only into the two buffers it is given,
        // both of which outlive the call, and reports everything through its
        // return value and `found`. `passwd` is plain data, so an all-zero
        // value is a valid starting point.
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
        // SAFETY: `found` is non-null, so `passwd` was filled in and `pw_dir`
        // points at a NUL-terminated string inside `buffer`, which is still
        // alive here. The bytes are copied out before `buffer` is dropped.
        let home = unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes().to_vec();
        let home = PathBuf::from(OsString::from_vec(home));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(not(unix))]
fn os_user_home() -> Option<PathBuf> {
    None
}

/// Which file a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    User,
    Repo,
    Project,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::User => "user",
            Scope::Repo => "repo",
            Scope::Project => "project",
        })
    }
}

/// One scope's file, parsed.
struct Layer {
    scope: Scope,
    path: PathBuf,
    document: Document,
}

/// How the backend seals the values it writes.
#[derive(Clone)]
enum Encryption {
    /// Encrypt with this device's keyset, generating one on first write.
    Device,
    /// Write readable plaintext (`set --plain`).
    Plaintext,
    /// A caller-supplied cipher. Tests only: it is what lets them exercise the
    /// encrypted path without the OS keyring.
    #[cfg(test)]
    Fixed(Arc<dyn Cipher + Send + Sync>),
    /// A device whose keyset cannot be loaded. Tests only, and deterministic:
    /// standing in for a missing keyring with `Device` would reach the
    /// developer's real login keychain.
    #[cfg(test)]
    Unavailable,
}

/// The `file` provider's backend.
#[derive(Clone)]
pub(crate) struct FileBackend {
    encryption: Encryption,
    /// The user-scope file, resolved once. `None` when the platform has no
    /// usable config directory, which just means "no user scope".
    user_path: Option<PathBuf>,
}

// No cipher, no key material, no paths beyond what the caller passed in.
impl std::fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackend")
            .field("user_path", &self.user_path)
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
    pub(crate) fn new(encrypt: bool) -> Self {
        FileBackend {
            encryption: if encrypt {
                Encryption::Device
            } else {
                Encryption::Plaintext
            },
            user_path: user_scope_path().ok(),
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

    /// The cipher for an encrypt-in-place pass.
    ///
    /// `None` means "no key on this device yet, and this run must not make
    /// one": a dry run is a preview the user may answer `n` to, and creating
    /// the device key is not something declining undoes. Reading the keyring
    /// without writing to it still surfaces an unusable credential store
    /// before the prompt rather than after it.
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

    /// The cipher used to open existing values.
    ///
    /// Called only once a value actually turns out to be encrypted, so reading
    /// a plaintext-only file never touches the keyring.
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

    /// Every value visible at `project_path`, user scope included.
    ///
    /// Returns the values that could be read plus a [`ReadWarnings`] describing
    /// what it could not. One unreadable entry must not take a whole file down
    /// with it: a committed `.env` carrying a teammate's device-local markers, or
    /// one bad entry in the user-scope file, would otherwise break every command
    /// in every project on the machine — including the plaintext half. A file
    /// where *nothing* could be read is still an error, not an empty result.
    ///
    /// The two kinds of warning are kept apart because they mean different
    /// things to different callers: a caller that *prints* what it read can
    /// carry on regardless, while a caller that *injects* the result into a
    /// child's environment must refuse rather than hand it a variable-shaped
    /// hole. See [`ReadWarnings::unreadable`].
    pub(crate) fn get_secrets(
        &self,
        project_path: &str,
    ) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
        let layers = self.layers(Path::new(project_path))?;
        if layers.is_empty() {
            return Err(SecretError::SecretNotFound {
                path: project_path.to_string(),
            }
            .into());
        }
        // A stray quote loses variables at parse time, so the read side has to
        // say so too — refusing to write is no help to `get` and `run`.
        // Every problem in every layer, not just the worst one per layer: this
        // is the reporting path, and a file can be broken in two places.
        let advisories = layers
            .iter()
            .flat_map(|layer| {
                layer
                    .document
                    .quote_problems()
                    .into_iter()
                    .map(|problem| format!("{}: {problem}", layer.path.display()))
            })
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

    /// Which scope each visible field's value came from, for the same read
    /// `get_secrets` does.
    ///
    /// Nothing is decrypted: the answer is which file won the merge, which is
    /// known before any value is opened. A reader that prints values wants to
    /// be able to say *why* this value and not the repository's.
    pub(crate) fn field_scopes(&self, project_path: &str) -> Result<BTreeMap<String, String>> {
        let layers = self.layers(Path::new(project_path))?;
        Ok(merge(&layers)
            .into_iter()
            .map(|(field, resolved)| (field.to_string(), resolved.scope.to_string()))
            .collect())
    }

    /// One value visible at `project_path`.
    ///
    /// Decrypts only the field asked for. Reading `DEBUG` must not fail because
    /// some unrelated entry is unreadable, and must not touch the keyring at
    /// all when the value it wants is plaintext.
    pub(crate) fn get_secret(&self, project_path: &str, field: &str) -> Result<SecretString> {
        let layers = self.layers(Path::new(project_path))?;
        if layers.is_empty() {
            return Err(SecretError::SecretNotFound {
                path: project_path.to_string(),
            }
            .into());
        }
        let merged = merge(&layers);
        let Some(resolved) = merged.get(field) else {
            // A field can be missing because a stray quote swallowed it, which
            // looks identical to "never set" unless we say so. `get_secret` has
            // no warning channel, so the hint goes in the error.
            //
            // Every layer with a problem is listed, and the wording says
            // "may be": there is no way to tell which file was supposed to
            // define a field that no file defines, so reporting only the first
            // — the user scope, which is searched first — sent the user off to
            // fix a file that has nothing to do with the field they asked for.
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
            let error: anyhow::Error = SecretError::FieldNotFound {
                field: field.to_string(),
            }
            .into();
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

    /// The names defined at `project_path` itself, ignoring the user scope.
    ///
    /// Used to warn about an overwrite before `set` writes, so it must not
    /// decrypt anything or touch the keyring.
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

    /// Create or update `fields` in the file at `path`.
    ///
    /// Every value is encrypted before anything is written, so a failure on
    /// the last field leaves the file exactly as it was.
    /// Returns any warning the write raised — never a reason it failed, which
    /// is an `Err` — so the caller can show it without this crate doing I/O.
    ///
    /// `expected_existing`, when given, is the set of names the caller has
    /// already told the user would be overwritten. Any *other* name that turns
    /// out to exist means the file changed between the prompt and the lock, and
    /// the write is refused: the confirmation the user gave was for a different
    /// file. `None` skips the check, for a caller that asked no question
    /// (`--yes`).
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

        let cipher = self.write_cipher()?;
        if cipher.is_none() {
            // Plaintext only: an encrypted value becomes a marker, which is a
            // reference by construction.
            for (key, value) in fields {
                reject_unstorable_plaintext(key, value.expose_secret())?;
            }
        }

        let mut locked = atomic::LockedFile::open(Path::new(path))?;
        let contents = locked.read()?;
        let mut document = Document::parse(&contents);
        if let Some(expected) = expected_existing {
            confirm_still_current(path, &document, fields, expected)?;
        }
        match document.quote_problem() {
            // Appending is exactly what makes this one worse: a new quoted value
            // hands the stray quote the partner it was missing.
            Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
                "{path}: {problem}. Writing to this file would let that quote pair with one of \
                 ours, silently swallowing the variables in between — no bytes are lost, but \
                 values disappear. Fix line {} first",
                problem.line()
            ),
            // The malformed line is not an entry, so writing the same name would
            // append a second assignment and leave the readable half of the
            // broken one on disk — exactly the stale-plaintext hazard a
            // duplicated key has.
            Some(problem @ QuoteProblem::TrailingAfterQuote { .. }) => bail!(
                "{path}: {problem}. Refusing to write to a file with a line whose value is \
                 partly outside its quotes; fix line {} first",
                problem.line()
            ),
            // Already misparsed, and only a heuristic, so this must not block a
            // legitimate multi-line value. The caller sees it via `warnings`.
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
        // Only now, with every value in hand, is the document touched.
        for (key, text) in rendered {
            // Say so when a key was assigned more than once: every assignment
            // is rewritten, but the user was told one field would be
            // overwritten and their file just lost more lines than that.
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

    /// Encrypt the plaintext values at `path`, in place.
    ///
    /// The whole read-modify-write happens under one lock: doing it as a read
    /// followed by a write would let a concurrent `set` land in between, and the
    /// second half would then re-encrypt a value it never read.
    ///
    /// Values that are already references are left byte-for-byte alone — this is
    /// idempotent, and re-running it must not churn ciphertext or spend a fresh
    /// nonce on a value that already has one. `only`, when given, restricts the
    /// pass to those names.
    pub(crate) fn encrypt_in_place(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
        dry_run: bool,
    ) -> Result<EncryptOutcome> {
        // Before anything that has a side effect: there is nothing to encrypt
        // in a file that is not there, and both of the next two steps would
        // leave a trace of a command whose whole output is "nothing to
        // encrypt" — `LockedFile::open` creates the file, and minting the
        // device key is not undone by declining the prompt.
        if std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(EncryptOutcome::default());
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

        // Loaded on first need, never up front: `encrypt_cipher(false)` mints
        // this device's master key, and a pass over a file with nothing to seal
        // must not have that side effect any more than a dry run does.
        let mut cipher: Option<Arc<dyn Cipher + Send + Sync>> = None;
        let mut cipher_loaded = false;
        let changed = document.map_values(|key, value| -> Result<Option<String>> {
            if only.is_some_and(|only| !only.contains(key)) {
                return Ok(None);
            }
            match classify(value) {
                // An empty value holds no secret, and sealing it device-locks a
                // placeholder for nothing: `API_KEY= # from the dashboard` would
                // become unreadable on every other machine while still carrying
                // no value. `set` refuses an empty value for the same reason.
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
                    // A dry run on a device with no keyset yet has nothing to
                    // encrypt *with*, and minting the key is the side effect
                    // this pass exists to avoid. Naming the value is all the
                    // preview needs.
                    let Some(cipher) = &cipher else {
                        return Ok(None);
                    };
                    let marker = cipher
                        .encrypt(key, value.as_bytes())
                        .with_context(|| format!("encrypting '{key}'"))?
                        .to_marker();
                    Ok(Some(marker))
                }
                // Already a reference: leave the bytes untouched.
                Ok(ValueKind::Encrypted(_)) => {
                    outcome.already_encrypted.push(key.to_string());
                    Ok(None)
                }
                // Another tool's marker. Encrypting it would bury a value we
                // cannot read inside one we can, so it is skipped and named.
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

    /// What a delete would do to the file at `path`, without touching it.
    ///
    /// The first of two phases, and the reason there are two: the confirmation
    /// prompt cannot be held inside the write lock — an unanswered prompt would
    /// block every other gitguardian process on the file for as long as the
    /// terminal sits there — so the decision is necessarily made against an
    /// unlocked read. What makes that safe is that the plan records a digest of
    /// the file it was made from, and [`Self::delete_planned`] refuses to write
    /// if the file has changed since.
    ///
    /// Everything the caller needs to reject the file happens here, before any
    /// question is put to the user: a missing file, a fatal quote problem, a
    /// name the file does not set, or an entry whose removal would destroy a
    /// variable nobody named.
    pub(crate) fn plan_delete(
        &self,
        path: &str,
        only: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<DeletePlan> {
        // Nothing to remove from a file that is not there. Checked before the
        // enumeration rather than inferred from it: an empty name list means
        // "this file sets nothing", and reporting that for a mistyped `--path`
        // tells the user their secrets were already gone.
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
            // A name the file does not set is a typo, and it is reported only
            // after the quote check above: a stray quote hides real
            // assignments from the parser, and "does not set API_KEY" for a
            // variable `grep` plainly shows sends the user looking in the
            // wrong place entirely.
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

        // A `BTreeSet` throughout, so naming the same variable twice cannot
        // inflate the count the user is shown or make the second pass report
        // the first pass as a concurrent writer.
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

    /// Carry out a [`DeletePlan`], removing every assignment it names.
    ///
    /// A line removal in the document the user maintains, not a rewrite from a
    /// map: comments, blank lines, ordering and every other value survive
    /// byte-for-byte. That is the whole reason `del` can support this provider
    /// while `import` cannot — a map-shaped write would sort the keys and drop
    /// the comments.
    ///
    /// Nothing is decrypted and the keyring is never touched. Deleting a value
    /// this device cannot read is not a degraded case but the main one: a
    /// teammate's device-local marker in a committed `.env` is exactly what a
    /// user needs to be able to remove, and demanding the key first would leave
    /// the file unfixable on every machine but the one that wrote it.
    ///
    /// Names are removed from *this* file only. The user scope is deliberately
    /// not consulted: it is a different file, `--scope user` names it, and
    /// deleting from it because a project file happened to inherit the same
    /// variable would reach outside the path the caller asked about.
    pub(crate) fn delete_planned(&self, path: &str, plan: &DeletePlan) -> Result<DeleteOutcome> {
        ensure!(
            !plan.targets.is_empty(),
            "no fields were named to delete from {path}; this provider removes named variables, \
             never a whole file"
        );

        let mut locked = atomic::LockedFile::open(Path::new(path))?;
        let contents = locked.read()?;

        // The plan was made against an unlocked read, with a prompt in
        // between. Any change at all invalidates it — including one that
        // leaves the names alone: a `set` that replaced the value under a name
        // being deleted would have its brand new, never-confirmed ciphertext
        // destroyed here, and there is no escrow to get it back from. Cheaper
        // and stricter than comparing names: the answer to "may I still do
        // this" is no whenever the file is not the one that was answered about.
        ensure!(
            digest_of(&contents) == plan.digest,
            "{path} changed since the delete was prepared, so nothing was removed. Re-run to see \
             what would be deleted now"
        );

        let mut document = Document::parse(&contents);
        let mut outcome = DeleteOutcome::default();
        // Re-checked under the lock even though the digest already proves the
        // contents are identical: the guarantee this file makes is that no
        // delete is written against an ambiguous document, and one that holds
        // only through another function's argument is one refactor from
        // holding by accident.
        fatal_quote_problem(path, &document)?;

        for key in &plan.targets {
            refuse_enclosed_assignments(path, &document, key)?;
            let removed = document.remove(key);
            if !removed.any() {
                // The plan was made outside this lock, so losing the race is an
                // ordinary outcome rather than a failure: the name is gone,
                // which is what was asked for. Only reachable when the digest
                // check above was skipped by a caller that planned and wrote in
                // one go.
                outcome
                    .warnings
                    .push(format!("{path} no longer set '{key}'; nothing to remove"));
                continue;
            }
            outcome.removed.push(key.clone());
            // Every assignment of the name goes, so no earlier value is left on
            // disk to be read back later — but say so, because the caller told
            // the user it was deleting one field.
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
            // Nothing to write — but the sweep of leftover temporaries lives in
            // `LockedFile::replace`, and skipping it would leave a killed
            // writer's copy of this file's secrets sitting beside it,
            // uncollected and unreported, until the next successful write.
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

    /// The scope files that exist, least specific first.
    fn layers(&self, project_path: &Path) -> Result<Vec<Layer>> {
        let mut layers = Vec::new();
        // A missing or unreadable home directory is not fatal: a project file
        // on its own is a perfectly good configuration.
        if let Some(user_path) = self.user_path.as_deref()
            && user_path != project_path
            && let Some(contents) = atomic::read_to_string(user_path)?
        {
            layers.push(Layer {
                scope: Scope::User,
                document: Document::parse(&contents),
                path: user_path.to_path_buf(),
            });
        }
        // Resolved per call rather than once in `new`: the project file names
        // the directory, and a long-lived store can be asked about files in
        // different repositories.
        if let Some(repo_path) = repo::scope_path(project_directory(project_path))
            && repo_path != project_path
            && self.user_path.as_deref() != Some(repo_path.as_path())
            && let Some(contents) = atomic::read_to_string(&repo_path)?
        {
            layers.push(Layer {
                scope: Scope::Repo,
                document: Document::parse(&contents),
                path: repo_path,
            });
        }
        if let Some(contents) = atomic::read_to_string(project_path)? {
            layers.push(Layer {
                scope: Scope::Project,
                document: Document::parse(&contents),
                path: project_path.to_path_buf(),
            });
        }
        Ok(layers)
    }
}

/// The directory `path` lives in, for walking up to a git directory. A bare
/// `.env` has no parent component, which means the current directory.
fn project_directory(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// What a bulk read could not do.
///
/// Two kinds, deliberately not one list: the caller has to be able to tell a
/// field that is *missing from the result* from a remark about the file.
#[derive(Debug, Default)]
pub struct ReadWarnings {
    /// Fields the file names but whose value could not be read — encrypted on
    /// another machine, or another tool's marker. One message each, naming the
    /// field and never a value.
    ///
    /// A caller that prints what it read may carry on; a caller that *injects*
    /// the result into a child's environment must not. A variable that silently
    /// fails to appear is indistinguishable from one nobody ever set, and the
    /// child then runs with a hole in its configuration and a zero exit code.
    pub unreadable: Vec<String>,
    /// Remarks about the files themselves — a stray quote somewhere in one —
    /// that lost no field of their own. Worth showing, never worth failing over:
    /// they are heuristics, and one of them firing on a legitimate multi-line
    /// value must not stop a command.
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

/// Refuse a write whose overwrite confirmation is out of date.
///
/// The names the user agreed to overwrite were read before the lock was taken,
/// so between the prompt and the write another process can have added one of the
/// names being set. Without this the answer to "API_KEY will be overwritten,
/// continue?" — a question the user was never asked, because API_KEY did not
/// exist then — is taken as a yes.
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

/// A delete that has been decided but not yet carried out.
///
/// Holds the file's digest as well as the names, so the write can refuse a file
/// that changed while the user was being asked about it. The digest is private:
/// a plan is something [`FileBackend::plan_delete`] hands out and
/// [`FileBackend::delete_planned`] consumes, never something a caller builds.
#[derive(Debug)]
pub struct DeletePlan {
    /// The names that will be removed, deduplicated.
    pub targets: Vec<String>,
    digest: String,
}

/// What a delete did.
#[derive(Debug, Default)]
pub struct DeleteOutcome {
    /// Names that were actually removed. Empty means the file was left alone,
    /// whatever the plan said.
    pub removed: Vec<String>,
    /// Things the user should know that did not stop the delete. Never a value.
    pub warnings: Vec<String>,
}

/// Refuse a document whose quoting is ambiguous enough that rewriting it would
/// change a variable nobody named.
///
/// Shared by both delete phases so the message cannot drift between the one the
/// user is refused with and the one the write would have used.
fn fatal_quote_problem(path: &str, document: &Document) -> Result<()> {
    match document.quote_problem() {
        // Removing a line moves the boundary of what an unterminated quote
        // swallows, so this rewrite can change the value of a variable nobody
        // named.
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
        // Not fatal on its own: the entry it describes may be a perfectly good
        // multi-line value. `refuse_enclosed_assignments` decides that per
        // entry, for the entry actually being removed.
        Some(QuoteProblem::SwallowedAssignment { .. }) | None => Ok(()),
    }
}

/// Refuse to remove an entry that has swallowed other assignments into its
/// value.
///
/// The one case where "remove the line" is not a safe reading of "remove the
/// variable". An entry's raw text is every physical line its value spans, so
/// when a stray quote has pulled later assignments inside it, removing the
/// entry deletes those variables too — unrecoverably, for an encrypted value,
/// and without ever naming them.
///
/// This is where `set` and `encrypt` get to be more relaxed than `delete`, and
/// it is not an inconsistency: they rewrite the *value*, so a swallowed
/// assignment survives (inside the ciphertext, for `encrypt`) and a warning is
/// a proportionate response. Deletion destroys it, so the same file has to be
/// refused rather than warned about.
///
/// Deliberately not driven by [`QuoteProblem::SwallowedAssignment`], whose
/// heuristic is tuned for a low false-positive rate and misses a one-character
/// or lowercase name — a miss there means silent destruction here.
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

/// SHA-256 of a file's contents, hex encoded.
///
/// Must be cryptographic: it is what decides whether a prepared delete may
/// still be written, so a cheap hash would let anyone who can write the file
/// craft a collision and slip a change past the check. Same reasoning as
/// [`trust`]'s digest.
fn digest_of(contents: &str) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(contents.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What an encrypt-in-place pass did.
#[derive(Debug, Default)]
pub struct EncryptOutcome {
    /// Names whose plaintext value was replaced with a reference.
    pub encrypted: Vec<String>,
    /// Names that were already references and were not touched.
    pub already_encrypted: Vec<String>,
    /// Names left alone, and why. Never contains a value.
    pub warnings: Vec<String>,
}

/// A value as it appears in a file, with where it came from.
struct Resolved<'a> {
    /// The value with the file's quoting resolved — a marker may perfectly
    /// well be written `KEY="gitguardian:..."`.
    value: String,
    scope: Scope,
    path: &'a Path,
}

/// Flatten the layers, most specific last.
///
/// This is the seam for scope policy. Today every user-scope value is
/// injected; a future `--user-scope declared-only` flag filters this map to
/// the keys the project layer declares, which is a change to *this* function
/// and nothing else.
///
/// # What "every user-scope value is injected" costs
///
/// Until that flag exists, the user-scope file is ambient authority. Every
/// variable in it is handed to every command `gitguardian run` starts, in every
/// repository on the machine — including one cloned a minute ago, whose
/// `package.json` script or `Makefile` target the user has not read. A
/// `MY_AWS_KEY` put there for one project is readable by all of them.
///
/// The rule that an already-set environment variable wins does not mitigate
/// this. That rule protects a value the environment *already* has; the
/// user-scope file exists precisely for variables that are not already set, so
/// it is exactly the values with no ambient counterpart that get injected.
///
/// So the user-scope file is for values whose blast radius the user accepts
/// machine-wide. Anything narrower belongs in a project file, and a reviewer
/// weighing the declared-only flag should treat this as the cost of not having
/// it rather than as a hypothetical.
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
    /// Decrypt the resolved values, loading this device's cipher only if some
    /// value actually needs it.
    ///
    /// Failures are carried per key rather than aborting the batch — see
    /// [`FileBackend::get_secrets`] for why — except when nothing at all could
    /// be read, which is reported as the first failure.
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
        // A file with a readable half is usable; a file with no readable value
        // at all is a failure the caller has to see.
        if fields.is_empty()
            && let Some(error) = first_error
        {
            return Err(error);
        }
        Ok((fields, unreadable))
    }

    /// Resolve one value, loading the read cipher on first need.
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
                    // Context here too: a bulk read reports failures per key, so
                    // "this device has no key" must say which value it could not
                    // open, not arrive as the same anonymous line once per entry.
                    *cipher = Some(self.read_cipher().with_context(source)?);
                }
                let cipher = cipher.as_ref().expect("the cipher was just loaded");
                let plaintext = cipher.decrypt(key, &envelope).with_context(source)?;
                // Borrowed, never `String::from_utf8(plaintext.to_vec())`: that
                // moves the bytes into a `FromUtf8Error` on the failure path,
                // leaving an unzeroized copy of a *decrypted secret* in an
                // allocation nothing wipes. `Utf8Error` carries only offsets.
                let text = std::str::from_utf8(&plaintext)
                    .map_err(|_| anyhow::anyhow!("'{key}' does not decrypt to text"))?;
                Ok(SecretString::from(text.to_owned()))
            }
        }
    }
}

/// Refuse a plaintext value that would not be read back as plaintext.
///
/// `set --plain` writes the value verbatim, so a value beginning with a marker
/// prefix is classified as a *reference* the next time it is read: `get` refuses
/// it, and per [`FileBackend::get_secrets`] it also drops out of every bulk
/// read of that file. Caught on the way in instead.
///
/// Names the field and never the value: the reason is the same whatever the
/// value was, and the value is a secret.
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
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
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
        /// A backend with a deterministic cipher and both scope files inside a
        /// temporary directory — the real keyring is never touched.
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let user_path = directory.path().join("user-secrets.env");
            Fixture {
                backend: FileBackend {
                    encryption: Encryption::Fixed(Arc::new(TestCipher::new(0x5a))),
                    user_path: Some(user_path),
                },
                directory,
            }
        }

        fn plaintext(mut self) -> Self {
            self.backend.encryption = Encryption::Plaintext;
            self
        }

        /// A device that cannot open anything: stands in for a machine whose
        /// keyring never held the key a file's values were sealed with.
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

        /// Make the fixture's directory a git checkout and write the
        /// repo-scope file inside its git directory.
        fn write_repo(&self, contents: &str) {
            let store = self.directory.path().join(".git").join("gitguardian");
            std::fs::create_dir_all(&store).unwrap();
            std::fs::write(store.join("secrets.env"), contents).unwrap();
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

        /// `get`, keeping the per-field warnings.
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

    /// Finding 19: the keyring entry is one per OS user, so the lock over it has
    /// to be one per OS user too. Keyed off `$HOME`/`$XDG_CONFIG_HOME`, the same
    /// user under two environments took two locks over one keyset, and a
    /// concurrent first write on each side could destroy the other's master key
    /// — unrecoverably, since there is no export or escrow.
    ///
    /// Asserted through the OS user's own home directory rather than by
    /// manipulating the environment, which a parallel test process cannot do
    /// safely: the lock must land under it whatever the environment says.
    #[cfg(unix)]
    #[test]
    fn the_keyset_lock_is_scoped_to_the_os_user_not_to_the_environment() {
        let home = os_user_home().expect("this test needs a passwd entry");
        let lock = keyset_lock_path().unwrap();
        assert!(lock.starts_with(&home), "{lock:?} is not under {home:?}");
        assert!(lock.ends_with("gitguardian/keyset.lock"), "{lock:?}");
        // And the user-scope file *is* environment-scoped, which is the whole
        // reason the two cannot share a derivation: it is a file the user
        // redirects on purpose.
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
        // Finding 7: the field is named, the kind — a fragment of the value —
        // is not.
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
        assert!(message.contains("user scope"), "{message}");
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

    /// Finding 7a: one unreadable entry must not take the readable ones with
    /// it. The everyday case is cloning a repo whose committed `.env` carries a
    /// teammate's device-local markers.
    #[test]
    fn one_unreadable_entry_does_not_hide_the_readable_ones() {
        let fixture = Fixture::new();
        fixture.write_project("DEBUG=true\nBAD=gitguardian:!!!not-base64!!!\nPORT=8080\n");

        let (fields, warnings) = fixture.get_reporting().unwrap();
        assert_eq!(value(&fields, "DEBUG"), "true");
        assert_eq!(value(&fields, "PORT"), "8080");
        assert!(!fields.contains_key("BAD"));

        // The failure is reported, by key name, and never silently swallowed.
        assert_eq!(warnings.unreadable.len(), 1, "{warnings:?}");
        assert!(warnings.unreadable[0].contains("BAD"), "{warnings:?}");
    }

    /// Finding 7a: and asking for the unrelated field by name works too.
    ///
    /// Round-3 finding 26c: over a `Fixed` cipher this asserted nothing —
    /// `decrypt` already tolerates a per-key failure, so the property held on
    /// the bulk path too and deleting `get_secret` entirely would have kept it
    /// green. The unreadable entry has to be one that needs a cipher this
    /// backend cannot produce at all.
    #[test]
    fn a_readable_field_resolves_past_an_unreadable_one() {
        let (fixture, cipher) = counting_fixture();
        assert_eq!(fixture.get_field("DEBUG").unwrap().expose_secret(), "true");
        // The point of the per-field path: nothing else in the file was opened,
        // so the malformed `BAD` never got the chance to fail the read.
        assert_eq!(cipher.decrypts(), 0, "an unrelated value was decrypted");
        // Proof the other entries really are there to trip over.
        assert!(fixture.get_field("BAD").is_err());
        assert_eq!(
            fixture.get_field("SEALED").unwrap().expose_secret(),
            FAKE_VALUE
        );
        assert_eq!(cipher.decrypts(), 1, "only the field asked for was opened");
    }

    /// A cipher that records how many values it was asked to open.
    ///
    /// The only way to assert "resolving this field decrypted nothing else". A
    /// deterministic cipher that simply works cannot show it, because the answer
    /// is the same whether one value was opened or all of them.
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

    /// A project file holding one plaintext entry, one genuinely encrypted one
    /// and one this device cannot open, over a cipher that counts its work.
    fn counting_fixture() -> (Fixture, Arc<CountingCipher>) {
        let sealing = Fixture::new();
        sealing.set(&[("SEALED", FAKE_VALUE)]).unwrap();
        let sealed = sealing.read_project();

        let cipher = Arc::new(CountingCipher::new(0x5a));
        let fixture = Fixture {
            backend: FileBackend {
                encryption: Encryption::Fixed(cipher.clone()),
                user_path: sealing.backend.user_path.clone(),
            },
            directory: sealing.directory,
        };
        fixture.write_project(&format!(
            "DEBUG=true\n{sealed}BAD=gitguardian:!!!not-base64!!!\n"
        ));
        (fixture, cipher)
    }

    /// Finding 7: but asking for the broken field itself must still fail, and
    /// say why.
    #[test]
    fn asking_for_the_unreadable_field_itself_fails() {
        let fixture = Fixture::new();
        fixture.write_project("DEBUG=true\nBAD=gitguardian:!!!not-base64!!!\n");
        let error = fixture.get_field("BAD").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("BAD"), "{message}");
        assert!(message.contains("envelope"), "{message}");
    }

    /// Every per-key warning must name its key — including the one raised when
    /// the device has no key at all, which otherwise arrives as the same
    /// anonymous sentence repeated once per encrypted value.
    #[test]
    fn a_missing_keyset_is_reported_per_key_by_name() {
        let fixture = Fixture::new();
        fixture
            .set(&[("ALPHA", FAKE_VALUE), ("BETA", FAKE_VALUE)])
            .unwrap();
        fixture.write_project(&format!("PLAIN=kept\n{}", fixture.read_project()));

        // A backend whose cipher cannot be loaded, over the same file.
        let blind = FileBackend {
            encryption: Encryption::Unavailable,
            user_path: fixture.backend.user_path.clone(),
        };
        let (fields, warnings) = blind.get_secrets(&fixture.project_path()).unwrap();

        assert_eq!(
            value(&fields, "PLAIN"),
            "kept",
            "plaintext must still resolve"
        );
        // Both are *unreadable fields*, not file advisories: a caller that
        // injects values has to be able to tell that two variables are missing.
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

    /// Finding 7b: a bad entry in the user-scope file must not break a project
    /// whose own file is fine — otherwise one typo breaks every project on the
    /// machine.
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

    /// Finding 7c: a plaintext field must not need the keyring.
    ///
    /// Round-3 finding 26b: the old version of this asserted neither property
    /// its name claims. Its cipher was `Fixed`, which never touches a keyring,
    /// so "no keyring access" was undetectable; and the bulk path already
    /// tolerates a per-key failure, so replacing `get_secret` with
    /// `get_secrets(path)?.remove(field)` kept it green. A counting cipher makes
    /// both claims checkable: the cipher must not be asked to open anything, and
    /// a value on this device *would* have opened had the bulk path been used.
    #[test]
    fn reading_a_plaintext_field_ignores_other_entries_entirely() {
        let (fixture, cipher) = counting_fixture();
        // A foreign marker on top, which would be an error if it were
        // classified at all.
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

    /// Finding 7: a file where nothing at all can be read is still an error.
    #[test]
    fn a_file_with_no_readable_value_is_an_error() {
        let fixture = Fixture::new();
        fixture.write_project("BAD=gitguardian:!!!not-base64!!!\n");
        let error = fixture.get().unwrap_err();
        assert!(format!("{error:#}").contains("BAD"), "{error:#}");
    }

    /// Finding 8: `--plain` must not accept a value that `get` will always
    /// reject. The error names the field and never the value.
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

    /// Finding 8: encrypting such a value is fine — it becomes a marker, so it
    /// is a reference by construction and reads back correctly.
    #[test]
    fn an_encrypted_value_may_look_like_anything() {
        let fixture = Fixture::new();
        fixture.set(&[("TOKEN", "encrypted:whatever")]).unwrap();
        assert_eq!(
            value(&fixture.get().unwrap(), "TOKEN"),
            "encrypted:whatever"
        );
    }

    /// Finding 9: appending next to a stray quote would swallow the variables
    /// in between, so it is refused with the line to fix.
    #[test]
    fn writing_to_a_file_with_an_unterminated_quote_is_refused() {
        let fixture = Fixture::new().plaintext();
        fixture.write_project("NOTE=\"oops\nAPI_KEY=abc\n");
        let error = fixture.set(&[("GREETING", "hello world")]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("quote"), "{message}");
        // The file is untouched, so API_KEY is still there to be read.
        assert_eq!(fixture.read_project(), "NOTE=\"oops\nAPI_KEY=abc\n");
        assert_eq!(value(&fixture.get().unwrap(), "API_KEY"), "abc");
    }

    /// Finding 9: and once the file is well formed, the same write succeeds and
    /// keeps every variable readable.
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

    /// Finding 2: a plaintext value a shell would expand must not be written
    /// bare into a file people `source`.
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

    /// The whole point: a value the CLI cannot prompt for — a multi-line key —
    /// is written into the file and encrypted from there.
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
        // The single-quoted entry keeps its quotes.
        assert!(after.contains("URL='gitguardian:"), "{after}");
        let fields = fixture.get().unwrap();
        assert_eq!(value(&fields, "PORT"), "3000");
        assert_eq!(value(&fields, "URL"), "http://x/y");
    }

    /// Running it twice must not re-encrypt: a fresh nonce for an unchanged
    /// value is pure churn in a committed file.
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

    /// Every assignment of a duplicated key must be encrypted. Encrypting only
    /// the one that wins on read would leave the other plaintext on disk.
    #[test]
    fn a_duplicated_key_is_encrypted_at_every_assignment() {
        let fixture = Fixture::new();
        fixture.write_project("A=first\nA=second\n");
        assert_eq!(encrypt_all(&fixture).encrypted.len(), 2);

        let after = fixture.read_project();
        assert!(!after.contains("first"), "{after}");
        assert!(!after.contains("second"), "{after}");
        assert_eq!(after.matches("gitguardian:").count(), 2, "{after}");
        // Last assignment still wins on read.
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

    /// Another tool's marker is skipped and named: encrypting it would bury a
    /// value we cannot read inside one we can.
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

    /// The same fail-closed rule as `set`: a file whose meaning is already
    /// ambiguous is not rewritten.
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

    /// Finding 9: the cipher is loaded only once a value is actually going to
    /// be sealed. Reaching for it up front made a pass with nothing to encrypt
    /// mint the device key anyway — and made a backend that cannot encrypt fail
    /// a file it would not have touched.
    #[test]
    fn a_pass_with_nothing_to_encrypt_never_asks_for_a_cipher() {
        // `Unavailable` bails the moment anything asks it for a cipher, so a
        // successful pass here is proof that nothing did.
        let fixture = Fixture::new();
        let blind = FileBackend {
            encryption: Encryption::Unavailable,
            user_path: fixture.backend.user_path.clone(),
        };
        // One foreign marker and one empty value: nothing to seal in either.
        fixture.write_project("FOREIGN=encrypted:dotenvx\nEMPTY=\n");
        let before = fixture.read_project();

        let outcome = blind
            .encrypt_in_place(&fixture.project_path(), None, false)
            .expect("a pass with nothing to encrypt must not need a cipher");
        assert!(outcome.encrypted.is_empty(), "{outcome:?}");
        assert_eq!(fixture.read_project(), before);

        // A plaintext-writing backend is the same story: no cipher is needed
        // for a file with nothing to seal, so there is nothing to complain
        // about.
        let plain = Fixture::new().plaintext();
        plain.write_project("FOREIGN=encrypted:dotenvx\n");
        let outcome = plain
            .backend
            .encrypt_in_place(&plain.project_path(), None, false)
            .expect("no cipher is needed when nothing is plaintext");
        assert!(outcome.encrypted.is_empty(), "{outcome:?}");
    }

    /// Finding 17: an empty value carries no secret, and sealing one
    /// device-locks a placeholder — `API_KEY= # from the dashboard` would become
    /// unreadable on every other machine while still holding nothing. `set`
    /// refuses an empty value for the same reason.
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

        // Naming it explicitly says why nothing happened, rather than reporting
        // a silent "nothing to encrypt".
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

    /// Finding 6: a line whose value is partly outside its quotes is not read as
    /// an assignment at all, so sealing "the value" would leave the rest of it
    /// on disk in cleartext — `API_KEY='super'password` becoming
    /// `API_KEY='<marker>'password`. Both writers refuse the file.
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

        // And a read says why the variable is missing instead of reporting the
        // truncated value as if it were the real one.
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

    /// Finding 13: the overwrite prompt reads the file before the write takes
    /// the lock — it has to, or an unanswered prompt would hold the lock — so
    /// the write re-checks that the file still looks like the one the user
    /// answered about.
    #[test]
    fn a_field_that_appears_after_the_overwrite_check_is_not_silently_replaced() {
        let fixture = Fixture::new();
        // The user was shown nothing: at prompt time the file had no API_KEY.
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

    /// Finding 21: layers are searched user-first, so reporting only the first
    /// quote problem blamed the user-scope file for a field that no file
    /// defines — sending the user off to fix something unrelated to what they
    /// asked for. Every layer with a problem is named, and the wording says
    /// "may be".
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
        assert!(message.contains("user scope"), "{message}");
        assert!(message.contains("project scope"), "{message}");
    }

    #[test]
    fn debug_output_shows_no_secrets() {
        let fixture = Fixture::new();
        fixture.set(&[("API_KEY", FAKE_VALUE)]).unwrap();
        let debug = format!("{:?}", fixture.backend);
        assert!(!debug.contains(FAKE_VALUE), "{debug}");
    }

    /// The reason `del` can support this provider while `import` cannot: the
    /// document survives, so what comes back is the user's file minus one line.
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

    /// The case that matters most: a teammate's marker in a committed `.env`,
    /// on a machine that has no key for it. If removing it needed the key, the
    /// file could only ever be fixed on the machine that wrote it.
    #[test]
    fn delete_does_not_need_the_key_the_value_was_sealed_with() {
        let fixture = Fixture::new();
        fixture.set(&[("THEIRS", FAKE_VALUE)]).unwrap();
        let sealed = fixture.read_project();
        assert!(sealed.contains("gitguardian:"), "{sealed}");

        let fixture = fixture.without_a_key();
        // Proof the device really cannot read it.
        assert!(fixture.get_field("THEIRS").is_err());

        fixture.delete(&["THEIRS"]).unwrap();
        assert_eq!(fixture.read_project(), "");
    }

    /// Emptying a whole file is not this API's to do: it holds the user's
    /// comments and their plaintext config as well as their secrets.
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

    /// Finding 1: the plan is decided against an unlocked read, with a prompt
    /// in between, so the write has to check that the file is still the one the
    /// user answered about. A `set` landing in that window would otherwise have
    /// its brand new ciphertext deleted, unrecoverably.
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

    /// A name appended while the prompt waited is not in the plan, so it is not
    /// deleted — but it does change the file, so the plan is refused outright
    /// rather than partly applied.
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

    /// Every assignment goes, so no earlier value is left on disk — but the
    /// user was told one field would be deleted, so say the file lost more
    /// lines than that.
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

    /// Naming the same variable twice must not report the first pass as a
    /// concurrent writer, nor count the field twice.
    #[test]
    fn delete_deduplicates_a_repeated_name() {
        let fixture = Fixture::new();
        fixture.write_project("A_KEY=1\nB_KEY=2\n");

        let outcome = fixture.delete(&["A_KEY", "A_KEY"]).unwrap();
        assert_eq!(outcome.removed, ["A_KEY"]);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fixture.read_project(), "B_KEY=2\n");
    }

    /// Finding 5: the value is what the caller asked to destroy; the note
    /// beside it is text the user wrote and did not name.
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

    /// Finding 4, the worst of the review: an entry's raw text is every
    /// physical line its value spans, so removing one whose quoting has
    /// swallowed later assignments deletes those variables too — silently, and
    /// unrecoverably for an encrypted value.
    #[test]
    fn delete_refuses_an_entry_that_swallowed_other_assignments() {
        let fixture = Fixture::new();
        let original = "A=\"oops\nB=keepme\nc=fine\"\nD=keep\n";
        fixture.write_project(original);

        let error = fixture.delete(&["A"]).unwrap_err();
        let message = format!("{error:#}");
        // Names what would have been destroyed, including the one-character
        // and lowercase names the warning heuristic misses.
        assert!(message.contains("'A'"), "{message}");
        assert!(message.contains("B, c"), "{message}");
        assert!(message.contains("fix the quoting first"), "{message}");
        assert_eq!(fixture.read_project(), original, "the file was rewritten");
    }

    /// `--all` reaches the same entry by enumeration rather than by name, so it
    /// has to be refused there too.
    #[test]
    fn delete_all_refuses_a_file_with_a_swallowed_assignment() {
        let fixture = Fixture::new();
        let original = "A=\"oops\nB=keepme\"\nD=keep\n";
        fixture.write_project(original);

        assert!(fixture.delete(&[]).is_err());
        assert_eq!(fixture.read_project(), original);
    }

    /// The refusal must not spread to the multi-line values this format exists
    /// to carry: a PEM key is one entry spanning many lines and deleting it has
    /// to keep working.
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

    /// Removing a line moves the boundary of what the stray quote swallows, so
    /// this rewrite could change a variable nobody named.
    #[test]
    fn delete_refuses_a_file_whose_quoting_is_already_ambiguous() {
        let fixture = Fixture::new();
        let original = "BROKEN=\"oops\nTARGET=gone\nEND=\"fine\n";
        fixture.write_project(original);

        let error = fixture.delete(&["TARGET"]).unwrap_err();
        assert!(format!("{error:#}").contains("fix line"), "{error:#}");
        assert_eq!(fixture.read_project(), original);
    }

    /// Finding 2c: a stray quote hides real assignments from the parser, and
    /// "does not set API_KEY" for a variable `grep` plainly shows sends the
    /// user looking in the wrong place. The quote problem is named first.
    #[test]
    fn a_hidden_assignment_is_reported_as_a_quote_problem_not_as_a_missing_name() {
        let fixture = Fixture::new();
        fixture.write_project("API_KEY='super'password\nKEEP=1\n");

        let error = fixture.plan(&["API_KEY"]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("fix line 1"), "{message}");
        assert!(!message.contains("does not set"), "{message}");
    }

    /// `del` names one file. A variable that only the user-scope file sets is
    /// not in it, and deleting from that file instead would reach outside the
    /// path the caller asked about.
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

    /// Finding 2b: an empty name list means "this file sets nothing", and
    /// reporting that for a file that is not there tells the user their secrets
    /// were already gone. A delete that deletes nothing must also not leave a
    /// brand new empty `.env` behind — `LockedFile::open` creates what it opens.
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
        // The whole reason the merge is per variable: a worktree pointing at a
        // different backend names that one variable, and keeps everything else
        // the repository already holds.
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
}
