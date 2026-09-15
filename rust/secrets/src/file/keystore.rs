//! Where the device's [`Keyset`] lives: the operating system's credential
//! store.
//!
//! The whole keyset is stored as **one** opaque blob under **one** entry:
//! keyring enumeration APIs differ too much across platforms to be worth
//! relying on, and a single blob means adding a key later needs no migration.
//!
//! This is fail-closed on purpose. If the platform has no usable credential
//! store, encryption is unavailable and the command fails — it never falls
//! back to a key file on disk, which would silently turn device-local
//! encryption into obfuscation.
//!
//! # Why creating a key takes a lock
//!
//! One blob for the whole keyset means every write is a read-modify-write, and
//! the keyring offers no compare-and-swap to hang it on. Two `gitguardian set`
//! calls on a machine with no keyset yet would both see "nothing stored", both
//! generate a master key, and the second store would replace the first — after
//! the first had already encrypted a value with the key it just lost. There is
//! deliberately no recovery or export mechanism, so that value is gone for good.
//!
//! Two things prevent it, and both are needed. [`load_or_create`] holds an
//! exclusive lock over generate-and-store, so the second caller finds the first
//! caller's key and simply uses it; and every store [`Keyset::absorb`]s what is
//! already there, so even a store that races anyway adds a key instead of
//! replacing one. Rotation and import will want the same two properties.

use std::path::PathBuf;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use super::atomic;
use super::crypto::Keyset;

/// Keyring service name, shared with the provider token lookups.
pub(crate) const KEYRING_SERVICE: &str = "gitguardian";
/// Keyring account holding the file provider's keyset.
pub(crate) const KEYRING_ACCOUNT: &str = "file:keyset";

/// The device's keyset, or `None` when nothing has been stored yet.
pub(crate) fn load() -> Result<Option<Keyset>> {
    #[cfg(feature = "test-keystore")]
    if let Some(path) = test_keystore_path()? {
        return match std::fs::read(&path) {
            // Zeroizing: the blob is the master key material, and a plain `Vec`
            // would be dropped unwiped.
            Ok(bytes) => Keyset::from_bytes(&Zeroizing::new(bytes)).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(anyhow::Error::new(error).context("reading the test keyset")),
        };
    }

    let entry = entry()?;
    match entry.get_secret() {
        Ok(bytes) if bytes.is_empty() => Ok(None),
        Ok(bytes) => {
            let keyset = Keyset::from_bytes(&Zeroizing::new(bytes))?;
            Ok(Some(keyset))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error).context(unavailable_context())),
    }
}

/// The device's keyset, generating and storing one on first use.
///
/// Generating on demand is what makes `set` work with no `init` step and no
/// passphrase. See the module docs for why the second half runs under a lock.
pub(crate) fn load_or_create() -> Result<Keyset> {
    if let Some(keyset) = load()? {
        return Ok(keyset);
    }

    // Nothing stored yet, and generating one is a read-modify-write of a blob
    // that has no compare-and-swap. Serialise the whole generate-and-store.
    let _guard = atomic::lock_sidecar(&lock_path()?)?;

    // Re-read under the lock: another process may have created the keyset while
    // we waited, and using its key is exactly right — a second key here would
    // be the bug.
    if let Some(keyset) = load()? {
        return Ok(keyset);
    }
    store(Keyset::generate()?)
}

/// Store `keyset`, keeping every key already in the keyring.
///
/// Returns what is now stored, which is `keyset` plus anything it did not
/// already hold. Never call the underlying keyring write directly: replacing
/// the blob destroys keys, and destroyed keys mean unreadable values with no
/// way back.
fn store(keyset: Keyset) -> Result<Keyset> {
    let mut keyset = keyset;
    if let Some(existing) = load()? {
        keyset.absorb(existing);
    }
    let bytes = keyset.to_bytes()?;

    #[cfg(feature = "test-keystore")]
    if let Some(path) = test_keystore_path()? {
        write_test_keystore(&path, &bytes)?;
        return Ok(keyset);
    }

    entry()?
        .set_secret(&bytes)
        .with_context(unavailable_context)?;
    Ok(keyset)
}

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).with_context(unavailable_context)
}

/// The lock file serialising writes to the keyset store.
///
/// **Scoped to the store it guards, not to the caller's environment.** The lock
/// only does its job if every process that will write one keyset takes the same
/// one, so the path has to be a function of *which store* is in use:
///
/// - the OS credential store holds one entry per login user, so the lock is
///   keyed on the OS user — see [`super::keyset_lock_path`], which derives it
///   from the password database rather than from `$HOME`/`$XDG_CONFIG_HOME`;
/// - the `test-keystore` stand-in is a file named by an environment variable,
///   and two workspaces naming two files are two independent stores, so the
///   lock goes beside that file.
///
/// There used to be a fallback to `$TMPDIR/gitguardian-keyset-<uid>.lock` for a
/// machine with no config directory (no `HOME`, no `XDG_CONFIG_HOME` — routine
/// in containers and systemd units). A world-writable directory is the one place
/// this lock cannot live: the sticky bit stops another user from *removing* the
/// file, not from creating it first, and whoever owns the inode can unlink and
/// recreate it between two `set` runs. The two runs then hold locks on different
/// inodes, both find no keyset, both mint a master key, and the second store
/// replaces the first — the unrecoverable key loss the module docs are about.
/// Failing closed is the rest of this module's answer to an unusable credential
/// store, and it is the right one here too.
fn lock_path() -> Result<PathBuf> {
    #[cfg(feature = "test-keystore")]
    if let Some(path) = test_keystore_path()? {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        return Ok(path.with_file_name(name));
    }

    super::keyset_lock_path().context(
        "no directory to put the keyset lock in, and creating this device's encryption key needs \
         one: two commands racing without it can each mint a key and destroy the other's. Set \
         $HOME (or $XDG_CONFIG_HOME) and try again",
    )
}

fn unavailable_context() -> String {
    format!(
        "cannot reach the operating system's credential store (service '{KEYRING_SERVICE}', \
         account '{KEYRING_ACCOUNT}'), which is where the file provider's encryption key \
         lives; unlock your login keyring or use a provider that does not need one"
    )
}

/// Second opt-in the test escape hatch needs, beyond naming a keyset file.
///
/// `$GITGUARDIAN_TEST_KEYSET_FILE` alone is not enough because it is not enough
/// of an accident: `cargo test` and `cargo build` write the same
/// `target/debug/gitguardian`, so the binary a developer runs after the test
/// suite is the one with the hatch compiled in. A second variable that has to
/// spell out what it does keeps a stray value in a shell profile from quietly
/// swapping the OS keyring for a cleartext file.
#[cfg(feature = "test-keystore")]
const TEST_KEYSTORE_ACK_VAR: &str = "GITGUARDIAN_TEST_KEYSET_INSECURE_ACK";
#[cfg(feature = "test-keystore")]
const TEST_KEYSTORE_ACK: &str = "i-understand-this-stores-the-master-key-in-cleartext";

/// Path of the file standing in for the credential store in tests.
///
/// Only compiled with the `test-keystore` feature, which nothing but this
/// workspace's own tests enables: it exists so the integration tests can
/// exercise real encryption without touching (or being blocked by) the
/// developer's login keychain.
///
/// Naming a file without the acknowledgement is an error rather than a silent
/// fall back to the real keyring: falling back would make a misconfigured test
/// run reach for the developer's login keychain, and would hide the fact that
/// encryption was not doing what the caller thought.
#[cfg(feature = "test-keystore")]
fn test_keystore_path() -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("GITGUARDIAN_TEST_KEYSET_FILE") else {
        return Ok(None);
    };
    if std::env::var_os(TEST_KEYSTORE_ACK_VAR).as_deref() != Some(TEST_KEYSTORE_ACK.as_ref()) {
        anyhow::bail!(
            "$GITGUARDIAN_TEST_KEYSET_FILE is set, which replaces the operating system's \
             credential store with a cleartext file on disk. This is for this workspace's own \
             tests only. Set {TEST_KEYSTORE_ACK_VAR}={TEST_KEYSTORE_ACK} to confirm, or unset \
             $GITGUARDIAN_TEST_KEYSET_FILE to use the real keyring"
        );
    }
    Ok(Some(PathBuf::from(path)))
}

/// Replace the test keyset file.
///
/// Atomically, like the real credential store's single set-secret call: a
/// truncate-then-write leaves a window in which a concurrent reader sees an
/// empty or partial blob and reports the keyset as corrupt. The stand-in has to
/// match the thing it stands in for, or the tests built on it prove nothing
/// about the real path.
#[cfg(feature = "test-keystore")]
fn write_test_keystore(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    atomic::replace_bytes(path, bytes).context("writing the test keyset")
}
