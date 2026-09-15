//! The device's [`Keyset`], stored as one blob in the OS credential store.
//!
//! Fail-closed: no usable credential store means no encryption, never a key
//! file on disk. Creation runs under a lock and every store absorbs the
//! existing keyset, because two racing first `set`s would otherwise each mint
//! a master key and the loser's encrypted value would be unrecoverable.

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
pub(crate) fn load_or_create() -> Result<Keyset> {
    if let Some(keyset) = load()? {
        return Ok(keyset);
    }

    let _guard = atomic::lock_sidecar(&lock_path()?)?;

    // Another process may have created the keyset while we waited.
    if let Some(keyset) = load()? {
        return Ok(keyset);
    }
    store(Keyset::generate()?)
}

/// Store `keyset` merged with every key already stored, and return the result.
///
/// Never write the keyring directly: replacing the blob destroys keys.
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

/// The lock serialising keyset writes, scoped to the store it guards.
///
/// Never under a world-writable temp dir: another user could recreate the
/// inode between two runs and defeat the lock.
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

/// Second opt-in so a stray `$GITGUARDIAN_TEST_KEYSET_FILE` cannot swap the
/// keyring for a cleartext file in a binary built with the test feature.
#[cfg(feature = "test-keystore")]
const TEST_KEYSTORE_ACK_VAR: &str = "GITGUARDIAN_TEST_KEYSET_INSECURE_ACK";
#[cfg(feature = "test-keystore")]
const TEST_KEYSTORE_ACK: &str = "i-understand-this-stores-the-master-key-in-cleartext";

/// File standing in for the credential store in tests; an error, not a
/// fallback to the real keyring, when the acknowledgement is missing.
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

/// Atomic, like the real keyring's single set-secret call, so concurrent
/// readers never see a partial blob.
#[cfg(feature = "test-keystore")]
fn write_test_keystore(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    atomic::replace_bytes(path, bytes).context("writing the test keyset")
}
