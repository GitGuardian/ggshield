//! Device-local XChaCha20-Poly1305 for dotenv values, keyed via HKDF-SHA256.
//!
//! The 192-bit nonce makes random nonces safe with no counter. The AAD binds
//! each ciphertext to its variable name and envelope header, and plaintext is
//! padded to [`PAD_BLOCK`] so markers don't publish exact value lengths.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::envelope::{
    Envelope, EnvelopeError, FORMAT_VERSION, HEADER_LEN, KEY_ID_LEN, KeyId, NONCE_LEN,
    SCHEME_DEVICE_LOCAL,
};

/// Master key length. Also the derived AEAD key length.
pub(crate) const KEY_LEN: usize = 32;
/// Changing this invalidates every existing value, hence the version suffix.
const HKDF_INFO: &[u8] = b"gitguardian-file-v1";
const PAD_BLOCK: usize = 32;

type MasterKey = Zeroizing<[u8; KEY_LEN]>;

/// Length of a base64url-nopad master key, as [`Keyset::to_bytes`] writes it.
const ENCODED_KEY_LEN: usize = KEY_LEN.div_ceil(3) * 4 - (3 - KEY_LEN % 3) % 3;
const KEY_ID_HEX_LEN: usize = KEY_ID_LEN * 2;

/// Seals and opens dotenv values.
pub(crate) trait Cipher {
    fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<Envelope>;
    fn decrypt(&self, key_name: &str, envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>>;
}

/// The device's keys; a set so rotation needs no format migration.
pub(crate) struct Keyset {
    current: KeyId,
    keys: BTreeMap<KeyId, MasterKey>,
}

// Key material must never reach a log or a panic message.
impl std::fmt::Debug for Keyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyset")
            .field("current", &self.current)
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl Keyset {
    /// A new keyset holding one freshly generated key.
    pub(crate) fn generate() -> Result<Self> {
        let mut key: MasterKey = Zeroizing::new([0; KEY_LEN]);
        fill_random(key.as_mut()).context("generating an encryption key")?;
        let mut id = [0_u8; 4];
        fill_random(&mut id).context("generating a key id")?;
        let key_id = KeyId(id);
        Ok(Keyset {
            current: key_id,
            keys: BTreeMap::from([(key_id, key)]),
        })
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> KeyId {
        self.current
    }

    /// Add every key of `other` not already held; `self`'s current key stays current.
    pub(crate) fn absorb(&mut self, other: Keyset) {
        for (id, key) in other.keys {
            self.keys.entry(id).or_insert(key);
        }
    }

    /// Serialise as one keyring blob.
    ///
    /// Hand-built (serde would leave unwiped copies of the keys) into an exactly
    /// presized buffer, since a reallocation frees an unwiped copy of the keys.
    pub(crate) fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut json = Zeroizing::new(String::with_capacity(self.stored_len()));
        let capacity = json.capacity();
        json.push_str(r#"{"current":""#);
        json.push_str(&self.current.to_string());
        json.push_str(r#"","keys":{"#);
        for (index, (id, key)) in self.keys.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            json.push('"');
            json.push_str(&id.to_string());
            json.push_str(r#"":""#);
            // No JSON escapes needed, which lets `from_bytes` borrow.
            let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(key.as_slice()));
            json.push_str(&encoded);
            json.push('"');
        }
        json.push_str("}}");
        debug_assert_eq!(
            json.capacity(),
            capacity,
            "the accumulator reallocated, so a copy of the key material was freed unwiped"
        );
        Ok(Zeroizing::new(json.as_bytes().to_vec()))
    }

    /// Exact byte length of what [`Keyset::to_bytes`] writes.
    fn stored_len(&self) -> usize {
        let framing = r#"{"current":"","keys":{}}"#.len() + KEY_ID_HEX_LEN;
        let per_key = KEY_ID_HEX_LEN + ENCODED_KEY_LEN + r#""":"""#.len();
        framing + self.keys.len() * per_key + self.keys.len().saturating_sub(1)
    }

    /// Parse a blob from [`Keyset::to_bytes`], borrowing so no key is copied.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let stored: StoredKeyset<'_> =
            serde_json::from_slice(bytes).context("the stored keyset is not valid JSON")?;
        let current =
            KeyId::from_hex(stored.current).context("the stored keyset has an invalid key id")?;
        let mut keys = BTreeMap::new();
        for (id, encoded) in &stored.keys {
            let key_id = KeyId::from_hex(id).context("the stored keyset has an invalid key id")?;
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded)
                    .context("the stored keyset has an unreadable key")?,
            );
            let mut key: MasterKey = Zeroizing::new([0; KEY_LEN]);
            if decoded.len() != KEY_LEN {
                bail!("the stored keyset has a key of the wrong length");
            }
            key.copy_from_slice(&decoded);
            keys.insert(key_id, key);
        }
        if !keys.contains_key(&current) {
            bail!("the stored keyset does not contain its current key");
        }
        Ok(Keyset { current, keys })
    }

    fn aead(&self, key_id: KeyId) -> Result<XChaCha20Poly1305> {
        let master = self.keys.get(&key_id).with_context(|| {
            format!(
                "no key '{key_id}' in this device's keyset: the value was encrypted on another \
                 machine or with a key that has since been removed"
            )
        })?;
        let mut derived: MasterKey = Zeroizing::new([0; KEY_LEN]);
        Hkdf::<Sha256>::new(None, master.as_slice())
            .expand(HKDF_INFO, derived.as_mut())
            .ok()
            .context("deriving the encryption key")?;
        XChaCha20Poly1305::new_from_slice(derived.as_slice())
            .ok()
            .context("initialising the cipher")
    }
}

impl Cipher for Keyset {
    fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<Envelope> {
        let aead = self.aead(self.current)?;
        let mut nonce = [0_u8; NONCE_LEN];
        fill_random(&mut nonce).context("generating a nonce")?;
        let mut envelope = Envelope {
            format_version: FORMAT_VERSION,
            scheme: SCHEME_DEVICE_LOCAL,
            key_id: self.current,
            nonce,
            ciphertext: Vec::new(),
        };
        let padded = pad(plaintext);
        envelope.ciphertext = aead
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &padded,
                    aad: &aad(key_name, &envelope),
                },
            )
            .ok()
            .context("encrypting the value")?;
        Ok(envelope)
    }

    fn decrypt(&self, key_name: &str, envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
        if envelope.scheme != SCHEME_DEVICE_LOCAL {
            return Err(EnvelopeError::UnsupportedScheme {
                scheme: envelope.scheme,
            }
            .into());
        }
        let aead = self.aead(envelope.key_id)?;
        // Deliberately vague: never say what was wrong, never echo bytes.
        let padded = Zeroizing::new(
            aead.decrypt(
                &XNonce::from(envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad(key_name, envelope),
                },
            )
            .ok()
            .with_context(|| {
                format!(
                    "could not decrypt '{key_name}': it was encrypted with a different key, \
                     stored under a different variable name, or has been modified"
                )
            })?,
        );
        unpad(&padded).with_context(|| format!("could not decrypt '{key_name}'"))
    }
}

/// Variable name then header; unambiguous without a separator because the
/// header is fixed-width and last.
fn aad(key_name: &str, envelope: &Envelope) -> Zeroizing<Vec<u8>> {
    let header = envelope.header_bytes();
    let mut aad = Vec::with_capacity(key_name.len() + HEADER_LEN);
    aad.extend_from_slice(key_name.as_bytes());
    aad.extend_from_slice(&header);
    Zeroizing::new(aad)
}

/// Pad to the next [`PAD_BLOCK`] boundary, PKCS#7 style.
fn pad(plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    let padding = PAD_BLOCK - (plaintext.len() % PAD_BLOCK);
    let mut padded = Zeroizing::new(Vec::with_capacity(plaintext.len() + padding));
    padded.extend_from_slice(plaintext);
    padded.resize(plaintext.len() + padding, padding as u8);
    padded
}

/// Strip the padding [`pad`] added, without echoing bytes on error.
fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        !padded.is_empty() && padded.len().is_multiple_of(PAD_BLOCK),
        "the decrypted value is not a whole number of blocks"
    );
    let padding = usize::from(padded[padded.len() - 1]);
    ensure!(
        (1..=PAD_BLOCK).contains(&padding) && padding <= padded.len(),
        "the decrypted value has invalid padding"
    );
    let body = padded.len() - padding;
    ensure!(
        padded[body..]
            .iter()
            .all(|byte| usize::from(*byte) == padding),
        "the decrypted value has invalid padding"
    );
    Ok(Zeroizing::new(padded[..body].to_vec()))
}

/// The stored keyset; borrowed, since an owned `String` key would drop unwiped.
#[derive(Deserialize)]
struct StoredKeyset<'a> {
    current: &'a str,
    #[serde(borrow)]
    keys: BTreeMap<&'a str, &'a str>,
}

fn fill_random(buffer: &mut [u8]) -> Result<()> {
    getrandom::fill(buffer).context("reading from the operating system's random source")?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_cipher {
    //! A deterministic stand-in for [`Keyset`].

    use super::*;

    /// Rejected by the real [`Keyset`] as an unsupported scheme.
    pub(crate) const SCHEME_TEST: u8 = 0xfe;

    pub(crate) struct TestCipher {
        pub(crate) key_id: KeyId,
        pub(crate) pad: u8,
    }

    impl TestCipher {
        pub(crate) fn new(pad: u8) -> Self {
            TestCipher {
                key_id: KeyId([pad, pad, pad, pad]),
                pad,
            }
        }

        fn transform(&self, key_name: &str, data: &[u8]) -> Vec<u8> {
            data.iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.pad ^ (index as u8) ^ name_byte(key_name))
                .collect()
        }
    }

    fn name_byte(key_name: &str) -> u8 {
        key_name
            .bytes()
            .fold(0_u8, |acc, byte| acc.wrapping_add(byte))
    }

    impl Cipher for TestCipher {
        fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<Envelope> {
            let mut ciphertext = self.transform(key_name, plaintext);
            ciphertext.extend_from_slice(&[name_byte(key_name); 16]);
            Ok(Envelope {
                format_version: FORMAT_VERSION,
                scheme: SCHEME_TEST,
                key_id: self.key_id,
                nonce: [self.pad; NONCE_LEN],
                ciphertext,
            })
        }

        fn decrypt(&self, key_name: &str, envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
            if envelope.scheme != SCHEME_TEST {
                return Err(EnvelopeError::UnsupportedScheme {
                    scheme: envelope.scheme,
                }
                .into());
            }
            if envelope.key_id != self.key_id {
                bail!("no key '{}' in this device's keyset", envelope.key_id);
            }
            let (body, tag) = envelope
                .ciphertext
                .split_at(envelope.ciphertext.len().saturating_sub(16));
            if tag != [name_byte(key_name); 16] {
                bail!("could not decrypt '{key_name}'");
            }
            Ok(Zeroizing::new(self.transform(key_name, body)))
        }
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::test_cipher::{SCHEME_TEST, TestCipher};
    use super::*;

    const FAKE_VALUE: &str = "fake-placeholder-value";

    #[test]
    fn values_round_trip_through_the_keyset() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        assert_eq!(envelope.scheme, SCHEME_DEVICE_LOCAL);
        assert_eq!(envelope.key_id, keyset.current());
        let plaintext = keyset.decrypt("API_KEY", &envelope).unwrap();
        assert_eq!(plaintext.as_slice(), FAKE_VALUE.as_bytes());
    }

    #[test]
    fn every_encryption_uses_a_fresh_nonce() {
        let keyset = Keyset::generate().unwrap();
        let first = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let second = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let marker = envelope.to_marker();
        assert!(!marker.contains(FAKE_VALUE));
        assert!(
            !envelope
                .ciphertext
                .windows(FAKE_VALUE.len())
                .any(|window| window == FAKE_VALUE.as_bytes())
        );
    }

    #[test]
    fn a_value_cannot_be_moved_to_another_variable() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let error = keyset.decrypt("OTHER_KEY", &envelope).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("OTHER_KEY"), "{message}");
        assert!(!message.contains(FAKE_VALUE), "{message}");
    }

    #[test]
    fn a_tampered_ciphertext_fails_to_authenticate() {
        let keyset = Keyset::generate().unwrap();
        let mut envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        envelope.ciphertext[0] ^= 0xff;
        let error = keyset.decrypt("API_KEY", &envelope).unwrap_err();
        assert!(format!("{error:#}").contains("could not decrypt"));
    }

    #[test]
    fn another_devices_key_is_reported_as_a_missing_key() {
        let mine = Keyset::generate().unwrap();
        let theirs = Keyset::generate().unwrap();
        let envelope = theirs.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let error = mine.decrypt("API_KEY", &envelope).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no key"), "{message}");
        assert!(message.contains(&envelope.key_id.to_string()), "{message}");
        assert!(!message.contains(FAKE_VALUE), "{message}");
    }

    #[test]
    fn an_unsupported_scheme_is_reported_before_any_crypto() {
        let keyset = Keyset::generate().unwrap();
        let envelope = TestCipher::new(3).encrypt("API_KEY", b"x").unwrap();
        assert_eq!(envelope.scheme, SCHEME_TEST);
        let error = keyset.decrypt("API_KEY", &envelope).unwrap_err();
        assert!(
            format!("{error:#}").contains("scheme 254 is not supported"),
            "{error:#}"
        );
    }

    #[test]
    fn keysets_round_trip_through_their_stored_form() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let restored = Keyset::from_bytes(&keyset.to_bytes().unwrap()).unwrap();
        assert_eq!(restored.current(), keyset.current());
        let plaintext = restored.decrypt("API_KEY", &envelope).unwrap();
        assert_eq!(plaintext.as_slice(), FAKE_VALUE.as_bytes());
    }

    #[test]
    fn the_stored_form_is_a_keyset_not_a_bare_key() {
        let keyset = Keyset::generate().unwrap();
        let bytes = keyset.to_bytes().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("current").is_some());
        assert!(json.get("keys").and_then(|keys| keys.as_object()).is_some());
    }

    #[test]
    fn a_corrupt_keyset_is_rejected_without_echoing_it() {
        for blob in [
            &b"not json"[..],
            br#"{"current":"zz","keys":{}}"#,
            br#"{"current":"aabbccdd","keys":{}}"#,
            br#"{"current":"aabbccdd","keys":{"aabbccdd":"c2hvcnQ"}}"#,
        ] {
            let error = Keyset::from_bytes(blob).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("keyset"), "{message}");
        }
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let keyset = Keyset::generate().unwrap();
        let debug = format!("{keyset:?}");
        let bytes = keyset.to_bytes().unwrap();
        let stored: StoredKeyset = serde_json::from_slice(&bytes).unwrap();
        for encoded in stored.keys.values() {
            assert!(!debug.contains(encoded), "{debug}");
        }
    }

    #[test]
    fn absorbing_a_keyset_keeps_both_keys_readable() {
        let mut mine = Keyset::generate().unwrap();
        let theirs = Keyset::generate().unwrap();
        let their_id = theirs.current();
        let sealed = theirs.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        assert!(mine.decrypt("API_KEY", &sealed).is_err());

        let my_id = mine.current();
        mine.absorb(theirs);

        assert_eq!(
            mine.current(),
            my_id,
            "absorbing must not change the current key"
        );
        assert_eq!(
            mine.decrypt("API_KEY", &sealed).unwrap().as_slice(),
            FAKE_VALUE.as_bytes(),
            "the absorbed key must still open its own values"
        );
        assert!(mine.keys.contains_key(&their_id));
    }

    #[test]
    fn absorbing_never_overwrites_a_key_already_held() {
        let mut mine = Keyset::generate().unwrap();
        let sealed = mine.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let clone = Keyset::from_bytes(&mine.to_bytes().unwrap()).unwrap();
        mine.absorb(clone);
        assert_eq!(mine.keys.len(), 1);
        assert_eq!(
            mine.decrypt("API_KEY", &sealed).unwrap().as_slice(),
            FAKE_VALUE.as_bytes()
        );
    }

    #[test]
    fn the_envelope_length_reveals_only_a_block_bucket() {
        let keyset = Keyset::generate().unwrap();
        let mut lengths = std::collections::BTreeSet::new();
        for length in 0..PAD_BLOCK {
            let plaintext = vec![b'x'; length];
            lengths.insert(
                keyset
                    .encrypt("API_KEY", &plaintext)
                    .unwrap()
                    .to_marker()
                    .len(),
            );
        }
        assert_eq!(
            lengths.len(),
            1,
            "plaintexts within one block must all seal to the same marker length: {lengths:?}"
        );

        let longer = vec![b'x'; PAD_BLOCK];
        let longer_length = keyset
            .encrypt("API_KEY", &longer)
            .unwrap()
            .to_marker()
            .len();
        assert!(longer_length > *lengths.iter().next().unwrap());
    }

    #[test]
    fn padding_round_trips_at_every_boundary() {
        let keyset = Keyset::generate().unwrap();
        for length in [0, 1, 31, 32, 33, 63, 64, 65, 200] {
            let plaintext = vec![b'z'; length];
            let envelope = keyset.encrypt("API_KEY", &plaintext).unwrap();
            assert_eq!(
                keyset.decrypt("API_KEY", &envelope).unwrap().as_slice(),
                plaintext.as_slice(),
                "length {length} did not round-trip"
            );
        }
    }

    #[test]
    fn the_sealed_length_is_always_a_whole_number_of_blocks() {
        for length in [0, 1, 32, 33] {
            let padded = pad(&vec![b'x'; length]);
            assert!(padded.len().is_multiple_of(PAD_BLOCK));
            assert!(
                padded.len() > length,
                "padding must always add at least a byte"
            );
            assert_eq!(unpad(&padded).unwrap().as_slice(), vec![b'x'; length]);
        }
    }

    #[test]
    fn invalid_padding_is_rejected_without_echoing_the_bytes() {
        assert!(unpad(&[1_u8; 5]).is_err());
        assert!(unpad(&[]).is_err());
        let mut bad = vec![0_u8; PAD_BLOCK];
        bad[PAD_BLOCK - 1] = 4;
        assert!(unpad(&bad).is_err());
        let mut bad = vec![99_u8; PAD_BLOCK];
        bad[PAD_BLOCK - 1] = 99;
        let error = unpad(&bad).unwrap_err();
        assert!(format!("{error:#}").contains("padding"));
        assert!(!format!("{error:#}").contains("99"));
    }

    #[test]
    fn the_envelope_header_is_authenticated() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();

        let mut downgraded = envelope.clone();
        downgraded.format_version = FORMAT_VERSION + 1;
        let error = keyset.decrypt("API_KEY", &downgraded).unwrap_err();
        assert!(
            format!("{error:#}").contains("could not decrypt"),
            "{error:#}"
        );

        let mut renonced = envelope.clone();
        renonced.nonce[0] ^= 0xff;
        let error = keyset.decrypt("API_KEY", &renonced).unwrap_err();
        assert!(
            format!("{error:#}").contains("could not decrypt"),
            "{error:#}"
        );
    }

    /// Two ids over one master key, so only the AAD can reject a relabelled id.
    #[test]
    fn the_key_id_is_part_of_what_the_tag_covers() {
        let first = KeyId([0x11; KEY_ID_LEN]);
        let second = KeyId([0x22; KEY_ID_LEN]);
        let shared: [u8; KEY_LEN] = [7; KEY_LEN];
        let keyset = Keyset {
            current: first,
            keys: BTreeMap::from([
                (first, Zeroizing::new(shared)),
                (second, Zeroizing::new(shared)),
            ]),
        };

        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        assert_eq!(envelope.key_id, first);
        assert!(keyset.decrypt("API_KEY", &envelope).is_ok());

        let mut relabelled = envelope.clone();
        relabelled.key_id = second;
        let error = keyset.decrypt("API_KEY", &relabelled).unwrap_err();
        assert!(
            format!("{error:#}").contains("could not decrypt"),
            "a rewritten key id verified: {error:#}"
        );
    }

    /// `stored_len` is exact, so the zeroized accumulator never reallocates.
    #[test]
    fn the_keyring_blob_is_built_without_reallocating_the_accumulator() {
        let mut keyset = Keyset::generate().unwrap();
        for _ in 0..2 {
            keyset.absorb(Keyset::generate().unwrap());
        }
        assert_eq!(keyset.keys.len(), 3);

        let bytes = keyset.to_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            keyset.stored_len(),
            "the reserved capacity is not the length actually written"
        );
        assert_eq!(Keyset::from_bytes(&bytes).unwrap().keys.len(), 3);
    }

    #[test]
    fn the_aad_is_the_variable_name_followed_by_the_header() {
        let keyset = Keyset::generate().unwrap();
        let envelope = keyset.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let bytes = aad("API_KEY", &envelope);
        assert_eq!(&bytes[..7], b"API_KEY");
        assert_eq!(&bytes[7..], &envelope.header_bytes());
        assert_eq!(bytes.len(), "API_KEY".len() + HEADER_LEN);
    }

    #[test]
    fn the_stored_form_holds_no_owned_copy_of_a_key() {
        let keyset = Keyset::generate().unwrap();
        let bytes = keyset.to_bytes().unwrap();
        let stored: StoredKeyset<'_> = serde_json::from_slice(&bytes).unwrap();
        for encoded in stored.keys.values() {
            let start = bytes.as_ptr() as usize;
            let borrowed = encoded.as_ptr() as usize;
            assert!(
                borrowed >= start && borrowed < start + bytes.len(),
                "the key was copied out of the zeroized buffer instead of borrowed"
            );
        }
    }

    #[test]
    fn the_test_cipher_is_deterministic_and_binds_the_variable_name() {
        let cipher = TestCipher::new(0x5a);
        let first = cipher.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        let second = cipher.encrypt("API_KEY", FAKE_VALUE.as_bytes()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            cipher.decrypt("API_KEY", &first).unwrap().as_slice(),
            FAKE_VALUE.as_bytes()
        );
        assert!(cipher.decrypt("OTHER", &first).is_err());
    }
}
