//! The on-disk form of an encrypted value: `KEY=gitguardian:<base64url envelope>`.
//!
//! Magic, version and scheme live inside the envelope, authenticated by the
//! AEAD. There is deliberately no unauthenticated ref-kind segment in the text:
//! base64url has no `:`, so a future `gitguardian:<kind>:...` stays distinguishable.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;
use zeroize::Zeroizing;

/// Prefix shared by every gitguardian value reference.
pub(crate) const MARKER_PREFIX: &str = "gitguardian:";

/// Envelope magic. Not a version: [`FORMAT_VERSION`] carries that.
const MAGIC: [u8; 4] = *b"GGFE";
/// The format this version writes.
pub(crate) const FORMAT_VERSION: u8 = 1;
/// Device-local XChaCha20-Poly1305, keyed from the OS keyring.
pub(crate) const SCHEME_DEVICE_LOCAL: u8 = 1;

pub(crate) const KEY_ID_LEN: usize = 4;
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag, always appended to the ciphertext by the AEAD.
const TAG_LEN: usize = 16;
pub(crate) const HEADER_LEN: usize = MAGIC.len() + 2 + KEY_ID_LEN + NONCE_LEN;

/// Identifies which key of the keyset encrypted a value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KeyId(pub [u8; KEY_ID_LEN]);

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl KeyId {
    /// Parse the hex rendering used as the keyset's JSON object key.
    ///
    /// The ASCII check keeps fixed byte-offset slicing from panicking.
    pub(crate) fn from_hex(text: &str) -> Option<Self> {
        if text.len() != KEY_ID_LEN * 2 || !text.is_ascii() {
            return None;
        }
        let mut bytes = [0_u8; KEY_ID_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(KeyId(bytes))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// What a dotenv value turned out to be.
#[derive(Debug)]
pub(crate) enum ValueKind {
    /// A plain, unencrypted value.
    Plain,
    /// A `gitguardian:` reference.
    Encrypted(Envelope),
}

/// A parsed encrypted value.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    pub(crate) format_version: u8,
    pub(crate) scheme: u8,
    pub(crate) key_id: KeyId,
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Ciphertext with the AEAD tag appended.
    pub(crate) ciphertext: Vec<u8>,
}

// Keep secret-adjacent ciphertext out of logs and panic messages.
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("format_version", &self.format_version)
            .field("scheme", &self.scheme)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Envelope {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        bytes.extend_from_slice(&self.header_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// The on-disk header, fed to the AEAD as associated data to block
    /// version/scheme downgrades. Fixed width, so it needs no separator in the AAD.
    pub(crate) fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let mut header = [0_u8; HEADER_LEN];
        header[..MAGIC.len()].copy_from_slice(&MAGIC);
        header[4] = self.format_version;
        header[5] = self.scheme;
        header[6..6 + KEY_ID_LEN].copy_from_slice(&self.key_id.0);
        header[6 + KEY_ID_LEN..].copy_from_slice(&self.nonce);
        header
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(EnvelopeError::Malformed);
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(EnvelopeError::Malformed);
        }
        let format_version = bytes[4];
        if format_version != FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedFormat { format_version });
        }
        let mut key_id = [0_u8; KEY_ID_LEN];
        key_id.copy_from_slice(&bytes[6..6 + KEY_ID_LEN]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[6 + KEY_ID_LEN..HEADER_LEN]);
        Ok(Envelope {
            format_version,
            scheme: bytes[5],
            key_id: KeyId(key_id),
            nonce,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// The value as written in the file.
    pub(crate) fn to_marker(&self) -> String {
        format!("{MARKER_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }
}

/// Decide whether a dotenv value is plain or an encrypted reference.
///
/// Other tools' markers are named so users don't hunt for a key they never had.
pub(crate) fn classify(value: &str) -> Result<ValueKind, EnvelopeError> {
    if let Some(payload) = value.strip_prefix(MARKER_PREFIX) {
        // base64url has no `:`, so a colon means a kind-qualified reference.
        if payload.contains(':') {
            return Err(EnvelopeError::UnknownRefKind);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| EnvelopeError::Malformed)?,
        );
        return Ok(ValueKind::Encrypted(Envelope::from_bytes(&bytes)?));
    }
    if value.starts_with("encrypted:") {
        return Err(EnvelopeError::ForeignMarker {
            tool: "dotenvx",
            marker: "encrypted:",
        });
    }
    if value.starts_with("varlock(") {
        return Err(EnvelopeError::ForeignMarker {
            tool: "varlock",
            marker: "varlock(",
        });
    }
    Ok(ValueKind::Plain)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum EnvelopeError {
    /// A `gitguardian:<kind>:...` reference of an unknown kind.
    ///
    /// The kind is kept out of the message: on a plaintext value it would leak
    /// a fragment of the secret to stderr and CI logs.
    #[error(
        "value is a '{MARKER_PREFIX}<kind>:' reference to a secret held elsewhere, which this \
         version of gitguardian cannot resolve; it understands only inline \
         '{MARKER_PREFIX}<envelope>' values. Upgrade the CLI"
    )]
    UnknownRefKind,
    #[error(
        "value looks like a {tool} secret ('{marker}' prefix), not a gitguardian one; \
         decrypt it with {tool} and re-run `gitguardian set` to store it here"
    )]
    ForeignMarker {
        tool: &'static str,
        marker: &'static str,
    },
    #[error("value is not a well-formed gitguardian envelope")]
    Malformed,
    #[error(
        "envelope format version {format_version} is not supported by this version of \
         gitguardian; upgrade the CLI"
    )]
    UnsupportedFormat { format_version: u8 },
    #[error(
        "envelope scheme {scheme} is not supported by this version of gitguardian; \
         upgrade the CLI"
    )]
    UnsupportedScheme { scheme: u8 },
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            format_version: FORMAT_VERSION,
            scheme: SCHEME_DEVICE_LOCAL,
            key_id: KeyId([0xde, 0xad, 0xbe, 0xef]),
            nonce: [7; NONCE_LEN],
            ciphertext: vec![0xab; 24],
        }
    }

    fn parse(value: &str) -> Result<Envelope, EnvelopeError> {
        match classify(value)? {
            ValueKind::Encrypted(envelope) => Ok(envelope),
            ValueKind::Plain => panic!("expected an encrypted value"),
        }
    }

    #[test]
    fn envelopes_round_trip_through_the_marker() {
        let original = envelope();
        let marker = original.to_marker();
        assert!(marker.starts_with("gitguardian:"));
        assert_eq!(parse(&marker).unwrap(), original);
    }

    #[test]
    fn the_marker_is_safe_unquoted_in_a_dotenv_file() {
        let marker = envelope().to_marker();
        assert!(
            marker
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':')),
            "{marker}"
        );
        assert!(!marker.contains('='), "base64url must be unpadded");
    }

    #[test]
    fn key_id_renders_and_parses_as_hex() {
        let key_id = KeyId([0x01, 0x23, 0xab, 0xff]);
        assert_eq!(key_id.to_string(), "0123abff");
        assert_eq!(KeyId::from_hex("0123abff"), Some(key_id));
        assert_eq!(KeyId::from_hex("0123abf"), None);
        assert_eq!(KeyId::from_hex("0123abfg"), None);
    }

    /// Non-ASCII text of the right byte length is rejected, not sliced into a panic.
    #[test]
    fn a_key_id_that_is_not_ascii_is_rejected_rather_than_panicking() {
        for text in ["🔐🔐", "abcd🔐", "\u{e9}\u{e9}\u{e9}\u{e9}"] {
            assert_eq!(
                text.len(),
                KEY_ID_LEN * 2,
                "{text:?} is not the byte length"
            );
            assert_eq!(KeyId::from_hex(text), None, "{text:?}");
        }
    }

    #[test]
    fn plain_values_are_plain() {
        for value in ["", "hello", "gitguardian", "not:a:marker", "https://x/y"] {
            assert!(
                matches!(classify(value).unwrap(), ValueKind::Plain),
                "{value}"
            );
        }
    }

    #[test]
    fn a_dotenvx_value_names_dotenvx() {
        let error = classify("encrypted:BLAHBLAH").unwrap_err();
        assert_eq!(
            error,
            EnvelopeError::ForeignMarker {
                tool: "dotenvx",
                marker: "encrypted:"
            }
        );
        assert!(error.to_string().contains("dotenvx"));
    }

    #[test]
    fn a_varlock_value_names_varlock() {
        let error = classify("varlock(BLAHBLAH)").unwrap_err();
        assert_eq!(
            error,
            EnvelopeError::ForeignMarker {
                tool: "varlock",
                marker: "varlock("
            }
        );
        assert!(error.to_string().contains("varlock"));
    }

    /// A colon in the payload is an unknown reference, not a corrupt envelope.
    #[test]
    fn a_colon_in_the_payload_is_a_reference_not_a_malformed_envelope() {
        for value in [
            "gitguardian:vault:secret/app#KEY",
            "gitguardian:kms:arn:aws:kms:eu-west-1:1:key/x",
            "gitguardian:file:QUJDREVGRw",
        ] {
            assert_eq!(
                classify(value).unwrap_err(),
                EnvelopeError::UnknownRefKind,
                "{value}"
            );
        }
    }

    #[test]
    fn an_unknown_ref_kind_is_not_a_crypto_error() {
        let error = classify("gitguardian:vault:secret/app#KEY").unwrap_err();
        assert_eq!(error, EnvelopeError::UnknownRefKind);
        let message = error.to_string();
        assert!(message.contains("held elsewhere"), "{message}");
        assert!(message.contains("Upgrade the CLI"), "{message}");
        assert!(!message.contains("decrypt"), "{message}");
    }

    /// The error message never echoes any fragment of the value.
    #[test]
    fn an_unknown_ref_kind_never_echoes_the_value() {
        let fragment = "fake-secret-fragment";
        let error = classify(&format!("gitguardian:{fragment}:rest")).unwrap_err();
        assert_eq!(error, EnvelopeError::UnknownRefKind);
        let message = error.to_string();
        assert!(!message.contains(fragment), "the value leaked: {message}");
        assert!(!message.contains("rest"), "the value leaked: {message}");
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        for value in [
            "gitguardian:",
            "gitguardian:!!!not-base64!!!",
            "gitguardian:QUJD",
            "gitguardian:file",
            &URL_SAFE_NO_PAD.encode([0_u8; 64]),
        ] {
            let value = if value.starts_with("gitguardian:") {
                value.to_string()
            } else {
                format!("gitguardian:{value}")
            };
            assert!(
                matches!(classify(&value), Err(EnvelopeError::Malformed)),
                "{value} should be malformed"
            );
        }
    }

    #[test]
    fn an_unknown_format_version_is_reported_as_such() {
        let mut bytes = envelope().to_bytes();
        bytes[4] = 9;
        let value = format!("gitguardian:{}", URL_SAFE_NO_PAD.encode(&bytes));
        let error = classify(&value).unwrap_err();
        assert_eq!(
            error,
            EnvelopeError::UnsupportedFormat { format_version: 9 }
        );
        assert!(error.to_string().contains("upgrade the CLI"));
    }

    #[test]
    fn the_scheme_byte_survives_parsing_so_the_cipher_can_reject_it() {
        let mut original = envelope();
        original.scheme = 200;
        assert_eq!(parse(&original.to_marker()).unwrap().scheme, 200);
    }

    #[test]
    fn debug_output_omits_the_ciphertext() {
        let debug = format!("{:?}", envelope());
        assert!(debug.contains("deadbeef"), "{debug}");
        assert!(!debug.contains("171"), "{debug}");
    }
}
