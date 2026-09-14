use secrecy::{ExposeSecret, SecretString};

/// Shown in place of a secret value when output is not exposed.
const REDACTED: &str = "[REDACTED, use --expose to show]";

/// A secret value rendered for output: the value itself if exposed, otherwise
/// a redaction placeholder.
pub(crate) fn show(value: &SecretString, expose: bool) -> &str {
    if expose {
        value.expose_secret()
    } else {
        REDACTED
    }
}
