use secrecy::{ExposeSecret, SecretString};

const REDACTED: &str = "[REDACTED, use --expose to show]";

pub(crate) fn show(value: &SecretString, expose: bool) -> &str {
    if expose {
        value.expose_secret()
    } else {
        REDACTED
    }
}
