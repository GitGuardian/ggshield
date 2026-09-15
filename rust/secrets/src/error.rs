use thiserror::Error;

/// Provider-neutral errors surfaced by the core secret store.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret not found at {path}")]
    SecretNotFound { path: String },
    #[error("authentication failed for provider '{provider}'")]
    AuthenticationFailed { provider: String },
    #[error("permission denied for provider '{provider}'")]
    PermissionDenied { provider: String },
    #[error("field not found in secret: {field}")]
    FieldNotFound { field: String },
    #[error("fields not found in secret: {}", fields.join(", "))]
    FieldsNotFound { fields: Vec<String> },
    #[error("provider '{provider}' does not support {operation}")]
    UnsupportedOperation {
        provider: String,
        operation: &'static str,
    },
}

impl SecretError {
    /// Whether `error`'s chain contains a [`SecretError::SecretNotFound`].
    ///
    /// Lets callers treat "the secret isn't there" differently from real
    /// failures without unwinding the anyhow chain themselves.
    pub fn is_secret_not_found(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<SecretError>()
                .is_some_and(|error| matches!(error, SecretError::SecretNotFound { .. }))
        })
    }

    pub(crate) fn missing_fields(fields: &[String]) -> Self {
        let mut unique_fields = Vec::new();
        for field in fields {
            if !unique_fields.contains(field) {
                unique_fields.push(field.clone());
            }
        }
        match unique_fields.as_slice() {
            [field] => SecretError::FieldNotFound {
                field: field.clone(),
            },
            _ => SecretError::FieldsNotFound {
                fields: unique_fields,
            },
        }
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_not_found_detection_walks_the_anyhow_chain() {
        let error = anyhow::Error::new(SecretError::SecretNotFound {
            path: "secret/myapp".to_string(),
        })
        .context("outer context");
        assert!(SecretError::is_secret_not_found(&error));

        let other = anyhow::anyhow!("plain failure");
        assert!(!SecretError::is_secret_not_found(&other));
    }
}
