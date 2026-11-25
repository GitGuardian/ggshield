use crate::error::{Cause, Error};
use crate::hook::config::CredentialStoreError;

#[cfg(target_os = "macos")]
const CREDENTIAL_STORE_DENIED_CAUSE: &str =
    "The Keychain may be locked, or its item may not trust this ggshield binary.";
#[cfg(windows)]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The Windows Credential Manager may be locked.";
#[cfg(target_os = "linux")]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The Secret Service may be locked.";
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The OS credential store may be locked.";

const NOT_SCANNED: &str = "this action was NOT scanned for secrets.";

pub fn warning(error: &Error) -> String {
    let mut warning = format!("{} — {NOT_SCANNED}", reason(error));
    let remediation = remediation(error.cause());
    for sentence in remediation.iter().chain(error.context_lines()) {
        warning.push(' ');
        warning.push_str(sentence);
    }
    warning
}

fn reason(error: &Error) -> String {
    let summary = error.summary();
    let summary = first_line(&summary);
    match error.cause() {
        Cause::HookInput(_)
        | Cause::UnrecognizedAgent
        | Cause::Unauthorized
        | Cause::CredentialStore(_)
        | Cause::Config(_)
        | Cause::Unsupported(_) => summary.to_string(),
        Cause::InvalidUrlScheme { .. }
        | Cause::Tls(_)
        | Cause::ServerUnavailable(_)
        | Cause::UnexpectedResponse(_)
        | Cause::Internal => format!("ggshield could not scan ({summary})"),
    }
}

fn remediation(cause: &Cause) -> Option<String> {
    match cause {
        Cause::HookInput(_) | Cause::Config(_) | Cause::Unsupported(_) => None,
        Cause::UnrecognizedAgent => {
            Some("Update ggshield, as this agent may need a newer version.".into())
        }
        Cause::Unauthorized => Some(
            "Run 'ggshield auth login' to authenticate. If you are already logged in, run \
             'ggshield api-status' once in a terminal: your OS credentials store may require an \
             interactive approval before agent-spawned processes can read the token."
                .into(),
        ),
        Cause::CredentialStore(CredentialStoreError::Denied) => Some(format!(
            "{CREDENTIAL_STORE_DENIED_CAUSE} Run 'ggshield auth login' in a terminal to store \
             the token again."
        )),
        Cause::CredentialStore(CredentialStoreError::Missing) => {
            Some("Run 'ggshield auth login' to store a new one.".into())
        }
        Cause::InvalidUrlScheme { .. }
        | Cause::Tls(_)
        | Cause::ServerUnavailable(_)
        | Cause::UnexpectedResponse(_)
        | Cause::Internal => Some("Run 'ggshield api-status' to diagnose.".into()),
    }
}

fn first_line(detail: &str) -> &str {
    detail.lines().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::ApiError;
    use crate::user_config::ConfigError;

    /// GIVEN a multi-line upstream error
    /// WHEN it becomes a fail-open warning
    /// THEN only its first line reaches the agent message.
    #[test]
    fn scan_warning_keeps_only_the_first_line() {
        let error = Error::from(ApiError::Status {
            status: 500,
            detail: Some("boom\nstack frame\nmore".into()),
        });
        let msg = warning(&error);
        assert!(msg.starts_with("ggshield could not scan ("), "{msg}");
        assert!(msg.contains("HTTP 500: boom) —"), "{msg}");
        assert!(!msg.contains("stack frame"));
        assert!(msg.ends_with("Run 'ggshield api-status' to diagnose."));
    }

    /// GIVEN a config-loading failure
    /// WHEN its warning is built
    /// THEN it names the failure and still says the action went unscanned.
    #[test]
    fn a_config_failure_still_says_what_it_cost() {
        let msg = warning(&Error::from(ConfigError::UnsupportedVersion(3)));
        assert!(
            msg.contains("Don't know how to load config version 3"),
            "{msg}"
        );
        assert!(msg.ends_with("NOT scanned for secrets."), "{msg}");
    }

    /// GIVEN an authentication failure
    /// WHEN it becomes a fail-open warning
    /// THEN it opens with the wording Python uses.
    #[test]
    fn auth_warning_matches_the_python_wording() {
        let msg = warning(&Error::from(Cause::Unauthorized));
        assert!(msg.starts_with(
            "ggshield could not authenticate to GitGuardian — this action was NOT scanned for secrets."
        ));
    }

    /// GIVEN a refused or a missing macOS Keychain read
    /// WHEN each becomes a fail-open warning
    /// THEN it is the text Python's `_cannot_scan_warning()` gives
    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_warnings_match_the_python_wording() {
        assert_eq!(
            warning(&Error::from(CredentialStoreError::Denied)),
            "ggshield could not read its token from the macOS Keychain — this action \
             was NOT scanned for secrets. The Keychain may be locked, or its item may \
             not trust this ggshield binary. Run 'ggshield auth login' in a terminal \
             to store the token again."
        );
        assert_eq!(
            warning(&Error::from(CredentialStoreError::Missing)),
            "ggshield's token should be in the macOS Keychain, but it is not there — \
             this action was NOT scanned for secrets. Run 'ggshield auth login' to \
             store a new one."
        );
    }

    /// GIVEN a refused Secret Service read
    /// WHEN it becomes a fail-open warning
    /// THEN it is the text Python's `_cannot_scan_warning()` gives
    #[cfg(target_os = "linux")]
    #[test]
    fn secret_service_warning_matches_the_python_wording() {
        assert_eq!(
            warning(&Error::from(CredentialStoreError::Denied)),
            "ggshield could not read its token from the Secret Service — this action \
             was NOT scanned for secrets. The Secret Service may be locked. Run \
             'ggshield auth login' in a terminal to store the token again."
        );
    }
}
