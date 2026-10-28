//! The failure modes of `ai_hook_cmd`, kept apart because they behave differently.

#[cfg(target_os = "macos")]
const CREDENTIAL_STORE: &str = "macOS Keychain";
#[cfg(windows)]
const CREDENTIAL_STORE: &str = "Windows Credential Manager";
#[cfg(target_os = "linux")]
const CREDENTIAL_STORE: &str = "Secret Service";
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
const CREDENTIAL_STORE: &str = "OS credential store";

#[cfg(target_os = "macos")]
const CREDENTIAL_STORE_DENIED_CAUSE: &str =
    "The Keychain may be locked, or its item may not trust this ggshield binary.";
#[cfg(windows)]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The Windows Credential Manager may be locked.";
#[cfg(target_os = "linux")]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The Secret Service may be locked.";
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
const CREDENTIAL_STORE_DENIED_CAUSE: &str = "The OS credential store may be locked.";

/// `Invalid` mirrors Python's `except ValueError` arm: the message on stderr, exit
/// 1, **nothing** on stdout. Agents treat a non-zero exit with no JSON as a
/// non-blocking error and surface stderr to the user.
///
/// `Fail` mirrors `except Exception`: fail open, i.e. `{"continue": true}` plus a
/// `systemMessage` warning and exit 0.
///
/// `Fatal` mirrors config loading, which happens in the `cli` group callback in
/// `__main__.py`, *before* `ai_hook_cmd` runs: a `ParseError` / `UnexpectedError`
/// raised there never reaches the command's `except Exception` and never fails
/// open — it prints `Error: <message>` on stderr and exits 128.
///
/// `Clone` so `Config::token()` can hand its memoised failure to every caller.
///
/// `Unsupported` is a configuration this binary knowingly cannot handle and
/// `ggshield-py` can: the dispatcher hands the event over instead of failing
/// open, so the message here is used only if handing over is impossible too.
#[derive(Debug, Clone)]
pub enum Error {
    Invalid(String),
    Fail(String),
    Fatal(String),
    Unsupported(String),
}

impl Error {
    /// `_cannot_scan_warning()` for an AuthError.
    pub fn auth() -> Self {
        Error::Fail(
            "ggshield could not authenticate to GitGuardian — this action was NOT \
             scanned for secrets. Run 'ggshield auth login' to authenticate. If you \
             are already logged in, run 'ggshield api-status' once in a terminal: \
             your OS credentials store may require an interactive approval before \
             agent-spawned processes can read the token."
                .into(),
        )
    }

    pub fn credential_store_denied() -> Self {
        Error::Fail(format!(
            "ggshield could not read its token from the {CREDENTIAL_STORE} — this \
             action was NOT scanned for secrets. {CREDENTIAL_STORE_DENIED_CAUSE} Run \
             'ggshield auth login' in a terminal to store the token again."
        ))
    }

    pub fn credential_store_missing() -> Self {
        Error::Fail(format!(
            "ggshield's token should be in the {CREDENTIAL_STORE}, but it is not \
             there — this action was NOT scanned for secrets. Run 'ggshield auth \
             login' to store a new one."
        ))
    }

    /// `_cannot_scan_warning()` for anything else.
    pub fn scan(detail: impl AsRef<str>) -> Self {
        Error::Fail(format!(
            "ggshield could not scan ({}) — this action was NOT scanned \
             for secrets. Run 'ggshield api-status' to diagnose.",
            first_line(detail.as_ref())
        ))
    }

    /// A config-loading failure. See the `Fatal` variant docs: these do not fail
    /// open, because in Python they happen before the command runs.
    pub fn fatal(detail: impl AsRef<str>) -> Self {
        Error::Fatal(format!(
            "ggshield could not load its configuration ({}) — this action was NOT \
             scanned for secrets.",
            first_line(detail.as_ref())
        ))
    }

    /// A capability this binary knowingly does not implement: running with the
    /// wrong rules is worse than not running.
    ///
    /// This does not fail open — the dispatcher hands the event to `ggshield-py`,
    /// which implements all of ggshield's configuration. The caller's remediation
    /// is the fallback for a bundle with no launcher to hand to.
    pub fn unimplemented(what: impl AsRef<str>, remediation: impl AsRef<str>) -> Self {
        Error::Unsupported(format!(
            "the native hook does not support {} — this action was NOT scanned for \
             secrets. {}",
            what.as_ref(),
            remediation.as_ref()
        ))
    }
}

/// Only the first line: connection and parser errors span several, and multi-line
/// noise does not belong in an agent message.
fn first_line(detail: &str) -> &str {
    detail.lines().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GIVEN a multi-line upstream error
    /// WHEN it becomes a fail-open warning
    /// THEN only its first line reaches the agent message.
    #[test]
    fn scan_warning_keeps_only_the_first_line() {
        let Error::Fail(msg) = Error::scan("boom\nstack frame\nmore") else {
            panic!("expected Fail");
        };
        assert!(msg.starts_with("ggshield could not scan (boom) —"), "{msg}");
        assert!(!msg.contains("stack frame"));
        assert!(msg.ends_with("Run 'ggshield api-status' to diagnose."));
    }

    /// GIVEN a config-loading failure and a scan failure
    /// WHEN each is built
    /// THEN they stay distinct variants, and the config one still says the action
    /// went unscanned.
    #[test]
    fn fatal_is_distinct_from_fail_open_but_still_says_what_it_cost() {
        let Error::Fatal(msg) = Error::fatal("bad YAML at line 3\nfoo") else {
            panic!("expected Fatal");
        };
        assert!(msg.contains("bad YAML at line 3"), "{msg}");
        assert!(msg.contains("NOT scanned for secrets"), "{msg}");
        assert!(!msg.contains("foo"), "{msg}");
        assert!(matches!(Error::scan("boom"), Error::Fail(_)));
    }

    /// GIVEN an authentication failure
    /// WHEN it becomes a fail-open warning
    /// THEN it opens with the wording Python uses.
    #[test]
    fn auth_warning_matches_the_python_wording() {
        let Error::Fail(msg) = Error::auth() else {
            panic!("expected Fail");
        };
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
        let Error::Fail(denied) = Error::credential_store_denied() else {
            panic!("expected Fail");
        };
        assert_eq!(
            denied,
            "ggshield could not read its token from the macOS Keychain — this action \
             was NOT scanned for secrets. The Keychain may be locked, or its item may \
             not trust this ggshield binary. Run 'ggshield auth login' in a terminal \
             to store the token again."
        );
        let Error::Fail(missing) = Error::credential_store_missing() else {
            panic!("expected Fail");
        };
        assert_eq!(
            missing,
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
        let Error::Fail(denied) = Error::credential_store_denied() else {
            panic!("expected Fail");
        };
        assert_eq!(
            denied,
            "ggshield could not read its token from the Secret Service — this action \
             was NOT scanned for secrets. The Secret Service may be locked. Run \
             'ggshield auth login' in a terminal to store the token again."
        );
    }
}
