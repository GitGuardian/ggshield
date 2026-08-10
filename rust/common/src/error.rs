//! The failure modes of `ai_hook_cmd`, kept apart because they behave very
//! differently and all are security-relevant.

/// `Invalid` mirrors Python's `except ValueError` arm: print the message on
/// stderr, exit 1, print **nothing** on stdout. Agents treat a non-zero exit
/// with no JSON as a non-blocking error and surface stderr to the user.
///
/// `Fail` mirrors `except Exception`: fail open, i.e. print `{"continue": true}`
/// plus a `systemMessage` warning and exit 0. Never block the agent on a bug of
/// ours, and never silently allow without telling the user scanning did not run.
///
/// `Fatal` mirrors config loading, which happens in the `cli` group callback in
/// `__main__.py`, *before* `ai_hook_cmd` runs: a `ParseError` /
/// `UnexpectedError` raised there never reaches the command's `except Exception`
/// and never fails open — it prints `Error: <message>` on stderr and exits 128
/// (`ExitCode.UNEXPECTED_ERROR`).
/// `Clone` so a memoised failure can be handed to every caller: `Config::token()`
/// caches the credential-store read, error included, and must not repeat it.
#[derive(Debug, Clone)]
pub enum Error {
    Invalid(String),
    Fail(String),
    Fatal(String),
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

    /// `_cannot_scan_warning()` for anything else.
    pub fn scan(detail: impl AsRef<str>) -> Self {
        Error::Fail(format!(
            "ggshield could not scan ({}) — this action was NOT scanned \
             for secrets. Run 'ggshield api-status' to diagnose.",
            first_line(detail.as_ref())
        ))
    }

    /// A config-loading failure. See the `Fatal` variant docs: these do not fail
    /// open, because in Python they happen before the command runs. The upstream
    /// detail (a YAML parser's message, say) is wrapped rather than printed bare,
    /// so the user is told what the failure cost them.
    pub fn fatal(detail: impl AsRef<str>) -> Self {
        Error::Fatal(format!(
            "ggshield could not load its configuration ({}) — this action was NOT \
             scanned for secrets.",
            first_line(detail.as_ref())
        ))
    }

    /// A capability this binary knowingly does not implement: running with the
    /// wrong rules is worse than not running. The caller supplies the
    /// remediation, because "use the Python hook" is not one — `ggshield secret
    /// scan ai-hook` is the very argv the dispatcher answers natively.
    pub fn unimplemented(what: impl AsRef<str>, remediation: impl AsRef<str>) -> Self {
        Error::Fail(format!(
            "the native hook does not support {} — this action was NOT scanned for \
             secrets. {}",
            what.as_ref(),
            remediation.as_ref()
        ))
    }
}

/// Only the first line of an upstream error is shown: connection and parser
/// errors span several lines, and multi-line noise does not belong in an agent
/// message.
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
    /// THEN they stay distinct variants, and the config one still tells the user
    /// the action went unscanned.
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
}
