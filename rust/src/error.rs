//! This module declares the top-level ggshield error.
//!
//! This error is the only error that should be stringified/returned by the CLI.
//! An error cause should not refer to a specific command. Callers should instead
//! use the `context` vector to add context-specific information to an error.
use std::error::Error as StdError;

use crate::config::ConfigError;
use crate::subcommands::secret::scan::ai_hook::config::CredentialStoreError;
use crate::subcommands::secret::scan::ai_hook::user_config::AiHookFailurePolicy;
use crate::subcommands::secret::scan::ai_hook::{ApiError, HookInputError, TlsError};

#[derive(Debug, thiserror::Error)]
pub struct Error {
    cause: Cause,
    context: Vec<String>,
}

/// The cause of an error.
/// This is the high-level reason for a failed operation.
/// Context-specific information should be added to [Error]'s context vector.
#[derive(Debug, thiserror::Error)]
pub enum Cause {
    #[error(transparent)]
    HookInput(#[from] HookInputError),
    #[error("ggshield does not recognize the AI agent that called it")]
    UnrecognizedAgent,
    #[error("ggshield could not authenticate to GitGuardian")]
    Unauthorized,
    #[error(transparent)]
    CredentialStore(#[from] CredentialStoreError),
    #[error("ggshield could not load its configuration")]
    Config(#[from] ConfigError),
    #[error("Invalid scheme for {kind} URL '{url}', expected HTTPS")]
    InvalidUrlScheme { kind: &'static str, url: String },
    #[error(transparent)]
    FileSystem(#[from] gg_fs::Error),
    #[error(transparent)]
    Usage(#[from] clap::Error),
    #[error("invalid setting")]
    InvalidSetting(#[source] Box<dyn StdError + Send + Sync>),
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error(transparent)]
    ServerUnavailable(#[from] ApiError),
    #[error("bad API response")]
    UnexpectedResponse(#[source] serde_json::Error),
    #[error("internal error")]
    Internal,
    #[error("the native hook does not support {0}")]
    Unsupported(String),
}

/// The exit codes of the ggshield command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success,
    HookInputFailure,
    UsageFailure,
    HookBlock,
    AuthenticationFailure,
    ServerUnavailable,
    GenericFailure,
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        match code {
            ExitCode::Success => 0,
            ExitCode::HookInputFailure => 1,
            ExitCode::UsageFailure | ExitCode::HookBlock => 2,
            ExitCode::AuthenticationFailure => 3,
            ExitCode::ServerUnavailable => 4,
            ExitCode::GenericFailure => 128,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FailurePolicy {
    pub ai_hook: Option<AiHookFailurePolicy>,
}

impl Error {
    pub fn cause(&self) -> &Cause {
        &self.cause
    }

    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.context.push(context.into());
        self
    }

    pub fn context_lines(&self) -> &[String] {
        &self.context
    }

    pub fn summary(&self) -> String {
        let mut summary = self.cause.to_string();
        let mut source = std::error::Error::source(&self.cause);
        while let Some(error) = source {
            let detail = error.to_string();
            if !summary.ends_with(&detail) {
                summary.push_str(&format!(": {detail}"));
            }
            source = error.source();
        }
        summary
    }

    pub fn exit_code(&self, policy: &FailurePolicy) -> ExitCode {
        use AiHookFailurePolicy::{Allow, Block};
        match (&self.cause, policy.ai_hook) {
            (Cause::HookInput(_), _) => ExitCode::HookInputFailure,
            (
                Cause::Config(
                    ConfigError::Read { .. }
                    | ConfigError::Parse { .. }
                    | ConfigError::UnsupportedVersion(_)
                    | ConfigError::DotEnvSyntax { .. },
                ),
                _,
            ) => ExitCode::GenericFailure,
            (_, Some(Allow)) => ExitCode::Success,
            (_, Some(Block)) => ExitCode::HookBlock,
            (Cause::Unauthorized | Cause::CredentialStore(_), None) => {
                ExitCode::AuthenticationFailure
            }
            (Cause::InvalidUrlScheme { .. } | Cause::Usage(_) | Cause::InvalidSetting(_), None) => {
                ExitCode::UsageFailure
            }
            (Cause::ServerUnavailable(_), None) => ExitCode::ServerUnavailable,
            (
                Cause::UnrecognizedAgent
                | Cause::Config(ConfigError::DirectoryNotFound)
                | Cause::FileSystem(_)
                | Cause::Tls(_)
                | Cause::UnexpectedResponse(_)
                | Cause::Internal
                | Cause::Unsupported(_),
                None,
            ) => ExitCode::GenericFailure,
        }
    }
}

impl<T: Into<Cause>> From<T> for Error {
    fn from(cause: T) -> Self {
        Error {
            cause: cause.into(),
            context: Vec::new(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())?;
        for context in &self.context {
            write!(f, "\n  {context}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: FailurePolicy = FailurePolicy {
        ai_hook: Some(AiHookFailurePolicy::Allow),
    };
    const BLOCK: FailurePolicy = FailurePolicy {
        ai_hook: Some(AiHookFailurePolicy::Block),
    };
    const NO_HOOK: FailurePolicy = FailurePolicy { ai_hook: None };

    fn server_error() -> Cause {
        ApiError::Status {
            status: 503,
            detail: None,
        }
        .into()
    }

    /// GIVEN errors that leave a hook event unscanned
    /// WHEN the exit code is resolved with an AI hook policy
    /// THEN allow gives success and block gives the hook's blocking code.
    #[test]
    fn the_ai_hook_policy_decides_the_exit_code_of_an_unscanned_event() {
        for cause in [
            Cause::Unauthorized,
            Cause::Internal,
            server_error(),
            ConfigError::DirectoryNotFound.into(),
        ] {
            let error = Error::from(cause);
            assert_eq!(error.exit_code(&ALLOW), ExitCode::Success, "{error}");
            assert_eq!(error.exit_code(&BLOCK), ExitCode::HookBlock, "{error}");
        }
    }

    /// GIVEN invalid hook input and a config file that cannot be loaded
    /// WHEN the exit code is resolved with any policy
    /// THEN the policy does not change it.
    #[test]
    fn hook_input_and_config_file_errors_ignore_the_policy() {
        for policy in [ALLOW, BLOCK, NO_HOOK] {
            assert_eq!(
                Error::from(HookInputError::Empty).exit_code(&policy),
                ExitCode::HookInputFailure
            );
            assert_eq!(
                Error::from(ConfigError::UnsupportedVersion(3)).exit_code(&policy),
                ExitCode::GenericFailure
            );
        }
    }

    /// GIVEN no AI hook policy
    /// WHEN the exit code is resolved
    /// THEN it follows the cause.
    #[test]
    fn without_a_hook_policy_the_exit_code_follows_the_cause() {
        let invalid_url = Cause::InvalidUrlScheme {
            kind: "API",
            url: "http://example.com".into(),
        };
        for (cause, expected) in [
            (Cause::Unauthorized, ExitCode::AuthenticationFailure),
            (
                CredentialStoreError::Missing.into(),
                ExitCode::AuthenticationFailure,
            ),
            (invalid_url, ExitCode::UsageFailure),
            (server_error(), ExitCode::ServerUnavailable),
            (Cause::Internal, ExitCode::GenericFailure),
        ] {
            let error = Error::from(cause);
            assert_eq!(error.exit_code(&NO_HOOK), expected, "{error}");
        }
    }

    /// GIVEN an error with a source and two contexts
    /// WHEN it is displayed
    /// THEN the source follows the cause and each context is on its own line.
    #[test]
    fn display_shows_the_source_chain_then_the_context() {
        let source = serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON");
        let expected =
            format!("Failed to parse JSON from stdin: {source}\n  first context\n  second context");

        let error = Error::from(HookInputError::Json(source))
            .context("first context")
            .context("second context");

        assert_eq!(error.to_string(), expected);
    }
}
