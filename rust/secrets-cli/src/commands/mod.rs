use clap::Subcommand;

pub(crate) mod activate;
pub(crate) mod encrypt;
pub(crate) mod get;
pub(crate) mod import;
pub(crate) mod list;
pub(crate) mod run;
pub(crate) mod set;
pub(crate) mod shared;
pub(crate) mod trust;
pub(crate) mod unset;

/// `ggshield secret <verb>`.
// A variant without a doc comment is deliberate: one would override the long help on its Args.
#[derive(Subcommand)]
pub(crate) enum SecretCommand {
    /// Read a secret from a provider.
    Get(get::Args),
    /// Create or update fields in a provider secret.
    Set(set::Args),
    Unset(unset::Args),
    List(list::Args),
    Import(import::Args),
    Encrypt(encrypt::Args),
}

impl SecretCommand {
    pub(crate) fn execute(self) -> anyhow::Result<()> {
        match self {
            SecretCommand::Get(args) => get::execute(args),
            SecretCommand::Set(args) => set::execute(args),
            SecretCommand::Unset(args) => unset::execute(args),
            SecretCommand::List(args) => list::execute(args),
            SecretCommand::Import(args) => import::execute(args),
            SecretCommand::Encrypt(args) => encrypt::execute(args),
        }
    }
}

/// `ggshield <verb>`.
#[derive(Subcommand)]
pub(crate) enum TopLevelCommand {
    /// Run a command with secrets injected as environment variables.
    Run(run::Args),
    Activate(activate::Args),
    Trust(trust::Args),
    /// Print the environment changes for the current directory (used by the
    /// shell hook `activate` installs).
    #[command(hide = true)]
    HookEnv(activate::HookArgs),
}

impl TopLevelCommand {
    pub(crate) fn execute(self) -> anyhow::Result<()> {
        match self {
            TopLevelCommand::Run(args) => run::execute(args),
            TopLevelCommand::Activate(args) => activate::execute(args),
            TopLevelCommand::Trust(args) => trust::execute(args),
            TopLevelCommand::HookEnv(args) => activate::hook_env(args),
        }
    }
}
