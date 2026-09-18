use clap::Subcommand;

pub(crate) mod activate;
pub(crate) mod del;
pub(crate) mod encrypt;
pub(crate) mod get;
pub(crate) mod import;
pub(crate) mod run;
pub(crate) mod set;
pub(crate) mod shared;
pub(crate) mod trust;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Read a secret from a provider.
    Get(get::Args),
    /// Create or update fields in a provider secret.
    Set(set::Args),
    // Help lives on `del::Args`, as for `encrypt`: the file provider never
    // deletes the secret itself, and that needs more than a summary line.
    Del(del::Args),
    // Help lives on `import::Args`: what it does with the file it read
    // needs more than a summary line.
    Import(import::Args),
    // Help lives on `encrypt::Args`: a doc comment here would override it and
    // drop the long help. See CLAUDE.md.
    Encrypt(encrypt::Args),
    /// Run a command with secrets injected as environment variables.
    Run(run::Args),
    // Help lives on `activate::Args`, as for `encrypt`.
    Activate(activate::Args),
    // Help lives on `trust::Args`.
    Trust(trust::Args),
    /// Print the environment changes for the current directory (used by the
    /// shell hook `activate` installs).
    #[command(hide = true)]
    HookEnv(activate::HookArgs),
}

impl Command {
    pub(crate) fn execute(self) -> anyhow::Result<()> {
        match self {
            Command::Get(args) => get::execute(args),
            Command::Set(args) => set::execute(args),
            Command::Del(args) => del::execute(args),
            Command::Import(args) => import::execute(args),
            Command::Encrypt(args) => encrypt::execute(args),
            Command::Run(args) => run::execute(args),
            Command::Activate(args) => activate::execute(args),
            Command::Trust(args) => trust::execute(args),
            Command::HookEnv(args) => activate::hook_env(args),
        }
    }
}
