use std::path::PathBuf;

use clap::{ArgAction, Args, Parser};
use gg_url::DashboardUrl;

use crate::config::{Config, Sources};
use crate::error::{Error, ExitCode};

/// ggshield's command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "ggshield",
    version = env!("GGSHIELD_VERSION"),
    args_override_self = true
)]
pub struct GGShield {
    #[command(flatten)]
    pub global_options: GlobalOptions,

    #[command(subcommand)]
    pub command: Subcommand,
}

/// Subcommands of the ggshield CLI
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {}

impl Subcommand {
    pub fn run(&self, _sources: &Sources, _config: &Config) -> Result<ExitCode, Error> {
        match *self {}
    }
}

#[derive(Debug, Args)]
pub struct GlobalOptions {
    /// Set a custom config file. Ignores local and global config files.
    #[arg(long, short, value_name = "FILE")]
    pub config_path: Option<PathBuf>,
    /// URL of the GitGuardian instance to use.
    #[arg(long, value_name = "URL")]
    pub instance: Option<DashboardUrl>,
    /// Verbose display mode
    #[arg(long, short, global = true, action = ArgAction::Count)]
    pub verbose: u8,
    /// Send log output to stderr. Equivalent to `--log-file -`
    #[arg(long, global = true)]
    pub debug: bool,
    /// Send log output to FILE. Use '-' to redirect to stderr
    #[arg(long, global = true, value_name = "FILE")]
    pub log_file: Option<PathBuf>,
    /// Skip all certificate verification checks. WARNING: this option makes the transfer insecure.
    #[arg(long, global = true)]
    pub insecure: bool,
    /// Deprecated: use --insecure.
    #[arg(long, global = true)]
    pub allow_self_signed: bool,
    /// After executing commands, check if a new version of ggshield is available
    #[arg(long, global = true, conflicts_with = "no_check_for_updates")]
    pub check_for_updates: bool,
    /// After executing commands, do not check if a new version of ggshield is available
    #[arg(long, global = true, conflicts_with = "check_for_updates")]
    pub no_check_for_updates: bool,
}
