//! `ggshield secret`: the verbs that read, write and inject secrets.
//!
//! Library only, no binary target: `rust/dispatcher` dispatches the argv forms listed
//! in [`NATIVE_VERBS`] here and hands everything else to `ggshield-py`, the
//! same split the hook uses.

use std::ffi::OsString;

use anyhow::Result;
use clap::Parser;

mod commands;
mod env;
mod output;

/// The `ggshield secret <verb>` forms answered by this crate.
///
/// The dispatcher matches on this list *before* anything is parsed, so a verb
/// missing here silently goes to Python and one added here shadows a Python
/// command of the same name.
pub const NATIVE_VERBS: [&str; 9] = [
    "get", "set", "del", "import", "encrypt", "run", "activate", "trust", "hook-env",
];

/// Read, write and inject secrets from a secret manager.
#[derive(Parser)]
#[command(
    name = "ggshield secret",
    version,
    about,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,
}

/// True when `args` (the argv after `ggshield`) is one of ours.
pub fn is_native(args: &[OsString]) -> bool {
    matches!(args.first().and_then(|arg| arg.to_str()), Some("secret"))
        && matches!(
            args.get(1).and_then(|arg| arg.to_str()),
            Some(verb) if NATIVE_VERBS.contains(&verb)
        )
}

/// Run one of the verbs. `args` is the argv after `ggshield`, starting at
/// `secret`, so clap sees the same command path the user typed.
pub fn run(args: &[OsString]) -> Result<()> {
    reset_sigpipe();
    let argv =
        std::iter::once(OsString::from("ggshield secret")).chain(args.iter().skip(1).cloned());
    Cli::parse_from(argv).command.execute()
}

/// Restore the default SIGPIPE handler. Rust ignores SIGPIPE at startup, which
/// turns a closed pipe into an `EPIPE` write error that `writeln!` would error
/// on; resetting it lets `ggshield secret ... | head` terminate quietly.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: setting a signal disposition to the default is sound here; we do
    // it once, before any threads are spawned.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}
