//! `ggshield`: `secret scan ai-hook` natively, everything else to Python.
//!
//! This is the `ggshield` the standalone bundle puts on the PATH, so a bug in
//! `dispatch` breaks every ggshield command, not just the hook. See
//! `doc/dev/os-packages.md`.

mod cli;
mod config;
mod dispatch;
mod error;
mod subcommands;
#[cfg(test)]
mod test_support;

use std::env::args_os;
use std::ffi::OsString;
use std::process::exit;

use clap::{ArgMatches, CommandFactory, FromArgMatches};

use crate::cli::GGShield;
use crate::config::{Config, Sources};
use crate::error::{Cause, Error, ExitCode, FailurePolicy};
use crate::subcommands::secret::scan::ai_hook;

fn main() {
    // Dispatch before touching stdin: `exec()` hands the untouched descriptor to
    // Python, and reading a byte here would eat the delegated command's input.
    let args: Vec<OsString> = args_os().skip(1).collect();
    if dispatch::is_native_hook(&args) {
        exit(ai_hook::run_native_hook());
    }
    if dispatch::is_warm_notifier(&args) {
        exit(ai_hook::warm_notifier());
    }
    let Ok(matches) = GGShield::command().try_get_matches_from(args_os()) else {
        dispatch::delegate(&args);
    };
    let code = match run(matches) {
        Ok(code) => code,
        Err(error) => {
            match error.cause() {
                Cause::Usage(usage) => {
                    let _ = usage.print();
                }
                _ => eprintln!("Error: {error}"),
            }
            error.exit_code(&FailurePolicy::default())
        }
    };
    exit(code.into());
}

fn run(matches: ArgMatches) -> Result<ExitCode, Error> {
    let cli = GGShield::from_arg_matches(&matches)?;
    let sources = Sources::load(matches)?;
    let config = Config::try_from(&sources)?;
    cli.command.run(&sources, &config)
}
