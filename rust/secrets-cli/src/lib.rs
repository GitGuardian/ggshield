//! The verbs that read, write and inject secrets: `ggshield secret <verb>` and
//! `ggshield run|activate|trust`.
//!
//! `rust/dispatcher` routes [`SECRET_VERBS`] and [`TOP_LEVEL_VERBS`] here and
//! everything else to `ggshield-py`.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

mod commands;
mod env;
mod output;

/// Matched before parsing: a verb missing here silently goes to Python, one
/// added here shadows the Python command of the same name.
pub const SECRET_VERBS: [&str; 6] = ["get", "set", "unset", "list", "import", "encrypt"];
pub const TOP_LEVEL_VERBS: [&str; 4] = ["run", "activate", "trust", "hook-env"];

/// Read, write and import secrets from a secret manager.
#[derive(Parser)]
#[command(
    name = "ggshield secret",
    version,
    about,
    arg_required_else_help = true
)]
struct SecretCli {
    #[command(subcommand)]
    command: commands::SecretCommand,
}

#[derive(Parser)]
#[command(name = "ggshield", version)]
struct TopLevelCli {
    #[command(subcommand)]
    command: commands::TopLevelCommand,
}

/// Python's root options (`ggshield --debug run ...`), which may precede the verb.
const ROOT_FLAGS: [&str; 7] = [
    "-v",
    "--verbose",
    "--debug",
    "--insecure",
    "--allow-self-signed",
    "--check-for-updates",
    "--no-check-for-updates",
];
const ROOT_OPTIONS_WITH_VALUE: [&str; 4] = ["-c", "--config-path", "--log-file", "--instance"];
/// Python repeats its common options on the `secret` group (`ggshield secret -v get`).
const GROUP_OPTIONS_WITH_VALUE: [&str; 1] = ["--log-file"];

struct Invocation {
    args: Vec<OsString>,
    config_path: Option<PathBuf>,
}

/// `None` when a root option is missing its value: Python reports that better.
fn split_root_options(args: &[OsString]) -> Option<Invocation> {
    let mut config_path = None;
    let index = skip_options(args, &ROOT_OPTIONS_WITH_VALUE, &mut config_path)?;
    let mut args = args[index..].to_vec();
    if args.first().and_then(|arg| arg.to_str()) == Some("secret") {
        let skipped = skip_options(&args[1..], &GROUP_OPTIONS_WITH_VALUE, &mut config_path)?;
        args.drain(1..1 + skipped);
    }
    Some(Invocation { args, config_path })
}

/// How many leading arguments are options from `ROOT_FLAGS` or `with_value`.
fn skip_options(
    args: &[OsString],
    with_value: &[&str],
    config_path: &mut Option<PathBuf>,
) -> Option<usize> {
    let mut index = 0;
    while let Some(arg) = args.get(index).and_then(|arg| arg.to_str()) {
        if ROOT_FLAGS.contains(&arg) {
            index += 1;
        } else if let Some((name, value)) = arg.split_once('=')
            && name.starts_with("--")
            && with_value.contains(&name)
        {
            if name == "--config-path" {
                *config_path = Some(PathBuf::from(value));
            }
            index += 1;
        } else if with_value.contains(&arg) {
            let value = args.get(index + 1)?;
            if arg == "-c" || arg == "--config-path" {
                *config_path = Some(PathBuf::from(value));
            }
            index += 2;
        } else {
            break;
        }
    }
    Some(index)
}

fn is_native_verb(args: &[OsString]) -> bool {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("secret") => matches!(
            args.get(1).and_then(|arg| arg.to_str()),
            Some(verb) if SECRET_VERBS.contains(&verb)
        ),
        Some(verb) => TOP_LEVEL_VERBS.contains(&verb),
        None => false,
    }
}

pub fn is_native(args: &[OsString]) -> bool {
    split_root_options(args).is_some_and(|invocation| is_native_verb(&invocation.args))
}

pub fn run(args: &[OsString]) -> Result<()> {
    reset_sigpipe();
    let invocation = split_root_options(args)
        .ok_or_else(|| anyhow::anyhow!("a root option is missing its value"))?;
    if let Some(path) = invocation.config_path {
        commands::shared::set_config_path(path);
    }
    let args = invocation.args;
    if args.first().and_then(|arg| arg.to_str()) == Some("secret") {
        let argv =
            std::iter::once(OsString::from("ggshield secret")).chain(args[1..].iter().cloned());
        SecretCli::parse_from(argv).command.execute()
    } else {
        let argv = std::iter::once(OsString::from("ggshield")).chain(args.iter().cloned());
        TopLevelCli::parse_from(argv).command.execute()
    }
}

/// Rust ignores SIGPIPE, so `ggshield secret ... | head` would fail with EPIPE
/// instead of exiting quietly.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: called once, before any threads are spawned.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn store_verbs_are_native_under_secret_and_runtime_verbs_at_top_level() {
        assert!(is_native(&args(&["secret", "get"])));
        assert!(is_native(&args(&["secret", "list"])));
        assert!(is_native(&args(&["run", "--", "true"])));
        assert!(is_native(&args(&["activate"])));
        assert!(!is_native(&args(&["secret", "run"])));
        assert!(!is_native(&args(&["get"])));
        assert!(!is_native(&args(&["secret", "scan", "path", "."])));
        assert!(!is_native(&args(&[])));
    }

    #[test]
    fn root_options_before_the_verb_are_skipped() {
        assert!(is_native(&args(&["--debug", "run", "--", "true"])));
        assert!(is_native(&args(&["-v", "--insecure", "secret", "list"])));
        assert!(is_native(&args(&["--instance", "https://x", "activate"])));
        assert!(is_native(&args(&["--log-file=-", "trust"])));
        let invocation = split_root_options(&args(&["-c", "cfg.yaml", "run"])).expect("parses");
        assert_eq!(invocation.config_path, Some(PathBuf::from("cfg.yaml")));
        assert_eq!(invocation.args, args(&["run"]));
        assert!(!is_native(&args(&["--instance"])));
        assert!(!is_native(&args(&["--unknown", "run"])));
        assert!(!is_native(&args(&["--debug", "secret", "scan"])));
    }

    #[test]
    fn common_options_after_secret_are_skipped() {
        assert!(is_native(&args(&["secret", "-v", "get", "KEY"])));
        assert!(is_native(&args(&["secret", "--debug", "list"])));
        assert!(is_native(&args(&[
            "secret",
            "--log-file",
            "x.log",
            "set",
            "K"
        ])));
        assert!(is_native(&args(&[
            "--debug",
            "secret",
            "--log-file=-",
            "list"
        ])));
        let invocation =
            split_root_options(&args(&["secret", "--debug", "-v", "get", "-v"])).expect("parses");
        assert_eq!(invocation.args, args(&["secret", "get", "-v"]));
        assert!(!is_native(&args(&["secret", "--debug", "scan"])));
        assert!(!is_native(&args(&["secret", "--log-file"])));
        // Root-only: Python rejects it on the group, and so should routing.
        assert!(!is_native(&args(&[
            "secret",
            "--instance",
            "https://x",
            "get"
        ])));
    }
}
