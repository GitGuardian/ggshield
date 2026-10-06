//! Approving a dotenv file for automatic loading by `activate`'s shell hook.

use anyhow::{Result, bail};
use ggshield_secrets::{Provider, trust};

use crate::commands::shared::{ScopeArgs, secret_path};

/// Approve this directory's dotenv file for `ggshield activate`.
///
/// The shell hook loads whatever directory you walk into, so unlike `get` and
/// `run` — where naming the file on the command line is itself the consent —
/// it needs to be told which files you have actually read. Until a file is
/// trusted the hook loads nothing from it and says so.
///
/// Approval covers the file's *contents*, not just its name: any edit revokes
/// it, so a line a colleague pushed cannot inherit yesterday's approval.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Dotenv file to approve (default: .env).
    #[arg(long)]
    path: Option<String>,
    #[command(flatten)]
    scope: ScopeArgs,
    /// Withdraw approval instead of granting it.
    #[arg(long, conflicts_with = "list")]
    revoke: bool,
    /// List every file currently approved.
    #[arg(long)]
    list: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    if args.list {
        let paths = trust::trusted_paths()?;
        if paths.is_empty() {
            eprintln!("no dotenv files are trusted for `ggshield activate`");
            return Ok(());
        }
        for path in paths {
            println!("{}", path.display());
        }
        return Ok(());
    }

    let path = secret_path(Provider::File, args.path, args.scope.get())?;
    let path = std::path::Path::new(&path);

    if args.revoke {
        if trust::untrust(path)? {
            eprintln!("{} is no longer trusted", path.display());
        } else {
            eprintln!("{} was not trusted", path.display());
        }
        return Ok(());
    }

    // Deliberately not a prompt: a y/n here would train users to approve
    // without reading, the failure mode this gate exists to prevent.
    if !path.exists() {
        bail!(
            "{} does not exist, so there is nothing to trust",
            path.display()
        );
    }
    if trust::trust(path)? {
        eprintln!(
            "{} is now trusted; `ggshield activate` will load it. Any edit revokes this",
            path.display()
        );
    } else {
        eprintln!("{} is already trusted, unchanged", path.display());
    }
    Ok(())
}
