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

fn main() {
    // Dispatch before touching stdin: `exec()` hands the untouched descriptor to
    // Python, and reading a byte here would eat the delegated command's input.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if dispatch::is_native_hook(&args) {
        std::process::exit(subcommands::secret::scan::ai_hook::run_native_hook());
    }
    if dispatch::is_warm_notifier(&args) {
        std::process::exit(subcommands::secret::scan::ai_hook::warm_notifier());
    }
    dispatch::delegate(&args);
}
