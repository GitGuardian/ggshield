//! `ggshield`: `secret scan ai-hook` natively, everything else to Python.
//!
//! This is the `ggshield` the standalone bundle puts on the PATH, so a bug in
//! `dispatch` breaks every ggshield command, not just the hook. See
//! `doc/dev/os-packages.md`.

mod binary_extensions;
mod cli;
mod config;
mod dispatch;
mod error;
mod hash;
mod hook;
mod machine;
mod secure_file;
#[cfg(test)]
mod test_support;
mod user_config;

fn main() {
    // Dispatch before touching stdin: `exec()` hands the untouched descriptor to
    // Python, and reading a byte here would eat the delegated command's input.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if dispatch::is_native_hook(&args) {
        std::process::exit(run_native_hook());
    }
    if dispatch::is_warm_notifier(&args) {
        std::process::exit(hook::warm_notifier());
    }
    dispatch::delegate(&args);
}

/// The native hook, handing over to `ggshield-py` for the configurations it does
/// not implement rather than failing open on them. Failing open is kept only for
/// a bundle whose launcher is missing or unrunnable.
fn run_native_hook() -> i32 {
    match hook::run_hook() {
        hook::Outcome::Done(code) => code,
        hook::Outcome::Delegate {
            stdin,
            fallback_warning,
        } => match dispatch::delegate_hook(&stdin) {
            Some(code) => code,
            None => hook::fail_open(&stdin, fallback_warning),
        },
    }
}
