//! `ggshield`: `secret scan ai-hook` and the `secret` store verbs natively,
//! everything else to Python.
//!
//! This is the `ggshield` the standalone bundle puts on the PATH, so a bug in
//! `dispatch` breaks every ggshield command, not just the hook. See
//! `doc/dev/os-packages.md`.

mod dispatch;

fn main() {
    // Dispatch before touching stdin: `exec()` hands the untouched descriptor to
    // Python, and reading a byte here would eat the delegated command's input.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if dispatch::is_native_hook(&args) {
        std::process::exit(run_native_hook());
    }
    if dispatch::is_warm_notifier(&args) {
        std::process::exit(ggshield_hook::warm_notifier());
    }
    if dispatch::is_native_secret(&args) {
        if dispatch::wants_insecure_tls(&args) {
            ggshield_secrets::SecretStore::allow_insecure_tls();
        }
        std::process::exit(run_secret_verb(&args));
    }
    dispatch::delegate(&args);
}

/// Unlike the hook there is no Python fallback: these verbs exist only here.
fn run_secret_verb(args: &[std::ffi::OsString]) -> i32 {
    match ggshield_secrets_cli::run(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error:?}");
            1
        }
    }
}

/// The native hook, handing over to `ggshield-py` for the configurations it does
/// not implement rather than failing open on them. Failing open is kept only for
/// a bundle whose launcher is missing or unrunnable.
fn run_native_hook() -> i32 {
    match ggshield_hook::run_hook() {
        ggshield_hook::Outcome::Done(code) => code,
        ggshield_hook::Outcome::Delegate {
            stdin,
            fallback_warning,
        } => match dispatch::delegate_hook(&stdin) {
            Some(code) => code,
            None => ggshield_hook::fail_open(&stdin, fallback_warning),
        },
    }
}
