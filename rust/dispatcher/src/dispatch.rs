//! One `ggshield` command, two implementations behind it: the exact
//! `secret scan ai-hook` argv is answered here, everything else goes to
//! `ggshield-py`, the PyInstaller launcher next to us in the bundle. See
//! `doc/dev/os-packages.md`.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{FALSE, TRUE};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
#[cfg(windows)]
use windows_sys::core::BOOL;

/// Exactly what `build_hook_command()` writes, and nothing more: nothing here
/// parses ggshield's grammar, so the only safe mistake is to hand an argv to
/// Python.
const NATIVE_HOOK_ARGS: [&str; 3] = ["secret", "scan", "ai-hook"];

/// What `machine setup` runs once the hooks are written. macOS only asks for
/// notification permission when an app first posts one, and until that is
/// answered the notification is dropped in silence -- so the asking is done
/// here, while the user is deliberately setting ggshield up, rather than the
/// first time a secret leaks.
const WARM_NOTIFIER_ARGS: [&str; 4] = ["secret", "scan", "ai-hook", "--warm-notifier"];

/// As named inside the bundle by `scripts/build-os-packages/build-os-packages`.
/// That name and "next to me" are the whole contract between the two binaries.
const PYTHON_LAUNCHER: &str = if cfg!(windows) {
    "ggshield-py.exe"
} else {
    "ggshield-py"
};

/// True only for the exact `secret scan ai-hook` form.
pub fn is_native_hook(args: &[OsString]) -> bool {
    args == NATIVE_HOOK_ARGS
}

/// True only for the exact `secret scan ai-hook --warm-notifier` form.
pub fn is_warm_notifier(args: &[OsString]) -> bool {
    args == WARM_NOTIFIER_ARGS
}

pub fn delegate(args: &[OsString]) -> ! {
    match python_launcher() {
        Ok(launcher) => exec(&launcher, args),
        Err(err) => broken_install(Path::new(PYTHON_LAUNCHER), &err),
    }
}

/// Hand the hook event to `ggshield-py` after the native hook declined it.
///
/// Not `exec`: the payload has already been read from our stdin and a child
/// cannot read it again, so it is piped in. Its verdict is then *the* verdict —
/// the native hook prints nothing before declining — but it is held in a pipe
/// until the hand-over is known to have worked, so only one answer can ever
/// reach the agent.
///
/// Returns the child's exit code, or `None` when the hand-over could not happen
/// at all — a hook that exits 128 on a broken install blocks nothing and tells
/// nobody, so the caller fails open instead.
pub fn delegate_hook(stdin: &str) -> Option<i32> {
    let launcher = python_launcher().ok()?;
    let mut child = Command::new(&launcher)
        .args(NATIVE_HOOK_ARGS)
        .stdin(Stdio::piped())
        // Not inherited: a child that dies before draining the payload would
        // otherwise still print its verdict, landing on the agent *after* the
        // caller has failed open. Two verdicts, and it acted on the first.
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;

    // Taken, so the pipe is dropped and the child sees EOF instead of hanging.
    // Python reads the whole payload before it answers, so writing it all before
    // draining the verdict cannot fill that pipe.
    let handed_over = child
        .stdin
        .take()
        .is_some_and(|mut pipe| pipe.write_all(stdin.as_bytes()).is_ok());
    if !handed_over {
        kill_and_wait(&mut child);
        return None;
    }

    let mut verdict = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut verdict);
    }
    let Ok(status) = child.wait() else {
        kill_and_wait(&mut child);
        return None;
    };

    // The hand-over went through, so this is *the* verdict: forward it verbatim.
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(&verdict);
    let _ = stdout.flush();
    status.code().or(Some(1))
}

/// Rust reaps no child on drop, so a `delegate_hook` that gives up without this
/// leaves `ggshield-py` running — holding our descriptors and still able to speak
/// to the agent.
fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// `ggshield-py`, next to the *canonicalised* executable: `current_exe()` can
/// hand back the exec'd symlink (`/usr/local/bin/ggshield`, on macOS), whose
/// directory is user-writable and holds no `ggshield-py`. Running a sibling of
/// *that* would be worse than failing, so the error propagates.
///
/// A sibling that resolves back to this very binary is such a case: it is a
/// broken install, and exec'ing it would loop forever instead of ever answering.
fn python_launcher() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let exe = std::fs::canonicalize(&exe)?;
    let dir = exe.parent().ok_or_else(|| {
        std::io::Error::other(format!("{} has no parent directory", exe.display()))
    })?;
    let launcher = dir.join(PYTHON_LAUNCHER);
    if std::fs::canonicalize(&launcher).is_ok_and(|resolved| resolved == exe) {
        return Err(std::io::Error::other(
            "that is this same executable, not the bundled Python implementation",
        ));
    }
    Ok(launcher)
}

#[cfg(unix)]
fn exec(launcher: &Path, args: &[OsString]) -> ! {
    // `exec()` only returns on failure.
    let err = Command::new(launcher).args(args).exec();
    broken_install(launcher, &err)
}

/// Windows has no `exec`, so spawn and wait.
#[cfg(windows)]
fn exec(launcher: &Path, args: &[OsString]) -> ! {
    keep_self_alive_through_ctrl_c();
    match Command::new(launcher).args(args).status() {
        // `code()` is always `Some` on Windows.
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => broken_install(launcher, &err),
    }
}

/// Survive a Ctrl-C ourselves, without silencing it for the child.
///
/// A console delivers `CTRL_C_EVENT` to every process in the group, so both this
/// dispatcher and `ggshield-py` see it. The default handler tears this process
/// down on the spot, so `status()` would never return and a wrapping script
/// would read an interrupted code instead of Python's. Installing a handler that
/// returns `TRUE` for Ctrl-C and Ctrl-Break keeps *this* process alive until the
/// child exits and its real code comes back; the child still receives its own
/// event and aborts.
#[cfg(windows)]
fn keep_self_alive_through_ctrl_c() {
    // SAFETY: registering a handler owns no memory and mutates no state but the
    // process's handler list. The handler only reads its argument and returns a
    // constant.
    unsafe {
        SetConsoleCtrlHandler(Some(swallow_ctrl_c), 1);
    }
}

/// Return `TRUE` for Ctrl-C and Ctrl-Break so the dispatcher is not torn down
/// while it waits on the child; let every other event (close, logoff, shutdown)
/// take its default action.
#[cfg(windows)]
unsafe extern "system" fn swallow_ctrl_c(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => TRUE,
        _ => FALSE,
    }
}

/// A missing or unrunnable launcher is a broken install, not a hook verdict, so
/// it fails loudly with 128 — ggshield's `UNEXPECTED_ERROR`.
fn broken_install(launcher: &Path, err: &std::io::Error) -> ! {
    eprintln!(
        "ggshield: cannot run '{}': {err}\n\
         This ggshield installation is incomplete: the bundled Python \
         implementation should sit next to the 'ggshield' executable. \
         Reinstall ggshield.",
        launcher.display()
    );
    std::process::exit(128);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// `python_launcher()` looks next to the *running* executable, so a stub has to
    /// be the real neighbour of this test binary. That path is shared, and `cargo
    /// test` runs tests in parallel threads, so the tests that plant one take this.
    static NEIGHBOUR: Mutex<()> = Mutex::new(());

    fn exclusive() -> MutexGuard<'static, ()> {
        NEIGHBOUR.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The canonical path of this test binary, and where it will look for the
    /// launcher.
    fn exe_and_launcher() -> (PathBuf, PathBuf) {
        let exe = std::fs::canonicalize(std::env::current_exe().expect("current_exe"))
            .expect("canonicalize");
        let launcher = exe.parent().expect("parent").join(PYTHON_LAUNCHER);
        (exe, launcher)
    }

    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    /// GIVEN argv that is exactly `secret scan ai-hook`
    /// WHEN it is tested against the native predicate
    /// THEN this binary claims it instead of delegating.
    #[test]
    fn the_exact_hook_invocation_is_handled_natively() {
        assert!(is_native_hook(&args(&["secret", "scan", "ai-hook"])));
    }

    /// GIVEN the warm-up invocation `machine setup` runs, and its near misses
    /// WHEN each is tested against both predicates
    /// THEN only the exact form warms, it is never mistaken for a hook event,
    /// and everything else still goes to Python.
    #[test]
    fn only_the_exact_warm_up_invocation_warms() {
        let warm = args(&["secret", "scan", "ai-hook", "--warm-notifier"]);
        assert!(is_warm_notifier(&warm));
        // It carries no payload, so answering it as a hook event would scan
        // an empty stdin and print a verdict nobody asked for.
        assert!(!is_native_hook(&warm));

        for case in [
            args(&["secret", "scan", "ai-hook"]),
            args(&["secret", "scan", "ai-hook", "--warm-notifier", "--verbose"]),
            args(&["secret", "scan", "ai-hook", "--warm-notifier=1"]),
            args(&["--warm-notifier", "secret", "scan", "ai-hook"]),
            args(&["secret", "scan", "ai-hook", "--Warm-Notifier"]),
        ] {
            assert!(
                !is_warm_notifier(&case),
                "{case:?} was claimed as a warm-up"
            );
        }
    }

    /// GIVEN near misses: empty argv, prefixes, an extra or a leading option, a
    /// different case, a trailing space, other commands
    /// WHEN each is tested against the native predicate
    /// THEN none of them is claimed as the native hook.
    #[test]
    fn everything_else_goes_to_python() {
        for case in [
            vec![],
            args(&["secret"]),
            args(&["secret", "scan"]),
            args(&["secret", "scan", "ai-hook", "--verbose"]),
            args(&["--verbose", "secret", "scan", "ai-hook"]),
            args(&["-v", "secret", "scan", "ai-hook"]),
            args(&["secret", "scan", "ai-hook", "--help"]),
            args(&["secret", "scan", "path", "."]),
            args(&["secret", "scan", "ai-hook", ""]),
            args(&["secret", "ai-hook", "scan"]),
            args(&["Secret", "scan", "ai-hook"]),
            args(&["secret", "scan", "ai-hook "]),
            args(&["auth", "login"]),
            args(&["--version"]),
            args(&["ai-hook"]),
        ] {
            assert!(!is_native_hook(&case), "should delegate: {case:?}");
        }
    }

    /// GIVEN a bundle with no `ggshield-py`, then one whose `ggshield-py` records
    /// the payload it is handed
    /// WHEN a declined hook event is delegated to each
    /// THEN a missing launcher is reported rather than fatal, and once it is there
    /// the payload the native hook already read reaches Python verbatim and
    /// Python's exit code comes back.
    ///
    /// One test, because both halves need the same path next to this binary.
    #[cfg(unix)]
    #[test]
    fn a_declined_event_reaches_python_with_its_payload() {
        let _guard = exclusive();
        let (_exe, launcher) = exe_and_launcher();
        let record = launcher.with_extension("payload");
        let _ = std::fs::remove_file(&record);
        let _ = std::fs::remove_file(&launcher);

        // No launcher yet: reported, not fatal.
        assert_eq!(delegate_hook("{}"), None, "a missing launcher must be soft");

        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\ncat > '{}'\necho \"$@\" >> '{}'\nexit 7\n",
                record.display(),
                record.display()
            ),
        )
        .expect("write stub");
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");

        let payload = r#"{"hook_event_name":"PreToolUse","session_id":"abc"}"#;
        let code = delegate_hook(payload);

        let handed = std::fs::read_to_string(&record).unwrap_or_default();
        let _ = std::fs::remove_file(&launcher);
        let _ = std::fs::remove_file(&record);

        assert_eq!(code, Some(7), "Python's exit code must come back");
        assert!(handed.starts_with(payload), "payload not piped: {handed:?}");
        // ...and it was asked for the hook, not for some other command.
        assert!(handed.contains("secret scan ai-hook"), "{handed:?}");
    }

    /// GIVEN this test binary standing in for an installed `ggshield`
    /// WHEN the Python launcher is resolved
    /// THEN it is the sibling of the *canonicalised* executable, not of the path
    /// the process happened to be exec'd with.
    #[test]
    fn the_launcher_is_looked_up_next_to_this_executable() {
        let _guard = exclusive();
        let (exe, launcher) = exe_and_launcher();
        assert_eq!(python_launcher().expect("launcher"), launcher);
        assert!(launcher != exe, "the launcher is never this binary");
    }
}
