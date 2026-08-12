//! The dispatcher's half of the delegation contract, with a `#!/bin/sh` stand-in
//! instead of a 100 MB PyInstaller bundle: find the sibling launcher, hand over
//! argv and stdin unchanged, propagate the exit code, or fail loudly when the
//! launcher is missing.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dispatcher() -> PathBuf {
    // tests/ binaries land in target/<profile>/deps/, so the binary under test is
    // two levels up. Not `CARGO_BIN_EXE_ggshield`: the fake launcher we write
    // beside it would then leak into other tests.
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    path.pop();
    path.push(format!("ggshield{}", std::env::consts::EXE_SUFFIX));
    assert!(path.is_file(), "{} not built", path.display());
    path
}

/// The bundle's launcher name, as `dispatch.rs` looks it up.
const LAUNCHER: &str = if cfg!(windows) {
    "ggshield-py.exe"
} else {
    "ggshield-py"
};

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

/// `Command::spawn` for a file another test has just written.
///
/// Cargo runs these tests as threads of one process, and `spawn` forks: a fork
/// taken while a sibling thread still holds its write descriptor open inherits
/// that descriptor, and until the child reaches `exec` and closes it, exec'ing
/// the file it points at earns `ETXTBSY`. Nothing is wrong with the binary — the
/// window is someone else's fork, so waiting it out is the whole fix.
///
/// To see it fail, relink first — `touch dispatcher/src/main.rs` before each
/// run, on Linux. A freshly linked binary fails about six runs in ten; a warm
/// one never fails, however many times it is run or however few cores it is
/// given. That is why CI hits this on nearly every run, building once and
/// testing once, while anyone reproducing it locally runs the suite a second
/// time and concludes there is nothing there. macOS does not enforce `ETXTBSY`
/// at all, so it cannot be reproduced there.
fn spawn_once_written(command: &mut Command) -> std::process::Child {
    for _ in 0..50 {
        match command.spawn() {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other.expect("spawn"),
        }
    }
    panic!("still ETXTBSY after 1s of sibling forks");
}

fn run(binary: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write;

    let mut child = spawn_once_written(
        Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    collect(child.wait_with_output().expect("wait"))
}

/// `run`, but bounded: a launcher that resolves to the dispatcher itself used to
/// exec forever, and a test that never returns reports nothing.
fn run_bounded(binary: &Path, args: &[&str]) -> Output {
    let mut child = spawn_once_written(
        Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    for _ in 0..300 {
        if child.try_wait().expect("try_wait").is_some() {
            return collect(child.wait_with_output().expect("wait"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("{} never exited", binary.display());
}

fn collect(out: std::process::Output) -> Output {
    Output {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// A bundle-shaped directory holding a copy of the dispatcher, and its path.
fn bundle_with_dispatcher() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let ggshield = dir
        .path()
        .join(format!("ggshield{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(dispatcher(), &ggshield).expect("copy dispatcher");
    (dir, ggshield)
}

/// GIVEN a bundle whose `ggshield-py` is another copy of the dispatcher, as a
/// mispackaged install has
/// WHEN a delegated command is run
/// THEN the hop that finds itself under the launcher's name reports a broken
/// install and exits 128, instead of exec'ing itself forever.
#[test]
fn a_dispatcher_that_is_its_own_launcher_stops_instead_of_looping() {
    let (dir, ggshield) = bundle_with_dispatcher();
    std::fs::copy(dispatcher(), dir.path().join(LAUNCHER)).expect("copy as launcher");

    let out = run_bounded(&ggshield, &["--version"]);

    assert_eq!(out.code, 128, "stderr was {:?}", out.stderr);
    assert!(
        out.stderr.contains(LAUNCHER) && out.stderr.contains("incomplete"),
        "stderr was {:?}",
        out.stderr
    );
}

/// GIVEN a bundle directory holding the dispatcher and no launcher beside it
/// WHEN a delegated command (`auth login`) is run
/// THEN it exits non-zero with nothing on stdout, naming the missing launcher and
/// an "incomplete" install on stderr.
///
/// The only test that drives the Windows spawn-and-wait branch for real.
#[test]
fn a_missing_launcher_is_a_loud_failure() {
    // Deliberately no `ggshield-py` next to it.
    let (_dir, ggshield) = bundle_with_dispatcher();

    let out = run(&ggshield, &["auth", "login"], "");

    assert_ne!(out.code, 0);
    assert!(out.stdout.is_empty(), "stdout was {:?}", out.stdout);
    assert!(
        out.stderr.contains(LAUNCHER) && out.stderr.contains("incomplete"),
        "stderr was {:?}",
        out.stderr
    );
}

/// GIVEN a dispatcher with no launcher beside it, an empty config dir and no key
/// WHEN `secret scan ai-hook` is run
/// THEN no launcher is ever reached — nothing echoes argv — and the native hook
/// answers by failing open with its own warning on stderr.
#[test]
fn the_hook_invocation_is_not_delegated() {
    let (_dir, ggshield) = bundle_with_dispatcher();
    let config = tempfile::tempdir().expect("tempdir");

    let out = spawn_once_written(
        Command::new(ggshield)
            .args(["secret", "scan", "ai-hook"])
            // An empty config dir and no API key: no token, so the hook fails open
            // without any network access.
            .env("GG_CONFIG_DIR", config.path())
            .env("GG_CACHE_DIR", config.path().join("cache"))
            .env("GITGUARDIAN_API_KEY", "")
            .env("GITGUARDIAN_DONT_LOAD_ENV", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .wait_with_output()
    .expect("run");

    assert!(!String::from_utf8_lossy(&out.stdout).contains("argv:"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Warning:"));
}

/// Unix-only: the stand-in launcher is a shell script and the symlink test needs a
/// unix symlink. A Windows equivalent would need a compiled `.exe` stand-in.
#[cfg(unix)]
mod unix {
    use std::process::{Command, Stdio};

    use super::run;

    /// A bundle-shaped directory: the real dispatcher plus a fake `ggshield-py`
    /// that reports everything the dispatcher gave it.
    fn fake_bundle(exit_code: i32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::copy(super::dispatcher(), dir.path().join("ggshield")).expect("copy dispatcher");

        let launcher = dir.path().join("ggshield-py");
        let script = format!(
            "#!/bin/sh\n\
             for arg in \"$@\" ; do echo \"argv:$arg\" ; done\n\
             echo \"stdin:$(cat)\"\n\
             echo 'on-stderr' >&2\n\
             exit {exit_code}\n"
        );
        std::fs::write(&launcher, script).expect("write launcher");
        let mut permissions = std::fs::metadata(&launcher).expect("stat").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&launcher, permissions).expect("chmod");

        dir
    }

    /// GIVEN a fake `ggshield-py` next to the dispatcher that echoes what it got
    /// WHEN a delegated command carrying an argument with a space is run with a
    /// payload on stdin
    /// THEN argv arrives split exactly as given, stdin and both output streams pass
    /// through untouched, and the exit code is the launcher's.
    #[test]
    fn argv_stdin_stdout_stderr_and_the_exit_code_all_pass_through() {
        let bundle = fake_bundle(0);

        let out = run(
            &bundle.path().join("ggshield"),
            &["secret", "scan", "path", "--json", "some file.txt"],
            "payload on stdin\n",
        );

        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout,
            "argv:secret\nargv:scan\nargv:path\nargv:--json\nargv:some file.txt\n\
             stdin:payload on stdin\n"
        );
        assert_eq!(out.stderr, "on-stderr\n");
    }

    /// GIVEN a `.env` the native hook declines to handle, a payload larger than a
    /// pipe buffer, and a `ggshield-py` that closes stdin without reading it and
    /// would print a deny a moment later
    /// WHEN the hook event is handed over and the payload cannot be written
    /// THEN the stdout the agent reads carries exactly one verdict — the fail-open
    /// allow — and the launcher that would have contradicted it is already dead.
    #[test]
    fn a_launcher_that_never_reads_the_payload_cannot_add_a_second_verdict() {
        use std::io::Write;

        let (dir, ggshield) = super::bundle_with_dispatcher();
        let pidfile = dir.path().join("launcher.pid");
        let launcher = dir.path().join("ggshield-py");
        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nexec 0<&-\nsleep 5\n\
                 echo '{{\"continue\":false,\"stopReason\":\"DENY\"}}'\nexit 2\n",
                pidfile.display()
            ),
        )
        .expect("write launcher");
        let mut permissions = std::fs::metadata(&launcher).expect("stat").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&launcher, permissions).expect("chmod");

        // The decline: a GITGUARDIAN_API_KEY binding the native hook will not
        // guess at, found in the cwd it is invoked from.
        let work = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            work.path().join(".env"),
            "GITGUARDIAN_API_KEY='unterminated\n",
        )
        .expect("write .env");
        let config = tempfile::tempdir().expect("tempdir");

        // A file the agent reads, and it is the agent's stdout the verdicts race
        // over — so give the dispatcher a real file, the way a pipe to the agent
        // would be inherited.
        let seen = dir.path().join("agent-stdout");
        let mut child = super::spawn_once_written(
            Command::new(&ggshield)
                .args(["secret", "scan", "ai-hook"])
                .current_dir(work.path())
                .env("GG_CONFIG_DIR", config.path())
                .env("GG_CACHE_DIR", config.path().join("cache"))
                .stdin(Stdio::piped())
                .stdout(Stdio::from(
                    std::fs::File::create(&seen).expect("create stdout file"),
                ))
                .stderr(Stdio::piped()),
        );
        // Bigger than any pipe buffer, so the write cannot land in a pipe nobody
        // reads.
        let payload = format!(
            r#"{{"session_id":"abc","transcript_path":"/home/u/.claude/projects/p/t.jsonl","cwd":"/home/u/p","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":"/tmp/{}"}}}}"#,
            "x".repeat(200 * 1024)
        );
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let out = child.wait_with_output().expect("wait");

        let verdicts = std::fs::read_to_string(&seen).expect("read stdout file");
        assert_eq!(out.status.code(), Some(0), "{:?}", verdicts);
        assert_eq!(
            verdicts.lines().count(),
            1,
            "the agent must read one verdict, got {verdicts:?}"
        );
        assert!(verdicts.contains(r#""continue":true"#), "{verdicts:?}");

        let pid = std::fs::read_to_string(&pidfile).expect("launcher never ran");
        assert!(
            !Command::new("kill")
                .args(["-0", pid.trim()])
                .stderr(Stdio::null())
                .status()
                .expect("kill -0")
                .success(),
            "launcher {} outlived the dispatcher",
            pid.trim()
        );
    }

    /// GIVEN a symlink in an unrelated directory pointing at the bundled dispatcher
    /// WHEN the dispatcher is invoked through that symlink
    /// THEN the launcher next to the symlink's *target* is the one that runs, argv
    /// still passes through and its non-zero exit code comes back verbatim rather
    /// than collapsed.
    ///
    /// The shape that ships on macOS, and the case a naive
    /// `current_exe().parent()` gets wrong.
    #[test]
    fn delegation_works_when_invoked_through_a_symlink() {
        let bundle = fake_bundle(7);
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let link = elsewhere.path().join("ggshield");
        std::os::unix::fs::symlink(bundle.path().join("ggshield"), &link).expect("symlink");

        let out = run(&link, &["--version"], "");

        assert_eq!(out.code, 7);
        assert_eq!(out.stdout, "argv:--version\nstdin:\n");
    }
}
