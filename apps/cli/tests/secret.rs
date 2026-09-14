//! End-to-end tests that run `ggshield secret ...` through the real binary.
//!
//! Every value here is an obvious fake placeholder; nothing in this file is a
//! real credential.
//!
//! The binary under test is built with `ggshield-secrets`'s `test-keystore`
//! feature (a dev-dependency of this crate, unified in by cargo for
//! `cargo test` only), so `$GITGUARDIAN_TEST_KEYSET_FILE` stands in for the OS
//! credential store. Real encryption, no login keychain.
//!
//! That feature ends up compiled into `target/debug/ggshield`, which is the
//! same path `cargo build` writes and therefore the binary a developer runs
//! afterwards. Naming a keyset file is deliberately not enough on its own to
//! activate it: `$GITGUARDIAN_TEST_KEYSET_INSECURE_ACK` has to spell out what
//! it does, so a stray value in a shell profile cannot quietly swap the OS
//! keyring for a cleartext file on disk.

// A failed unwrap here is the assertion failing, which is what these tests
// are for; the workspace lint targets shipped code.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::prelude::*;

const FAKE_VALUE: &str = "fake-placeholder-value";

/// A throwaway machine: its own home directory, keyset and project directory.
struct Workspace {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        Workspace {
            home: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
        }
    }

    fn project_file(&self, name: &str) -> PathBuf {
        self.project.path().join(name)
    }

    fn write_project(&self, name: &str, contents: &str) {
        std::fs::write(self.project_file(name), contents).unwrap();
    }

    fn read_project(&self, name: &str) -> String {
        std::fs::read_to_string(self.project_file(name)).unwrap()
    }

    /// The `ggshield` binary, pointed at this workspace's home and project.
    ///
    /// Every caller passes the verb alone ("get", "activate", ...): the
    /// `secret` prefix is added here, so the argv under test is exactly the one
    /// the dispatcher routes.
    fn command(&self) -> Command {
        let mut command = self.prepare(Command::cargo_bin("ggshield").expect("ggshield binary"));
        command.arg("secret");
        command
    }

    /// The same environment, for a copy of the binary at another path.
    fn command_at_path(&self, program: &Path) -> Command {
        let mut command = self.prepare(Command::new(program));
        command.arg("secret");
        command
    }

    fn prepare(&self, mut command: Command) -> Command {
        command
            .current_dir(self.project.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env("USERPROFILE", self.home.path())
            .env("APPDATA", self.home.path().join("AppData/Roaming"))
            .env(
                "GITGUARDIAN_TEST_KEYSET_FILE",
                self.home.path().join("keyset.json"),
            )
            .env(
                "GITGUARDIAN_TEST_KEYSET_INSECURE_ACK",
                "i-understand-this-stores-the-master-key-in-cleartext",
            )
            // The tests must never depend on the developer's own environment.
            .env_remove("VAULT_TOKEN")
            .env_remove("VAULT_ADDR")
            .env_remove("OP_CONNECT_TOKEN");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// `run`, from another directory and/or with extra environment.
    ///
    /// The hook is a function of the current directory and of what a previous
    /// hook left in `$__GITGUARDIAN_ACTIVE`, so several tests below have to set
    /// both.
    fn run_with(&self, directory: Option<&Path>, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut command = self.command();
        if let Some(directory) = directory {
            command.current_dir(directory);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        command.args(args).output().unwrap()
    }

    /// `set`, answering the value prompt on stdin.
    fn set(&self, args: &[&str], value: &str) -> Output {
        use std::io::Write;

        let mut child = self
            .command()
            .args(args)
            // `--expose` reads the value from stdin instead of the terminal.
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{value}\n").as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// `set`, writing `stdin` verbatim (no trailing newline added).
    ///
    /// Lets a test hand the command an empty stdin, or fewer lines than fields.
    fn set_with_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;

        let mut child = self
            .command()
            .args(args)
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Start a `set` without waiting for it, so two can be in flight at once.
    fn spawn_set(&self, args: &[&str], value: &str) -> std::process::Child {
        use std::io::Write;

        let mut child = self
            .command()
            .args(args)
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{value}\n").as_bytes())
            .unwrap();
        child
    }

    /// Approve this workspace's project dotenv file for the hook.
    ///
    /// The hook refuses an untrusted file, so every test that expects a load
    /// consents first — that is the gate working, not a nuisance.
    fn trust_project(&self) {
        let output = self.run(&["trust"]);
        assert!(output.status.success(), "trust failed: {}", stderr(&output));
    }

    /// Approve an arbitrary dotenv file (not just the project default). Only
    /// the symlink test needs it, and that test is unix-only.
    #[cfg(unix)]
    fn trust_file(&self, path: &std::path::Path) {
        let output = self.run(&["trust", "--path", &path.display().to_string()]);
        assert!(output.status.success(), "trust failed: {}", stderr(&output));
    }

    /// Run `program` in a real `shell`, in this workspace's environment.
    ///
    /// The generated hook is shell code, so the only test that proves anything
    /// about it runs it in the shell it was generated for.
    fn shell(&self, shell: &str, program: &str) -> Output {
        let mut command = Command::new(shell);
        // -f / --no-rcs: the developer's own rc files must not change what the
        // hook sees, and must not slow every case down.
        match shell {
            "zsh" => {
                command.arg("-f");
            }
            "bash" => {
                command.arg("--norc").arg("--noprofile");
            }
            // fish reads its own config even for `-c`, and the developer's own
            // functions must not change what the hook sees.
            "fish" => {
                command.arg("--no-config");
            }
            _ => {}
        }
        command
            .arg("-c")
            .arg(program)
            .current_dir(self.project.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env(
                "GITGUARDIAN_TEST_KEYSET_FILE",
                self.home.path().join("keyset.json"),
            )
            .env(
                "GITGUARDIAN_TEST_KEYSET_INSECURE_ACK",
                "i-understand-this-stores-the-master-key-in-cleartext",
            )
            .env_remove("VAULT_TOKEN")
            .env_remove("VAULT_ADDR")
            .env_remove("OP_CONNECT_TOKEN");
        command.output().unwrap()
    }

    /// The user-scope file this workspace's home resolves to.
    fn user_scope_file(&self) -> PathBuf {
        let home = self.home.path();
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/gitguardian/secrets.env")
        } else if cfg!(windows) {
            home.join("AppData/Roaming/gitguardian/secrets.env")
        } else {
            home.join(".config/gitguardian/secrets.env")
        }
    }
}

/// Whether `shell` can be run here, for a test that drives a real shell.
///
/// The hook is shell code, so asserting on the generated string proves
/// nothing — these tests have to run it. That makes them dependent on the
/// machine having bash, zsh and fish, which a developer's laptop may not.
///
/// A missing shell is skipped locally and **fatal** under
/// `$GITGUARDIAN_REQUIRE_SHELLS`, which CI sets. Silently skipping in CI is
/// the failure mode that matters: these are the only tests that prove a
/// dotenv value cannot execute code, and coverage that can quietly vanish
/// is the exact class of defect the last review round was full of.
fn has_shell(shell: &str) -> bool {
    let found = Command::new(shell)
        .arg("-c")
        .arg("exit 0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !found {
        assert!(
            std::env::var_os("GITGUARDIAN_REQUIRE_SHELLS").is_none(),
            "{shell} is not installed, and $GITGUARDIAN_REQUIRE_SHELLS demands it: this \
             test proves the shell hook cannot be made to execute a dotenv value, and \
             skipping it would drop that coverage silently"
        );
        eprintln!("skipping: {shell} is not installed");
    }
    found
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        stdout(output),
        stderr(output)
    );
}

#[test]
fn the_file_provider_is_offered_on_the_command_line() {
    let workspace = Workspace::new();
    let output = workspace.run(&["set", "--help"]);
    assert_ok(&output);
    assert!(stdout(&output).contains("file"), "{}", stdout(&output));
}

#[test]
fn an_unknown_provider_is_rejected() {
    let workspace = Workspace::new();
    let output = workspace.run(&["get", "--provider", "nope", "--path", "x/y"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("invalid value 'nope'"));
}

#[test]
fn set_encrypts_by_default_and_get_reads_it_back() {
    let workspace = Workspace::new();
    let output = workspace.set(
        &["set", "--provider", "file", "--path", ".env", "API_KEY"],
        FAKE_VALUE,
    );
    assert_ok(&output);
    // The report names the key, the path and the count — never the value.
    assert!(stderr(&output).contains("API_KEY"), "{}", stderr(&output));
    assert!(!stderr(&output).contains(FAKE_VALUE), "{}", stderr(&output));

    let contents = workspace.read_project(".env");
    assert!(contents.starts_with("API_KEY=gitguardian:"), "{contents}");
    assert!(!contents.contains(FAKE_VALUE), "{contents}");

    // Piped output exposes values, matching the other providers.
    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--path",
        ".env",
        "--field",
        "API_KEY",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), FAKE_VALUE);
}

#[test]
fn set_plain_stores_a_readable_value() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &[
            "set",
            "--provider",
            "file",
            "--path",
            ".env",
            "--plain",
            "DEBUG",
        ],
        "true",
    ));
    assert_eq!(workspace.read_project(".env"), "DEBUG=true\n");
}

#[test]
fn plain_is_rejected_for_other_providers() {
    let workspace = Workspace::new();
    let output = workspace.run(&[
        "set",
        "--provider",
        "vault",
        "--path",
        "secret/app",
        "--plain",
        "KEY",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--plain only applies to the file provider"));
}

#[test]
fn run_injects_the_decrypted_value() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--path", ".env", "API_KEY"],
        FAKE_VALUE,
    ));

    let output = workspace.run(&[
        "run",
        "--provider",
        "file",
        "--path",
        ".env",
        "--",
        "printenv",
        "API_KEY",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), FAKE_VALUE);
}

#[test]
fn the_project_path_defaults_to_dot_env() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "PLAIN_KEY", "--plain"], "42"));
    assert_eq!(workspace.read_project(".env"), "PLAIN_KEY=42\n");

    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "PLAIN_KEY"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "42");
}

#[test]
fn a_user_scope_value_resolves_into_a_project_that_does_not_define_it() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--scope", "user", "SHARED_KEY"],
        FAKE_VALUE,
    ));
    let user_file = workspace.user_scope_file();
    assert!(user_file.exists(), "{user_file:?} should exist");
    assert!(
        std::fs::read_to_string(&user_file)
            .unwrap()
            .contains("gitguardian:")
    );

    // A project that defines something else entirely still sees it.
    workspace.write_project(".env", "PROJECT_KEY=local\n");
    let output = workspace.run(&[
        "run",
        "--provider",
        "file",
        "--path",
        ".env",
        "--",
        "printenv",
        "SHARED_KEY",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), FAKE_VALUE);
}

#[test]
fn the_project_scope_wins_over_the_user_scope() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &[
            "set",
            "--provider",
            "file",
            "--scope",
            "user",
            "--plain",
            "SHARED_KEY",
        ],
        "from-user",
    ));
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        "from-project",
    ));

    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "SHARED_KEY"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "from-project");
}

#[test]
fn an_existing_environment_variable_wins_unless_overridden() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        "from-file",
    ));

    let output = workspace
        .command()
        .env("SHARED_KEY", "from-environment")
        .args(["run", "--provider", "file", "--", "printenv", "SHARED_KEY"])
        .output()
        .unwrap();
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "from-environment");
    assert!(
        stderr(&output).contains("already set in the environment"),
        "{}",
        stderr(&output)
    );

    let output = workspace
        .command()
        .env("SHARED_KEY", "from-environment")
        .args([
            "run",
            "--provider",
            "file",
            "--no-env-override",
            "--",
            "printenv",
            "SHARED_KEY",
        ])
        .output()
        .unwrap();
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "from-file");
}

#[test]
fn provider_credentials_are_scrubbed_from_the_child() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        "value",
    ));

    // The child reports only the variables under test, rather than dumping its
    // whole environment for a substring search: the parent environment is
    // passed through as it should be, and anything in it — a CI runner's
    // `CI_COMMIT_MESSAGE`, say, quoting this very commit — can contain the
    // name of a credential without a credential having leaked.
    let output = workspace
        .command()
        .env("VAULT_TOKEN", "fake-vault-token")
        .env("OP_CONNECT_TOKEN", "fake-connect-token")
        .env("VAULT_TOKEN_FILE_PATH", "/tmp/fake-token-path")
        .args([
            "run",
            "--provider",
            "file",
            "--",
            "sh",
            "-c",
            r#"for name in VAULT_TOKEN OP_CONNECT_TOKEN VAULT_TOKEN_FILE_PATH SHARED_KEY; do
                 eval "value=\${$name-<unset>}"
                 echo "$name=[$value]"
               done"#,
        ])
        .output()
        .unwrap();
    assert_ok(&output);
    let reported = stdout(&output);
    for name in ["VAULT_TOKEN", "OP_CONNECT_TOKEN", "VAULT_TOKEN_FILE_PATH"] {
        assert!(
            reported.contains(&format!("{name}=[<unset>]")),
            "{name} reached the child:\n{reported}"
        );
    }
    // ...while the value the child actually asked for is there.
    assert!(reported.contains("SHARED_KEY=[value]"), "{reported}");
}

#[test]
fn get_pipes_the_value_when_stdout_is_not_a_terminal() {
    // stdout here is a pipe, so `get` exposes — the documented behaviour it
    // shares with the other providers.
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        "value",
    ));
    let output = workspace.run(&["get", "--provider", "file"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "SHARED_KEY=value");
}

/// Finding 23: the other half, which nothing exercised end to end.
///
/// `assert_cmd` hands the child a pipe, so `IsTerminal` was always false and
/// `expose` always true: a regression that printed values on a real terminal —
/// into scrollback, into a screen share — would have shipped green. A pty is
/// the only way to make the child believe it is on a terminal.
#[cfg(unix)]
#[test]
fn get_redacts_when_stdout_is_a_terminal() {
    use std::os::fd::{FromRawFd, OwnedFd};

    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        FAKE_VALUE,
    ));

    let mut controller = 0;
    let mut terminal = 0;
    // SAFETY: `openpty` fills the two file descriptors and takes null for the
    // three optional out-parameters, which is what its contract asks for.
    let opened = unsafe {
        libc::openpty(
            &mut controller,
            &mut terminal,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "could not open a pty");
    // SAFETY: both descriptors were just created by `openpty` and are owned by
    // nothing else.
    let (controller, terminal) = unsafe {
        (
            OwnedFd::from_raw_fd(controller),
            OwnedFd::from_raw_fd(terminal),
        )
    };

    let mut child = workspace
        .command()
        .args(["get", "--provider", "file"])
        .stdout(terminal.try_clone().unwrap())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // The writing end must be closed here, or the reader below never finishes.
    drop(terminal);
    // Read while the child runs: once the last writer is gone the controller
    // reports EIO rather than handing back what was buffered, so reading after
    // the child exits can come back empty.
    let reader = std::thread::spawn(move || {
        let mut written = Vec::new();
        let mut file = std::fs::File::from(controller);
        let _ = std::io::Read::read_to_end(&mut file, &mut written);
        written
    });
    let mut child_err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut child_err).unwrap();
    let status = child.wait().unwrap();
    let printed = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();

    assert!(status.success(), "stdout {printed} stderr {child_err}");
    assert!(
        !printed.contains(FAKE_VALUE),
        "the value was printed to a terminal: {printed}"
    );
    assert!(printed.contains("SHARED_KEY="), "{printed}");
    assert!(printed.contains("[REDACTED"), "{printed}");
}

#[test]
fn a_dotenvx_marker_names_dotenvx() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=encrypted:BASE64BLOBHERE\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("dotenvx"), "{}", stderr(&output));
}

#[test]
fn a_varlock_marker_names_varlock() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=varlock(something)\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("varlock"), "{}", stderr(&output));
}

#[test]
fn an_unknown_ref_kind_is_not_reported_as_a_crypto_failure() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=gitguardian:vault:secret/app\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("held elsewhere"), "{message}");
    assert!(message.contains("Upgrade the CLI"), "{message}");
    assert!(!message.contains("decrypt"), "{message}");
    // The field is named, so the user knows which line to look at.
    assert!(message.contains("API_KEY"), "{message}");
}

/// Finding 7: the "kind" is the first colon-separated segment of a value in a
/// file gitguardian did not necessarily write. On a plaintext value that merely
/// starts with `gitguardian:` it is a fragment of that value, and this message
/// goes to stderr — which in CI is a log file.
#[test]
fn an_unknown_ref_kind_does_not_echo_the_value_to_stderr() {
    let workspace = Workspace::new();
    let fragment = "fake-secret-fragment";
    workspace.write_project(".env", &format!("API_KEY=gitguardian:{fragment}:rest\n"));

    for args in [
        vec!["get", "--provider", "file", "--field", "API_KEY"],
        vec!["get", "--provider", "file"],
        vec!["run", "--provider", "file", "--", "true"],
    ] {
        let output = workspace.run(&args);
        let message = stderr(&output);
        assert!(
            !message.contains(fragment),
            "{args:?} leaked part of the value: {message}"
        );
    }
}

#[test]
fn a_value_from_another_device_fails_without_leaking_anything() {
    let source = Workspace::new();
    assert_ok(&source.set(
        &["set", "--provider", "file", "--path", ".env", "API_KEY"],
        FAKE_VALUE,
    ));
    let encrypted = source.read_project(".env");

    // Another machine: same file, its own keyset (created by a write of its
    // own), so the failure is "I do not have that key", not "I have no key".
    let other = Workspace::new();
    assert_ok(&other.set(
        &[
            "set",
            "--provider",
            "file",
            "--path",
            "other.env",
            "BOOTSTRAP",
        ],
        "unrelated",
    ));
    other.write_project(".env", &encrypted);
    let output = other.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("API_KEY"), "{message}");
    assert!(message.contains("no key"), "{message}");
    assert!(!message.contains(FAKE_VALUE), "{message}");
}

#[test]
fn a_device_with_no_key_at_all_says_where_the_key_should_live() {
    let source = Workspace::new();
    assert_ok(&source.set(
        &["set", "--provider", "file", "--path", ".env", "API_KEY"],
        FAKE_VALUE,
    ));

    let other = Workspace::new();
    other.write_project(".env", &source.read_project(".env"));
    let output = other.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(
        message.contains("no gitguardian encryption key"),
        "{message}"
    );
    assert!(message.contains("file:keyset"), "{message}");
    assert!(!message.contains(FAKE_VALUE), "{message}");
}

#[test]
fn a_value_moved_to_another_variable_fails_to_decrypt() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "API_KEY"], FAKE_VALUE));
    let marker = workspace
        .read_project(".env")
        .trim()
        .strip_prefix("API_KEY=")
        .unwrap()
        .to_string();
    workspace.write_project(".env", &format!("OTHER_KEY={marker}\n"));

    let output = workspace.run(&["get", "--provider", "file", "--field", "OTHER_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("OTHER_KEY"), "{message}");
    assert!(!message.contains(FAKE_VALUE), "{message}");
}

#[test]
fn a_malformed_envelope_is_reported_as_malformed() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=gitguardian:QUJDRA\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a well-formed"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn writing_preserves_comments_layout_and_untouched_ciphertext() {
    let workspace = Workspace::new();
    let original = "\
# Application configuration
export DEBUG='true'

# Third-party credentials
API_KEY=gitguardian:SOMETHINGOLD
TRAILING=no newline at the end";
    workspace.write_project(".env", original);
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "DEBUG"],
        "false",
    ));

    // Byte for byte, including the missing final newline: only DEBUG's value
    // changed, and API_KEY's ciphertext was never re-encrypted.
    let updated = workspace.read_project(".env");
    assert_eq!(
        updated,
        original.replace("export DEBUG='true'", "export DEBUG='false'")
    );

    // Appending a new key does have to terminate that last line.
    assert_ok(&workspace.set(&["set", "--provider", "file", "--plain", "ADDED"], "1"));
    assert!(
        workspace
            .read_project(".env")
            .ends_with("the end\nADDED=1\n"),
        "{}",
        workspace.read_project(".env")
    );
}

#[test]
fn a_new_file_is_created_private() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "--plain", "KEY"], "1"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(workspace.project_file(".env"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_dotenv_is_refused() {
    let workspace = Workspace::new();
    let real = workspace.project_file("real.env");
    std::fs::write(&real, "KEY=1\n").unwrap();
    std::os::unix::fs::symlink(&real, workspace.project_file(".env")).unwrap();

    let output = workspace.set(&["set", "--provider", "file", "--plain", "KEY"], "2");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("symbolic link"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "KEY=1\n");
}

/// The refusal must describe the operation the user actually asked for, all the
/// way out to the terminal. A failed `get` that reports "refusing to write"
/// sends the reader looking for a write that never happened — and the wording is
/// produced deep in the file layer, so only an end-to-end check proves the right
/// one arrives.
#[cfg(unix)]
#[test]
fn a_symlinked_dotenv_names_the_operation_it_refused() {
    let workspace = Workspace::new();
    let real = workspace.project_file("real.env");
    std::fs::write(&real, "KEY=1\n").unwrap();
    std::os::unix::fs::symlink(&real, workspace.project_file(".env")).unwrap();

    // Reads.
    for args in [
        vec!["get", "--provider", "file", "--field", "KEY"],
        vec!["get", "--provider", "file"],
        vec!["run", "--provider", "file", "--", "true"],
    ] {
        let output = workspace.run(&args);
        assert!(!output.status.success(), "{args:?} should fail");
        assert!(
            stderr(&output).contains("refusing to read through it"),
            "{args:?}: {}",
            stderr(&output)
        );
    }

    // Writes. `--yes` goes straight to the write; without it the overwrite
    // pre-check reads the file first and is refused as a read, which is equally
    // truthful — the point is that neither ever claims the wrong operation.
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "KEY"],
        "2",
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to write through it"),
        "{}",
        stderr(&output)
    );

    let output = workspace.set(&["set", "--provider", "file", "--plain", "KEY"], "2");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to read through it"),
        "the overwrite pre-check is a read: {}",
        stderr(&output)
    );

    // Whichever it refused, the link target is untouched.
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "KEY=1\n");
}

#[test]
fn nothing_is_written_when_a_key_name_is_invalid() {
    let workspace = Workspace::new();
    let output = workspace.set(&["set", "--provider", "file", "--plain", "not-a-name"], "1");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a valid env var name"),
        "{}",
        stderr(&output)
    );
    assert!(!workspace.project_file(".env").exists());
}

/// `import` has nothing to do here — the provider's storage is a dotenv file
/// already — and doing it as a map write would sort the keys and drop the
/// comments. `del` is not in this boat: it removes a named line.
#[test]
fn import_says_it_does_not_apply_to_the_file_provider() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "KEY=1\n");
    let output = workspace.run(&["import", "--provider", "file", "--path", ".env"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("its storage is a dotenv file already"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("ggshield secret encrypt"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn del_removes_a_variable_and_keeps_the_rest_of_the_file() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# keep me\nPORT=3000\n\nSTALE=old\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "STALE"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("deleted 1 field from .env: STALE"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        workspace.read_project(".env"),
        "# keep me\nPORT=3000\n\n",
        "del rewrote the document instead of removing one line"
    );
}

/// An encrypted value is removed by name like any other: nothing is decrypted,
/// so the value never reaches the process doing the deleting.
#[test]
fn del_removes_an_encrypted_value_without_exposing_it() {
    let workspace = Workspace::new();
    let set = workspace.set(&["set", "--provider", "file", "TOKEN"], FAKE_VALUE);
    assert_ok(&set);

    let output = workspace.run(&["del", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(!stderr(&output).contains(FAKE_VALUE), "{}", stderr(&output));
    assert!(!stdout(&output).contains(FAKE_VALUE), "{}", stdout(&output));
    assert_eq!(workspace.read_project(".env"), "");
}

/// The most important case for a committed `.env`: a marker this machine has no
/// key for has to be removable here, or the file can only be fixed on the
/// machine that wrote it.
#[test]
fn del_removes_a_value_this_device_cannot_read() {
    let workspace = Workspace::new();
    let set = workspace.set(&["set", "--provider", "file", "THEIRS"], FAKE_VALUE);
    assert_ok(&set);
    // A different machine: same file, no key for it.
    std::fs::remove_file(workspace.home.path().join("keyset.json")).unwrap();

    let output = workspace.run(&["del", "--provider", "file", "--yes", "THEIRS"]);
    assert_ok(&output);
    assert_eq!(workspace.read_project(".env"), "");
}

#[test]
fn del_names_a_variable_the_file_does_not_set() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "KEEP=here\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "NEVER_SET"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(".env does not set NEVER_SET"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "KEEP=here\n");
}

/// A variable only the user-scope file sets is not in the project file, and
/// `del` must not quietly reach into the other file to satisfy the request.
#[test]
fn del_does_not_reach_into_the_user_scope_file() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--scope", "user", "USER_ONLY"],
        FAKE_VALUE,
    );
    assert_ok(&set);
    workspace.write_project(".env", "KEEP=here\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "USER_ONLY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("does not set USER_ONLY"),
        "{}",
        stderr(&output)
    );
    // Still there, and still readable.
    let get = workspace.run(&["get", "--provider", "file", "--field", "USER_ONLY"]);
    assert_ok(&get);
    assert!(stdout(&get).contains(FAKE_VALUE), "{}", stdout(&get));
}

/// Finding 6: the user-scope file is merged into every project read, so
/// deleting the project value does not stop the name resolving — it resolves to
/// an older value. Someone rotating a leaked credential has to be told.
#[test]
fn del_says_when_a_user_scope_value_is_left_showing_through() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--scope", "user", "TOKEN"],
        "user-scope-fake",
    );
    assert_ok(&set);
    let set = workspace.set(&["set", "--provider", "file", "TOKEN"], "project-fake");
    assert_ok(&set);

    let output = workspace.run(&["del", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("still set by the user-scope file"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("--scope user"),
        "{}",
        stderr(&output)
    );
    // Never the value itself.
    assert!(
        !stderr(&output).contains("user-scope-fake"),
        "{}",
        stderr(&output)
    );
    // And the notice is true: the name still resolves, to the older value.
    let get = workspace.run(&["get", "--provider", "file", "--field", "TOKEN", "--expose"]);
    assert_ok(&get);
    assert!(stdout(&get).contains("user-scope-fake"), "{}", stdout(&get));
}

/// Nothing shows through when there is no user-scope value, so no notice.
#[test]
fn del_says_nothing_about_the_user_scope_when_nothing_shows_through() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=only-here\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(
        !stderr(&output).contains("user-scope"),
        "{}",
        stderr(&output)
    );
}

/// `--scope user` is how you name that file instead.
#[test]
fn del_scope_user_edits_the_user_file() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--scope", "user", "USER_ONLY"],
        FAKE_VALUE,
    );
    assert_ok(&set);

    let output = workspace.run(&[
        "del",
        "--provider",
        "file",
        "--scope",
        "user",
        "--yes",
        "USER_ONLY",
    ]);
    assert_ok(&output);
    assert_eq!(
        std::fs::read_to_string(workspace.user_scope_file()).unwrap(),
        ""
    );
}

/// `--all` empties the assignments, not the file: the comments and the blank
/// lines are the user's, and `rm` is how you delete a file.
#[test]
fn del_all_removes_every_variable_but_keeps_the_file() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# a note\nPORT=3000\n\nTOKEN=abc\n");

    let output = workspace.run(&["del", "--provider", "file", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("PORT") && stderr(&output).contains("TOKEN"),
        "{}",
        stderr(&output)
    );
    // The blank line too, which is what the help promises.
    assert_eq!(workspace.read_project(".env"), "# a note\n\n");
}

/// Matching `encrypt`: the requested state is the state it is already in.
#[test]
fn del_all_on_a_file_that_sets_nothing_is_not_an_error() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# only a comment\n");

    let output = workspace.run(&["del", "--provider", "file", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("nothing to delete"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "# only a comment\n");
}

/// Finding 2b: "it sets no variables" for a file that is not there tells the
/// user their secrets were already gone. A mistyped `--path` must not exit 0.
#[test]
fn del_all_on_a_missing_file_is_an_error_not_an_empty_success() {
    let workspace = Workspace::new();

    let output = workspace.run(&[
        "del",
        "--provider",
        "file",
        "--all",
        "--yes",
        "--path",
        "prod-typo.env",
    ]);
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prod-typo.env does not exist"),
        "{}",
        stderr(&output)
    );
    assert!(!workspace.project_file("prod-typo.env").exists());
}

/// Finding 4: an entry's raw text is every physical line its value spans, so
/// removing one whose quoting has swallowed later assignments would delete
/// those variables too — silently, and unrecoverably for an encrypted value.
#[test]
fn del_refuses_an_entry_that_swallowed_other_assignments() {
    let workspace = Workspace::new();
    let original = "A=\"oops\nB=keepme\nc=fine\"\nD=keep\n";
    workspace.write_project(".env", original);

    for args in [
        vec!["del", "--provider", "file", "--yes", "A"],
        vec!["del", "--provider", "file", "--all", "--yes"],
    ] {
        let output = workspace.run(&args);
        assert!(!output.status.success(), "{args:?} should refuse");
        assert!(
            stderr(&output).contains("B, c"),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("fix the quoting first"),
            "{args:?}: {}",
            stderr(&output)
        );
        assert_eq!(workspace.read_project(".env"), original);
    }
}

/// And the refusal must not spread to the multi-line values the format exists
/// to carry: deleting a PEM key has to keep working.
#[test]
fn del_removes_a_multiline_value() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw==\n-----END PRIVATE KEY-----\"\nKEEP=1\n",
    );

    let output = workspace.run(&["del", "--provider", "file", "--yes", "PRIVATE_KEY"]);
    assert_ok(&output);
    assert_eq!(workspace.read_project(".env"), "KEEP=1\n");
}

/// Finding 5: the value is what the user asked to destroy; the note beside it
/// is text they wrote and did not name, and it may be the only copy.
#[test]
fn del_keeps_an_inline_comment_and_says_so() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "API_KEY=abc # obtain from the break-glass owner\nKEEP=1\n",
    );

    let output = workspace.run(&["del", "--provider", "file", "--yes", "API_KEY"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("kept the comment that followed 'API_KEY'"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        workspace.read_project(".env"),
        "# obtain from the break-glass owner\nKEEP=1\n"
    );
}

/// Finding 2c: a stray quote hides real assignments from the parser. Telling
/// the user the variable is not set, while `grep` plainly shows it, sends them
/// looking in the wrong place — and `del` was the only writer that did.
#[test]
fn del_names_a_quote_problem_rather_than_calling_the_variable_unset() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY='super'password\nKEEP=1\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "API_KEY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("fix line 1"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("does not set"),
        "{}",
        stderr(&output)
    );
    // The same file, and the same diagnosis, as every other writer gives.
    let encrypt = workspace.run(&["encrypt", "--yes", "KEEP"]);
    assert!(
        stderr(&encrypt).contains("fix line 1"),
        "{}",
        stderr(&encrypt)
    );
}

/// Finding 3: naming the same variable twice must not report the first pass as
/// a concurrent writer, nor count the field twice.
#[test]
fn del_deduplicates_a_repeated_name() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "A_KEY=1\nB_KEY=2\n");

    let output = workspace.run(&["del", "--provider", "file", "--yes", "A_KEY", "A_KEY"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("deleted 1 field from .env: A_KEY"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("no longer set"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "B_KEY=2\n");
}

/// Deleting is not reversible for an encrypted value, so a bare `del` on a
/// pipe must not proceed silently — and the message it prints first is the one
/// the user would have answered, so assert what it actually promises.
#[test]
fn del_needs_yes_when_stdin_is_not_a_terminal() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=abc\n");

    let output = workspace.run(&["del", "--provider", "file", "TOKEN"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--yes"), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("1 field will be deleted from .env: TOKEN"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output)
            .contains("Comments, blank lines and every other value are kept, and the file itself is not removed"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "TOKEN=abc\n");
}

/// A delete that deletes nothing must not conjure a `.env` into existence.
#[test]
fn del_on_a_missing_file_creates_nothing() {
    let workspace = Workspace::new();

    let output = workspace.run(&["del", "--provider", "file", "--yes", "ANY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("does not exist"),
        "{}",
        stderr(&output)
    );
    assert!(!workspace.project_file(".env").exists());
}

#[test]
fn scope_user_cannot_be_combined_with_an_explicit_path() {
    let workspace = Workspace::new();
    let output = workspace.run(&[
        "set",
        "--provider",
        "file",
        "--scope",
        "user",
        "--path",
        ".env",
        "KEY",
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot be combined"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn other_providers_still_require_a_path() {
    let workspace = Workspace::new();
    let output = workspace.run(&["get", "--provider", "vault", "--field", "KEY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("--path is required"),
        "{}",
        stderr(&output)
    );
}

/// Finding 25: what this claims has to hold for the *user* scope too.
///
/// The old version listed the project directory only, and under the test
/// keystore the lock file lived beside the fake keyset in `$HOME` — so the
/// listing came back `[".env"]` whether or not the production path was right.
/// The lock now goes where it goes in production, next to `secrets.env`, and
/// what this asserts is the property that actually matters: no file holding key
/// material is ever written beside the secrets, in either scope.
#[test]
fn no_key_material_is_ever_written_next_to_the_secrets() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "API_KEY"], FAKE_VALUE));
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--scope", "user", "USER_KEY"],
        FAKE_VALUE,
    ));

    let names = std::fs::read_dir(workspace.project.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, vec![".env".to_string()], "{names:?}");

    // The keyring stand-in is the whole master key in cleartext; nothing with
    // its contents may appear in the directory holding the dotenv files.
    let keyset = std::fs::read_to_string(workspace.home.path().join("keyset.json")).unwrap();
    let encoded = keyset
        .rsplit_once("\":\"")
        .and_then(|(_, tail)| tail.split('"').next())
        .expect("the test keyset should hold a base64 key");
    assert!(encoded.len() > 32, "{keyset}");

    let user_directory = workspace.user_scope_file().parent().unwrap().to_path_buf();
    let mut beside = std::fs::read_dir(&user_directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    beside.sort();
    assert_eq!(beside, vec!["secrets.env".to_string()], "{beside:?}");
    for name in &beside {
        let contents = std::fs::read(user_directory.join(name)).unwrap();
        assert!(
            !String::from_utf8_lossy(&contents).contains(encoded),
            "{name} beside the secrets holds the master key"
        );
    }

    // Finding 19: the lock is scoped to the *store it guards*, not to the
    // caller's environment. Under the test stand-in that store is a file, so
    // the lock is beside that file — and not in the config directory, which
    // two environments of one OS user can point at two different places while
    // sharing one store.
    let lock = workspace.home.path().join("keyset.json.lock");
    assert!(lock.exists(), "the keyset lock was never taken");
    // The lock is a lock: it carries nothing at all.
    assert_eq!(std::fs::metadata(&lock).unwrap().len(), 0);
}

#[test]
fn no_plaintext_reaches_stdout_stderr_or_the_file_on_a_normal_set() {
    let workspace = Workspace::new();
    let output = workspace.set(&["set", "--provider", "file", "API_KEY"], FAKE_VALUE);
    assert_ok(&output);
    assert!(!stdout(&output).contains(FAKE_VALUE));
    assert!(!stderr(&output).contains(FAKE_VALUE));
    assert!(!workspace.read_project(".env").contains(FAKE_VALUE));
    assert!(
        !std::fs::read_to_string(workspace.home.path().join("keyset.json"))
            .unwrap()
            .contains(FAKE_VALUE)
    );
}

/// A sanity check on the harness itself: if the binary under test were built
/// without the `test-keystore` feature it would reach for the developer's
/// real credential store, and every encrypted test above would be lying.
#[test]
fn the_test_keystore_is_actually_in_use() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "API_KEY"], FAKE_VALUE));
    let keyset = workspace.home.path().join("keyset.json");
    assert!(keyset.exists(), "the test keyset was not created");
    assert!(
        std::fs::read_to_string(&keyset)
            .unwrap()
            .contains("current"),
        "the test keyset does not look like a keyset"
    );
    assert!(Path::new(&keyset).is_file());
}

// ---------------------------------------------------------------------------
// Regressions for the review findings.
// ---------------------------------------------------------------------------

/// Finding 1: two concurrent `set` calls for different keys must both land.
///
/// The advisory lock lives on the inode, and the write replaces the inode, so
/// the second writer used to wake up holding a lock on an orphan and rename its
/// pre-first-writer snapshot over the winner. Both processes printed success and
/// one key was gone. Reproduced 15 times out of 15 before the fix.
#[test]
fn concurrent_sets_for_different_keys_both_survive() {
    for attempt in 0..6 {
        let workspace = Workspace::new();
        workspace.write_project(".env", "BASE=0\n");

        let first = workspace.spawn_set(
            &["set", "--provider", "file", "--plain", "--yes", "AAA"],
            "value-a",
        );
        let second = workspace.spawn_set(
            &["set", "--provider", "file", "--plain", "--yes", "BBB"],
            "value-b",
        );
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert_ok(&first);
        assert_ok(&second);

        let contents = workspace.read_project(".env");
        assert!(
            contents.contains("AAA=value-a") && contents.contains("BBB=value-b"),
            "attempt {attempt} lost a key: {contents:?}"
        );
        assert!(
            contents.contains("BASE=0"),
            "attempt {attempt}: {contents:?}"
        );
    }
}

/// Finding 5: two concurrent first writes on a fresh machine must not destroy a
/// master key.
///
/// Both processes saw "no keyset", both generated one, and the second store
/// replaced the first — after the first had already encrypted a value with the
/// key it just lost. With no recovery mechanism that value was gone for good.
/// Reproduced 1 time in 12 before the fix.
#[test]
fn concurrent_first_writes_do_not_destroy_a_key() {
    for attempt in 0..12 {
        let workspace = Workspace::new();
        // No keyset yet: both calls will want to create one.
        let first = workspace.spawn_set(
            &["set", "--provider", "file", "--yes", "--path", "a.env", "A"],
            "value-a",
        );
        let second = workspace.spawn_set(
            &["set", "--provider", "file", "--yes", "--path", "b.env", "B"],
            "value-b",
        );
        assert_ok(&first.wait_with_output().unwrap());
        assert_ok(&second.wait_with_output().unwrap());

        // Both values were reported as stored, so both must be readable.
        for (path, field, expected) in [("a.env", "A", "value-a"), ("b.env", "B", "value-b")] {
            let output = workspace.run(&[
                "get",
                "--provider",
                "file",
                "--path",
                path,
                "--field",
                field,
                "--expose",
            ]);
            assert!(
                output.status.success(),
                "attempt {attempt}: {field} was reported stored but cannot be read:\n{}",
                stderr(&output)
            );
            assert_eq!(stdout(&output).trim(), expected, "attempt {attempt}");
        }
    }
}

/// Finding 6a: `set --yes KEY < /dev/null` used to report success and store an
/// encryption of the empty string over good ciphertext.
#[test]
fn set_refuses_to_store_a_value_read_at_end_of_file() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "API_KEY"],
        FAKE_VALUE,
    ));
    let before = workspace.read_project(".env");

    let output = workspace.set_with_stdin(&["set", "--provider", "file", "--yes", "API_KEY"], "");
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("end of file"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("API_KEY"), "{}", stderr(&output));

    // The good ciphertext is exactly as it was, and still decrypts.
    assert_eq!(workspace.read_project(".env"), before);
    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), FAKE_VALUE);
}

/// Finding 6b: piping fewer lines than fields must not silently empty the rest.
#[test]
fn set_refuses_when_fewer_lines_are_piped_than_fields() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(
        &["set", "--provider", "file", "--plain", "--yes", "A", "B"],
        "only-one\n",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("'B'"), "{}", stderr(&output));
    // Nothing was written: the whole batch is refused before the file is
    // touched, so A is not left half-set either.
    assert!(!workspace.project_file(".env").exists());
}

/// Finding 6c: a brand-new key was the case that reached no terminal check at
/// all, so an empty stdin sailed through even without `--yes`.
#[test]
fn set_refuses_an_end_of_file_value_for_a_new_key_without_yes() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(&["set", "--provider", "file", "NEWKEY"], "");
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(!workspace.project_file(".env").exists());
}

/// Finding 6: an empty value needs an explicit opt-in, and then works.
#[test]
fn an_empty_value_needs_allow_empty() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(
        &["set", "--provider", "file", "--plain", "--yes", "EMPTY"],
        "\n",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--allow-empty"),
        "{}",
        stderr(&output)
    );

    let output = workspace.set_with_stdin(
        &[
            "set",
            "--provider",
            "file",
            "--plain",
            "--yes",
            "--allow-empty",
            "EMPTY",
        ],
        "\n",
    );
    assert_ok(&output);
    let output = workspace.run(&["get", "--provider", "file", "--field", "EMPTY", "--expose"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "");
}

/// Finding 7a: one unreadable entry used to fail the whole read, so cloning a
/// repo whose `.env` carries a teammate's markers broke everything — including
/// the plaintext half.
#[test]
fn an_unreadable_entry_does_not_break_the_rest_of_the_file() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "DEBUG=true\nBAD=gitguardian:!!!not-base64!!!\nPORT=8080\n",
    );

    let output = workspace.run(&["get", "--provider", "file", "--field", "DEBUG", "--expose"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "true");

    // ...but `run` refuses: injecting the readable half hands the child a
    // variable-shaped hole and exits 0. See the dedicated test below.
    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "DEBUG"]);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(stderr(&output).contains("BAD"), "{}", stderr(&output));

    // A full dump lists the readable values and warns about the other.
    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("DEBUG=true"),
        "{}",
        stdout(&output)
    );
    assert!(stdout(&output).contains("PORT=8080"), "{}", stdout(&output));
    assert!(!stdout(&output).contains("BAD="), "{}", stdout(&output));
    assert!(stderr(&output).contains("BAD"), "{}", stderr(&output));
}

/// Finding 7b: and a bad entry in the user-scope file must not break every
/// *read* on the machine. `run` is deliberately stricter (finding 10).
#[test]
fn a_bad_user_scope_entry_does_not_break_a_plaintext_project() {
    let workspace = Workspace::new();
    let user_file = workspace.user_scope_file();
    std::fs::create_dir_all(user_file.parent().unwrap()).unwrap();
    std::fs::write(&user_file, "BROKEN=gitguardian:!!!not-base64!!!\n").unwrap();
    workspace.write_project(".env", "DEBUG=true\n");

    let output = workspace.run(&["get", "--provider", "file", "--field", "DEBUG", "--expose"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "true");

    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("DEBUG=true"),
        "{}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("BROKEN"), "{}", stderr(&output));
}

/// Finding 10: reading part of a file is right for `get`, which prints what it
/// found and says what it could not. Injecting part of one is not: the child
/// used to start with the variable simply absent — indistinguishable from one
/// nobody ever set — and `run` exited 0, in a CI job where nobody reads stderr.
#[test]
fn run_refuses_to_inject_a_partially_readable_file() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "PLAIN"],
        "readable",
    ));
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "SEALED"],
        FAKE_VALUE,
    ));
    // The device's key is gone, so `SEALED` can no longer be opened here — the
    // fresh-clone-of-a-teammate's-repo case.
    std::fs::remove_file(workspace.home.path().join("keyset.json")).unwrap();
    workspace.trust_project();

    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "PLAIN"]);
    assert!(
        !output.status.success(),
        "run injected a partial environment and succeeded: {}",
        stdout(&output)
    );
    let message = stderr(&output);
    assert!(message.contains("SEALED"), "{message}");
    assert!(message.contains("refusing to run printenv"), "{message}");
    // The child never started, so it printed nothing.
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    // And no plaintext of the unreadable value appears anywhere.
    assert!(!message.contains(FAKE_VALUE), "{message}");

    // `get` still reports what it could read, with the same warning.
    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("PLAIN=readable"),
        "{}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("SEALED"), "{}", stderr(&output));
}

/// Finding 7: asking for the broken field itself still fails, naming it.
#[test]
fn asking_for_the_unreadable_field_still_fails() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "DEBUG=true\nBAD=gitguardian:!!!nope!!!\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "BAD"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("BAD"), "{}", stderr(&output));
}

/// Finding 8: `--plain` used to accept a value `get` would always reject, and
/// per finding 7 that entry then blocked the whole file.
#[test]
fn a_plaintext_value_that_looks_like_a_marker_is_refused() {
    let workspace = Workspace::new();
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "TOKEN"],
        "encrypted:whatever",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("TOKEN"), "{}", stderr(&output));
    // The reason is explained without echoing the value.
    assert!(
        !stderr(&output).contains("encrypted:whatever"),
        "the value leaked: {}",
        stderr(&output)
    );
    assert!(!workspace.project_file(".env").exists());
}

/// Finding 9: appending next to a stray quote used to swallow two variables.
#[test]
fn writing_next_to_an_unterminated_quote_is_refused() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "NOTE=\"oops\nAPI_KEY=abc\n");

    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "GREETING"],
        "hello world",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("line 1"), "{}", stderr(&output));

    // API_KEY is still readable, which is what used to stop being true.
    assert_eq!(workspace.read_project(".env"), "NOTE=\"oops\nAPI_KEY=abc\n");
    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "abc");
}

/// Finding 10: an inline comment is not part of the value, and survives an
/// update of that value.
#[test]
fn an_inline_comment_is_neither_read_nor_destroyed() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# header\nAPI_KEY=old # rotated monthly\n");

    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "old");

    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "API_KEY"],
        "new",
    ));
    assert_eq!(
        workspace.read_project(".env"),
        "# header\nAPI_KEY=new # rotated monthly\n"
    );
}

/// Finding 11: `run` scrubbed a provider credential and then decided not to
/// replace it because the ambient value it had just removed was still visible,
/// leaving the child with no token at all.
#[test]
fn a_scrubbed_credential_is_replaced_by_the_providers_value() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "VAULT_TOKEN=app-token-from-file\n");

    let output = workspace
        .command()
        .env("VAULT_TOKEN", "bootstrap-token")
        .args(["run", "--provider", "file", "--", "printenv", "VAULT_TOKEN"])
        .output()
        .unwrap();
    assert_ok(&output);
    assert_eq!(
        stdout(&output).trim(),
        "app-token-from-file",
        "stderr: {}",
        stderr(&output)
    );
}

/// Finding 11: an ordinary variable still keeps its ambient value, which is the
/// behaviour the credential case was wrongly borrowing.
#[test]
fn an_ordinary_ambient_variable_still_wins() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "APP_MODE=from-file\n");

    let output = workspace
        .command()
        .env("APP_MODE", "from-environment")
        .args(["run", "--provider", "file", "--", "printenv", "APP_MODE"])
        .output()
        .unwrap();
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "from-environment");
    assert!(
        stderr(&output).contains("already set"),
        "{}",
        stderr(&output)
    );
}

/// Finding 13: naming a cleartext keyset file is not enough to activate the
/// test escape hatch. This is what stops `target/debug/gitguardian` — the
/// binary a developer runs after `cargo test` — from honouring a stray
/// environment variable and quietly bypassing the OS keyring.
#[test]
fn the_test_keystore_requires_an_explicit_acknowledgement() {
    use std::io::Write;

    let workspace = Workspace::new();
    // A real value on stdin, so the command gets all the way to the keystore
    // rather than stopping at the value prompt.
    let mut child = workspace
        .command()
        .env_remove("GITGUARDIAN_TEST_KEYSET_INSECURE_ACK")
        .args(["set", "--provider", "file", "--yes", "--expose", "API_KEY"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{FAKE_VALUE}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success(), "{}", stderr(&output));
    // Fail closed: it must not silently fall back to the real login keyring.
    assert!(!workspace.project_file(".env").exists());
    assert!(
        stderr(&output).contains("cleartext file on disk"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("GITGUARDIAN_TEST_KEYSET_INSECURE_ACK"),
        "{}",
        stderr(&output)
    );
}

/// Finding 15: a committed marker must not publish its plaintext's length.
#[test]
fn markers_of_different_short_values_are_the_same_length() {
    let workspace = Workspace::new();
    let mut lengths = std::collections::BTreeSet::new();
    for (index, value) in [
        "a",
        "ab-20-char-key-xxxxx",
        "a-31-character-token-aaaaaaaaaa",
    ]
    .iter()
    .enumerate()
    {
        let key = format!("KEY{index}");
        assert_ok(&workspace.set(&["set", "--provider", "file", "--yes", &key], value));
        let contents = workspace.read_project(".env");
        let line = contents
            .lines()
            .find(|line| line.starts_with(&format!("{key}=")))
            .unwrap();
        lengths.insert(line.len() - key.len() - 1);
    }
    assert_eq!(
        lengths.len(),
        1,
        "marker length leaks the plaintext length: {lengths:?}"
    );
}

/// Finding 17a: a temporary left behind by a killed write is collected rather
/// than sitting in the project directory holding a copy of the file — and
/// finding 8: a *user's* file that merely looks like one is not, and what is
/// deleted is reported.
#[test]
fn a_leftover_temporary_file_is_collected_by_the_next_write() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "A=1\n");
    // The shape this writer generates: the target's name, the tag, exactly the
    // generated number of random alphanumerics, `.tmp`.
    let generated = ".env.gitguardian-a1b2c3d4e5f6g7h8i9j0k1.tmp";
    let leftover = workspace.project_file(generated);
    std::fs::write(&leftover, "A=1\nSECRET=plaintext-from-a-killed-run\n").unwrap();
    // Things a person could plausibly have created by hand, each holding the
    // only copy of a value. They share the prefix and the suffix and must
    // survive.
    //
    // Round-3 finding 12b: the second of these is the one that matters, and the
    // one this test used to be unable to catch. `backup` is six characters, so
    // it could never match the predicate however loose it was; a backup tagged
    // with a ticket number is twelve alphanumerics, which the predicate *did*
    // match — so the next write deleted it.
    let mut mine = Vec::new();
    for name in [
        ".env.gitguardian-backup.tmp",
        ".env.gitguardian-backupABC123.tmp",
    ] {
        let path = workspace.project_file(name);
        std::fs::write(&path, "A=1\n").unwrap();
        mine.push(path);
    }

    let output = workspace.set(&["set", "--provider", "file", "--plain", "--yes", "B"], "2");
    assert_ok(&output);
    assert!(!leftover.exists(), "the stale temporary was not collected");
    for path in &mine {
        assert!(path.exists(), "a file the user made was deleted: {path:?}");
    }
    // Deleting a copy of the user's secrets is not something to do silently.
    assert!(
        stderr(&output).contains(generated),
        "the deletion was not reported: {}",
        stderr(&output)
    );
}

/// A stray quote that pairs with a later legitimate one leaves nothing
/// unterminated, so a quote count says the file is fine — but two variables have
/// already been swallowed into one value. The reads must say so; refusing to
/// write is no help to `get` and `run`.
#[test]
fn a_swallowed_variable_is_reported_on_every_read() {
    let workspace = Workspace::new();
    // Balanced: the stray quote pairs with the one on the last line and nothing
    // follows it, so a quote count says the file is fine. `NOTE` has swallowed
    // `API_KEY`, and only the heuristic can say so.
    //
    // (A tail *after* that closing quote — `OTHER="fine` — is a different and
    // fatal problem, and round-3 finding 1a is that it used to be reported as
    // this one. See `a_value_partly_outside_its_quotes_is_refused_even_multiline`.)
    workspace.write_project(".env", "NOTE=\"oops\nAPI_KEY=abc\nOTHER=\"\n");

    // `get` of everything, and `run`, both warn, naming the entry that grew and
    // the line to look at.
    for args in [
        vec!["get", "--provider", "file", "--expose"],
        vec!["run", "--provider", "file", "--", "true"],
    ] {
        let output = workspace.run(&args);
        assert_ok(&output);
        let message = stderr(&output);
        assert!(
            message.contains("'NOTE'") && message.contains("stray quote"),
            "{args:?} did not warn: {message}"
        );
        assert!(message.contains("line 1"), "{args:?}: {message}");
        // Finding 25: the name found *inside* the value is a fragment of that
        // value — a PEM body or a JSON blob if the heuristic is wrong — and
        // this message lands in CI logs.
        assert!(
            !message.contains("API_KEY"),
            "{args:?} echoed a fragment of the value: {message}"
        );
    }

    // Asking for the swallowed name explains why it is missing, rather than
    // reporting a bare "field not found" that reads as "never set".
    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("stray quote"), "{message}");
    assert!(message.contains("field not found"), "{message}");

    // Writing is still allowed — the quotes are balanced, so appending is safe —
    // but it warns.
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "NEW"],
        "v",
    );
    assert_ok(&output);
    assert!(
        stderr(&output).contains("stray quote"),
        "{}",
        stderr(&output)
    );

    // Round-3 finding 26g: `run` succeeding here is a decision, not an
    // oversight, and this is what it costs — so assert both halves rather than
    // only that the exit code is zero.
    //
    // The heuristic can fire on a legitimate multi-line value (a PEM body
    // containing `KEY=`), and there is no flag to override it, so escalating it
    // to fatal would make `run` refuse a file that is perfectly fine. The
    // warning is the whole mitigation. What the user pays for that:
    // the swallowed variable really is absent from the child's environment.
    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "NOTE"]);
    assert_ok(&output);
    assert!(stdout(&output).contains("oops"), "{}", stdout(&output));
    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "API_KEY"]);
    assert!(
        !output.status.success(),
        "the swallowed variable was injected after all: {}",
        stdout(&output)
    );
}

/// `get` prints `KEY=value` per line, so a value containing a newline is
/// indistinguishable from several variables unless it is quoted. One multi-line
/// secret must not read as three assignments.
#[test]
fn a_multiline_value_is_quoted_so_the_output_is_unambiguous() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "PEM=\"-----BEGIN X-----\nabcdef\n-----END X-----\"\nPORT=3000\n",
    );

    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    let out = stdout(&output);
    // The multi-line value is delimited...
    assert!(out.contains("PEM='-----BEGIN X-----"), "{out}");
    assert!(out.contains("-----END X-----'"), "{out}");
    // ...and re-parsing the output yields two variables, not four.
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("PEM=") || line.starts_with("PORT="))
            .count(),
        2,
        "{out}"
    );
    // A single-line value is untouched, so existing output is unchanged.
    assert!(out.contains("PORT=3000"), "{out}");

    // `--field` still prints the raw value: it is the whole output, so there is
    // nothing to disambiguate, and `$(gg get --field PEM)` must stay usable.
    let output = workspace.run(&["get", "--provider", "file", "--field", "PEM", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).starts_with("-----BEGIN X-----"),
        "{}",
        stdout(&output)
    );
}

/// A `.env` copied from a `.env.example` has empty values with the instructions
/// beside them. Writing into one must not glue the value to the comment: the
/// plaintext form reads back as a different string, and the encrypted form does
/// not read back at all, both while `set` reports success.
#[test]
fn setting_an_empty_value_that_has_an_inline_comment_keeps_them_apart() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "# copy of .env.example\nAPI_KEY= # get this from the dashboard\nPORT=3000\n",
    );

    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "API_KEY"],
        FAKE_VALUE,
    ));

    let contents = workspace.read_project(".env");
    assert!(
        contents.contains("# get this from the dashboard"),
        "the comment was lost: {contents}"
    );
    let line = contents
        .lines()
        .find(|line| line.starts_with("API_KEY="))
        .unwrap_or_else(|| panic!("{contents}"));
    let marker = line["API_KEY=".len()..].split_whitespace().next().unwrap();
    assert!(marker.starts_with("gitguardian:"), "{contents}");
    // The marker must end at the whitespace, not run into the comment.
    assert!(!marker.contains('#'), "{contents}");

    // The whole point: it reads back, and it reads back as what was stored.
    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim_end(), FAKE_VALUE);
}

/// The same shape written in plaintext: the marker case fails loudly, this one
/// fails silently, which is worse.
#[test]
fn a_plain_value_written_beside_an_inline_comment_reads_back_unchanged() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY= # get this from the dashboard\n");

    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "API_KEY"],
        FAKE_VALUE,
    ));

    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(
        stdout(&output).trim_end(),
        FAKE_VALUE,
        "the value picked up the comment: {}",
        workspace.read_project(".env")
    );
}

/// A key assigned twice is where the old plaintext hides: rewriting only the
/// assignment a shell would use leaves the earlier cleartext in a file this
/// feature exists to make committable, while `get` reports the new value and
/// everything looks right.
#[test]
fn setting_a_duplicated_key_leaves_no_earlier_plaintext_behind() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "API_KEY=old-plaintext-secret\nOTHER=1\nAPI_KEY=another-plaintext\n",
    );

    let output = workspace.set(
        &["set", "--provider", "file", "--yes", "API_KEY"],
        FAKE_VALUE,
    );
    assert_ok(&output);

    let contents = workspace.read_project(".env");
    assert!(
        !contents.contains("old-plaintext-secret") && !contents.contains("another-plaintext"),
        "an earlier assignment kept its cleartext: {contents}"
    );
    assert_eq!(contents.matches("gitguardian:").count(), 2, "{contents}");
    // And the user is told, because they were warned about one field.
    assert!(
        stderr(&output).contains("assigned 2 times"),
        "{}",
        stderr(&output)
    );
}

/// `encrypt` is the answer to the value `set` cannot read: a multi-line key is
/// written into the file (or arrives there from a vendor download) and sealed
/// from there, which is how varlock's `encrypt --file` works too.
#[test]
fn encrypt_seals_a_multiline_value_in_place() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "# config\nPORT=3000   # stays readable\nPRIVATE_KEY=\"-----BEGIN KEY-----\nfake-line-two\n-----END KEY-----\"\n",
    );

    let output = workspace.run(&["encrypt", "--yes", "PRIVATE_KEY"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("PRIVATE_KEY"),
        "{}",
        stderr(&output)
    );

    let contents = workspace.read_project(".env");
    assert!(!contents.contains("fake-line-two"), "{contents}");
    // Untouched: the comment, and the value we did not name.
    assert!(
        contents.contains("PORT=3000   # stays readable"),
        "{contents}"
    );

    // And it reads back whole, all three lines.
    let output = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "PRIVATE_KEY",
        "--expose",
    ]);
    assert_ok(&output);
    assert_eq!(stdout(&output).lines().count(), 3, "{}", stdout(&output));
    assert!(stdout(&output).contains("fake-line-two"));
}

/// Without a name, `encrypt` would also seal ordinary config, so it insists on
/// either names or an explicit --all.
#[test]
fn encrypt_refuses_to_guess_what_is_secret() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "PORT=3000\nTOKEN=abc\n");

    let output = workspace.run(&["encrypt", "--yes"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--all"), "{}", stderr(&output));
    // Nothing was touched.
    assert_eq!(workspace.read_project(".env"), "PORT=3000\nTOKEN=abc\n");

    // A misspelt name is an error, not a quiet "nothing to encrypt".
    let output = workspace.run(&["encrypt", "--yes", "TOKEM"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("TOKEM"), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), "PORT=3000\nTOKEN=abc\n");
}

/// Running it twice must not churn ciphertext in a committed file.
#[test]
fn encrypt_is_idempotent_and_reports_what_it_skipped() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "A=one\nB=two\nFOREIGN=encrypted:dotenvx\n");

    let first = workspace.run(&["encrypt", "--all", "--yes"]);
    assert_ok(&first);
    assert!(stderr(&first).contains("FOREIGN"), "{}", stderr(&first));
    let after_first = workspace.read_project(".env");

    let second = workspace.run(&["encrypt", "--all", "--yes"]);
    assert_ok(&second);
    assert!(
        stderr(&second).contains("nothing to encrypt"),
        "{}",
        stderr(&second)
    );
    assert_eq!(
        workspace.read_project(".env"),
        after_first,
        "ciphertext churned on a second run"
    );
    // The other tool's value is still exactly as it was.
    assert!(
        after_first.contains("FOREIGN=encrypted:dotenvx"),
        "{after_first}"
    );
}

/// Encrypting is one-way for anyone without this device's key, so a bare
/// `encrypt` on a pipe must not proceed silently.
#[test]
fn encrypt_needs_yes_when_stdin_is_not_a_terminal() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=abc\n");
    let output = workspace.run(&["encrypt", "TOKEN"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--yes"), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), "TOKEN=abc\n");
}

/// `encrypt` reporting "nothing to encrypt" must actually have changed nothing:
/// no `.env` conjured into existence, and no device key minted for a run the
/// user could still have declined.
#[test]
fn encrypt_with_no_dotenv_file_creates_neither_the_file_nor_a_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");

    let output = workspace.run(&["encrypt", "--all"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("nothing to encrypt"),
        "{}",
        stderr(&output)
    );

    assert!(
        !workspace.project_file(".env").exists(),
        "a command that reported no changes created .env"
    );
    assert!(
        !keyset.exists(),
        "a command that reported no changes minted the device key"
    );
}

/// Finding 9, a regression of the dry-run fix: `--yes` skips the preview
/// entirely, so it walked straight past the branch that fix built. The key was
/// minted before the file was even parsed — printing "nothing to encrypt" while
/// leaving a keyset behind on a machine that had none.
#[test]
fn encrypt_yes_on_a_file_with_nothing_to_encrypt_mints_no_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");
    // The only entry is another tool's marker: recognised, skipped, never
    // sealed.
    workspace.write_project(".env", "FOREIGN=encrypted:dotenvx\n");

    let output = workspace.run(&["encrypt", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("nothing to encrypt"),
        "{}",
        stderr(&output)
    );
    assert!(
        !keyset.exists(),
        "a command that reported no changes minted the device key: {}",
        stderr(&output)
    );
    assert_eq!(
        workspace.read_project(".env"),
        "FOREIGN=encrypted:dotenvx\n"
    );
}

/// The same for a file whose only entry is already encrypted — the idempotent
/// re-run, on a machine where the key has since been removed. Re-minting there
/// is worse than pointless: the new key cannot read the value that is in the
/// file, so the "no changes" run leaves the device holding a key for nothing.
#[test]
fn encrypt_yes_on_an_already_encrypted_file_mints_no_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "API_KEY"],
        FAKE_VALUE,
    ));
    let sealed = workspace.read_project(".env");
    assert!(sealed.starts_with("API_KEY=gitguardian:"), "{sealed}");
    std::fs::remove_file(&keyset).unwrap();

    let output = workspace.run(&["encrypt", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("nothing to encrypt"),
        "{}",
        stderr(&output)
    );
    assert!(
        !keyset.exists(),
        "a pass with nothing to seal minted a device key: {}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), sealed);
}

/// Finding 18: the injectability rule was applied to names only, though the
/// comment claimed it was about values. A NUL is valid UTF-8, so it survives
/// being read out of a dotenv file, and the spawn then failed with "nul byte
/// found in provided data" — naming neither the field nor the file, and taking
/// every other variable down with it.
#[test]
fn run_names_the_field_and_the_file_when_a_value_cannot_be_injected() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "GOOD=ok\nBAD=be\u{0}fore\n");

    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "GOOD"]);
    assert!(!output.status.success(), "{}", stdout(&output));
    let message = stderr(&output);
    assert!(message.contains("BAD"), "{message}");
    assert!(message.contains("NUL"), "{message}");
    assert!(message.contains(".env"), "{message}");
    // Not "running printenv failed": the child never started.
    assert!(!message.contains("running printenv"), "{message}");
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
}

/// The preview half of an interactive `encrypt` is a dry run, and a dry run the
/// user may answer `n` to must not leave the device key behind either.
#[test]
fn an_encrypt_preview_that_is_declined_mints_no_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");
    workspace.write_project(".env", "API_KEY=plaintext-fake\n");

    // No `--yes` and stdin is not a terminal, so this stops at the confirmation.
    let output = workspace.run(&["encrypt", "--all"]);
    assert!(!output.status.success(), "{}", stderr(&output));
    // It got far enough to name what would be encrypted...
    assert!(stderr(&output).contains("API_KEY"), "{}", stderr(&output));
    // ...without creating the key that would have done it.
    assert!(
        !keyset.exists(),
        "a declined preview minted the device key: {}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "API_KEY=plaintext-fake\n");
}

/// `activate` prints shell code and touches nothing: it must not read a file,
/// reach the keyring, or need a project to exist.
///
/// Round-3 finding 26d: the old side-effect assertion was
/// `assert!(!project_file(".env").exists())` on a workspace where the file had
/// never been created, so it passed whatever `activate` did. Here there *is* a
/// file, it holds an encrypted value, and there is no keyset on the device — so
/// reading the file, or reaching for a key, would leave a trace this can see.
#[test]
fn activate_prints_a_hook_for_each_shell_without_side_effects() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "API_KEY"],
        FAKE_VALUE,
    ));
    let sealed = workspace.read_project(".env");
    let keyset = workspace.home.path().join("keyset.json");
    std::fs::remove_file(&keyset).unwrap();
    let before = std::fs::metadata(workspace.project_file(".env")).unwrap();

    for shell in ["bash", "zsh", "fish"] {
        let output = workspace.run(&["activate", shell]);
        assert_ok(&output);
        let script = stdout(&output);
        assert!(script.contains("_ggshield_hook"), "{shell}: {script}");
        assert!(
            script.contains(&format!("secret hook-env {shell}")),
            "{shell}: {script}"
        );
        // Nothing was said, so nothing went wrong quietly either.
        assert_eq!(stderr(&output), "", "{shell}");
        // No key was minted, and the file was neither read into the output nor
        // rewritten.
        assert!(!keyset.exists(), "{shell} minted a device key");
        assert!(!script.contains(FAKE_VALUE), "{shell}: {script}");
        assert!(!script.contains("gitguardian:"), "{shell}: {script}");
        assert_eq!(workspace.read_project(".env"), sealed, "{shell}");
        let after = std::fs::metadata(workspace.project_file(".env")).unwrap();
        assert_eq!(
            before.modified().unwrap(),
            after.modified().unwrap(),
            "{shell}"
        );
    }
}

/// The hook is the thing users actually run, so exercise the real shell rather
/// than the generated string: load on entering, keep it in a subdirectory, drop
/// it on leaving.
#[test]
fn the_hook_loads_and_unloads_secrets_around_a_project_directory() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "PORT=3000\nAPI_KEY=fake-hook-value\n");
    std::fs::create_dir_all(workspace.project_file("sub")).unwrap();

    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let outside = workspace.home.path().display().to_string();
    let program = format!(
        "{script}\n\
         cd {project}; _ggshield_hook; print -r -- \"in=[$API_KEY]\"\n\
         cd {project}/sub; _ggshield_hook; print -r -- \"sub=[$API_KEY]\"\n\
         cd {outside}; _ggshield_hook; print -r -- \"out=[$API_KEY]\"\n"
    );
    let output = workspace.shell("zsh", &program);
    let text = stdout(&output);
    assert!(text.contains("in=[fake-hook-value]"), "{text}");
    // Walking up: a project's secrets must not vanish because you stepped into
    // a subdirectory.
    assert!(text.contains("sub=[fake-hook-value]"), "{text}");
    assert!(text.contains("out=[]"), "{text}");
}

/// A value is data, never shell syntax. This is the injection that a naive
/// `export KEY=$value` would hand an attacker who can edit a committed `.env`.
#[test]
fn a_hostile_value_cannot_escape_its_assignment_in_any_shell() {
    let canary = std::env::temp_dir().join("gitguardian-hook-injection-canary");
    let _ = std::fs::remove_file(&canary);
    let hostile = format!("x'; touch {}; echo '", canary.display());

    // Round-3 finding 26e: fish was missing from this loop, so breaking
    // `fish_quote` — a different quoting dialect, with its own backslash rules —
    // left the test green. `| source` needs its own probe because fish has no
    // `-c`-with-a-sourced-block equivalent of the other two.
    for (shell, probe) in [
        ("zsh", "print -r -- \"value=[$EVIL]\""),
        ("bash", "printf '%s\\n' \"value=[$EVIL]\""),
        ("fish", "printf '%s\\n' \"value=[$EVIL]\""),
    ] {
        let workspace = Workspace::new();
        workspace.write_project(".env", &format!("EVIL={hostile}\n"));
        workspace.trust_project();
        let script = stdout(&workspace.run(&["activate", shell, "--no-hook-env"]));
        let project = workspace.project.path().display().to_string();
        let program = format!("{script}\ncd {project}\n_ggshield_hook\n{probe}\n");
        if !has_shell(shell) {
            continue;
        }
        let output = workspace.shell(shell, &program);
        assert!(
            stdout(&output).contains(&format!("value=[{hostile}]")),
            "{shell}: {}\n{}",
            stdout(&output),
            stderr(&output)
        );
    }
    assert!(
        !canary.exists(),
        "a dotenv value executed as shell code from the hook"
    );
}

/// Encrypted values are the point: the hook decrypts, and the marker itself
/// never reaches the environment.
#[test]
fn the_hook_decrypts_sealed_values() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-sealed-value\n");
    assert_ok(&workspace.run(&["encrypt", "--all", "--yes"]));
    assert!(workspace.read_project(".env").contains("gitguardian:"));

    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program = format!("{script}\ncd {project}\n_ggshield_hook\nprint -r -- \"v=[$API_KEY]\"\n");
    let text = stdout(&workspace.shell("zsh", &program));
    assert!(text.contains("v=[fake-sealed-value]"), "{text}");
    assert!(!text.contains("gitguardian:"), "{text}");
}

/// A variable the user set themselves outranks the file, matching `run`.
#[test]
fn the_hook_does_not_clobber_a_variable_the_user_already_set() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-from-file\n");
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program = format!(
        "{script}\nexport API_KEY=set-by-hand\ncd {project}\n_ggshield_hook\nprint -r -- \"v=[$API_KEY]\"\n"
    );
    let text = stdout(&workspace.shell("zsh", &program));
    assert!(text.contains("v=[set-by-hand]"), "{text}");
}

/// Overriding a variable *after* the hook loaded it makes it yours: leaving the
/// directory must not take your value with it. The earlier no-clobber test sets
/// the variable before the first load, which is a different and easier case.
#[test]
fn the_hook_does_not_unload_a_value_the_user_changed_after_it_loaded() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-from-file\nOTHER=fake-other\n");
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let outside = workspace.home.path().display().to_string();
    let program = format!(
        "{script}\n\
         cd {project}; _ggshield_hook\n\
         export API_KEY=set-by-hand\n\
         cd {outside}; _ggshield_hook\n\
         print -r -- \"left=[$API_KEY] other=[$OTHER]\"\n\
         cd {project}; _ggshield_hook\n\
         print -r -- \"back=[$API_KEY]\"\n"
    );
    let text = stdout(&workspace.shell("zsh", &program));
    // Kept on the way out, and not overwritten on the way back in.
    assert!(text.contains("left=[set-by-hand]"), "{text}");
    assert!(text.contains("back=[set-by-hand]"), "{text}");
    // A value we did set is still unloaded normally.
    assert!(text.contains("other=[]"), "{text}");
}

// ---------------------------------------------------------------------------
// Round-3 review findings.
// ---------------------------------------------------------------------------

/// The environment variable the hook keeps its state in.
const STATE_VAR: &str = "__GITGUARDIAN_ACTIVE";

/// The state value out of a `hook-env` block, so a test can hand it back.
fn state_value(block: &str) -> String {
    block
        .lines()
        .find_map(|line| line.strip_prefix(&format!("export {STATE_VAR}=")))
        .map(|value| value.trim_end_matches(';').trim_matches('\'').to_string())
        .unwrap_or_else(|| panic!("no state assignment in:\n{block}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Finding 1a: the round-2 "trailing bytes after a closing quote" fix skipped
/// multi-line values entirely, so `PRIVATE_KEY="a\nb"SECRETTAIL` parsed as well
/// formed. `encrypt` then sealed the quoted half, reported success, and left
/// `SECRETTAIL` on disk in cleartext; `set` did the same.
#[test]
fn a_value_partly_outside_its_quotes_is_refused_even_multiline() {
    let source = "PRIVATE_KEY=\"line one\nline two\"SECRETTAIL\nPORT=80\n";

    let workspace = Workspace::new();
    workspace.write_project(".env", source);
    let output = workspace.run(&["encrypt", "--all", "--yes"]);
    assert!(
        !output.status.success(),
        "encrypt rewrote a file whose value is partly outside its quotes: {}",
        stderr(&output)
    );
    let message = stderr(&output);
    assert!(message.contains("line 1"), "{message}");
    assert!(message.contains("outside its quotes"), "{message}");
    assert!(!message.contains("encrypted 2"), "{message}");
    assert_eq!(workspace.read_project(".env"), source);

    // Naming the variable does not get past it either: the malformed line is not
    // an assignment, so there is nothing there called `PRIVATE_KEY` to seal.
    let output = workspace.run(&["encrypt", "--yes", "PRIVATE_KEY"]);
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("encrypted 1"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), source);

    // And `set`, which used to append a second assignment and leave the
    // malformed line's cleartext behind.
    let workspace = Workspace::new();
    workspace.write_project(".env", source);
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "OTHER"],
        "v",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), source);
    // The tail is still cleartext, which is the point: nothing pretended to
    // have sealed it.
    assert!(workspace.read_project(".env").contains("SECRETTAIL"));
}

/// Finding 2a: the hook discarded the read warnings, so a value it could not
/// decrypt simply never appeared — and every later command in that shell ran
/// with a variable-shaped hole, with no exit code to notice it by. `run`
/// refuses the same file; so must this.
#[test]
fn the_hook_loads_nothing_when_a_value_cannot_be_read() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "PLAIN"],
        "readable",
    ));
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "SEALED"],
        FAKE_VALUE,
    ));
    // The fresh-clone-of-a-teammate's-repo case: the key this was sealed with
    // is not on this device.
    std::fs::remove_file(workspace.home.path().join("keyset.json")).unwrap();
    workspace.trust_project();

    let output = workspace.run(&["hook-env", "bash"]);
    assert_ok(&output);
    let block = stdout(&output);
    assert!(
        !block.contains("export PLAIN="),
        "the hook exported a partial environment: {block}"
    );
    assert!(
        block.contains("SEALED"),
        "the failure was not named: {block}"
    );
    assert!(!block.contains(FAKE_VALUE), "{block}");
    // The state still records the file, so this is said once — see finding 7.
    assert!(block.contains(&format!("export {STATE_VAR}=")), "{block}");

    // The same thing in a real shell: nothing is set, and the reason is on
    // stderr rather than nowhere.
    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program =
        format!("{script}\ncd {project}\n_ggshield_hook\nprint -r -- \"plain=[$PLAIN]\"\n");
    let output = workspace.shell("zsh", &program);
    assert!(stdout(&output).contains("plain=[]"), "{}", stdout(&output));
    assert!(stderr(&output).contains("SEALED"), "{}", stderr(&output));
}

/// Finding 7: a load failure used to be recorded as *cleared* state, so the
/// unchanged-file fast path could never engage again — the same two-line
/// message, and the same keyring round trip, before every prompt for as long as
/// the shell sat in the directory.
#[test]
fn a_hook_load_failure_is_reported_once_not_on_every_prompt() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--yes", "SEALED"],
        FAKE_VALUE,
    ));
    workspace.write_project(
        ".env",
        &format!("PLAIN=readable\n{}", workspace.read_project(".env")),
    );
    std::fs::remove_file(workspace.home.path().join("keyset.json")).unwrap();

    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program =
        format!("{script}\ncd {project}\n_ggshield_hook\n_ggshield_hook\n_ggshield_hook\n");
    let output = workspace.shell("zsh", &program);
    let reports = stderr(&output).matches("SEALED").count();
    assert_eq!(
        reports,
        1,
        "the same failure was reported {reports} times:\n{}",
        stderr(&output)
    );
}

/// Finding 5: a symlinked `.env` was skipped in silence and the walk carried
/// on, so the hook loaded a *different* directory's secrets. `get` and `run`
/// both refuse loudly; the three must not disagree without a word.
#[cfg(unix)]
#[test]
fn the_hook_refuses_a_symlinked_dotenv_rather_than_loading_a_parents() {
    let workspace = Workspace::new();
    let outer = workspace.project_file("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::write(outer.join(".env"), "PARENT_KEY=parent-value\n").unwrap();
    std::fs::write(outer.join("real.env"), "LINKED=linked-value\n").unwrap();
    let link = inner.join(".env");
    std::os::unix::fs::symlink(outer.join("real.env"), &link).unwrap();

    let output = workspace.run_with(Some(&inner), &[], &["hook-env", "bash"]);
    assert_ok(&output);
    let block = stdout(&output);
    assert!(
        !block.contains("PARENT_KEY"),
        "the hook loaded another directory's file: {block}"
    );
    assert!(
        !block.contains("LINKED"),
        "the hook read through a link: {block}"
    );
    assert!(block.contains("symbolic link"), "nothing was said: {block}");

    // `get` from the same directory refuses in the same words, which is the
    // agreement that was missing.
    let output = workspace.run_with(
        Some(&inner),
        &[],
        &["get", "--provider", "file", "--path", ".env", "--expose"],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("symbolic link"),
        "{}",
        stderr(&output)
    );

    // Proof the walk really was stopped: without the link, the parent's file is
    // exactly what would have loaded.
    std::fs::remove_file(&link).unwrap();
    workspace.trust_file(&outer.join(".env"));
    let output = workspace.run_with(Some(&inner), &[], &["hook-env", "bash"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("export PARENT_KEY='parent-value'"),
        "{}",
        stdout(&output)
    );
}

/// Finding 6: `current_exe()` went into all three generated scripts unquoted,
/// so an installation directory with a space in it — `~/Library/Application
/// Support/…`, `~/My Drive/…` — made every prompt try to execute the first word
/// and no secret was ever loaded.
#[test]
fn the_hook_runs_from_an_installation_path_with_a_space_in_it() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-spaced-path-value\n");

    let tools = workspace.home.path().join("My Tools");
    std::fs::create_dir_all(&tools).unwrap();
    workspace.trust_project();
    let installed = tools.join("ggshield");
    std::fs::copy(
        Command::cargo_bin("ggshield").unwrap().get_program(),
        &installed,
    )
    .unwrap();

    let output = workspace
        .command_at_path(&installed)
        .args(["activate", "zsh", "--no-hook-env"])
        .output()
        .unwrap();
    assert_ok(&output);
    let script = stdout(&output);
    let project = workspace.project.path().display().to_string();
    let program = format!("{script}\ncd {project}\n_ggshield_hook\nprint -r -- \"v=[$API_KEY]\"\n");
    let shell_output = workspace.shell("zsh", &program);
    assert!(
        stdout(&shell_output).contains("v=[fake-spaced-path-value]"),
        "stdout: {}\nstderr: {}",
        stdout(&shell_output),
        stderr(&shell_output)
    );
    assert!(
        !stderr(&shell_output).contains("not found"),
        "{}",
        stderr(&shell_output)
    );
}

/// Finding 3: a `.env` in a repository you cloned could run code in your
/// interactive shell rather than merely set variables. The shadow guard was
/// "already exported", and `PROMPT_COMMAND`, `PS1`, `BASH_ENV`, `LD_PRELOAD`
/// and the rest are normally *not* exported — so the file's value won, and the
/// shell executed it. Quoting is beside the point: the value is well-formed
/// data that something else has agreed to run.
#[test]
fn a_dotenv_cannot_change_how_the_shell_runs_commands() {
    if !has_shell("bash") {
        return;
    }
    if !has_shell("zsh") {
        return;
    }
    let canary = std::env::temp_dir().join("gitguardian-hook-control-canary");
    let _ = std::fs::remove_file(&canary);

    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        &format!(
            "PROMPT_COMMAND=touch {}\nPS1=hacked\nBASH_ENV=/tmp/evil.sh\n\
             LD_PRELOAD=/tmp/evil.so\nGIT_SSH_COMMAND=id\nAPI_KEY=fine\n",
            canary.display()
        ),
    );
    workspace.trust_project();

    let output = workspace.run(&["hook-env", "bash"]);
    assert_ok(&output);
    let block = stdout(&output);
    // The ordinary variable is still loaded.
    assert!(block.contains("export API_KEY='fine'"), "{block}");
    for refused in [
        "PROMPT_COMMAND",
        "PS1",
        "BASH_ENV",
        "LD_PRELOAD",
        "GIT_SSH_COMMAND",
    ] {
        assert!(
            !block.contains(&format!("export {refused}=")),
            "{refused} was exported: {block}"
        );
    }
    // And the refusal is named, not silent.
    assert!(block.contains("refused to export"), "{block}");
    assert!(block.contains("PROMPT_COMMAND"), "{block}");

    // In a real bash: the hook's own registration survives, the file's value
    // never becomes the prompt command, and running the prompt command runs
    // nothing of the file's choosing.
    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "bash", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program = format!(
        "{script}\ncd {project}\n_ggshield_hook\n\
         printf 'pc=[%s]\\n' \"${{PROMPT_COMMAND:-}}\"\n\
         eval \"${{PROMPT_COMMAND:-}}\"\n\
         printf 'key=[%s]\\n' \"${{API_KEY:-}}\"\n"
    );
    let output = workspace.shell("bash", &program);
    let out = stdout(&output);
    assert!(out.contains("pc=[_ggshield_hook]"), "{out}");
    assert!(out.contains("key=[fine]"), "{out}");
    assert!(!canary.exists(), "a dotenv value was executed by the shell");

    // zsh's prompt is a variable too, and `prompt_subst` expands it.
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let program = format!(
        "{script}\nsetopt prompt_subst\ncd {project}\n_ggshield_hook\n\
         print -r -- \"ps1=[$PS1]\"\n"
    );
    let out = stdout(&workspace.shell("zsh", &program));
    assert!(!out.contains("ps1=[hacked]"), "{out}");
    let _ = std::fs::remove_file(&canary);
}

/// Finding 4: names read back out of `$__GITGUARDIAN_ACTIVE` were interpolated
/// raw into `unset {key};`, which the shell then evals. The state is an ordinary
/// environment variable, so anything that can write the environment — a
/// container's `ENV`, `ssh SendEnv`, `sudoers env_keep`, a shared profile
/// fragment — could put shell code there.
#[test]
fn a_forged_state_cannot_carry_shell_code_into_the_block() {
    if !has_shell("bash") {
        return;
    }
    let canary = std::env::temp_dir().join("gitguardian-hook-state-canary");
    let _ = std::fs::remove_file(&canary);

    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fine\n");
    workspace.trust_project();
    let directory = workspace.project.path();
    let keys = format!("EVIL; touch {}; :=1", canary.display());
    let forged = format!(
        "1.{}.{}.0.{}",
        hex(directory.as_os_str().as_encoded_bytes()),
        hex(directory.join(".env").as_os_str().as_encoded_bytes()),
        hex(keys.as_bytes())
    );

    let output = workspace.run_with(None, &[(STATE_VAR, &forged)], &["hook-env", "bash"]);
    assert_ok(&output);
    let block = stdout(&output);
    assert!(
        !block.contains("touch"),
        "the forged name reached the block: {block}"
    );
    // Refused as a whole, and said so, rather than half-read in silence.
    assert!(block.contains("cannot read"), "{block}");
    // The directory still loads: a bad state must not cost the user the feature.
    assert!(block.contains("export API_KEY='fine'"), "{block}");

    // And the block really is inert when a shell evaluates it.
    workspace.trust_project();
    workspace.shell("bash", &block);
    assert!(!canary.exists(), "the forged state executed a command");
    let _ = std::fs::remove_file(&canary);
}

/// Finding 4, the lesser variant: a state that claims exports the shell does
/// not have must not short-circuit the load. Otherwise a blob planted with a
/// matching fingerprint silently keeps a directory from ever loading.
#[test]
fn a_state_claiming_exports_that_are_gone_does_not_stop_a_reload() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-reload-value\n");
    workspace.trust_project();

    let first = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        first.contains("export API_KEY='fake-reload-value'"),
        "{first}"
    );
    let state = state_value(&first);

    // The same state, but nothing exported: the claim is not true any more.
    let output = workspace.run_with(None, &[(STATE_VAR, &state)], &["hook-env", "bash"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("export API_KEY='fake-reload-value'"),
        "a stale state stopped the reload: {}",
        stdout(&output)
    );

    // With the variable actually present and unchanged, the fast path engages
    // and the hook says and does nothing — which is what keeps a prompt cheap.
    let output = workspace.run_with(
        None,
        &[(STATE_VAR, &state), ("API_KEY", "fake-reload-value")],
        &["hook-env", "bash"],
    );
    assert_ok(&output);
    assert_eq!(stdout(&output), "", "the unchanged fast path did work");
}

/// Finding 8: the hook injects the user-scope layer but fingerprinted only the
/// project file, so rotating a machine-wide credential left every other shell
/// exporting the old value until its project file happened to change.
#[test]
fn the_hook_notices_a_rotated_user_scope_value() {
    let workspace = Workspace::new();
    let user_file = workspace.user_scope_file();
    std::fs::create_dir_all(user_file.parent().unwrap()).unwrap();
    std::fs::write(&user_file, "USER_WIDE=v1\n").unwrap();
    workspace.write_project(".env", "PROJECT_KEY=p\n");
    workspace.trust_project();

    let first = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(first.contains("export USER_WIDE='v1'"), "{first}");
    let state = state_value(&first);

    // Another shell rotates it.
    std::fs::write(&user_file, "USER_WIDE=v2-rotated\n").unwrap();

    let output = workspace.run_with(
        None,
        &[
            (STATE_VAR, &state),
            ("USER_WIDE", "v1"),
            ("PROJECT_KEY", "p"),
        ],
        &["hook-env", "bash"],
    );
    assert_ok(&output);
    let block = stdout(&output);
    assert!(
        block.contains("export USER_WIDE='v2-rotated'"),
        "the rotated machine-wide value was not picked up: {block}"
    );
}

/// Finding 9: "already set" meant `is_some()` here and
/// `is_some_and(|v| !v.is_empty())` in `run`, so `export API_KEY=` in a profile
/// made the hook keep the empty placeholder while `run` injected the real value.
/// The hook's own documentation says the rule is `run`'s.
#[test]
fn an_ambient_empty_variable_does_not_shadow_the_file() {
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-real-value\n");
    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program = format!(
        "{script}\nexport API_KEY=\ncd {project}\n_ggshield_hook\n\
         print -r -- \"v=[$API_KEY]\"\n"
    );
    let out = stdout(&workspace.shell("zsh", &program));
    assert!(out.contains("v=[fake-real-value]"), "{out}");

    // And `run` agrees, which is the whole point.
    let output = workspace.run_with(
        None,
        &[("API_KEY", "")],
        &["run", "--provider", "file", "--", "printenv", "API_KEY"],
    );
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "fake-real-value");
}

/// Finding 10b: the hook's output *is* assignments of decrypted values, so
/// `set -x` printed every one of them — at the `eval` in the hook function,
/// where nothing `hook-env` emits could suppress it. Only the generated
/// function can turn tracing off, and it has to put it back.
#[test]
fn shell_tracing_never_prints_a_decrypted_value() {
    const CANARY: &str = "fake-trace-canary";
    // The probe runs with tracing off again: the point is what the *hook* puts
    // in the trace, and a traced `printf "$API_KEY"` of the test's own would
    // print the value whatever the hook did.
    for (shell, trace_on, trace_off, restored, probe) in [
        (
            "bash",
            "set -x",
            "set +x",
            "set +x",
            "printf 'v=[%s]\\n' \"$API_KEY\"",
        ),
        (
            "zsh",
            "set -x",
            "set +x",
            "set +x",
            "print -r -- \"v=[$API_KEY]\"",
        ),
        (
            "fish",
            "set -g fish_trace 1",
            "set -e fish_trace",
            "fish_trace",
            "printf 'v=[%s]\\n' \"$API_KEY\"",
        ),
    ] {
        let workspace = Workspace::new();
        workspace.write_project(".env", &format!("API_KEY={CANARY}\n"));
        workspace.trust_project();
        let script = stdout(&workspace.run(&["activate", shell, "--no-hook-env"]));
        let project = workspace.project.path().display().to_string();
        let program =
            format!("{script}\n{trace_on}\ncd {project}\n_ggshield_hook\n{trace_off}\n{probe}\n");
        if !has_shell(shell) {
            continue;
        }
        let output = workspace.shell(shell, &program);

        assert!(
            stdout(&output).contains(&format!("v=[{CANARY}]")),
            "{shell} did not load the value: {}\n{}",
            stdout(&output),
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains(CANARY),
            "{shell} traced the decrypted value:\n{}",
            stderr(&output)
        );
        // Tracing came back on after the hook returned: the mitigation is a
        // save/restore, not a way to quietly turn the user's tracing off.
        assert!(
            stderr(&output).contains(restored),
            "{shell} left tracing off:\n{}",
            stderr(&output)
        );
    }
}

/// Finding 13: `PROMPT_COMMAND` ending in `;` is the recommended idiom — macOS's
/// own `/etc/bashrc_Apple_Terminal` documents it — and appending `;<hook>` to it
/// produced `;;`. bash then reported a syntax error before every prompt and no
/// secret was ever loaded, with nothing in the message naming gitguardian.
#[test]
fn a_prompt_command_ending_in_a_separator_still_installs_the_hook() {
    if !has_shell("bash") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-prompt-value\n");
    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "bash", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();

    for existing in ["true;", "true; ", "true", ""] {
        let program = format!(
            "PROMPT_COMMAND='{existing}'\n{script}\n\
             printf 'pc=[%s]\\n' \"${{PROMPT_COMMAND:-}}\"\n\
             cd {project}\n_ggshield_hook\n\
             printf 'v=[%s]\\n' \"${{API_KEY:-}}\"\n\
             eval \"${{PROMPT_COMMAND:-}}\"\n"
        );
        let output = workspace.shell("bash", &program);
        let out = stdout(&output);
        assert!(out.contains("v=[fake-prompt-value]"), "{existing:?}: {out}");
        assert!(
            !out.contains(";;"),
            "{existing:?} produced a doubled separator: {out}"
        );
        assert!(
            !stderr(&output).contains("syntax error"),
            "{existing:?}: {}",
            stderr(&output)
        );
    }
}

/// Finding 14: the "stop at `$HOME`" boundary compared a literal `$HOME` against
/// a canonicalised cwd, so any symlink on the way to the home directory — `/tmp`
/// on macOS being the everyday one — made the comparison never match and let the
/// walk run to `/`, loading exactly the stray ancestor file the boundary exists
/// to stop.
///
/// Finding 15: and `GITGUARDIAN_SHELL_OUTPUT=debug`, which the help advertises,
/// is what explains it.
#[cfg(unix)]
#[test]
fn the_home_boundary_holds_when_home_is_reached_through_a_symlink() {
    let workspace = Workspace::new();
    let root = workspace.project.path();
    let real_home = root.join("ggh/home");
    let deep = real_home.join("proj/deep");
    std::fs::create_dir_all(&deep).unwrap();
    // A stray file one level above the home directory.
    std::fs::write(root.join("ggh/.env"), "STRAY=stray-value\n").unwrap();
    let link = root.join("home-link");
    std::os::unix::fs::symlink(&real_home, &link).unwrap();

    let output = workspace.run_with(
        Some(&deep),
        &[
            ("HOME", link.to_str().unwrap()),
            ("GITGUARDIAN_SHELL_OUTPUT", "debug"),
        ],
        &["hook-env", "bash"],
    );
    assert_ok(&output);
    let block = stdout(&output);
    assert!(
        !block.contains("STRAY"),
        "the walk ran past the home directory: {block}"
    );
    assert!(
        block.contains("stopped at the home directory"),
        "debug output did not explain it: {block}"
    );
}

/// Finding 15: `=debug` is documented in `activate`'s long help and had no
/// implementation at all, so the exact cases a user would want explained
/// produced no output at any level.
#[test]
fn debug_output_explains_why_nothing_was_loaded() {
    let workspace = Workspace::new();

    let output = workspace.run_with(
        None,
        &[("GITGUARDIAN_SHELL_OUTPUT", "debug")],
        &["hook-env", "bash"],
    );
    assert_ok(&output);
    assert!(
        stdout(&output).contains("no dotenv file"),
        "{}",
        stdout(&output)
    );

    // The default level and `=none` both stay silent, which is why `debug` had
    // to exist.
    for level in [None, Some("none"), Some("normal")] {
        let env: Vec<(&str, &str)> = level
            .map(|level| vec![("GITGUARDIAN_SHELL_OUTPUT", level)])
            .unwrap_or_default();
        let output = workspace.run_with(None, &env, &["hook-env", "bash"]);
        assert_ok(&output);
        assert_eq!(stdout(&output), "", "{level:?}");
    }
}

/// Finding 18: `--hook none` installed no new trigger but also failed to remove
/// an existing one, so after `eval "$(gitguardian activate zsh)"` a later
/// `--hook none` left directories loading secrets — the opposite of the flag.
///
/// Round-3 finding 26h: the old test inspected a freshly generated string, which
/// cannot fail on a *transition*.
#[test]
fn hook_none_unregisters_a_hook_that_was_already_installed() {
    if !has_shell("bash") {
        return;
    }
    if !has_shell("fish") {
        return;
    }
    if !has_shell("zsh") {
        return;
    }
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-unregister-value\n");
    let project = workspace.project.path().display().to_string();

    // zsh: the registration lives in an array the snippet can be seen editing.
    let installed = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let disabled = stdout(&workspace.run(&["activate", "zsh", "--hook", "none"]));
    let program = format!(
        "{installed}\n{disabled}\ncd {project}\n\
         print -r -- \"funcs=[$chpwd_functions $precmd_functions]\"\n\
         print -r -- \"v=[$API_KEY]\"\n"
    );
    let out = stdout(&workspace.shell("zsh", &program));
    assert!(!out.contains("funcs=[_ggshield_hook"), "{out}");
    assert!(out.contains("v=[]"), "the hook still fired: {out}");

    // fish: the trigger is a function with an event binding.
    let installed = stdout(&workspace.run(&["activate", "fish", "--no-hook-env"]));
    let disabled = stdout(&workspace.run(&["activate", "fish", "--hook", "none"]));
    let program = format!(
        "{installed}\n{disabled}\ncd {project}\n\
         printf 'trigger=[%s]\\n' (functions -q _ggshield_hook_trigger; \
         and echo yes; or echo no)\n\
         printf 'v=[%s]\\n' \"$API_KEY\"\n"
    );
    let output = workspace.shell("fish", &program);
    let out = stdout(&output);
    assert!(out.contains("trigger=[no]"), "{out}\n{}", stderr(&output));
    assert!(out.contains("v=[]"), "the hook still fired: {out}");

    // bash: the registration is a word in PROMPT_COMMAND.
    let installed = stdout(&workspace.run(&["activate", "bash", "--no-hook-env"]));
    let disabled = stdout(&workspace.run(&["activate", "bash", "--hook", "none"]));
    let program =
        format!("{installed}\n{disabled}\nprintf 'pc=[%s]\\n' \"${{PROMPT_COMMAND:-}}\"\n");
    let out = stdout(&workspace.shell("bash", &program));
    assert!(out.contains("pc=[]"), "{out}");
}

/// Finding 22: `set` validated the name it was given and not the value it just
/// read, so a NUL byte was sealed into perfectly good ciphertext and reported as
/// stored — after which nothing could ever inject it, because neither `run` nor
/// the shell hook can put a NUL in an environment.
#[test]
fn set_refuses_a_value_containing_a_nul() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(
        &["set", "--provider", "file", "--yes", "BAD"],
        "before\0after\n",
    );
    assert!(
        !output.status.success(),
        "a value nothing can inject was stored: {}",
        stderr(&output)
    );
    let message = stderr(&output);
    assert!(message.contains("BAD"), "{message}");
    assert!(message.contains("NUL"), "{message}");
    assert!(!message.contains("after"), "the value leaked: {message}");
    assert!(!workspace.project_file(".env").exists());
}

/// The gate itself: a `.env` you have not read does not reach your shell.
///
/// This is the direct answer to the finding that a cloned repository's dotenv
/// file executed code before the user had seen a line of it. Even with the
/// shell-control denylist in place, an untrusted file should load nothing at
/// all — the denylist is the second layer, not the first.
#[test]
fn an_untrusted_dotenv_loads_nothing_until_it_is_trusted() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");

    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        !block.contains("API_KEY"),
        "loaded without consent: {block}"
    );
    assert!(
        block.contains("not trusted"),
        "no explanation given: {block}"
    );
    assert!(
        block.contains("ggshield secret trust"),
        "no remedy named: {block}"
    );

    workspace.trust_project();
    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        block.contains("export API_KEY='fake-gated-value'"),
        "{block}"
    );
}

/// Trust covers the contents, not the name. A line pushed after you approved
/// the file does not inherit that approval — this is what stops "trust it once
/// on clone" from being a permanent bypass.
#[test]
fn editing_a_trusted_dotenv_revokes_its_approval() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");
    workspace.trust_project();
    assert!(stdout(&workspace.run(&["hook-env", "bash"])).contains("API_KEY"));

    // The upstream commit an attacker would push.
    workspace.write_project(
        ".env",
        "API_KEY=fake-gated-value\nPROMPT_COMMAND=touch /tmp/gg-trust-bypass\n",
    );
    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(block.contains("not trusted"), "edit kept approval: {block}");
    assert!(!block.contains("API_KEY"), "{block}");
    assert!(!block.contains("PROMPT_COMMAND=touch"), "{block}");

    // Reverting to the approved bytes does not silently restore approval,
    // because the entry was replaced rather than accumulated.
    workspace.trust_project();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");
    assert!(
        stdout(&workspace.run(&["hook-env", "bash"])).contains("not trusted"),
        "an old digest came back"
    );
}

/// `trust --revoke` and `--list` are the other half of the story.
#[test]
fn trust_can_be_listed_and_revoked() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");

    assert!(
        stderr(&workspace.run(&["trust", "--list"])).contains("no dotenv files are trusted"),
        "empty listing not reported"
    );
    workspace.trust_project();
    assert!(stdout(&workspace.run(&["trust", "--list"])).contains(".env"));

    let output = workspace.run(&["trust", "--revoke"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("no longer trusted"),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&workspace.run(&["hook-env", "bash"])).contains("not trusted"));
    // Revoking twice is not an error, it just says nothing changed.
    assert!(stderr(&workspace.run(&["trust", "--revoke"])).contains("was not trusted"));
}

/// The gate is only for implicit loading. Naming a file on the command line is
/// itself the consent, so `get` and `run` must not require trust — otherwise
/// every scripted use would break.
#[test]
fn get_and_run_are_not_gated_by_trust() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-ungated-value\n");

    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "fake-ungated-value");

    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "API_KEY"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "fake-ungated-value");
}
