//! End-to-end tests that run the store verbs through the real binary. All values are fake.
//!
//! Built with `test-keystore`: `$GITGUARDIAN_TEST_KEYSET_FILE` stands in for the OS keyring.

// A failed unwrap is a failed assertion; the workspace lint targets shipped code.
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
    fn command(&self) -> Command {
        self.prepare(Command::cargo_bin("ggshield").expect("ggshield binary"))
    }

    fn command_at_path(&self, program: &Path) -> Command {
        self.prepare(Command::new(program))
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
            .env_remove("VAULT_ADDR");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(cli_args(args)).output().unwrap()
    }

    /// `run`, from another directory and/or with extra environment.
    fn run_with(&self, directory: Option<&Path>, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut command = self.command();
        if let Some(directory) = directory {
            command.current_dir(directory);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        command.args(cli_args(args)).output().unwrap()
    }

    /// `set`, answering the value prompt on stdin.
    fn set(&self, args: &[&str], value: &str) -> Output {
        let mut child = self
            .command()
            .args(cli_args(args))
            // `--expose` reads the value from stdin instead of the terminal.
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        feed(&mut child, format!("{value}\n").as_bytes());
        child.wait_with_output().unwrap()
    }

    /// `set`, writing `stdin` verbatim (no trailing newline added).
    fn set_with_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .command()
            .args(cli_args(args))
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        feed(&mut child, input.as_bytes());
        child.wait_with_output().unwrap()
    }

    /// Start a `set` without waiting for it, so two can be in flight at once.
    fn spawn_set(&self, args: &[&str], value: &str) -> std::process::Child {
        let mut child = self
            .command()
            .args(cli_args(args))
            .arg("--expose")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        feed(&mut child, format!("{value}\n").as_bytes());
        child
    }

    fn trust_project(&self) {
        let output = self.run(&["trust"]);
        assert!(output.status.success(), "trust failed: {}", stderr(&output));
    }

    #[cfg(unix)]
    fn trust_file(&self, path: &std::path::Path) {
        let output = self.run(&["trust", "--path", &path.display().to_string()]);
        assert!(output.status.success(), "trust failed: {}", stderr(&output));
    }

    /// Run `program` in a real `shell`, in this workspace's environment.
    fn shell(&self, shell: &str, program: &str) -> Output {
        let mut command = Command::new(shell);
        // The developer's rc files must not change what the hook sees.
        match shell {
            "zsh" => {
                command.arg("-f");
            }
            "bash" => {
                command.arg("--norc").arg("--noprofile");
            }
            // fish reads its own config even for `-c`.
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
            .env_remove("VAULT_ADDR");
        command.output().unwrap()
    }

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

/// Whether `shell` can run here. A missing shell is skipped locally and fatal
/// under `$GITGUARDIAN_REQUIRE_SHELLS`, which CI sets.
fn has_shell(shell: &str) -> bool {
    let found = Command::new(shell)
        .arg("-c")
        .arg("exit 0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        // Windows runners resolve `bash` to the WSL launcher, which exits non-zero with no distro.
        .is_ok_and(|status| status.success());
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

/// Store verbs live under `ggshield secret`; `run`, `activate` and `trust` are top level.
fn cli_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    match args.first() {
        Some(verb) if ggshield_secrets_cli::SECRET_VERBS.contains(verb) => {
            std::iter::once("secret")
                .chain(args.iter().copied())
                .collect()
        }
        _ => args.to_vec(),
    }
}

/// A command that fails before reading its input closes the pipe; that is not a test failure.
fn feed(child: &mut std::process::Child, input: &[u8]) {
    use std::io::Write;
    match child.stdin.as_mut().unwrap().write_all(input) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        result => result.unwrap(),
    }
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
        &["set", "--provider", "file", "--global", "SHARED_KEY"],
        FAKE_VALUE,
    ));
    let user_file = workspace.user_scope_file();
    assert!(user_file.exists(), "{user_file:?} should exist");
    assert!(
        std::fs::read_to_string(&user_file)
            .unwrap()
            .contains("gitguardian:")
    );

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
            "--global",
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

    // Print only the variables under test: the inherited CI env can name credentials.
    let output = workspace
        .command()
        .env("VAULT_TOKEN", "fake-vault-token")
        .env("VAULT_TOKEN_FILE_PATH", "/tmp/fake-token-path")
        .args([
            "run",
            "--provider",
            "file",
            "--",
            "sh",
            "-c",
            r#"for name in VAULT_TOKEN VAULT_TOKEN_FILE_PATH SHARED_KEY; do
                 eval "value=\${$name-<unset>}"
                 echo "$name=[$value]"
               done"#,
        ])
        .output()
        .unwrap();
    assert_ok(&output);
    let reported = stdout(&output);
    for name in ["VAULT_TOKEN", "VAULT_TOKEN_FILE_PATH"] {
        assert!(
            reported.contains(&format!("{name}=[<unset>]")),
            "{name} reached the child:\n{reported}"
        );
    }
    assert!(reported.contains("SHARED_KEY=[value]"), "{reported}");
}

#[test]
fn get_pipes_the_value_when_stdout_is_not_a_terminal() {
    // stdout here is a pipe, so `get` exposes.
    let workspace = Workspace::new();
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--plain", "SHARED_KEY"],
        "value",
    ));
    let output = workspace.run(&["get", "--provider", "file"]);
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "SHARED_KEY=value");
}

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
    // SAFETY: `openpty` fills both descriptors and accepts null for the optional out-parameters.
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
    // SAFETY: both descriptors were just created by `openpty` and are owned by nothing else.
    let (controller, terminal) = unsafe {
        (
            OwnedFd::from_raw_fd(controller),
            OwnedFd::from_raw_fd(terminal),
        )
    };

    let mut child = workspace
        .command()
        .args(["secret", "get", "--provider", "file"])
        .stdout(terminal.try_clone().unwrap())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // The writing end must be closed here, or the reader below never finishes.
    drop(terminal);
    // Read while the child runs: once the last writer is gone the controller reports EIO.
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
    assert!(message.contains("API_KEY"), "{message}");
}

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

    // Another machine with its own keyset, so the failure is "wrong key", not "no key".
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

    // Byte for byte, missing final newline included: API_KEY was not re-encrypted.
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

#[cfg(unix)]
#[test]
fn a_symlinked_dotenv_names_the_operation_it_refused() {
    let workspace = Workspace::new();
    let real = workspace.project_file("real.env");
    std::fs::write(&real, "KEY=1\n").unwrap();
    std::os::unix::fs::symlink(&real, workspace.project_file(".env")).unwrap();

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

    // Without `--yes` the overwrite pre-check reads first, and is refused as a read.
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

#[test]
fn import_preserves_the_documents_comments_and_order() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# first\nA=1\n# second\nB=2\n");
    workspace.write_project("incoming.env", "B=two\nC=three\n");

    let output = workspace.run(&[
        "import",
        "--provider",
        "file",
        "--project",
        "--plain",
        "--yes",
        workspace.project_file("incoming.env").to_str().unwrap(),
    ]);
    assert_ok(&output);

    let written = workspace.read_project(".env");
    assert!(
        written.starts_with("# first\nA=1\n# second\nB=two\n"),
        "{written}"
    );
    assert!(written.contains("C=three"), "{written}");
}

#[test]
fn del_removes_a_variable_and_keeps_the_rest_of_the_file() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# keep me\nPORT=3000\n\nSTALE=old\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "STALE"]);
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

#[test]
fn del_removes_an_encrypted_value_without_exposing_it() {
    let workspace = Workspace::new();
    let set = workspace.set(&["set", "--provider", "file", "TOKEN"], FAKE_VALUE);
    assert_ok(&set);

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(!stderr(&output).contains(FAKE_VALUE), "{}", stderr(&output));
    assert!(!stdout(&output).contains(FAKE_VALUE), "{}", stdout(&output));
    assert_eq!(workspace.read_project(".env"), "");
}

#[test]
fn del_removes_a_value_this_device_cannot_read() {
    let workspace = Workspace::new();
    let set = workspace.set(&["set", "--provider", "file", "THEIRS"], FAKE_VALUE);
    assert_ok(&set);
    // A different machine: same file, no key for it.
    std::fs::remove_file(workspace.home.path().join("keyset.json")).unwrap();

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "THEIRS"]);
    assert_ok(&output);
    assert_eq!(workspace.read_project(".env"), "");
}

#[test]
fn del_names_a_variable_the_file_does_not_set() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "KEEP=here\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "NEVER_SET"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(".env does not set NEVER_SET"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "KEEP=here\n");
}

#[test]
fn del_does_not_reach_into_the_user_scope_file() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--global", "USER_ONLY"],
        FAKE_VALUE,
    );
    assert_ok(&set);
    workspace.write_project(".env", "KEEP=here\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "USER_ONLY"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("does not set USER_ONLY"),
        "{}",
        stderr(&output)
    );
    let get = workspace.run(&["get", "--provider", "file", "--field", "USER_ONLY"]);
    assert_ok(&get);
    assert!(stdout(&get).contains(FAKE_VALUE), "{}", stdout(&get));
}

#[test]
fn del_says_when_a_user_scope_value_is_left_showing_through() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--global", "TOKEN"],
        "user-scope-fake",
    );
    assert_ok(&set);
    let set = workspace.set(&["set", "--provider", "file", "TOKEN"], "project-fake");
    assert_ok(&set);

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("still set by the user-scope file"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("--global"), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("user-scope-fake"),
        "{}",
        stderr(&output)
    );
    let get = workspace.run(&["get", "--provider", "file", "--field", "TOKEN", "--expose"]);
    assert_ok(&get);
    assert!(stdout(&get).contains("user-scope-fake"), "{}", stdout(&get));
}

#[test]
fn del_says_nothing_about_the_user_scope_when_nothing_shows_through() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=only-here\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "TOKEN"]);
    assert_ok(&output);
    assert!(
        !stderr(&output).contains("user-scope"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn del_scope_user_edits_the_user_file() {
    let workspace = Workspace::new();
    let set = workspace.set(
        &["set", "--provider", "file", "--global", "USER_ONLY"],
        FAKE_VALUE,
    );
    assert_ok(&set);

    let output = workspace.run(&[
        "unset",
        "--provider",
        "file",
        "--global",
        "--yes",
        "USER_ONLY",
    ]);
    assert_ok(&output);
    assert_eq!(
        std::fs::read_to_string(workspace.user_scope_file()).unwrap(),
        ""
    );
}

#[test]
fn del_all_removes_every_variable_but_keeps_the_file() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# a note\nPORT=3000\n\nTOKEN=abc\n");

    let output = workspace.run(&["unset", "--provider", "file", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("PORT") && stderr(&output).contains("TOKEN"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "# a note\n\n");
}

#[test]
fn del_all_on_a_file_that_sets_nothing_is_not_an_error() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "# only a comment\n");

    let output = workspace.run(&["unset", "--provider", "file", "--all", "--yes"]);
    assert_ok(&output);
    assert!(
        stderr(&output).contains("nothing to delete"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "# only a comment\n");
}

#[test]
fn del_all_on_a_missing_file_is_an_error_not_an_empty_success() {
    let workspace = Workspace::new();

    let output = workspace.run(&[
        "unset",
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

#[test]
fn del_refuses_an_entry_that_swallowed_other_assignments() {
    let workspace = Workspace::new();
    let original = "A=\"oops\nB=keepme\nc=fine\"\nD=keep\n";
    workspace.write_project(".env", original);

    for args in [
        vec!["unset", "--provider", "file", "--yes", "A"],
        vec!["unset", "--provider", "file", "--all", "--yes"],
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

#[test]
fn del_removes_a_multiline_value() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw==\n-----END PRIVATE KEY-----\"\nKEEP=1\n",
    );

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "PRIVATE_KEY"]);
    assert_ok(&output);
    assert_eq!(workspace.read_project(".env"), "KEEP=1\n");
}

#[test]
fn del_keeps_an_inline_comment_and_says_so() {
    let workspace = Workspace::new();
    workspace.write_project(
        ".env",
        "API_KEY=abc # obtain from the break-glass owner\nKEEP=1\n",
    );

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "API_KEY"]);
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

#[test]
fn del_names_a_quote_problem_rather_than_calling_the_variable_unset() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY='super'password\nKEEP=1\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "API_KEY"]);
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
    let encrypt = workspace.run(&["encrypt", "--yes", "KEEP"]);
    assert!(
        stderr(&encrypt).contains("fix line 1"),
        "{}",
        stderr(&encrypt)
    );
}

/// A repeated name is not reported as a concurrent writer, nor counted twice.
#[test]
fn del_deduplicates_a_repeated_name() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "A_KEY=1\nB_KEY=2\n");

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "A_KEY", "A_KEY"]);
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

#[test]
fn del_needs_yes_when_stdin_is_not_a_terminal() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=abc\n");

    let output = workspace.run(&["unset", "--provider", "file", "TOKEN"]);
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

#[test]
fn del_on_a_missing_file_creates_nothing() {
    let workspace = Workspace::new();

    let output = workspace.run(&["unset", "--provider", "file", "--yes", "ANY"]);
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
        "--global",
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

#[test]
fn no_key_material_is_ever_written_next_to_the_secrets() {
    let workspace = Workspace::new();
    assert_ok(&workspace.set(&["set", "--provider", "file", "API_KEY"], FAKE_VALUE));
    assert_ok(&workspace.set(
        &["set", "--provider", "file", "--global", "USER_KEY"],
        FAKE_VALUE,
    ));

    let names = std::fs::read_dir(workspace.project.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, vec![".env".to_string()], "{names:?}");

    // The keyring stand-in is the whole master key in cleartext.
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

    // The lock is scoped to the store it guards, which here is the keyset file.
    let lock = workspace.home.path().join("keyset.json.lock");
    assert!(lock.exists(), "the keyset lock was never taken");
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

#[test]
fn set_refuses_when_fewer_lines_are_piped_than_fields() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(
        &["set", "--provider", "file", "--plain", "--yes", "A", "B"],
        "only-one\n",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("'B'"), "{}", stderr(&output));
    assert!(!workspace.project_file(".env").exists());
}

#[test]
fn set_refuses_an_end_of_file_value_for_a_new_key_without_yes() {
    let workspace = Workspace::new();
    let output = workspace.set_with_stdin(&["set", "--provider", "file", "NEWKEY"], "");
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(!workspace.project_file(".env").exists());
}

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

    // `run` is stricter: see `run_refuses_to_inject_a_partially_readable_file`.
    let output = workspace.run(&["run", "--provider", "file", "--", "printenv", "DEBUG"]);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(stderr(&output).contains("BAD"), "{}", stderr(&output));

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
    // The device key is gone, so `SEALED` can no longer be opened here.
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
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert!(!message.contains(FAKE_VALUE), "{message}");

    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("PLAIN=readable"),
        "{}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("SEALED"), "{}", stderr(&output));
}

#[test]
fn asking_for_the_unreadable_field_still_fails() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "DEBUG=true\nBAD=gitguardian:!!!nope!!!\n");
    let output = workspace.run(&["get", "--provider", "file", "--field", "BAD"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("BAD"), "{}", stderr(&output));
}

#[test]
fn a_plaintext_value_that_looks_like_a_marker_is_refused() {
    let workspace = Workspace::new();
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "TOKEN"],
        "encrypted:whatever",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("TOKEN"), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("encrypted:whatever"),
        "the value leaked: {}",
        stderr(&output)
    );
    assert!(!workspace.project_file(".env").exists());
}

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

#[test]
fn the_test_keystore_requires_an_explicit_acknowledgement() {
    let workspace = Workspace::new();
    // A real value on stdin, so the command gets as far as the keystore.
    let mut child = workspace
        .command()
        .env_remove("GITGUARDIAN_TEST_KEYSET_INSECURE_ACK")
        .args([
            "secret",
            "set",
            "--provider",
            "file",
            "--yes",
            "--expose",
            "API_KEY",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    feed(&mut child, format!("{FAKE_VALUE}\n").as_bytes());
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success(), "{}", stderr(&output));
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

/// Hand-made look-alikes survive, and what is deleted is reported.
#[test]
fn a_leftover_temporary_file_is_collected_by_the_next_write() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "A=1\n");
    // The exact shape this writer generates.
    let generated = ".env.gitguardian-a1b2c3d4e5f6g7h8i9j0k1.tmp";
    let leftover = workspace.project_file(generated);
    std::fs::write(&leftover, "A=1\nSECRET=plaintext-from-a-killed-run\n").unwrap();
    // Look-alikes a person could create by hand, each holding the only copy of a value.
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
    assert!(
        stderr(&output).contains(generated),
        "the deletion was not reported: {}",
        stderr(&output)
    );
}

#[test]
fn a_swallowed_variable_is_reported_on_every_read() {
    let workspace = Workspace::new();
    // Balanced quotes: `NOTE` has swallowed `API_KEY`, yet a quote count says the file is fine.
    workspace.write_project(".env", "NOTE=\"oops\nAPI_KEY=abc\nOTHER=\"\n");

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
        // The name found inside the value is a fragment of it, and this lands in CI logs.
        assert!(
            !message.contains("API_KEY"),
            "{args:?} echoed a fragment of the value: {message}"
        );
    }

    let output = workspace.run(&["get", "--provider", "file", "--field", "API_KEY"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("stray quote"), "{message}");
    assert!(message.contains("field not found"), "{message}");

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

    // `run` succeeds by design (the heuristic can misfire on a PEM), so API_KEY is absent.
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
    assert!(out.contains("PEM='-----BEGIN X-----"), "{out}");
    assert!(out.contains("-----END X-----'"), "{out}");
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("PEM=") || line.starts_with("PORT="))
            .count(),
        2,
        "{out}"
    );
    assert!(out.contains("PORT=3000"), "{out}");

    // `--field` prints the raw value, so command substitution stays usable.
    let output = workspace.run(&["get", "--provider", "file", "--field", "PEM", "--expose"]);
    assert_ok(&output);
    assert!(
        stdout(&output).starts_with("-----BEGIN X-----"),
        "{}",
        stdout(&output)
    );
}

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
    assert!(!marker.contains('#'), "{contents}");

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
    assert!(
        stderr(&output).contains("assigned 2 times"),
        "{}",
        stderr(&output)
    );
}

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
    assert!(
        contents.contains("PORT=3000   # stays readable"),
        "{contents}"
    );

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

#[test]
fn encrypt_refuses_to_guess_what_is_secret() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "PORT=3000\nTOKEN=abc\n");

    let output = workspace.run(&["encrypt", "--yes"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--all"), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), "PORT=3000\nTOKEN=abc\n");

    let output = workspace.run(&["encrypt", "--yes", "TOKEM"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("TOKEM"), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), "PORT=3000\nTOKEN=abc\n");
}

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
    assert!(
        after_first.contains("FOREIGN=encrypted:dotenvx"),
        "{after_first}"
    );
}

#[test]
fn encrypt_needs_yes_when_stdin_is_not_a_terminal() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "TOKEN=abc\n");
    let output = workspace.run(&["encrypt", "TOKEN"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--yes"), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), "TOKEN=abc\n");
}

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

#[test]
fn encrypt_yes_on_a_file_with_nothing_to_encrypt_mints_no_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");
    // The only entry is another tool's marker, so there is nothing to encrypt.
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
    assert!(!message.contains("running printenv"), "{message}");
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
}

#[test]
fn an_encrypt_preview_that_is_declined_mints_no_key() {
    let workspace = Workspace::new();
    let keyset = workspace.home.path().join("keyset.json");
    workspace.write_project(".env", "API_KEY=plaintext-fake\n");

    // No `--yes` and stdin is not a terminal, so this stops at the confirmation.
    let output = workspace.run(&["encrypt", "--all"]);
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("API_KEY"), "{}", stderr(&output));
    assert!(
        !keyset.exists(),
        "a declined preview minted the device key: {}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), "API_KEY=plaintext-fake\n");
}

/// An encrypted `.env` and no keyset, so any read or key lookup would leave a trace.
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
            script.contains(&format!("hook-env {shell}")),
            "{shell}: {script}"
        );
        assert_eq!(stderr(&output), "", "{shell}");
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

#[test]
fn the_provider_defaults_to_file() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-default-value\n");
    let output = workspace.run(&["list"]);
    assert_ok(&output);
    assert_eq!(stdout(&output), "API_KEY\n");
}

#[test]
fn the_provider_default_comes_from_gitguardian_yaml() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-default-value\n");
    workspace.write_project(
        ".gitguardian.yaml",
        "version: 2\nsecret:\n  provider: vault\n",
    );
    let output = workspace.run(&["list"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("--path is required for provider 'vault'"),
        "{}",
        stderr(&output)
    );

    let output = workspace.run(&["list", "--provider", "file"]);
    assert_ok(&output);

    workspace.write_project(
        ".gitguardian.yaml",
        "version: 2\nsecret:\n  provider: onepassword\n",
    );
    let output = workspace.run(&["list"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("expected one of: file, vault"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn list_prints_names_without_values() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-list-value\nPORT=3000\n");
    let output = workspace.run(&["list", "--provider", "file", "--show-scope"]);
    assert_ok(&output);
    assert_eq!(stdout(&output), "API_KEY  # project\nPORT  # project\n");

    let output = workspace.run(&["list", "--provider", "file", "--project"]);
    assert_ok(&output);
    assert_eq!(stdout(&output), "API_KEY\nPORT\n");
}

#[test]
fn activate_without_a_shell_falls_back_to_the_login_shell() {
    let workspace = Workspace::new();
    let output = workspace
        .command()
        .env("SHELL", "/bin/zsh")
        .args(["activate", "--no-hook-env"])
        .output()
        .unwrap();
    assert_ok(&output);
    assert!(
        stdout(&output).contains("hook-env zsh"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn activate_without_a_recognisable_shell_asks_for_one() {
    let workspace = Workspace::new();
    let output = workspace
        .command()
        .env("SHELL", "/bin/sh")
        .args(["activate"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("activate bash|zsh|fish"),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
}

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
    assert!(text.contains("sub=[fake-hook-value]"), "{text}");
    assert!(text.contains("out=[]"), "{text}");
}

#[test]
fn a_hostile_value_cannot_escape_its_assignment_in_any_shell() {
    let canary = std::env::temp_dir().join("gitguardian-hook-injection-canary");
    let _ = std::fs::remove_file(&canary);
    let hostile = format!("x'; touch {}; echo '", canary.display());

    // fish has no `-c` equivalent of sourcing a block, so it needs its own probe.
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
    assert!(text.contains("left=[set-by-hand]"), "{text}");
    assert!(text.contains("back=[set-by-hand]"), "{text}");
    assert!(text.contains("other=[]"), "{text}");
}

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

    let output = workspace.run(&["encrypt", "--yes", "PRIVATE_KEY"]);
    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("encrypted 1"),
        "{}",
        stderr(&output)
    );
    assert_eq!(workspace.read_project(".env"), source);

    let workspace = Workspace::new();
    workspace.write_project(".env", source);
    let output = workspace.set(
        &["set", "--provider", "file", "--plain", "--yes", "OTHER"],
        "v",
    );
    assert!(!output.status.success(), "{}", stderr(&output));
    assert_eq!(workspace.read_project(".env"), source);
    assert!(workspace.read_project(".env").contains("SECRETTAIL"));
}

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
    // The key this was sealed with is not on this device.
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
    // The state still records the file, so the failure is reported only once.
    assert!(block.contains(&format!("export {STATE_VAR}=")), "{block}");

    workspace.trust_project();
    let script = stdout(&workspace.run(&["activate", "zsh", "--no-hook-env"]));
    let project = workspace.project.path().display().to_string();
    let program =
        format!("{script}\ncd {project}\n_ggshield_hook\nprint -r -- \"plain=[$PLAIN]\"\n");
    let output = workspace.shell("zsh", &program);
    assert!(stdout(&output).contains("plain=[]"), "{}", stdout(&output));
    assert!(stderr(&output).contains("SEALED"), "{}", stderr(&output));
}

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

    // Without the link, the parent's file is exactly what would have loaded.
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
    assert!(block.contains("refused to export"), "{block}");
    assert!(block.contains("PROMPT_COMMAND"), "{block}");

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
    assert!(block.contains("cannot read"), "{block}");
    assert!(block.contains("export API_KEY='fine'"), "{block}");

    workspace.trust_project();
    workspace.shell("bash", &block);
    assert!(!canary.exists(), "the forged state executed a command");
    let _ = std::fs::remove_file(&canary);
}

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

    let output = workspace.run_with(None, &[(STATE_VAR, &state)], &["hook-env", "bash"]);
    assert_ok(&output);
    assert!(
        stdout(&output).contains("export API_KEY='fake-reload-value'"),
        "a stale state stopped the reload: {}",
        stdout(&output)
    );

    let output = workspace.run_with(
        None,
        &[(STATE_VAR, &state), ("API_KEY", "fake-reload-value")],
        &["hook-env", "bash"],
    );
    assert_ok(&output);
    assert_eq!(stdout(&output), "", "the unchanged fast path did work");
}

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

    let output = workspace.run_with(
        None,
        &[("API_KEY", "")],
        &["run", "--provider", "file", "--", "printenv", "API_KEY"],
    );
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "fake-real-value");
}

#[test]
fn shell_tracing_never_prints_a_decrypted_value() {
    const CANARY: &str = "fake-trace-canary";
    // Probes run untraced: a traced probe would print the value whatever the hook did.
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
        assert!(
            stderr(&output).contains(restored),
            "{shell} left tracing off:\n{}",
            stderr(&output)
        );
    }
}

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

/// Also pins that `GITGUARDIAN_SHELL_OUTPUT=debug` explains the stop.
#[cfg(unix)]
#[test]
fn the_home_boundary_holds_when_home_is_reached_through_a_symlink() {
    let workspace = Workspace::new();
    let root = workspace.project.path();
    let real_home = root.join("ggh/home");
    let deep = real_home.join("proj/deep");
    std::fs::create_dir_all(&deep).unwrap();
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

    for level in [None, Some("none"), Some("normal")] {
        let env: Vec<(&str, &str)> = level
            .map(|level| vec![("GITGUARDIAN_SHELL_OUTPUT", level)])
            .unwrap_or_default();
        let output = workspace.run_with(None, &env, &["hook-env", "bash"]);
        assert_ok(&output);
        assert_eq!(stdout(&output), "", "{level:?}");
    }
}

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

    let installed = stdout(&workspace.run(&["activate", "bash", "--no-hook-env"]));
    let disabled = stdout(&workspace.run(&["activate", "bash", "--hook", "none"]));
    let program =
        format!("{installed}\n{disabled}\nprintf 'pc=[%s]\\n' \"${{PROMPT_COMMAND:-}}\"\n");
    let out = stdout(&workspace.shell("bash", &program));
    assert!(out.contains("pc=[]"), "{out}");
}

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
    assert!(block.contains("ggshield trust"), "no remedy named: {block}");

    workspace.trust_project();
    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        block.contains("export API_KEY='fake-gated-value'"),
        "{block}"
    );
}

#[test]
fn editing_a_trusted_dotenv_revokes_its_approval() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");
    workspace.trust_project();
    assert!(stdout(&workspace.run(&["hook-env", "bash"])).contains("API_KEY"));

    workspace.write_project(
        ".env",
        "API_KEY=fake-gated-value\nPROMPT_COMMAND=touch /tmp/gg-trust-bypass\n",
    );
    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(block.contains("not trusted"), "edit kept approval: {block}");
    assert!(!block.contains("API_KEY"), "{block}");
    assert!(!block.contains("PROMPT_COMMAND=touch"), "{block}");

    // Re-trusting replaces the old digest rather than adding to it.
    workspace.trust_project();
    workspace.write_project(".env", "API_KEY=fake-gated-value\n");
    assert!(
        stdout(&workspace.run(&["hook-env", "bash"])).contains("not trusted"),
        "an old digest came back"
    );
}

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
    assert!(stderr(&workspace.run(&["trust", "--revoke"])).contains("was not trusted"));
}

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

/// Make the project directory a git checkout; returns its repo-scope file.
fn make_repository(workspace: &Workspace) -> PathBuf {
    let git_dir = workspace.project.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    git_dir.join("gitguardian").join("secrets.env")
}

#[test]
fn a_value_set_in_a_repository_is_written_to_the_shared_store() {
    let workspace = Workspace::new();
    let store = make_repository(&workspace);

    let output = workspace.set(
        &["set", "--provider", "file", "API_KEY"],
        "fake-shared-value",
    );
    assert_ok(&output);

    assert!(store.exists(), "{} was not written", store.display());
    assert!(
        !workspace.project.path().join(".env").exists(),
        "the checkout's .env was written instead of the repository's store"
    );
    let read = workspace.run(&[
        "get",
        "--provider",
        "file",
        "--field",
        "API_KEY",
        "--expose",
    ]);
    assert_eq!(stdout(&read).trim(), "fake-shared-value");
}

#[test]
fn a_linked_worktree_reads_the_same_store() {
    let workspace = Workspace::new();
    let git_dir = workspace.project.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    workspace.set(
        &["set", "--provider", "file", "SHARED"],
        "fake-shared-value",
    );

    // The layout `git worktree add` writes.
    let worktree_git = git_dir.join("worktrees/feature");
    std::fs::create_dir_all(&worktree_git).unwrap();
    std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
    let worktree = workspace.home.path().join("feature");
    std::fs::create_dir_all(&worktree).unwrap();
    std::fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", worktree_git.display()),
    )
    .unwrap();

    let output = workspace.run_with(
        Some(&worktree),
        &[],
        &["get", "--provider", "file", "--field", "SHARED", "--expose"],
    );
    assert_ok(&output);
    assert_eq!(stdout(&output).trim(), "fake-shared-value");
}

#[test]
fn a_checkouts_env_overrides_the_repository_one_variable_at_a_time() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.set(&["set", "--provider", "file", "API_URL"], "https://shared");
    workspace.set(&["set", "--provider", "file", "TOKEN"], "fake-shared-token");
    workspace.set(
        &["set", "--provider", "file", "--project", "API_URL"],
        "https://this-branch",
    );

    let output = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert_ok(&output);
    let printed = stdout(&output);
    assert!(printed.contains("API_URL=https://this-branch"), "{printed}");
    assert!(printed.contains("TOKEN=fake-shared-token"), "{printed}");
}

#[test]
fn get_scopes_names_the_file_each_value_won_in() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.set(&["set", "--provider", "file", "SHARED"], "fake-repo-value");
    workspace.set(
        &["set", "--provider", "file", "--project", "LOCAL"],
        "fake-local-value",
    );

    let output = workspace.run(&["get", "--provider", "file", "--show-scope", "--expose"]);
    assert_ok(&output);
    let printed = stdout(&output);
    assert!(
        printed.contains("SHARED=fake-repo-value  # local"),
        "{printed}"
    );
    assert!(
        printed.contains("LOCAL=fake-local-value  # project"),
        "{printed}"
    );
}

#[test]
fn scope_repo_outside_a_repository_is_refused_rather_than_guessed() {
    let workspace = Workspace::new();
    let output = workspace.set(
        &["set", "--provider", "file", "--local", "API_KEY"],
        "fake-value",
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("needs a git repository"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn without_a_repository_set_still_writes_the_project_file() {
    let workspace = Workspace::new();
    let output = workspace.set(&["set", "--provider", "file", "API_KEY"], "fake-value");
    assert_ok(&output);
    assert!(workspace.project.path().join(".env").exists());
}

#[test]
fn the_hook_loads_the_repository_store_when_the_checkout_has_no_dotenv() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.set(
        &["set", "--provider", "file", "SHARED"],
        "fake-shared-value",
    );

    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        block.contains("export SHARED='fake-shared-value'"),
        "{block}"
    );
}

#[test]
fn the_repository_store_needs_no_trust_decision() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.set(
        &["set", "--provider", "file", "SHARED"],
        "fake-shared-value",
    );

    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(!block.contains("not trusted"), "{block}");
    assert!(block.contains("export SHARED="), "{block}");
}

#[test]
fn an_untrusted_dotenv_is_still_refused_in_a_repository_with_a_store() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.set(
        &["set", "--provider", "file", "SHARED"],
        "fake-shared-value",
    );
    workspace.write_project(".env", "PLANTED=fake-planted-value\n");

    let block = stdout(&workspace.run(&["hook-env", "bash"]));
    assert!(
        !block.contains("PLANTED"),
        "loaded without consent: {block}"
    );
    assert!(block.contains("not trusted"), "{block}");
}

#[test]
fn get_scope_reads_one_file_rather_than_the_merge() {
    let workspace = Workspace::new();
    workspace.set(
        &["set", "--provider", "file", "--global", "SHARED"],
        "fake-user-value",
    );
    workspace.set(
        &["set", "--provider", "file", "--project", "SHARED"],
        "fake-project-value",
    );

    let merged = stdout(&workspace.run(&["get", "--provider", "file", "--expose"]));
    assert!(merged.contains("SHARED=fake-project-value"), "{merged}");

    let scoped = stdout(&workspace.run(&["get", "--provider", "file", "--global", "--expose"]));
    assert!(scoped.contains("SHARED=fake-user-value"), "{scoped}");
}

#[test]
fn scope_and_path_cannot_be_combined() {
    let workspace = Workspace::new();
    let output = workspace.run(&["get", "--provider", "file", "--system", "--path", ".env"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot be combined"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn import_moves_a_dotenv_into_the_repository_store_and_removes_it() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.write_project(".env", "API_KEY=fake-value\n# a comment\nPORT=8080\n");
    let source = workspace.project_file(".env");

    let output = workspace.run(&[
        "import",
        "--provider",
        "file",
        "--remove-source",
        "--yes",
        source.to_str().unwrap(),
    ]);
    assert_ok(&output);

    assert!(!source.exists(), "the source dotenv was left behind");
    let stored = std::fs::read_to_string(
        workspace
            .project
            .path()
            .join(".git/gitguardian/secrets.env"),
    )
    .unwrap();
    assert!(stored.contains("API_KEY=gitguardian:"), "{stored}");
    let read = workspace.run(&["get", "--provider", "file", "--expose"]);
    assert!(
        stdout(&read).contains("API_KEY=fake-value"),
        "{}",
        stdout(&read)
    );
}

#[test]
fn import_without_remove_source_says_the_cleartext_is_still_there() {
    let workspace = Workspace::new();
    make_repository(&workspace);
    workspace.write_project(".env", "API_KEY=fake-value\n");
    let source = workspace.project_file(".env");

    let output = workspace.run(&[
        "import",
        "--provider",
        "file",
        "--yes",
        source.to_str().unwrap(),
    ]);
    assert_ok(&output);
    assert!(source.exists());
    assert!(
        stderr(&output).contains("still holds the values in cleartext"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn import_refuses_a_file_that_is_also_the_target() {
    let workspace = Workspace::new();
    workspace.write_project(".env", "API_KEY=fake-value\n");
    let source = workspace.project_file(".env");

    let output = workspace.run(&[
        "import",
        "--provider",
        "file",
        "--project",
        "--remove-source",
        "--yes",
        source.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("both the source and the target"),
        "{}",
        stderr(&output)
    );
    assert!(source.exists(), "the source was removed anyway");
}
