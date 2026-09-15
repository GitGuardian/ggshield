//! Shell integration: load a project's secrets on entering its directory and
//! unload them on leaving. `activate` prints a snippet that installs a prompt
//! hook running `hook-env`, so upgrading the binary upgrades the behaviour.
//!
//! `$__GITGUARDIAN_ACTIVE` is not authenticated: everything read back from it
//! is untrusted input, re-validated before it reaches a shell statement.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ggshield_secrets::{
    DEFAULT_PROJECT_PATH, Provider, SecretStore, repo_scope_path, trust, user_scope_path,
};
use secrecy::{ExposeSecret, SecretString};

use crate::env::{validate_env_key, validate_env_value};

/// Environment variable holding what the hook loaded last time.
const STATE_VAR: &str = "__GITGUARDIAN_ACTIVE";
/// How chatty the hook is on stderr: `none`, `normal` (default) or `debug`.
const OUTPUT_VAR: &str = "GITGUARDIAN_SHELL_OUTPUT";

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn from_name(name: &str) -> Option<Shell> {
        // Login shells are started as `-zsh`; Nix wraps binaries as `.zsh-wrapped`.
        let name = name.trim_start_matches(['-', '.']);
        let name = name.strip_suffix("-wrapped").unwrap_or(name);
        match name {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            _ => None,
        }
    }

    /// The parent shell first: `$SHELL` is the login shell, which is wrong when
    /// e.g. bash is started from zsh.
    fn detect() -> Result<Shell> {
        let from_path = |path: &str| {
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(Shell::from_name)
        };
        parent_process_name()
            .as_deref()
            .and_then(from_path)
            .or_else(|| std::env::var("SHELL").ok().as_deref().and_then(from_path))
            .context("could not tell which shell this is; name it: activate bash|zsh|fish")
    }

    fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
        }
    }
}

/// `pwd` is the default; `prompt` also catches edits to `.env` in a long-lived
/// shell, at the cost of a `stat` per prompt.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Hook {
    /// Never automatically; call `_ggshield_hook` yourself.
    None,
    /// On every prompt.
    Prompt,
    /// On directory change only (the default).
    Pwd,
}

#[cfg(target_os = "linux")]
fn parent_process_name() -> Option<String> {
    let comm = std::fs::read_to_string(format!(
        "/proc/{}/comm",
        std::os::unix::process::parent_id()
    ))
    .ok()?;
    Some(comm.trim_end().to_string())
}

#[cfg(target_os = "macos")]
fn parent_process_name() -> Option<String> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is valid for the length passed.
    let length = unsafe {
        libc::proc_pidpath(
            libc::getppid(),
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    buffer.truncate(usize::try_from(length).ok().filter(|&length| length > 0)?);
    String::from_utf8(buffer).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn parent_process_name() -> Option<String> {
    None
}

/// Print the shell code that installs the prompt hook.
///
/// The counterpart to `run` for an interactive shell: instead of naming a
/// command to wrap, the secrets for the directory you are in are already in
/// your environment.
///
/// Add to your shell's startup file:
///
///   bash  eval "$(ggshield activate bash)"   # ~/.bashrc
///
///   zsh   eval "$(ggshield activate zsh)"    # ~/.zshrc
///
///   fish  ggshield activate fish | source    # ~/.config/fish/config.fish
///
/// The shell can be left out, in which case it is detected from the calling
/// process, falling back to $SHELL.
///
/// Values are decrypted on entering a directory that has a dotenv file, and
/// unset again on leaving it. The machine-wide user-scope file
/// (`ggshield secret set --global`) is loaded alongside the project's own, so
/// anything in it reaches every shell that enters a project directory.
///
/// Variables that change how the shell runs commands — PROMPT_COMMAND,
/// BASH_ENV, LD_PRELOAD, GIT_SSH_COMMAND and the like — are never exported,
/// whatever a file says; the hook names the ones it refused.
///
/// A dotenv file is loaded only after you approve it with `ggshield trust`, and
/// any edit revokes that approval, so a freshly cloned `.env` cannot reach your
/// shell unread. `get` and `run` need no approval: naming the file is the consent.
///
/// Set GITGUARDIAN_SHELL_OUTPUT=none to silence the one-line report, or =debug
/// to see why a directory was skipped.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Shell to generate the hook for (default: detected).
    #[arg(value_enum)]
    shell: Option<Shell>,
    /// When the hook fires: on directory change (default), on every prompt,
    /// or never.
    #[arg(long, value_enum, default_value = "pwd")]
    hook: Hook,
    /// Install the hook without running it once immediately.
    ///
    /// Useful when testing the snippet itself.
    #[arg(long)]
    no_hook_env: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let shell = match args.shell {
        Some(shell) => shell,
        None => Shell::detect()?,
    };
    print!("{}", hook_script(shell, args.hook, !args.no_hook_env));
    Ok(())
}

/// The binary path is quoted (it may contain spaces or metacharacters), and
/// shell tracing is off around the eval, since `set -x` would print every
/// decrypted value.
fn hook_script(shell: Shell, hook: Hook, run_now: bool) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_string))
        .unwrap_or_else(|| "ggshield".to_string());

    // `\builtin`/`\command`: `eval`, `typeset` or `printf` may be aliased in the user's shell.
    let mut script = match shell {
        Shell::Bash => {
            let exe = posix_quote(&exe);
            format!(
                r#"_ggshield_hook() {{
  local __ggshield_status=$?
  local __ggshield_flags=$-
  {{ set +xv; }} 2>/dev/null
  \builtin eval "$(\command {exe} hook-env bash)"
  case $__ggshield_flags in
    *x*) set -x ;;
  esac
  case $__ggshield_flags in
    *v*) set -v ;;
  esac
  \builtin return $__ggshield_status
}}
"#
            )
        }
        // `local_options` restores the options when the function returns.
        Shell::Zsh => {
            let exe = posix_quote(&exe);
            format!(
                r#"_ggshield_hook() {{
  \builtin setopt local_options no_xtrace no_verbose
  \builtin eval "$(\command {exe} hook-env zsh)"
}}
"#
            )
        }
        // fish has no `\command` idiom; its `command` already skips alias functions.
        // Restoring with `set -g` drops an export flag, a smaller cost than printing secrets.
        Shell::Fish => {
            let exe = fish_quote(&exe);
            format!(
                r#"function _ggshield_hook
  set -l __ggshield_trace $fish_trace
  set -e fish_trace
  command {exe} hook-env fish | source
  if set -q __ggshield_trace[1]
    set -g fish_trace $__ggshield_trace
  end
end
"#
            )
        }
    };

    script.push_str(&hook_installation(shell, hook));
    if run_now && hook != Hook::None {
        script.push_str("_ggshield_hook\n");
    }
    script
}

/// Removes any previous registration before adding one, so switching `--hook`
/// (including to `none`) never leaves the old trigger behind.
fn hook_installation(shell: Shell, hook: Hook) -> String {
    let removal = hook_removal(shell);
    match (shell, hook) {
        (_, Hook::None) => removal,

        (Shell::Zsh, _) => {
            let array = match hook {
                Hook::Prompt => "precmd_functions",
                _ => "chpwd_functions",
            };
            format!("{removal}{array}+=(_ggshield_hook)\n")
        }

        // `PROMPT_COMMAND` may be a string (bash < 5.1) or an array. Trailing separators
        // are trimmed first: appending to `...;` would yield `;;`, a syntax error on every prompt.
        (Shell::Bash, _) => format!(
            r#"{removal}if [[ "$(\builtin declare -p PROMPT_COMMAND 2>&1)" == "declare -a"* ]]; then
  PROMPT_COMMAND=(${{PROMPT_COMMAND[@]+"${{PROMPT_COMMAND[@]}}"}} _ggshield_hook)
else
  while [[ -n ${{PROMPT_COMMAND:-}} && ${{PROMPT_COMMAND}} == *[$' \t\n;'] ]]; do
    PROMPT_COMMAND=${{PROMPT_COMMAND%?}}
  done
  PROMPT_COMMAND="${{PROMPT_COMMAND:+${{PROMPT_COMMAND}}; }}_ggshield_hook"
fi
"#
        ),

        (Shell::Fish, Hook::Prompt) => format!(
            "{removal}function _ggshield_hook_trigger --on-event fish_prompt\n  \
             _ggshield_hook\nend\n"
        ),
        (Shell::Fish, _) => format!(
            "{removal}function _ggshield_hook_trigger --on-variable PWD\n  \
             _ggshield_hook\nend\n"
        ),
    }
}

fn hook_removal(shell: Shell) -> String {
    match shell {
        Shell::Zsh => r#"\builtin typeset -ga precmd_functions
\builtin typeset -ga chpwd_functions
precmd_functions=("${(@)precmd_functions:#_ggshield_hook}")
chpwd_functions=("${(@)chpwd_functions:#_ggshield_hook}")
"#
        .to_string(),

        // Only the shape this file writes (hook last) is unhooked from a string; editing
        // the middle would turn `a; _ggshield_hook; b` into `a; ; b`, a syntax error.
        Shell::Bash => r#"if [[ ${PROMPT_COMMAND[*]:-} == *'_ggshield_hook'* ]]; then
  if [[ "$(\builtin declare -p PROMPT_COMMAND 2>&1)" == "declare -a"* ]]; then
    __ggshield_kept=()
    for __ggshield_one in "${PROMPT_COMMAND[@]}"; do
      if [[ $__ggshield_one != _ggshield_hook ]]; then
        __ggshield_kept+=("$__ggshield_one")
      fi
    done
    PROMPT_COMMAND=(${__ggshield_kept[@]+"${__ggshield_kept[@]}"})
    \builtin unset __ggshield_kept __ggshield_one
  else
    PROMPT_COMMAND=${PROMPT_COMMAND%_ggshield_hook}
    while [[ -n ${PROMPT_COMMAND:-} && ${PROMPT_COMMAND} == *[$' \t\n;'] ]]; do
      PROMPT_COMMAND=${PROMPT_COMMAND%?}
    done
  fi
fi
"#
        .to_string(),

        Shell::Fish => "functions -q _ggshield_hook_trigger; and functions -e \
                        _ggshield_hook_trigger\n"
            .to_string(),
    }
}

/// Emit the export/unset statements for the current directory.
#[derive(clap::Args)]
pub(crate) struct HookArgs {
    /// Shell whose syntax to emit.
    #[arg(value_enum)]
    shell: Shell,
}

pub(crate) fn hook_env(args: HookArgs) -> Result<()> {
    hook_env_to(args, std::io::stdout().is_terminal())
}

/// Takes `stdout_is_terminal` so tests can exercise the refusal without a pty.
fn hook_env_to(args: HookArgs, stdout_is_terminal: bool) -> Result<()> {
    let shell = args.shell;

    // This prints every secret in cleartext, and the hook always runs inside a
    // command substitution, so a terminal here means someone typed it by hand.
    if stdout_is_terminal {
        bail!(
            "hook-env writes the shell statements that load this directory's secrets, in \
             cleartext, and stdout is a terminal. It is meant to be run by the snippet \
             `ggshield activate {}` installs, not by hand",
            shell.name()
        );
    }

    let stored = State::from_env();
    // An unreadable blob leaves its exports stranded; say so once and clear it.
    let unreadable_state = matches!(stored, Stored::Invalid);
    if unreadable_state {
        report_always(
            shell,
            &format!(
                "${STATE_VAR} was set to something this version cannot read, so any variables a \
                 previous hook exported are still in this shell and will stay. It has been reset; \
                 re-enter the directory to load it again"
            ),
        );
    }
    let previous = match stored {
        Stored::Loaded(state) => Some(state),
        Stored::Empty | Stored::Invalid => None,
    };
    let target = nearest_dotenv(shell);

    match (&previous, &target) {
        // The common case on every prompt: no keyring, no decryption, no output.
        (None, None) => {
            report_debug(shell, "no dotenv file at or above this directory");
            if unreadable_state {
                emit("", State::CLEARED, shell)?;
            }
            return Ok(());
        }
        // `still_ours` keeps a stale or planted state from short-circuiting a load.
        (Some(state), Some(found)) if state.matches(found) && state.still_ours() => {
            report_debug(shell, "unchanged since it was loaded");
            return Ok(());
        }
        _ => {}
    }

    let mut script = String::new();
    // Ours to remove only while the value is still the one we set.
    let mut still_ours: Vec<&str> = Vec::new();
    let mut taken_over: Vec<&str> = Vec::new();
    if let Some(state) = &previous {
        for (key, digest) in &state.keys {
            match std::env::var(key) {
                Ok(live) if digest_of(&live) == *digest => {
                    script.push_str(&unset_statement(shell, key)?);
                    still_ours.push(key);
                }
                _ => taken_over.push(key),
            }
        }
        if !still_ours.is_empty() {
            report(
                shell,
                &format!("-{} {}", still_ours.len(), still_ours.join(", ")),
            );
        }
        if !taken_over.is_empty() {
            report(
                shell,
                &format!(
                    "left {} changed since we set {}: {}",
                    taken_over.len(),
                    if taken_over.len() == 1 { "it" } else { "them" },
                    taken_over.join(", ")
                ),
            );
        }
    }

    let Some(found) = target else {
        emit(&script, State::CLEARED, shell)?;
        return Ok(());
    };

    // Stop rather than walk past a symlink or fifo and load another project's secrets.
    if let Some(refusal) = &found.refusal {
        report_always(shell, refusal);
        return emit_state(&script, &found, Vec::new(), shell);
    }

    // Entering a directory is not consent the way naming a file to `get`/`run` is.
    // Not a prompt: a y/n on every `cd` gets answered without reading.
    if found.needs_trust && !trust::is_trusted(&found.path)? {
        report_always(
            shell,
            &format!(
                "{} is not trusted, so nothing was loaded. Read it, then run `ggshield \
                 trust` in that directory",
                found.path.display()
            ),
        );
        return emit_state(&script, &found, Vec::new(), shell);
    }

    let loaded = match load(&found.path) {
        Ok(loaded) => loaded,
        Err(error) => {
            // Never fatal on a prompt. The state still records this file so the error is
            // reported once per file version rather than before every prompt.
            report_always(shell, &format!("{}: {error:#}", found.path.display()));
            return emit_state(&script, &found, Vec::new(), shell);
        }
    };
    for advisory in &loaded.advisories {
        report(shell, advisory);
    }

    // Only names we just unset are replaceable; one the user took over keeps their value.
    let carried_over = still_ours;

    let mut exported = Vec::new();
    let mut shadowed = Vec::new();
    let mut refused = Vec::new();
    for (key, value) in &loaded.fields {
        if is_shell_control_var(key) {
            refused.push(key.clone());
            continue;
        }
        // A user-set variable outranks the file, as in `run`; exported-empty counts as unset.
        if std::env::var_os(key).is_some_and(|value| !value.is_empty())
            && !carried_over.contains(&key.as_str())
        {
            shadowed.push(key.clone());
            continue;
        }
        let plain = value.expose_secret();
        script.push_str(&export_statement(shell, key, plain)?);
        exported.push((key.clone(), digest_of(plain)));
    }

    if !refused.is_empty() {
        // `report_always`: `GITGUARDIAN_SHELL_OUTPUT=none` must not hide a refusal.
        report_always(
            shell,
            &format!(
                "refused to export {} that {} how the shell runs commands: {}",
                if refused.len() == 1 {
                    "1 variable".to_string()
                } else {
                    format!("{} variables", refused.len())
                },
                if refused.len() == 1 {
                    "changes"
                } else {
                    "change"
                },
                refused.join(", ")
            ),
        );
    }
    if !shadowed.is_empty() {
        report(
            shell,
            &format!(
                "kept {} already set in this shell: {}",
                shadowed.len(),
                shadowed.join(", ")
            ),
        );
    }
    if !exported.is_empty() {
        let names: Vec<&str> = exported.iter().map(|(name, _)| name.as_str()).collect();
        report(shell, &format!("+{} {}", names.len(), names.join(", ")));
    }

    emit_state(&script, &found, exported, shell)
}

fn emit_state(script: &str, found: &Found, keys: Vec<(String, u64)>, shell: Shell) -> Result<()> {
    let state = State {
        directory: found.directory.clone(),
        path: found.path.clone(),
        fingerprint: found.fingerprint,
        keys,
    };
    emit(script, &state.encode(), shell)
}

fn emit(script: &str, state: &str, shell: Shell) -> Result<()> {
    print!("{script}");
    print!("{}", export_statement(shell, STATE_VAR, state)?);
    Ok(())
}

struct Loaded {
    fields: BTreeMap<String, SecretString>,
    advisories: Vec<String>,
}

fn load(path: &Path) -> Result<Loaded> {
    let store = SecretStore::builder(Provider::File)
        .env_override(false)
        .build()?;
    let text = path
        .to_str()
        .context("the dotenv path is not valid UTF-8")?
        .to_string();
    let (fields, warnings) = store.get_secrets_with_warnings(&text)?;
    // As in `run`: never export a partial set, which looks like secrets never set.
    if !warnings.unreadable.is_empty() {
        bail!(
            "{} value(s) here could not be read, so none of this directory's secrets were \
             loaded — a shell with some of them missing behaves like one where they were never \
             set. Re-encrypt them on this device (`ggshield secret encrypt`), remove them, or run \
             `ggshield secret get` to see the rest. {}",
            warnings.unreadable.len(),
            warnings.unreadable.join("; ")
        );
    }
    for (key, value) in &fields {
        validate_env_key(key)?;
        validate_env_value(key, value)?;
    }
    Ok(Loaded {
        fields,
        advisories: warnings.advisories,
    })
}

struct Found {
    directory: PathBuf,
    path: PathBuf,
    fingerprint: u64,
    /// False for the repository's own store: `git clone` never transfers it.
    needs_trust: bool,
    /// Recorded like any other outcome so the message appears once.
    refusal: Option<String>,
}

/// Walks up to `$HOME`, canonicalised because `current_dir()` is physical (`/tmp`
/// is a symlink on macOS), so a stray `.env` above every project never loads.
fn nearest_dotenv(shell: Shell) -> Option<Found> {
    let cwd = std::env::current_dir().ok()?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|home| std::fs::canonicalize(home).ok());
    for directory in cwd.ancestors() {
        let path = directory.join(DEFAULT_PROJECT_PATH);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                return Some(Found {
                    directory: directory.to_path_buf(),
                    fingerprint: fingerprint(&metadata) ^ user_scope_fingerprint(),
                    path,
                    refusal: None,
                    needs_trust: true,
                });
            }
            Ok(metadata) => {
                let what = if metadata.file_type().is_symlink() {
                    "is a symbolic link; refusing to read through it"
                } else {
                    "is not a regular file"
                };
                return Some(Found {
                    directory: directory.to_path_buf(),
                    fingerprint: fingerprint(&metadata) ^ user_scope_fingerprint(),
                    refusal: Some(format!(
                        "{} {what}, the same way `get` and `run` do. Nothing was loaded — \
                         walking past it would have loaded another directory's secrets instead",
                        path.display()
                    )),
                    path,
                    needs_trust: true,
                });
            }
            Err(_) => {}
        }
        if home.as_deref() == Some(directory) {
            report_debug(
                shell,
                &format!("stopped at the home directory {}", directory.display()),
            );
            break;
        }
    }
    // No dotenv above: fall back to the repository store, a fresh worktree's `.env`.
    repo_store(&cwd)
}

/// The repository's store, as a load target, when it exists.
fn repo_store(cwd: &Path) -> Option<Found> {
    let path = repo_scope_path(cwd)?;
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some(Found {
        // The shell's directory, not the store's: one store serves every worktree.
        directory: cwd.to_path_buf(),
        fingerprint: fingerprint(&metadata) ^ user_scope_fingerprint(),
        path,
        refusal: None,
        needs_trust: false,
    })
}

/// Mtime and length, not a hash: this runs on every prompt.
fn fingerprint(metadata: &std::fs::Metadata) -> u64 {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|delta| delta.as_nanos() as u64)
        .unwrap_or(0);
    modified ^ metadata.len().rotate_left(32)
}

/// Every load merges the user-scope file, so its edits must invalidate the state too.
fn user_scope_fingerprint() -> u64 {
    let Ok(path) = user_scope_path() else {
        return 0;
    };
    std::fs::symlink_metadata(&path)
        .map(|metadata| fingerprint(&metadata).rotate_left(17))
        .unwrap_or(0)
}

enum Stored {
    /// Unset or empty: nothing was loaded.
    Empty,
    /// Well-formed, and every name in it is a legal variable name.
    Loaded(State),
    /// Set to something that is not a state this version wrote.
    Invalid,
}

struct State {
    directory: PathBuf,
    path: PathBuf,
    fingerprint: u64,
    /// Exported name -> digest of the value we gave it.
    keys: Vec<(String, u64)>,
}

/// So a blob from another version is reported unreadable rather than half-parsed.
const STATE_VERSION: &str = "1";

impl State {
    const CLEARED: &'static str = "";

    fn from_env() -> Stored {
        let Ok(raw) = std::env::var(STATE_VAR) else {
            return Stored::Empty;
        };
        if raw.is_empty() {
            return Stored::Empty;
        }
        match Self::decode(&raw) {
            Some(state) => Stored::Loaded(state),
            None => Stored::Invalid,
        }
    }

    fn decode(raw: &str) -> Option<Self> {
        let mut parts = raw.split('.');
        if parts.next()? != STATE_VERSION {
            return None;
        }
        let directory = PathBuf::from(String::from_utf8(from_hex(parts.next()?)?).ok()?);
        let path = PathBuf::from(String::from_utf8(from_hex(parts.next()?)?).ok()?);
        let fingerprint = parts.next()?.parse().ok()?;
        let keys_blob = String::from_utf8(from_hex(parts.next()?)?).ok()?;
        if parts.next().is_some() {
            return None;
        }
        let mut keys = Vec::new();
        for entry in keys_blob.split(',').filter(|entry| !entry.is_empty()) {
            let (name, digest) = entry.split_once('=')?;
            // Untrusted: each name reaches an eval'd `unset`. Refuse the whole blob.
            validate_env_key(name).ok()?;
            keys.push((name.to_string(), digest.parse().ok()?));
        }
        Some(State {
            directory,
            path,
            fingerprint,
            keys,
        })
    }

    fn matches(&self, found: &Found) -> bool {
        self.directory == found.directory
            && self.path == found.path
            && self.fingerprint == found.fingerprint
    }

    /// Checked before the fast path: a state claiming exports the environment
    /// lacks is stale or not ours.
    fn still_ours(&self) -> bool {
        self.keys
            .iter()
            .all(|(key, digest)| std::env::var(key).is_ok_and(|live| digest_of(&live) == *digest))
    }

    /// Hex fields joined by `.`: never needs shell quoting, and no path byte can
    /// collide with the delimiter.
    fn encode(&self) -> String {
        let keys = self
            .keys
            .iter()
            .map(|(name, digest)| format!("{name}={digest}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{STATE_VERSION}.{}.{}.{}.{}",
            to_hex(self.directory.as_os_str().as_encoded_bytes()),
            to_hex(self.path.as_os_str().as_encoded_bytes()),
            self.fingerprint,
            to_hex(keys.as_bytes())
        )
    }
}

/// FNV-1a: not cryptographic, and needn't be; it sits beside the plaintext it digests.
fn digest_of(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

/// Variables whose *value is executed*, so the hook never exports them: a dotenv
/// file may say what a variable holds, not what the shell does. A class, not an
/// inventory; many are shell-only variables, so "the user has not set it" is no
/// protection. `ggshield run` is the way to set one for a single command.
const SHELL_CONTROL_VARS: &[&str] = &[
    // Startup files and shell configuration.
    "BASHOPTS",
    "BASH_ENV",
    "BASH_XTRACEFD",
    "ENV",
    "FPATH",
    "SHELLOPTS",
    "ZDOTDIR",
    // Prompts. Executed on every prompt, or expanded by it.
    "PROMPT",
    "PROMPT_COMMAND",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "RPROMPT",
    "RPS1",
    "RPS2",
    "SPROMPT",
    // What a bare word resolves to, and how words are split.
    "CDPATH",
    "GLOBIGNORE",
    "HOME",
    "IFS",
    "PATH",
    "SHELL",
    // The dynamic linker and the C library.
    "GCONV_PATH",
    "HOSTALIASES",
    "LOCPATH",
    "NLSPATH",
    // Programs other programs shell out to.
    "BROWSER",
    "EDITOR",
    "GIT_ASKPASS",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_EDITOR",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_PROXY_COMMAND",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "LESSCLOSE",
    "LESSOPEN",
    "MANPAGER",
    "PAGER",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "VISUAL",
    // Language runtimes that take code, a module path or extra flags.
    "JAVA_TOOL_OPTIONS",
    "LUA_CPATH",
    "LUA_INIT",
    "LUA_PATH",
    "NODE_OPTIONS",
    "PERL5DB",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYLIB",
    "RUBYOPT",
    "_JAVA_OPTIONS",
];

/// Prefixes covering families of the same thing: every `LD_*` and `DYLD_*`
/// loader knob, and bash's exported-function encoding.
const SHELL_CONTROL_PREFIXES: &[&str] = &["BASH_FUNC_", "DYLD_", "LD_"];

fn is_shell_control_var(key: &str) -> bool {
    SHELL_CONTROL_VARS.contains(&key)
        || SHELL_CONTROL_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// The name is validated too: it is interpolated unquoted and may come from the
/// untrusted state blob.
fn export_statement(shell: Shell, key: &str, value: &str) -> Result<String> {
    validate_env_key(key)?;
    Ok(match shell {
        Shell::Bash | Shell::Zsh => format!("export {key}={};\n", posix_quote(value)),
        Shell::Fish => format!("set -gx {key} {};\n", fish_quote(value)),
    })
}

fn unset_statement(shell: Shell, key: &str) -> Result<String> {
    validate_env_key(key)?;
    Ok(match shell {
        Shell::Bash | Shell::Zsh => format!("unset {key};\n"),
        Shell::Fish => format!("set -e {key};\n"),
    })
}

/// Single quotes are literal in POSIX shells; an embedded `'` becomes `'\''`.
fn posix_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Fish's single quotes are literal too, but they take backslash escapes for
/// `\` and `'` — so those two, and only those two, need doubling.
fn fish_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => quoted.push_str("\\'"),
            '\\' => quoted.push_str("\\\\"),
            other => quoted.push(other),
        }
    }
    quoted.push('\'');
    quoted
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Verbosity {
    /// Nothing but what [`report_always`] emits.
    Silent,
    /// The one-line report (the default).
    Normal,
    /// Plus why a directory was skipped.
    Debug,
}

fn verbosity() -> Verbosity {
    match std::env::var(OUTPUT_VAR).as_deref() {
        Ok("none") => Verbosity::Silent,
        Ok("debug") => Verbosity::Debug,
        _ => Verbosity::Normal,
    }
}

/// Names and counts only. Printed as a shell statement because our stderr is
/// inside the command substitution the shell is capturing.
fn report(shell: Shell, message: &str) {
    if verbosity() < Verbosity::Normal {
        return;
    }
    report_always(shell, message);
}

/// Why a directory was skipped, at `GITGUARDIAN_SHELL_OUTPUT=debug`.
fn report_debug(shell: Shell, message: &str) {
    if verbosity() < Verbosity::Debug {
        return;
    }
    report_always(shell, message);
}

fn report_always(shell: Shell, message: &str) {
    let line = format!("ggshield: {message}");
    match shell {
        Shell::Bash | Shell::Zsh => println!("printf '%s\\n' {} >&2;", posix_quote(&line)),
        Shell::Fish => println!("printf '%s\\n' {} >&2;", fish_quote(&line)),
    }
}

#[cfg(test)]
// A failed unwrap is the assertion failing; the lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn posix_quoting_survives_every_metacharacter() {
        for value in [
            "plain",
            "with space",
            "it's",
            "$HOME",
            "`id`",
            "a\nb",
            "back\\slash",
            "\"double\"",
            "$(touch /tmp/pwned)",
        ] {
            let quoted = posix_quote(value);
            assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            // Round-trip through a real shell, byte for byte.
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s' {quoted}"))
                .output()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout), value, "{quoted}");
        }
    }

    #[test]
    fn a_value_cannot_break_out_of_its_assignment() {
        // The shape an attacker would need: close the quote, run a command.
        let hostile = "x'; touch /tmp/gitguardian-pwned; echo '";
        let statement = export_statement(Shell::Bash, "API_KEY", hostile).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{statement} printf '%s' \"$API_KEY\""))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), hostile);
        assert!(!Path::new("/tmp/gitguardian-pwned").exists());
    }

    /// Names are interpolated unquoted, so they must be validated.
    #[test]
    fn a_name_cannot_carry_shell_code_into_a_statement() {
        for hostile in [
            "EVIL; touch /tmp/gitguardian-pwned-unset; :",
            "GGX; printf STATE_INJECTED >&2; #",
            "A=1",
            "A B",
            "$(id)",
            "`id`",
            "",
            "1LEADING_DIGIT",
        ] {
            for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
                assert!(
                    unset_statement(shell, hostile).is_err(),
                    "{hostile:?} was accepted by unset_statement"
                );
                assert!(
                    export_statement(shell, hostile, "value").is_err(),
                    "{hostile:?} was accepted by export_statement"
                );
            }
        }
        assert!(unset_statement(Shell::Bash, "API_KEY_2").is_ok());
    }

    /// A state blob carrying such a name is refused as a whole.
    #[test]
    fn a_state_naming_something_that_is_not_a_variable_is_refused() {
        let state = State {
            directory: PathBuf::from("/tmp/p"),
            path: PathBuf::from("/tmp/p/.env"),
            fingerprint: 1,
            keys: vec![("EVIL; touch /tmp/x; :".to_string(), 2)],
        };
        assert!(State::decode(&state.encode()).is_none());
        assert!(
            State::decode("1.2f746d702f70.2f746d702f702f2e656e76.1.6e6f742d68657866").is_none()
        );
    }

    /// Quoting cannot make `PROMPT_COMMAND` safe, so the name is refused.
    #[test]
    fn variables_that_change_how_the_shell_runs_commands_are_refused() {
        for key in [
            "PROMPT_COMMAND",
            "PS1",
            "BASH_ENV",
            "ENV",
            "IFS",
            "PATH",
            "SHELL",
            "HOME",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "GIT_SSH_COMMAND",
            "PERL5OPT",
            "RUBYOPT",
            "ZDOTDIR",
            "FPATH",
            "BASH_FUNC_ls%%",
            "PAGER",
            "EDITOR",
        ] {
            assert!(is_shell_control_var(key), "{key} was allowed");
        }
        for key in [
            "API_KEY",
            "DATABASE_URL",
            "PORT",
            "DEBUG",
            "AWS_SECRET_ACCESS_KEY",
            "STRIPE_KEY",
            "PATH_PREFIX",
            "NODE_ENV",
            "HOMEPAGE",
            "PROMPT_TEMPLATE",
        ] {
            assert!(!is_shell_control_var(key), "{key} was refused");
        }
    }

    #[test]
    fn state_round_trips_through_its_encoding() {
        let state = State {
            directory: PathBuf::from("/tmp/a project"),
            path: PathBuf::from("/tmp/a project/.env"),
            fingerprint: 12345,
            keys: vec![("A".to_string(), 1), ("B_TWO".to_string(), 2)],
        };
        let encoded = state.encode();
        assert!(
            encoded
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || ch == '.'),
            "{encoded}"
        );

        let parsed = State::decode(&encoded).unwrap();
        assert_eq!(parsed.directory, state.directory);
        assert_eq!(parsed.path, state.path);
        assert_eq!(parsed.fingerprint, state.fingerprint);
        assert_eq!(parsed.keys, state.keys);
    }

    /// Awkward path bytes (`0x1f`, `.`, `,`, newline, quote) round-trip.
    #[test]
    fn a_path_containing_the_old_delimiter_still_round_trips() {
        for directory in [
            "/tmp/a\u{1f}b",
            "/tmp/a.b",
            "/tmp/a=b",
            "/tmp/a,b",
            "/tmp/a\nb",
            "/tmp/a'b",
        ] {
            let state = State {
                directory: PathBuf::from(directory),
                path: PathBuf::from(format!("{directory}/.env")),
                fingerprint: 7,
                keys: vec![("A".to_string(), 1)],
            };
            let parsed = State::decode(&state.encode())
                .unwrap_or_else(|| panic!("{directory:?} did not round-trip"));
            assert_eq!(parsed.directory, state.directory, "{directory:?}");
            assert_eq!(parsed.path, state.path, "{directory:?}");
            assert_eq!(parsed.keys, state.keys, "{directory:?}");
        }
    }

    /// A blob that does not parse is not "nothing was loaded".
    #[test]
    fn an_unparsable_state_is_told_apart_from_an_empty_one() {
        assert!(State::decode("").is_none());
        for broken in [
            // wrong version
            "2.2f74.2f74.1.",
            // odd-length hex
            "1.2f7.2f74.1.",
            // non-hex
            "1.zzzz.2f74.1.",
            // missing a field
            "1.2f74.2f74.1",
            // one field too many
            "1.2f74.2f74.1..",
            // a fingerprint that is not a number
            "1.2f74.2f74.x.",
        ] {
            assert!(State::decode(broken).is_none(), "{broken:?} parsed");
        }
        // SAFETY: single-threaded test, and the variable is ours.
        unsafe { std::env::set_var(STATE_VAR, State::CLEARED) };
        assert!(matches!(State::from_env(), Stored::Empty));
        unsafe { std::env::set_var(STATE_VAR, "not-a-state") };
        assert!(matches!(State::from_env(), Stored::Invalid));
        unsafe { std::env::remove_var(STATE_VAR) };
        assert!(matches!(State::from_env(), Stored::Empty));
    }

    /// `hook-env` is hidden but typeable; it refuses a terminal outright.
    #[test]
    fn hook_env_refuses_to_write_secrets_to_a_terminal() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let error =
                hook_env_to(HookArgs { shell }, true).expect_err("hook-env wrote to a terminal");
            let message = format!("{error:#}");
            assert!(message.contains("stdout is a terminal"), "{message}");
            assert!(
                message.contains(&format!("activate {}", shell.name())),
                "{message}"
            );
        }
    }

    #[test]
    fn every_shell_script_mentions_its_own_hook_and_command() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let script = hook_script(shell, Hook::Pwd, true);
            assert!(script.contains("_ggshield_hook"), "{}", shell.name());
            assert!(
                script.contains(&format!("hook-env {}", shell.name())),
                "{}",
                shell.name()
            );
        }
    }

    /// The binary's own path is quoted in every script.
    #[test]
    fn the_binarys_own_path_is_quoted_in_every_script() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let script = hook_script(shell, Hook::Pwd, false);
            let exe = std::env::current_exe().unwrap();
            let exe = exe.to_str().unwrap();
            let quoted = match shell {
                Shell::Fish => fish_quote(exe),
                _ => posix_quote(exe),
            };
            assert!(script.contains(&quoted), "{}: {script}", shell.name());
            assert!(
                !script.contains(&format!("command {exe} hook-env")),
                "{}: the path was spliced in unquoted",
                shell.name()
            );
        }
    }

    /// `set -x` would trace every decrypted value at the eval.
    #[test]
    fn every_generated_hook_suppresses_shell_tracing_around_the_eval() {
        assert!(hook_script(Shell::Bash, Hook::Pwd, false).contains("set +xv"));
        let zsh = hook_script(Shell::Zsh, Hook::Pwd, false);
        assert!(zsh.contains("local_options"), "{zsh}");
        assert!(zsh.contains("no_xtrace"), "{zsh}");
        let fish = hook_script(Shell::Fish, Hook::Pwd, false);
        assert!(fish.contains("set -e fish_trace"), "{fish}");
        assert!(fish.contains("set -g fish_trace"), "{fish}");
    }

    #[test]
    fn hook_none_installs_no_trigger_and_runs_nothing() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let script = hook_script(shell, Hook::None, true);
            // Defined for manual calls, but neither wired up nor invoked.
            assert!(
                script.contains("_ggshield_hook()") || script.contains("function _ggshield_hook")
            );
            assert!(
                !script.contains("precmd_functions+=(_ggshield_hook)"),
                "{}",
                shell.name()
            );
            assert!(
                !script.contains("chpwd_functions+=(_ggshield_hook)"),
                "{}",
                shell.name()
            );
            assert!(
                !script.contains("_ggshield_hook\"") && !script.contains("--on-variable"),
                "{}",
                shell.name()
            );
            assert!(
                !script.trim_end().ends_with("_ggshield_hook"),
                "{}",
                shell.name()
            );
        }
    }

    /// `--hook none` removes an existing registration, not merely declines to add one.
    #[test]
    fn hook_none_removes_an_existing_registration() {
        let zsh = hook_script(Shell::Zsh, Hook::None, true);
        assert!(
            zsh.contains(r#"precmd_functions=("${(@)precmd_functions:#_ggshield_hook}")"#),
            "{zsh}"
        );
        assert!(
            zsh.contains(r#"chpwd_functions=("${(@)chpwd_functions:#_ggshield_hook}")"#),
            "{zsh}"
        );
        let bash = hook_script(Shell::Bash, Hook::None, true);
        assert!(
            bash.contains("PROMPT_COMMAND=${PROMPT_COMMAND%_ggshield_hook}"),
            "{bash}"
        );
        let fish = hook_script(Shell::Fish, Hook::None, true);
        assert!(
            fish.contains("functions -e _ggshield_hook_trigger"),
            "{fish}"
        );
    }

    #[test]
    fn zsh_registers_in_exactly_one_array_and_clears_the_other() {
        let pwd = hook_script(Shell::Zsh, Hook::Pwd, false);
        assert!(pwd.contains("chpwd_functions+=(_ggshield_hook)"));
        assert!(!pwd.contains("precmd_functions+=(_ggshield_hook)"));
        let prompt = hook_script(Shell::Zsh, Hook::Prompt, false);
        assert!(prompt.contains("precmd_functions+=(_ggshield_hook)"));
        assert!(!prompt.contains("chpwd_functions+=(_ggshield_hook)"));
        for script in [&pwd, &prompt] {
            assert!(
                script.contains(r#"precmd_functions=("${(@)precmd_functions:#_ggshield_hook}")"#)
            );
            assert!(
                script.contains(r#"chpwd_functions=("${(@)chpwd_functions:#_ggshield_hook}")"#)
            );
        }
    }

    #[test]
    fn bash_handles_prompt_command_as_string_or_array() {
        let script = hook_script(Shell::Bash, Hook::Pwd, false);
        assert!(script.contains("declare -a"));
        assert!(script.contains(
            r#"PROMPT_COMMAND=(${PROMPT_COMMAND[@]+"${PROMPT_COMMAND[@]}"} _ggshield_hook)"#
        ));
        // A trailing `;` is trimmed so the append cannot produce `;;`.
        assert!(
            script.contains(r#"PROMPT_COMMAND=${PROMPT_COMMAND%?}"#),
            "{script}"
        );
        assert!(
            script.contains(
                r#"PROMPT_COMMAND="${PROMPT_COMMAND:+${PROMPT_COMMAND}; }_ggshield_hook""#
            )
        );
    }

    #[test]
    fn fish_picks_its_trigger_from_the_hook_mode() {
        assert!(hook_script(Shell::Fish, Hook::Pwd, false).contains("--on-variable PWD"));
        assert!(hook_script(Shell::Fish, Hook::Prompt, false).contains("--on-event fish_prompt"));
    }

    #[test]
    fn no_hook_env_installs_without_running() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let installed = hook_script(shell, Hook::Pwd, false);
            assert!(installed.contains("_ggshield_hook"));
            assert!(!installed.trim_end().ends_with("_ggshield_hook"));
            assert!(
                hook_script(shell, Hook::Pwd, true)
                    .trim_end()
                    .ends_with("_ggshield_hook")
            );
        }
    }

    #[test]
    fn shell_names_are_recognised_through_login_and_nix_prefixes() {
        assert!(Shell::from_name("zsh") == Some(Shell::Zsh));
        assert!(Shell::from_name("-bash") == Some(Shell::Bash));
        assert!(Shell::from_name(".fish-wrapped") == Some(Shell::Fish));
        assert!(Shell::from_name("sh").is_none());
        assert!(Shell::from_name("cargo").is_none());
    }
}
