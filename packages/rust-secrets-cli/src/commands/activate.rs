//! Shell integration: load a project's secrets on entering its directory and
//! unload them on leaving.
//!
//! Two commands, split the way `mise` and `fnox` split theirs. [`Args`]
//! (`activate`) prints a shell snippet the user `eval`s once from their rc
//! file; that snippet installs a prompt hook which runs `hook-env` and evals
//! *its* output. All the work happens in `hook-env`, so upgrading the binary
//! upgrades the behaviour without the user re-sourcing anything.
//!
//! # What this trades away
//!
//! `run` hands secrets to one child process and nothing else. `activate` puts
//! them in the interactive shell, where every command inherits them — that is
//! the entire point, and it is strictly weaker. There is deliberately no
//! allow-list gate before a directory loads, matching `fnox`: entering a
//! directory is the consent. A `.env` in a repository you just cloned is
//! therefore in your environment as soon as you `cd` into it.
//!
//! The user-scope file (`<config dir>/gitguardian/secrets.env`) is loaded too,
//! because the hook reads through the same [`SecretStore`] every other command
//! does and that store merges it. `merge`'s own documentation in the core crate
//! calls that scope "ambient authority" and weighs its blast radius for `run`;
//! here the radius is wider still — the interactive shell and everything started
//! from it, in every directory that has a `.env`. Values whose blast radius the
//! user does not accept machine-wide belong in a project file.
//!
//! # A dotenv value must not be able to run code
//!
//! Setting a variable and changing how the shell runs commands are not the same
//! act, and the environment does not separate them. `PROMPT_COMMAND`,
//! `BASH_ENV`, `LD_PRELOAD`, `GIT_SSH_COMMAND` and their relatives are ordinary
//! variables whose *values are executed*; several are normally not exported, so
//! "the user has not set it" is no protection at all. Quoting cannot help — the
//! value is perfectly well-formed data; it is the variable that is dangerous.
//! So [`is_shell_control_var`] refuses to export that whole class, by name, and
//! says which names it refused. See its documentation for the boundary.
//!
//! `run` deliberately does not apply this list: it hands the environment to one
//! command the user typed, and injecting `NODE_OPTIONS` into `node` is a normal
//! thing to want. The hook hands it to the shell itself and everything the
//! shell will ever start, which is a different bargain.
//!
//! # Why the state lives in an environment variable
//!
//! The hook has no memory between prompts, but unloading requires knowing what
//! was loaded. [`State`] is serialised into `$__GITGUARDIAN_ACTIVE`, which the
//! shell carries for us: the directory whose file was loaded, a cheap
//! fingerprint of that file, and the names that were exported, each with a
//! digest of the value it was given. Names and digests only — never a value.
//! The digest is what makes unloading safe: a variable the user re-exported by
//! hand after we loaded it no longer matches, so leaving the directory leaves
//! their value alone instead of destroying it.
//!
//! ## What the state is not
//!
//! It is not authenticated, and it cannot be: there is no key this process and
//! the next prompt's process both have and an attacker does not. Everything read
//! back out of it is therefore treated as untrusted input — every name is
//! re-validated before it reaches a generated statement, and a blob that does
//! not parse is reported rather than read as "nothing was loaded". What remains,
//! and is accepted, is that somebody who can already write your environment can
//! plant a blob that says a directory is up to date and so keep the hook from
//! loading it. That is a denial of service by somebody who is already inside the
//! environment; it cannot make the hook run code, and it cannot reveal a value.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ggshield_secrets::{DEFAULT_PROJECT_PATH, Provider, SecretStore, trust, user_scope_path};
use secrecy::{ExposeSecret, SecretString};

use crate::env::{validate_env_key, validate_env_value};

/// Environment variable holding what the hook loaded last time.
const STATE_VAR: &str = "__GITGUARDIAN_ACTIVE";
/// How chatty the hook is on stderr: `none`, `normal` (default) or `debug`.
const OUTPUT_VAR: &str = "GITGUARDIAN_SHELL_OUTPUT";

/// Shells the hook can be generated for.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
        }
    }
}

/// When the hook runs.
///
/// Borrowed from `zoxide init --hook`, and the trade is the same one: a
/// directory-change hook is nearly free but cannot notice the file being
/// edited underneath you, while a prompt hook notices but pays a `stat` on
/// every prompt. `stat` is cheap and the hook returns before touching the
/// keyring when the fingerprint is unchanged, so `pwd` stays the default and
/// `prompt` is there for anyone who edits `.env` in a long-lived shell.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Hook {
    /// Never automatically; call `_ggshield_hook` yourself.
    None,
    /// On every prompt.
    Prompt,
    /// On directory change only (the default).
    Pwd,
}

/// Print the shell code that installs the prompt hook.
///
/// The counterpart to `run` for an interactive shell: instead of naming a
/// command to wrap, the secrets for the directory you are in are already in
/// your environment.
///
/// Add to your shell's startup file:
///
///   bash  eval "$(ggshield secret activate bash)"   # ~/.bashrc
///   zsh   eval "$(ggshield secret activate zsh)"    # ~/.zshrc
///   fish  ggshield secret activate fish | source    # ~/.config/fish/config.fish
///
/// Values are decrypted on entering a directory that has a dotenv file, and
/// unset again on leaving it. The machine-wide user-scope file
/// (`ggshield secret set --scope user`) is loaded alongside the project's own, so
/// anything in it reaches every shell that enters a project directory.
///
/// Variables that change how the shell runs commands — PROMPT_COMMAND,
/// BASH_ENV, LD_PRELOAD, GIT_SSH_COMMAND and the like — are never exported,
/// whatever a file says; the hook names the ones it refused.
///
/// A dotenv file is loaded only after you have approved it with `ggshield secret
/// trust`, and any edit revokes that approval. Without the gate, a `.env` in a
/// repository you had just cloned would reach your shell before you had read
/// it — `get` and `run` need no approval because naming the file is itself the
/// consent.
///
/// Set GITGUARDIAN_SHELL_OUTPUT=none to silence the one-line report, or =debug
/// to see why a directory was skipped.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Shell to generate the hook for.
    #[arg(value_enum)]
    shell: Shell,
    /// When the hook fires: on directory change (default), on every prompt,
    /// or never.
    #[arg(long, value_enum, default_value = "pwd")]
    hook: Hook,
    /// Install the hook without running it once immediately.
    ///
    /// The hook normally runs as soon as it is installed, so a shell started
    /// inside a project directory has its secrets straight away. This skips
    /// that first run, which is what you want when testing the snippet itself.
    #[arg(long)]
    no_hook_env: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    print!("{}", hook_script(args.shell, args.hook, !args.no_hook_env));
    Ok(())
}

/// The shell snippet `activate` prints.
///
/// Each shell gets a guard so a doubled `eval` in an rc file does not install
/// the hook twice — cheap to do here and confusing to debug if it happens.
///
/// # Two things the generated function does before it evals anything
///
/// **The binary's own path is quoted.** `current_exe()` is a real filesystem
/// path, and an application directory with a space in it (`~/Library/Application
/// Support/…`, `~/My Drive/…`) is ordinary. Spliced in bare, the hook tries to
/// execute the first word and the feature silently never loads a secret; with a
/// shell metacharacter in the path it executes something else entirely. The same
/// quoters the values go through handle it.
///
/// **Shell tracing is turned off around the eval.** The hook's output *is*
/// `export API_KEY='…'` statements, so under `set -x` the trace of the `eval`
/// prints every decrypted value — and it prints it in the hook function, before
/// anything `hook-env` emits could suppress it. So the function saves the trace
/// options, clears them, evals, and restores them. It is a real mitigation for
/// the case people actually hit (a `set -x` left on in a script, or `bash -x`),
/// not a guarantee: anything that captures the shell's own memory or a core
/// dump is outside what a generated function can defend.
fn hook_script(shell: Shell, hook: Hook, run_now: bool) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_string))
        .unwrap_or_else(|| "ggshield".to_string());

    // `\builtin` and `\command` throughout: the emitted code runs in the
    // user's shell, where `eval`, `typeset` or `printf` may be shadowed by an
    // alias or function. Borrowed from zoxide's generated init for the same
    // reason.
    let mut script = match shell {
        Shell::Bash => {
            let exe = posix_quote(&exe);
            format!(
                r#"_ggshield_hook() {{
  local __ggshield_status=$?
  local __ggshield_flags=$-
  {{ set +xv; }} 2>/dev/null
  \builtin eval "$(\command {exe} secret hook-env bash)"
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
        // `local_options` makes the two `no_` options below last only until the
        // function returns, which is zsh's own way of doing the save/restore
        // bash has to spell out.
        Shell::Zsh => {
            let exe = posix_quote(&exe);
            format!(
                r#"_ggshield_hook() {{
  \builtin setopt local_options no_xtrace no_verbose
  \builtin eval "$(\command {exe} secret hook-env zsh)"
}}
"#
            )
        }
        // fish has no backslash-escape-to-bypass-alias idiom — `\command` is
        // simply an unknown command there. Its `command` / `builtin` are real
        // words, and fish aliases are functions that `command` already skips.
        //
        // `fish_trace` is a variable rather than an option, so it is erased and
        // put back. Restoring it with `set -g` loses an export flag it may have
        // had, which is a smaller cost than printing secrets.
        Shell::Fish => {
            let exe = fish_quote(&exe);
            format!(
                r#"function _ggshield_hook
  set -l __ggshield_trace $fish_trace
  set -e fish_trace
  command {exe} secret hook-env fish | source
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

/// The part that wires `_ggshield_hook` into the shell's own hook system.
///
/// Written to be idempotent by *removing* any previous registration before
/// adding one, rather than by testing whether one exists: re-running
/// `activate` with a different `--hook` must not leave the old registration
/// behind in the other array. zoxide's init does the same.
///
/// `--hook none` therefore emits the removal and nothing else. Emitting nothing
/// at all was wrong: after `eval "$(ggshield secret activate zsh)"`, asking for
/// `--hook none` left `_ggshield_hook` in `chpwd_functions`, so directories
/// went on loading secrets — the opposite of what the flag says.
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

        // `PROMPT_COMMAND` is a string in bash before 5.1 and may be an array
        // from 5.1 on; appending to the wrong one silently never runs the
        // hook. bash has no directory-change hook, so `pwd` and `prompt` are
        // the same wiring here — `hook_env` itself returns early when nothing
        // changed, which is what keeps the prompt hook cheap.
        //
        // The trailing-separator trim is not cosmetic. `PROMPT_COMMAND` ending
        // in `;` is the *recommended* idiom — macOS's own
        // `/etc/bashrc_Apple_Terminal` documents
        // `"${PROMPT_COMMAND:+$PROMPT_COMMAND; }your_code"` — and appending
        // `;_ggshield_hook` to it produces `;;`, which is a syntax error
        // bash reports before every single prompt while never loading a secret.
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

        // Redefining a fish function replaces the previous definition and its
        // event binding, so the erase above is only load-bearing for
        // `--hook none`.
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

/// Shell code that removes any registration of `_ggshield_hook`.
fn hook_removal(shell: Shell) -> String {
    match shell {
        Shell::Zsh => r#"\builtin typeset -ga precmd_functions
\builtin typeset -ga chpwd_functions
precmd_functions=("${(@)precmd_functions:#_ggshield_hook}")
chpwd_functions=("${(@)chpwd_functions:#_ggshield_hook}")
"#
        .to_string(),

        // The string branch only unhooks a registration in the shape this file
        // writes — the hook last, after a separator. Somebody who moved it into
        // the middle of their own `PROMPT_COMMAND` by hand keeps it; taking a
        // string apart by pattern is how `a; _ggshield_hook; b` turns into
        // `a; ; b`, which is the syntax error this code exists to avoid.
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
///
/// Hidden: it is an implementation detail of [`Args`], runs on every prompt,
/// and its output is only meaningful to `eval`.
#[derive(clap::Args)]
pub(crate) struct HookArgs {
    /// Shell whose syntax to emit.
    #[arg(value_enum)]
    shell: Shell,
}

pub(crate) fn hook_env(args: HookArgs) -> Result<()> {
    hook_env_to(args, std::io::stdout().is_terminal())
}

/// [`hook_env`], with "is my stdout a terminal" supplied.
///
/// Taken as an argument rather than read here so a test can exercise the refusal
/// without a pseudo-terminal.
fn hook_env_to(args: HookArgs, stdout_is_terminal: bool) -> Result<()> {
    let shell = args.shell;

    // Every other output path in this CLI redacts on a terminal — `get` does it
    // deliberately, and requires `--expose` otherwise. This one prints
    // `export API_KEY='…'` for every secret in scope, so typed at a prompt it
    // dumps the lot into scrollback, a terminal recording, or a CI log somebody
    // pasted it into. It costs the hook nothing to refuse: it always runs inside
    // a command substitution, where stdout is a pipe.
    if stdout_is_terminal {
        bail!(
            "hook-env writes the shell statements that load this directory's secrets, in \
             cleartext, and stdout is a terminal. It is meant to be run by the snippet \
             `ggshield secret activate {}` installs, not by hand",
            shell.name()
        );
    }

    let stored = State::from_env();
    // Whatever an unreadable blob is, it is not ours, and the variables it was
    // supposed to account for are still in the environment with nobody left to
    // unload them. Say so — and clear it, so this is said once rather than
    // before every prompt for the life of the shell.
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
        // Nothing loaded, nothing to load: the overwhelmingly common case on a
        // prompt, and it must cost nothing — no keyring, no decryption, no
        // output at all.
        (None, None) => {
            report_debug(shell, "no dotenv file at or above this directory");
            if unreadable_state {
                emit("", State::CLEARED, shell)?;
            }
            return Ok(());
        }
        // Still in the same file, unchanged since we loaded it, and every
        // variable we exported is still the one we exported. That last clause is
        // what keeps a stale or planted state from short-circuiting a load it has
        // no business short-circuiting.
        (Some(state), Some(found)) if state.matches(found) && state.still_ours() => {
            report_debug(shell, "unchanged since it was loaded");
            return Ok(());
        }
        _ => {}
    }

    let mut script = String::new();
    // Ours to remove only while the value is still the one we set. If the user
    // re-exported it by hand since, it is theirs now and leaving the directory
    // must not take it with us.
    let mut still_ours: Vec<&str> = Vec::new();
    let mut taken_over: Vec<&str> = Vec::new();
    if let Some(state) = &previous {
        for (key, digest) in &state.keys {
            match std::env::var(key) {
                Ok(live) if digest_of(&live) == *digest => {
                    script.push_str(&unset_statement(shell, key)?);
                    still_ours.push(key);
                }
                // Changed by hand, or already gone: either way, not ours.
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

    // A file that is there but must not be read — a symlink, a fifo. `get` and
    // `run` refuse these loudly; walking past one and loading an ancestor's file
    // instead would hand this shell a *different project's* secrets without a
    // word, so the walk stops and says so here too.
    if let Some(refusal) = &found.refusal {
        report_always(shell, refusal);
        return emit_state(&script, &found, Vec::new(), shell);
    }

    // The consent gate. `get`, `run` and `encrypt` are ungated because naming
    // a file on the command line *is* the consent; the hook loads whatever
    // directory you walk into, which is not the same act. Without this, a
    // `.env` in a repository you had just cloned reached your shell before you
    // had read a line of it.
    //
    // Trust covers the file's contents, so a line pushed after you approved it
    // does not inherit that approval. Deliberately not a prompt: a y/n on every
    // `cd` is answered without reading, which is the failure this exists to
    // prevent.
    if !trust::is_trusted(&found.path)? {
        report_always(
            shell,
            &format!(
                "{} is not trusted, so nothing was loaded. Read it, then run `ggshield secret \
                 trust` in that directory",
                found.path.display()
            ),
        );
        return emit_state(&script, &found, Vec::new(), shell);
    }

    // Only now is the keyring touched, and only because the directory really
    // changed. A prompt in an unchanged directory returns above.
    let loaded = match load(&found.path) {
        Ok(loaded) => loaded,
        Err(error) => {
            // A hook cannot be fatal: it runs on every prompt, and a broken
            // file or a locked keyring must not make the shell unusable. Say
            // so once and leave the environment as it is.
            //
            // "Once" is why the state records this file rather than being
            // cleared. Cleared, `previous` was `None` on the next prompt, the
            // unchanged-file fast path could never engage again, and the same
            // two-line message — plus, for a file whose entries need the
            // keyring, the same Security-framework round trip — repeated before
            // every prompt for as long as the shell sat in the directory.
            // Recording it means the report appears once per version of the
            // file; `cd` out and back retries, which is what to do once the
            // keyring is unlocked.
            report_always(shell, &format!("{}: {error:#}", found.path.display()));
            return emit_state(&script, &found, Vec::new(), shell);
        }
    };
    for advisory in &loaded.advisories {
        report(shell, advisory);
    }

    // Only the names we just unset count as replaceable; one the user took
    // over keeps their value.
    let carried_over = still_ours;

    let mut exported = Vec::new();
    let mut shadowed = Vec::new();
    let mut refused = Vec::new();
    for (key, value) in &loaded.fields {
        // Not a variable at all as far as this command is concerned: its value
        // would be executed rather than read. See the module docs.
        if is_shell_control_var(key) {
            refused.push(key.clone());
            continue;
        }
        // A variable the user set themselves outranks the file, the same way
        // it does for `run` — including what "set" means there: a variable
        // exported empty is a placeholder, not a value, and `run` injects over
        // it. One we exported last time is ours to replace.
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
        // Through `report_always`: refusing to do something the file asked for
        // is not a status line, and `GITGUARDIAN_SHELL_OUTPUT=none` must not
        // hide it. It appears once per version of the file, like every other
        // report here.
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

/// Print the statements plus a state that records `found`, whether or not
/// anything was exported.
fn emit_state(script: &str, found: &Found, keys: Vec<(String, u64)>, shell: Shell) -> Result<()> {
    let state = State {
        directory: found.directory.clone(),
        path: found.path.clone(),
        fingerprint: found.fingerprint,
        keys,
    };
    emit(script, &state.encode(), shell)
}

/// Print the statements plus the state assignment, as one eval-able block.
fn emit(script: &str, state: &str, shell: Shell) -> Result<()> {
    print!("{script}");
    print!("{}", export_statement(shell, STATE_VAR, state)?);
    Ok(())
}

/// What one load of a directory produced.
struct Loaded {
    fields: BTreeMap<String, SecretString>,
    /// Remarks about the files, worth showing and never worth failing over.
    advisories: Vec<String>,
}

/// Read the dotenv layers for `path` the same way `run` does.
fn load(path: &Path) -> Result<Loaded> {
    let store = SecretStore::builder(Provider::File)
        .env_override(false)
        .build()?;
    let text = path
        .to_str()
        .context("the dotenv path is not valid UTF-8")?
        .to_string();
    let (fields, warnings) = store.get_secrets_with_warnings(&text)?;
    // The guard `run` applies, for the same reason and with the same rule: a
    // variable that silently fails to appear is indistinguishable from one
    // nobody ever set. `run` refuses to start the child; the hook refuses to
    // export *anything*, because a shell holding half a project's secrets is
    // the same hole, only longer-lived — every command run in that directory
    // gets it, and there is no exit code to notice.
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
    // The same guard `run` applies: a name or value we cannot inject faithfully
    // would silently define something else in the user's shell.
    for (key, value) in &fields {
        validate_env_key(key)?;
        validate_env_value(key, value)?;
    }
    Ok(Loaded {
        fields,
        advisories: warnings.advisories,
    })
}

/// A dotenv file found for the current directory.
struct Found {
    directory: PathBuf,
    path: PathBuf,
    fingerprint: u64,
    /// Why the file must not be read, when it must not be. Recorded like any
    /// other outcome so the message appears once rather than on every prompt.
    refusal: Option<String>,
}

/// The nearest dotenv file at or above the current directory.
///
/// Walking up matters: a project's secrets should not vanish because you
/// stepped into `src/`. The walk stops at the home directory rather than
/// continuing to `/`, so a stray `.env` in a parent of every project cannot
/// quietly load itself into every shell.
///
/// `$HOME` is canonicalised before it is compared, because `current_dir()`
/// returns the *physical* path: with `HOME=/tmp/x` on macOS, where `/tmp` is a
/// symlink to `/private/tmp`, a literal comparison never matches and the walk
/// runs all the way to `/` — loading exactly the stray ancestor file the
/// boundary exists to stop. A home that cannot be resolved at all (no `HOME`, as
/// in a container or a systemd unit) leaves the root as the only boundary.
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
                });
            }
            // There *is* something here, and it is not a file we may read.
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
    None
}

/// Cheap "has this file changed" stamp: modification time and length.
///
/// Not a hash — this runs on every prompt, and a hash would mean reading the
/// whole file each time to answer "no" in the common case. An edit that keeps
/// both the length and the mtime is not a case worth paying for on every
/// prompt; the next `cd` picks it up.
fn fingerprint(metadata: &std::fs::Metadata) -> u64 {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|delta| delta.as_nanos() as u64)
        .unwrap_or(0);
    modified ^ metadata.len().rotate_left(32)
}

/// The user-scope file's contribution to a directory's fingerprint.
///
/// Every load merges that file in, so it is part of what was loaded and has to
/// be part of what "unchanged" means. Fingerprinting the project file alone made
/// a rotated machine-wide credential invisible: `set --scope user` in one shell
/// rewrote the value, and every other shell went on exporting the old one
/// because the project file it was watching had not moved. Costs one extra
/// `stat` per prompt, which is the same order as the one already being paid.
fn user_scope_fingerprint() -> u64 {
    let Ok(path) = user_scope_path() else {
        return 0;
    };
    std::fs::symlink_metadata(&path)
        .map(|metadata| fingerprint(&metadata).rotate_left(17))
        .unwrap_or(0)
}

/// What `$__GITGUARDIAN_ACTIVE` held.
enum Stored {
    /// Unset or empty: nothing was loaded.
    Empty,
    /// Well-formed, and every name in it is a legal variable name.
    Loaded(State),
    /// Set to something that is not a state this version wrote.
    Invalid,
}

/// What the hook loaded last time, as carried in `$__GITGUARDIAN_ACTIVE`.
struct State {
    directory: PathBuf,
    path: PathBuf,
    fingerprint: u64,
    /// Exported name -> digest of the value we gave it.
    keys: Vec<(String, u64)>,
}

/// Version tag the state blob starts with.
///
/// So a blob written by another version is reported as unreadable rather than
/// half-parsed into something that happens to fit.
const STATE_VERSION: &str = "1";

impl State {
    /// The value written when nothing is loaded.
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
            // Every name here ends up in an `unset` statement the shell evals.
            // It was a legal variable name when it was written; anything else
            // arriving now did not come from us. Refusing the whole blob rather
            // than dropping the entry is the point — a state we cannot account
            // for in full is a state we must not act on.
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

    /// Whether `found` is the same file, unchanged, as this state loaded.
    fn matches(&self, found: &Found) -> bool {
        self.directory == found.directory
            && self.path == found.path
            && self.fingerprint == found.fingerprint
    }

    /// Whether every variable this state claims to have exported is still in the
    /// environment with the value it was given.
    ///
    /// Checked before the "nothing changed, return immediately" shortcut. A
    /// state that claims exports the environment does not have is either stale
    /// (something unset them) or not ours, and in both cases the right answer is
    /// to do the full pass rather than to believe it.
    fn still_ours(&self) -> bool {
        self.keys
            .iter()
            .all(|(key, digest)| std::env::var(key).is_ok_and(|live| digest_of(&live) == *digest))
    }

    /// Hex fields, joined by `.`.
    ///
    /// Hex so the shell never has to quote it, and so a path with a newline or a
    /// quote in it cannot break out of the assignment. Field by field rather
    /// than one hex blob with delimiters inside it: `0x1f` is a legal byte in a
    /// Unix path, and a path containing one produced a blob whose own delimiter
    /// count was wrong — the hook then lost track of its exports and left them
    /// in the shell for good. `.` cannot appear in a hex field, so nothing needs
    /// escaping. Hex rather than base64 because it costs no dependency in this
    /// crate and the blob is a couple of paths long, where the doubling does not
    /// matter.
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

/// A short digest of a value, used only to tell "still what we set" from
/// "the user changed it".
///
/// FNV-1a, not a cryptographic hash, and deliberately so: it lives in the
/// environment beside the exported value itself, so an attacker who can read
/// it can already read the plaintext, and nothing here depends on it being
/// hard to invert. What it must be is stable and collision-free enough that a
/// changed value never looks unchanged.
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

/// Variables whose *value is executed*, and which the hook therefore never
/// exports.
///
/// The rule this encodes: a dotenv file may say what a variable holds, not what
/// the shell does. Every name here (and every name under one of the prefixes)
/// makes some later command run something of the file's choosing — a prompt
/// command, a startup file, a preloaded library, a replacement for `ssh` or
/// `git`'s pager. Refusing them is not defence against a hostile *value*, which
/// the quoters already handle; it is defence against a hostile *variable*, where
/// quoting is beside the point because the value is well-formed data that
/// something else has agreed to execute.
///
/// Two things worth being explicit about.
///
/// **Why "the user has not set it" is no protection.** The shadowing rule below
/// skips a variable the environment already has, and `PATH` is only safe by
/// accident because it is always exported. `PROMPT_COMMAND`, `PS1`, `IFS` and
/// `ENV` are *shell* variables, not environment ones, in a normal interactive
/// session — so the file's value wins, and bash runs it.
///
/// **This is a class, not an inventory.** It cannot be complete: every language
/// runtime and every tool with an `*_OPTIONS` or `*_PRELOAD` convention adds to
/// it. What is here is the class the review enumerated plus its immediate
/// neighbours, and the standing rule for adding to it is "does a later command
/// execute this value". A file that wants to set one of these for one command
/// should use `ggshield secret run`, which hands the environment to that command and
/// not to the shell.
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

/// Whether exporting `key` would let a dotenv file change how commands run,
/// rather than what a variable holds. See [`SHELL_CONTROL_VARS`].
fn is_shell_control_var(key: &str) -> bool {
    SHELL_CONTROL_VARS.contains(&key)
        || SHELL_CONTROL_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// `export KEY=<quoted>` in the shell's own syntax.
///
/// The name is validated, not only the value. Names reaching here come from two
/// places: the dotenv layer, which restricts them already, and
/// `$__GITGUARDIAN_ACTIVE`, which is just an environment variable anyone can
/// write. A name is interpolated into the statement unquoted — it has to be, it
/// is a name — so an unvalidated one is arbitrary shell code in the block the
/// shell evals. Checked in both statement builders, beside the quoting the
/// values already get.
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

/// Wrap in single quotes, which are literal in every POSIX shell.
///
/// A single quote cannot be escaped inside single quotes, so the string is
/// closed, an escaped quote is appended, and it is reopened — the standard
/// `'\''` dance. Everything else, newlines and `$` and backticks included,
/// passes through untouched because nothing expands inside single quotes.
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

/// How much the hook says, from `$GITGUARDIAN_SHELL_OUTPUT`.
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

/// A one-line report on stderr, unless the user turned it off.
///
/// Names and counts only — the same rule as everywhere else in this CLI.
/// It goes through the shell rather than straight to our own stderr because
/// our stderr is inside a command substitution the shell is capturing.
fn report(shell: Shell, message: &str) {
    if verbosity() < Verbosity::Normal {
        return;
    }
    report_always(shell, message);
}

/// Why a directory was skipped, at `GITGUARDIAN_SHELL_OUTPUT=debug`.
///
/// The cases a user would ask about — nothing found, a file refused, the walk
/// stopping at `$HOME`, a fingerprint that has not moved — produce no output at
/// all at the default level, by design: this runs on every prompt. `debug` is
/// where they are explained.
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
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
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
            // The only unescaped quote characters must be the outer pair.
            assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            // Round-trip through a real shell: the value must come back byte
            // for byte, which is the property that keeps a secret from being
            // reinterpreted as shell syntax.
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

    /// Finding 4: a *name* is interpolated unquoted, because it has to be — so
    /// it has to be validated instead. Names come back out of
    /// `$__GITGUARDIAN_ACTIVE`, which is an environment variable anybody can
    /// write, and the unset statement built from one is code the shell evals.
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
        // And the legitimate shape still works.
        assert!(unset_statement(Shell::Bash, "API_KEY_2").is_ok());
    }

    /// Finding 4: a state blob carrying such a name is refused as a whole, not
    /// silently reduced to the entries that happen to be well formed.
    #[test]
    fn a_state_naming_something_that_is_not_a_variable_is_refused() {
        let state = State {
            directory: PathBuf::from("/tmp/p"),
            path: PathBuf::from("/tmp/p/.env"),
            fingerprint: 1,
            keys: vec![("EVIL; touch /tmp/x; :".to_string(), 2)],
        };
        assert!(State::decode(&state.encode()).is_none());
        // Not merely unparsable — reported as invalid, so a shell whose exports
        // are now unaccounted for is told about it.
        assert!(
            State::decode("1.2f746d702f70.2f746d702f702f2e656e76.1.6e6f742d68657866").is_none()
        );
    }

    /// Finding 3: a value is data, but some *variables* are executed. Quoting
    /// cannot make `PROMPT_COMMAND` safe, so the name is refused.
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
        // And the ordinary things a dotenv file is for are not swept up.
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
        // Safe in a shell assignment: hex and dots have no quote, space,
        // newline or dollar to reinterpret.
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

    /// Finding 17: `0x1f` is a legal byte in a Unix path, and the old encoding
    /// used it as its field delimiter without escaping. A project under such a
    /// path produced a blob the next prompt could not parse, so the hook lost
    /// track of its own exports and left them in the shell for good.
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

    /// Finding 16: a blob that does not parse is *not* "nothing was loaded".
    /// Read that way, previously exported secrets stayed in the environment for
    /// the life of the shell with nobody left to unset them and no message.
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
        // Empty *is* empty, and is not reported as broken.
        // SAFETY: single-threaded test, and the variable is ours.
        unsafe { std::env::set_var(STATE_VAR, State::CLEARED) };
        assert!(matches!(State::from_env(), Stored::Empty));
        unsafe { std::env::set_var(STATE_VAR, "not-a-state") };
        assert!(matches!(State::from_env(), Stored::Invalid));
        unsafe { std::env::remove_var(STATE_VAR) };
        assert!(matches!(State::from_env(), Stored::Empty));
    }

    /// Finding 10a: `hook-env` is `hide = true`, but it is still a subcommand
    /// anyone can type — and its output is every secret in scope, in cleartext.
    /// `get` redacts on a terminal and demands `--expose`; this refuses
    /// outright, because there is no legitimate way to run it on one.
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

    /// Finding 6: the binary's own path is data too. A space in it made the hook
    /// try to execute the first word — every prompt printed an error and no
    /// secret was ever loaded — and a metacharacter in it executed.
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
            // And never bare: the unquoted form must not appear on its own.
            assert!(
                !script.contains(&format!("command {exe} secret hook-env")),
                "{}: the path was spliced in unquoted",
                shell.name()
            );
        }
    }

    /// Finding 10b: the hook's output *is* assignments of decrypted values, so
    /// `set -x` traces every one of them — at the `eval` in the function, before
    /// anything `hook-env` prints could suppress it. The generated function is
    /// the only place that can turn tracing off.
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
            // The function is defined so it can be called by hand, but nothing
            // is wired up and it is not invoked.
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

    /// Finding 18: `--hook none` has to *remove* a registration, not merely
    /// decline to add one. Emitting nothing left the previous `activate`'s
    /// trigger in place, so directories went on loading secrets.
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
        // Both scripts strip the hook from both arrays first, so switching
        // --hook cannot leave a stale registration behind.
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
        // bash 5.1 made PROMPT_COMMAND an array; appending to the wrong form
        // silently never runs the hook.
        assert!(script.contains("declare -a"));
        assert!(script.contains(
            r#"PROMPT_COMMAND=(${PROMPT_COMMAND[@]+"${PROMPT_COMMAND[@]}"} _ggshield_hook)"#
        ));
        // Finding 13: a trailing separator is trimmed before the append, so a
        // `PROMPT_COMMAND` ending in `;` — the idiom macOS's own bashrc
        // documents — does not become `;;`.
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
            // The trailing bare invocation is the only difference.
            assert!(!installed.trim_end().ends_with("_ggshield_hook"));
            assert!(
                hook_script(shell, Hook::Pwd, true)
                    .trim_end()
                    .ends_with("_ggshield_hook")
            );
        }
    }
}
