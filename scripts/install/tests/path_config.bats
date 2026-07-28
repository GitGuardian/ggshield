#!/usr/bin/env bats
#
# Functional tests for the PATH-configuration behavior in install.sh /
# uninstall.sh. Sources the real functions into a sandboxed $HOME and drives
# fish/nu/pwsh with fake stub binaries — needs no real shell, only bats.
#
#   bats scripts/install/tests/path_config.bats
#
# shellcheck disable=SC2034,SC2030,SC2031 # shellcheck treats each @test body
# as a subshell, which it isn't — modifications made here do persist

bats_require_minimum_version 1.5.0

INSTALL_SH="$BATS_TEST_DIRNAME/../install.sh"
UNINSTALL_SH="$BATS_TEST_DIRNAME/../uninstall.sh"

setup() {
    SANDBOX="$(mktemp -d)"
    export HOME="$SANDBOX"
    export XDG_CONFIG_HOME="$SANDBOX/.config"
    FAKEBIN="$SANDBOX/fakebin"
    mkdir -p "$FAKEBIN"
    export PATH="$FAKEBIN:$PATH"
}

teardown() {
    rm -rf "$SANDBOX"
}

# Sources install.sh's functions without running main(). BIN_DIR/OS are set
# afterwards the same way install_tarball()/detect_platform() would.
load_install() {
    # shellcheck disable=SC1090
    source "$INSTALL_SH"
    BIN_DIR="$HOME/.local/bin"
    OS="${1:-linux}"
}

load_uninstall() {
    # shellcheck disable=SC1090
    source "$UNINSTALL_SH"
}

# Octal permission bits, portable across GNU (Linux CI) and BSD (macOS CI)
# stat: their -c/-f flags and format specifiers are mutually incompatible.
perm_bits() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1"
}

# A fake `fish` faithful enough for the four -c scripts install.sh/uninstall.sh
# run, backing fish_user_paths with $FISH_STORE. Emulates fish's own trailing-
# slash normalization (builtin realpath -s). Knobs via env:
#   FISH_FAIL_ADD=1   fish_add_path exits non-zero
#   FISH_NO_PERSIST=1 fish_add_path succeeds but stores nothing (config.fish
#                     managing fish_user_paths as a global → throwaway no-op)
install_fake_fish() {
    export FISH_STORE="$SANDBOX/fish_user_paths"
    : >"$FISH_STORE"
    cat >"$FAKEBIN/fish" <<'SH'
#!/bin/sh
store="$FISH_STORE"
script="$2"
strip_slash() { s="$1"; while [ "$s" != "${s%/}" ]; do s="${s%/}"; done; printf '%s' "$s"; }
case "$script" in
*"set fish_user_paths"*)          # uninstall removal loop
    # Honor what the fish script actually does: normalize only if it invokes
    # realpath, so a code path that skips canonicalization is genuinely observable.
    case "$script" in
    *realpath*) target=$(strip_slash "$GGSHIELD_FISH_BIN_DIR") ;;
    *) target="$GGSHIELD_FISH_BIN_DIR" ;;
    esac
    tmp="$store.tmp"; : >"$tmp"
    while IFS= read -r line; do [ "$line" = "$target" ] || printf '%s\n' "$line" >>"$tmp"; done <"$store"
    mv "$tmp" "$store"
    ;;
*realpath*)                        # canonicalize (builtin realpath -s)
    strip_slash "$GGSHIELD_FISH_BIN_DIR"; printf '\n'
    ;;
*fish_add_path*)                   # add to fish_user_paths (dedup)
    [ "${FISH_FAIL_ADD:-0}" = 1 ] && exit 1
    [ "${FISH_NO_PERSIST:-0}" = 1 ] && exit 0
    p=$(strip_slash "$GGSHIELD_FISH_BIN_DIR")
    grep -qxF "$p" "$store" 2>/dev/null || printf '%s\n' "$p" >>"$store"
    ;;
*contains*)                        # persistence check
    grep -qxF "$GGSHIELD_FISH_CANON" "$store" 2>/dev/null || exit 1
    ;;
esac
exit 0
SH
    chmod +x "$FAKEBIN/fish"
}

# Regression test: `${BASH_SOURCE[0]}` alone trips "unbound variable" when piped
# (no file on disk); `${BASH_SOURCE[0]:-}` alone then silently skips main() instead.
@test "install.sh runs main() when piped via stdin, not just when sourced" {
    run bash -s -- --help < "$INSTALL_SH"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage: install.sh"* ]]
}

@test "uninstall.sh runs main() when piped via stdin, not just when sourced" {
    run bash -s -- --help < "$UNINSTALL_SH"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage: uninstall.sh"* ]]
}

@test "bash: configures PATH when missing, no prior rc file" {
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    run emit_path_hint_rc bash
    [ "$status" -eq 0 ]
    grep -qxF ". \"$OPT_DIR/env\" $PATH_SENTINEL" "$HOME/.bashrc"
    grep -qF "$BIN_DIR" "$OPT_DIR/env"
    grep -qxF "path_rc_file=$HOME/.bashrc" "$STATE_FILE"
}

@test "write_state preserves a previously-recorded path_rc_file across a reinstall" {
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    mkdir -p "$STATE_DIR"
    write_state
    emit_path_hint_rc bash
    grep -qxF "path_rc_file=$HOME/.bashrc" "$STATE_FILE"

    # Simulate a reinstall post-restart: write_state runs again, but
    # emit_path_hint doesn't fire (nothing left to configure).
    write_state
    grep -qxF "path_rc_file=$HOME/.bashrc" "$STATE_FILE"
}

@test "bash: rerunning the same install is idempotent" {
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    emit_path_hint_rc bash
    emit_path_hint_rc bash
    [ "$(grep -c "ggshield-standalone/env" "$HOME/.bashrc")" -eq 1 ]
}

# F5: record_path_state must not re-append a line write_state already preserved.
@test "state file does not accumulate duplicate path_ lines across same-session reruns" {
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    mkdir -p "$STATE_DIR"
    write_state
    emit_path_hint_rc bash
    write_state           # preserves the path_rc_file line
    emit_path_hint_rc bash # would blind-append it again without the dedup guard
    [ "$(grep -c "^path_rc_file=$HOME/.bashrc$" "$STATE_FILE")" -eq 1 ]
}

@test "zsh: configures ~/.zshrc" {
    load_install
    ASSUME_YES=1 SHELL=/bin/zsh
    run emit_path_hint_rc zsh
    [ "$status" -eq 0 ]
    grep -qxF ". \"$OPT_DIR/env\" $PATH_SENTINEL" "$HOME/.zshrc"
}

@test "--no-modify-path only prints instructions, writes nothing" {
    load_install
    ASSUME_YES=1 NO_MODIFY_PATH=1 SHELL=/bin/bash
    run emit_path_hint_rc bash
    [ "$status" -eq 0 ]
    [ ! -e "$HOME/.bashrc" ]
    [[ "$output" == *"not on your PATH"* ]]
}

@test "fish: runs fish_add_path and records a single self-contained state line" {
    load_install
    install_fake_fish
    ASSUME_YES=1 SHELL=/usr/bin/fish
    run emit_path_hint_fish
    [ "$status" -eq 0 ]
    grep -qxF "$BIN_DIR" "$FISH_STORE"
    grep -qxF "path_fish_bin_dir=$BIN_DIR" "$STATE_FILE"
    # The old two-line (path_shell_bin_dir + path_shell) scheme is gone.
    run ! grep -q "^path_shell=" "$STATE_FILE"
}

@test "assert_safe_path_value rejects characters that could break out of a generated snippet" {
    load_install
    # shellcheck disable=SC1003 # '\' here is one literal backslash char, not a botched escape
    for bad in '"' "'" '`' '$' ';' '\' $'\n'; do
        run assert_safe_path_value TEST "/tmp/x${bad}y"
        [ "$status" -ne 0 ]
    done
    run assert_safe_path_value TEST "/tmp/a-plain-path_123"
    [ "$status" -eq 0 ]
}

# F4: relative dirs would land in profiles as `. "opt/env"`, resolved against
# whatever cwd a future shell starts in.
@test "assert_safe_path_value rejects relative paths and accepts absolute ones" {
    load_install
    for rel in "opt" "./rel" "../rel" ""; do
        run assert_safe_path_value TEST "$rel"
        [ "$status" -ne 0 ]
        [[ "$output" == *"absolute path"* ]]
    done
    run assert_safe_path_value TEST "/abs/path"
    [ "$status" -eq 0 ]
}

# F4/F3: a user-supplied dir with a trailing slash must be normalized once at
# startup so the PATH-membership test and the fish canonical form line up.
@test "trailing slashes are stripped from BIN_DIR/OPT_DIR at startup" {
    GGSHIELD_BIN_DIR="$HOME/.local/bin/" GGSHIELD_OPT_DIR="$HOME/opt/" run bash -c "
        source '$INSTALL_SH'
        printf 'bin=[%s]\nopt=[%s]\n' \"\$BIN_DIR\" \"\$OPT_DIR\"
    "
    [[ "$output" == *"bin=[$HOME/.local/bin]"* ]]
    [[ "$output" == *"opt=[$HOME/opt]"* ]]
}

@test "main() rejects an unsafe GGSHIELD_BIN_DIR before touching the network" {
    GGSHIELD_BIN_DIR='/tmp/x"; touch '"$SANDBOX"'/pwned; #' \
        run bash "$INSTALL_SH" --install-only -y
    [ "$status" -ne 0 ]
    [[ "$output" == *"cannot safely appear"* ]]
    [ ! -e "$SANDBOX/pwned" ]
}

@test "main() rejects a relative GGSHIELD_OPT_DIR before touching the network" {
    GGSHIELD_OPT_DIR='opt' run bash "$INSTALL_SH" --install-only -y
    [ "$status" -ne 0 ]
    [[ "$output" == *"absolute path"* ]]
}

@test "configure_fish passes BIN_DIR via env var, never interpolates it into the fish script text" {
    load_install
    # Emulate realpath so configure_fish proceeds; re-evaluate the other -c
    # scripts as a shell would, so a leftover interpolation bug would fire.
    cat >"$FAKEBIN/fish" <<'SH'
#!/bin/sh
case "$2" in
*realpath*) printf '%s\n' "$GGSHIELD_FISH_BIN_DIR" ;;
*) sh -c "$2" ;;
esac
SH
    chmod +x "$FAKEBIN/fish"
    BIN_DIR="/tmp/evil'; touch $SANDBOX/pwned; echo '"
    run configure_fish
    [ ! -e "$SANDBOX/pwned" ]
}

@test "fish: a failing fish_add_path falls back to the printed hint instead of a false success" {
    load_install
    install_fake_fish
    export FISH_FAIL_ADD=1
    ASSUME_YES=1 SHELL=/usr/bin/fish
    run emit_path_hint_fish
    [ "$status" -eq 0 ]
    [[ "$output" == *"Add it permanently with"* ]]
    [[ "$output" != *"Restart your terminal"* ]]
    [ ! -f "$STATE_FILE" ]
}

# Bug B: a config.fish that manages fish_user_paths as a global makes the
# throwaway `fish -c fish_add_path` a no-op; don't claim success or record it.
@test "fish: does not record success when fish_add_path did not persist" {
    load_install
    install_fake_fish
    export FISH_NO_PERSIST=1
    ASSUME_YES=1 SHELL=/usr/bin/fish
    run emit_path_hint_fish
    [ "$status" -eq 0 ]
    [[ "$output" == *"Add it permanently with"* ]]
    [ ! -f "$STATE_FILE" ] || run ! grep -q "^path_fish_bin_dir=" "$STATE_FILE"
}

@test "bash: a write failure falls back to the printed hint instead of crashing" {
    [ "$(id -u)" = 0 ] && skip "root ignores the permission bits this test relies on"
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    # OPT_DIR doesn't exist yet; making its parent unwritable makes write_env_sh's
    # mkdir fail, without ever needing to touch OPT_DIR itself.
    mkdir -p "$(dirname "$OPT_DIR")"
    chmod 555 "$(dirname "$OPT_DIR")"
    run emit_path_hint_rc bash
    chmod 755 "$(dirname "$OPT_DIR")"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Add it, then restart your terminal"* ]]
    [[ "$output" != *"Restart your terminal (or run"* ]]
    # The rc file must not have been edited (record-first only wrote intent).
    [ ! -e "$HOME/.bashrc" ]
}

@test "nu_config_path resolves per nushell's own XDG_CONFIG_HOME/OS precedence" {
    load_install
    XDG_CONFIG_HOME="" OS=darwin
    [ "$(nu_config_path)" = "$HOME/Library/Application Support/nushell/config.nu" ]

    XDG_CONFIG_HOME="$HOME/.myxdg"
    [ "$(nu_config_path)" = "$HOME/.myxdg/nushell/config.nu" ]

    XDG_CONFIG_HOME="" OS=linux
    [ "$(nu_config_path)" = "$HOME/.config/nushell/config.nu" ]
}

@test "nushell: configured opportunistically when present, independent of \$SHELL" {
    load_install
    printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/nu"
    chmod +x "$FAKEBIN/nu"
    ASSUME_YES=1 SHELL=/bin/bash
    run emit_path_hint_rc bash
    [ "$status" -eq 0 ]
    local nu_cfg="$XDG_CONFIG_HOME/nushell/config.nu"
    grep -qxF "source \"$OPT_DIR/env.nu\" $PATH_SENTINEL" "$nu_cfg"
    grep -qF "prepend" "$OPT_DIR/env.nu"
}

# A real bash subprocess, not `run FUNC`: bats' `run` disables errexit for the
# whole call, so a same-shell run could never observe a set -e abort here.
@test "nushell: a failing (e.g. read-only) config.nu doesn't abort the whole install" {
    load_install # only to compute $OPT_DIR for the assertion below
    printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/nu"
    chmod +x "$FAKEBIN/nu"
    mkdir -p "$XDG_CONFIG_HOME/nushell"
    touch "$XDG_CONFIG_HOME/nushell/config.nu"
    chmod 444 "$XDG_CONFIG_HOME/nushell/config.nu"
    run bash -c "
        source '$INSTALL_SH'
        BIN_DIR=\"\$HOME/.local/bin\"
        OS=linux
        ASSUME_YES=1
        SHELL=/bin/bash
        emit_path_hint_rc bash
    "
    chmod 644 "$XDG_CONFIG_HOME/nushell/config.nu"
    [ "$status" -eq 0 ]
    # bash's own rc edit must still have gone through despite nu failing.
    grep -qxF ". \"$OPT_DIR/env\" $PATH_SENTINEL" "$HOME/.bashrc"
}

@test "pwsh: configured on Linux when present" {
    load_install linux
    printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/pwsh"
    chmod +x "$FAKEBIN/pwsh"
    ASSUME_YES=1 SHELL=/bin/bash OS=linux
    run emit_path_hint_rc bash
    [ "$status" -eq 0 ]
    grep -qxF ". \"$OPT_DIR/env.ps1\" $PATH_SENTINEL" "$XDG_CONFIG_HOME/powershell/profile.ps1"
}

@test "pwsh: NOT configured on macOS even when present" {
    load_install darwin
    printf '#!/bin/sh\nexit 0\n' >"$FAKEBIN/pwsh"
    chmod +x "$FAKEBIN/pwsh"
    ASSUME_YES=1 SHELL=/bin/bash OS=darwin
    run emit_path_hint_rc bash
    [ "$status" -eq 0 ]
    [ ! -e "$XDG_CONFIG_HOME/powershell/profile.ps1" ]
}

# F6: -notcontains is case-insensitive; on a case-sensitive FS it would skip
# adding the real dir when a case-variant is already on PATH.
@test "pwsh: env.ps1 uses the case-sensitive -cnotcontains" {
    load_install
    write_env_ps1
    grep -qF -- "-cnotcontains" "$OPT_DIR/env.ps1"
    run ! grep -qE -- '[^c]notcontains' "$OPT_DIR/env.ps1"
}

@test "uninstall reverses a bash PATH edit without touching unrelated lines" {
    load_install
    ASSUME_YES=1 SHELL=/bin/bash
    mkdir -p "$STATE_DIR"
    write_state
    emit_path_hint_rc bash
    printf '\nexport MY_OTHER_TOOL=1\n' >>"$HOME/.bashrc"

    load_uninstall
    ASSUME_YES=1
    run remove_standalone
    [ "$status" -eq 0 ]
    run ! grep -qF "ggshield-standalone" "$HOME/.bashrc"
    grep -qxF "export MY_OTHER_TOOL=1" "$HOME/.bashrc"
    [ ! -d "$OPT_DIR" ]
}

# F2: a line pointing at a *different* OPT_DIR (an earlier install) still carries
# the sentinel and must be stripped, even though it's not the current opt_dir.
@test "uninstall strips sentinel lines from any opt_dir, not just the recorded one" {
    load_install
    printf '. "%s/other-opt/env" %s\n' "$HOME" "$PATH_SENTINEL" >"$HOME/.bashrc"
    printf 'export KEEP=1\n' >>"$HOME/.bashrc"
    mkdir -p "$STATE_DIR"
    printf 'opt_dir=%s/current-opt\npath_rc_file=%s/.bashrc\n' "$HOME" "$HOME" >"$STATE_FILE"

    load_uninstall
    ASSUME_YES=1
    run remove_path_lines
    [ "$status" -eq 0 ]
    run ! grep -qF "other-opt/env" "$HOME/.bashrc"
    grep -qxF "export KEEP=1" "$HOME/.bashrc"
}

@test "uninstall preserves a symlinked rc file (stow/chezmoi-style) and its permissions" {
    load_install
    # A name of its own: load_uninstall below re-sources uninstall.sh, which
    # recomputes OPT_DIR from the environment (the default), clobbering this.
    local install_opt_dir="$SANDBOX/opt"
    mkdir -p "$install_opt_dir" "$SANDBOX/dotfiles"
    printf 'export EXISTING=1\n. "%s/env" %s\n' "$install_opt_dir" "$PATH_SENTINEL" >"$SANDBOX/dotfiles/bashrc"
    chmod 600 "$SANDBOX/dotfiles/bashrc"
    ln -s "$SANDBOX/dotfiles/bashrc" "$HOME/.bashrc"
    mkdir -p "$STATE_DIR"
    printf 'opt_dir=%s\npath_rc_file=%s/.bashrc\n' "$install_opt_dir" "$HOME" >"$STATE_FILE"

    load_uninstall
    run remove_path_lines
    [ "$status" -eq 0 ]
    [ -L "$HOME/.bashrc" ]
    [ "$(perm_bits "$SANDBOX/dotfiles/bashrc")" = 600 ]
    grep -qxF "export EXISTING=1" "$SANDBOX/dotfiles/bashrc"
    run ! grep -qF "$install_opt_dir" "$SANDBOX/dotfiles/bashrc"
}

# A real bash subprocess, not `run FUNC` (see the matching nushell test above):
# bats' `run` disables errexit for the whole call it wraps.
@test "uninstall's fish removal survives a failing fish -c instead of aborting" {
    load_uninstall # only to compute $STATE_DIR for the setup below
    printf '#!/bin/sh\nexit 1\n' >"$FAKEBIN/fish"
    chmod +x "$FAKEBIN/fish"
    mkdir -p "$STATE_DIR"
    printf 'path_fish_bin_dir=%s/.local/bin\n' "$HOME" >"$STATE_DIR/state"
    run bash -c "source '$UNINSTALL_SH'; remove_path_lines"
    [ "$status" -eq 0 ]
}

@test "uninstall's rc removal survives a tmp-file write failure instead of aborting" {
    load_install
    OPT_DIR="$SANDBOX/opt"
    mkdir -p "$OPT_DIR" "$SANDBOX/rcdir"
    printf '. "%s/env" %s\n' "$OPT_DIR" "$PATH_SENTINEL" >"$SANDBOX/rcdir/.bashrc"
    mkdir -p "$STATE_DIR"
    printf 'opt_dir=%s\npath_rc_file=%s/rcdir/.bashrc\n' "$OPT_DIR" "$SANDBOX" >"$STATE_FILE"
    chmod 555 "$SANDBOX/rcdir"

    run bash -c "source '$UNINSTALL_SH'; remove_path_lines"
    chmod 755 "$SANDBOX/rcdir"
    [ "$status" -eq 0 ]
    # Couldn't write through; the original must survive untouched, not be lost.
    grep -qxF ". \"$OPT_DIR/env\" $PATH_SENTINEL" "$SANDBOX/rcdir/.bashrc"
}

# F1: if the strip can't be verified, deleting OPT_DIR would leave config.nu
# sourcing a now-missing env.nu — which aborts nushell's entire config at parse
# time. The env files must be kept (neutralized) instead of removed.
@test "uninstall keeps env* as stubs when a strip fails, instead of bricking nushell" {
    [ "$(id -u)" = 0 ] && skip "root ignores the permission bits this test relies on"
    load_install
    local opt="$SANDBOX/opt"
    mkdir -p "$opt/ggshield-1.0-x/bin" "$SANDBOX/nudir"
    # shellcheck disable=SC2016 # nushell literal — $env must NOT expand in bash
    printf '$env.PATH = ($env.PATH | prepend "x")\n' >"$opt/env.nu"
    printf 'source "%s/env.nu" %s\n' "$opt" "$PATH_SENTINEL" >"$SANDBOX/nudir/config.nu"
    mkdir -p "$STATE_DIR"
    printf 'opt_dir=%s\nbin_link=%s/.local/bin/ggshield\npath_rc_file_nu=%s/nudir/config.nu\n' \
        "$opt" "$HOME" "$SANDBOX" >"$STATE_FILE"
    chmod 555 "$SANDBOX/nudir" # make the tmp-file write (hence the strip) fail

    load_uninstall
    ASSUME_YES=1 GGSHIELD_OPT_DIR="$opt"
    OPT_DIR="$opt"
    run remove_standalone
    chmod 755 "$SANDBOX/nudir"
    [ "$status" -eq 0 ]
    # env.nu kept (so the surviving `source` still resolves) but neutralized...
    [ -f "$opt/env.nu" ]
    run ! grep -qF "prepend" "$opt/env.nu"
    # ...the binary tree and state are gone / kept for retry.
    [ ! -d "$opt/ggshield-1.0-x" ]
    [ -f "$STATE_FILE" ]
}

# F1 scenario (b): XDG_STATE_HOME differs between install and uninstall, so the
# state file isn't found; OPT_DIR still exists. env* must survive.
@test "uninstall keeps env* when the state file is missing but OPT_DIR exists" {
    load_uninstall
    local opt="$SANDBOX/opt"
    mkdir -p "$opt/ggshield-1.0-x"
    printf '# path shim\n' >"$opt/env"
    ASSUME_YES=1
    OPT_DIR="$opt" BIN_DIR="$HOME/.local/bin"
    run remove_standalone
    [ "$status" -eq 0 ]
    [ -f "$opt/env" ]
    [ ! -d "$opt/ggshield-1.0-x" ]
}

# F3: fish stores the canonicalized (trailing-slash-stripped) form; uninstall
# must re-canonicalize the recorded value so it matches and gets removed.
@test "uninstall removes the fish entry even when the recorded value had a trailing slash" {
    load_install
    install_fake_fish
    printf '%s/.local/bin\n' "$HOME" >"$FISH_STORE"
    printf '%s/other/bin\n' "$HOME" >>"$FISH_STORE"
    mkdir -p "$STATE_DIR"
    printf 'path_fish_bin_dir=%s/.local/bin/\n' "$HOME" >"$STATE_FILE" # note trailing slash

    load_uninstall
    run remove_path_lines
    [ "$status" -eq 0 ]
    run ! grep -qxF "$HOME/.local/bin" "$FISH_STORE"
    grep -qxF "$HOME/other/bin" "$FISH_STORE" # unrelated entry untouched
}

# Bug A: install under a custom GGSHIELD_OPT_DIR, uninstall without it set. The
# uninstaller must target the recorded dir, not the default, or it orphans the
# real install and then deletes its state.
@test "uninstall targets the recorded opt_dir/bin_link, not the current environment's defaults" {
    load_install
    local opt="$SANDBOX/custom-opt" bindir="$SANDBOX/custom-bin"
    mkdir -p "$opt/ggshield-1.0-x/bin" "$bindir"
    printf '#!/bin/sh\n' >"$opt/ggshield-1.0-x/bin/ggshield"
    ln -s "$opt/ggshield-1.0-x/bin/ggshield" "$bindir/ggshield"
    mkdir -p "$STATE_DIR"
    printf 'opt_dir=%s\nbin_link=%s/ggshield\n' "$opt" "$bindir" >"$STATE_FILE"

    load_uninstall # re-sources with default OPT_DIR/BIN_DIR (env unset)
    ASSUME_YES=1
    run remove_standalone
    [ "$status" -eq 0 ]
    [ ! -d "$opt" ]
    [ ! -e "$bindir/ggshield" ]
}

@test "uninstall no longer rejects a pre-PR GGSHIELD_OPT_DIR containing a quote" {
    load_uninstall
    ASSUME_YES=1
    OPT_DIR="$SANDBOX/it's-here"
    mkdir -p "$OPT_DIR"
    run remove_standalone
    [ "$status" -eq 0 ]
}

@test "uninstall empties an rc file whose only content is the ggshield line, leaving no stray tmp file" {
    load_install
    OPT_DIR="$SANDBOX/opt"
    mkdir -p "$OPT_DIR"
    printf '. "%s/env" %s\n' "$OPT_DIR" "$PATH_SENTINEL" >"$HOME/.bashrc"
    mkdir -p "$STATE_DIR"
    printf 'path_rc_file=%s/.bashrc\n' "$HOME" >"$STATE_FILE"

    load_uninstall
    OPT_DIR="$SANDBOX/opt"
    run remove_path_lines
    [ "$status" -eq 0 ]
    run ! grep -qF "$OPT_DIR" "$HOME/.bashrc"
    [ ! -e "$HOME/.bashrc.ggshield-tmp" ]
}
