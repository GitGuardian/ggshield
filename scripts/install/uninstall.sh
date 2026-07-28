#!/usr/bin/env bash
#
# ggshield uninstaller (Linux / macOS).
#
# By default removes ONLY the standalone install this script created
# (the ~/.local/bin symlink and ~/.local/share/ggshield-standalone tree).
# It does not touch ggshield installed another way (Homebrew, apt/rpm, pipx,
# uv, pip…). Pass --purge to also remove ggshield's config, cache and data.
#
#   curl -sSfL \
#     https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.sh | bash

set -euo pipefail

BIN_DIR="${GGSHIELD_BIN_DIR:-$HOME/.local/bin}"
BIN_DIR="${BIN_DIR%/}"
OPT_DIR="${GGSHIELD_OPT_DIR:-$HOME/.local/share/ggshield-standalone}"
OPT_DIR="${OPT_DIR%/}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ggshield-install"

# Must match install.sh: the trailing marker on every rc source line it added.
PATH_SENTINEL="# ggshield-install PATH"

ASSUME_YES=0
PURGE=0
# Set by remove_path_lines: 1 only if every recorded rc line was verifiably
# stripped. Gates whether remove_standalone may delete OPT_DIR (see there).
PATH_STRIP_VERIFIED=1

usage() {
    cat <<EOF
Usage: uninstall.sh [OPTIONS]

Remove the standalone ggshield installed by install.sh. By default this only
removes the script-owned install; it leaves configuration, caches and any
ggshield installed another way untouched.

Options:
  -y, --yes     never prompt
      --purge   also remove config, cache and data
                (~/.gitguardian.yaml, ~/.ggshield, plugins)
  -h, --help    show this help
EOF
}

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply=""
    if [ -t 0 ]; then
        read -r -p "$1 [y/N] " reply
    elif { : </dev/tty; } 2>/dev/null; then
        # the node can exist yet be unopenable (container/CI, no controlling
        # tty); test the actual open so we reach the -y hint instead of dying
        # on `reply` unbound under set -u
        read -r -p "$1 [y/N] " reply </dev/tty
    else
        die "cannot prompt for '$1' (no TTY). Re-run with -y"
    fi
    case "$reply" in
    y* | Y*) return 0 ;;
    *) return 1 ;;
    esac
}

# Never 'rm -rf' a misconfigured OPT_DIR (empty, relative, /, $HOME, the bin dir).
# Relative is rejected too: `rm -rf` would resolve it against the current cwd.
assert_safe_optdir() {
    local p="${OPT_DIR%/}"
    case "$p" in
    "" | [!/]*)
        die "refusing to remove non-absolute OPT_DIR='$OPT_DIR'; use an absolute path" ;;
    "/" | "$HOME" | "${HOME%/}" | "$BIN_DIR" | "${BIN_DIR%/}")
        die "refusing to remove unsafe OPT_DIR='$OPT_DIR'; point it at a dedicated directory" ;;
    esac
}

# Undo install.sh's PATH edits using what it recorded in the state file, not by
# re-detecting the shell (env vars may differ by uninstall time). Best-effort, but
# sets PATH_STRIP_VERIFIED=0 whenever a strip can't be confirmed, so the caller
# knows not to delete OPT_DIR out from under a still-live `source` line.
remove_path_lines() {
    local state_file="$STATE_DIR/state" key value
    # No state file: we can't know which rc files to strip, so nothing is verified.
    [ -f "$state_file" ] || { PATH_STRIP_VERIFIED=0; return 0; }
    while IFS='=' read -r key value; do
        case "$key" in
        path_rc_file | path_rc_file_nu | path_rc_file_pwsh)
            [ -f "$value" ] || continue
            # Strip by our own trailing sentinel, not by the OPT_DIR the line points
            # at: opt_dir-independent, so lines from a prior install under a different
            # OPT_DIR are removed too (and we never touch unrelated user lines).
            #
            # grep -v exits 1 both when nothing survives to output and when the >tmp
            # redirect failed; indistinguishable, so treat both as best-effort.
            local grep_status=0
            # 2>/dev/null must precede the >tmp redirect, else its own failure prints
            # before 2>/dev/null takes effect. Anchored $ so only lines ENDING in the
            # sentinel match, never a user comment that merely contains the words.
            grep -v "${PATH_SENTINEL}$" "$value" 2>/dev/null >"$value.ggshield-tmp" || grep_status=$?
            case "$grep_status" in
            # `cp`, not `mv` (replaces a symlinked rc file with a plain one) or `cat >`
            # (truncates the destination before checking the source is readable): `cp`
            # writes through symlinks, preserves permissions, and won't empty the rc
            # file if the tmp file was never created.
            0 | 1) cp "$value.ggshield-tmp" "$value" 2>/dev/null || PATH_STRIP_VERIFIED=0 ;;
            *) PATH_STRIP_VERIFIED=0 ;;
            esac
            rm -f "$value.ggshield-tmp"
            # Confirm the sentinel is actually gone; a swallowed cp/grep failure above
            # would otherwise leave a live source line while we delete its target.
            grep -q "${PATH_SENTINEL}$" "$value" 2>/dev/null && PATH_STRIP_VERIFIED=0
            ;;
        path_fish_bin_dir)
            # fish stores paths canonicalized (builtin realpath -s); install recorded
            # that exact form. Re-canonicalize here (idempotent) and drop the matching
            # entry. Plain `set` (not -U) updates fish_user_paths in whatever scope it
            # lives in; `set -a keep` preserves entries verbatim where `echo` would
            # mangle newline/flag-like values. BIN_DIR travels via an env var, never
            # interpolated into the fish script text.
            command -v fish >/dev/null 2>&1 || continue
            # shellcheck disable=SC2016 # intentional: fish expands this, not bash
            GGSHIELD_FISH_BIN_DIR="$value" fish -c '
                set -l target (builtin realpath -s -- $GGSHIELD_FISH_BIN_DIR)
                set -l keep
                for p in $fish_user_paths
                    test "$p" != "$target"; and set -a keep $p
                end
                set fish_user_paths $keep' 2>/dev/null || true
            ;;
        esac
    done <"$state_file"
    return 0
}

# Overwrite any surviving env* with a comment-only stub: valid sh/nu/pwsh, so a
# leftover `source`/`.` line still resolves (no nushell parse abort) but stops
# touching PATH. Best-effort — an unwritable file is left intact (still resolvable).
neutralize_env_files() {
    local f
    for f in env env.nu env.ps1; do
        [ -f "$OPT_DIR/$f" ] || continue
        printf '# ggshield uninstalled; this file is intentionally a no-op\n' \
            2>/dev/null >"$OPT_DIR/$f" || true
    done
}

# Removes the bin symlink (only if it points into our own dir — uv/pipx also
# drop a shim in ~/.local/bin), OPT_DIR, and any PATH edit install.sh made.
remove_standalone() {
    # Prefer the recorded install targets over the current environment: GGSHIELD_OPT_DIR/
    # GGSHIELD_BIN_DIR may be unset or different now, and acting on the wrong value would
    # orphan the real install and then delete its state, making it unrecoverable.
    local bin_link="$BIN_DIR/ggshield" k v
    if [ -f "$STATE_DIR/state" ]; then
        while IFS='=' read -r k v; do
            case "$k" in
            opt_dir) [ -n "$v" ] && OPT_DIR="${v%/}" ;;
            bin_link) [ -n "$v" ] && bin_link="$v" ;;
            esac
        done <"$STATE_DIR/state"
    fi

    assert_safe_optdir
    local owns_symlink=0 found=0
    if [ -L "$bin_link" ]; then
        case "$(readlink "$bin_link")" in
        "$OPT_DIR"/*) owns_symlink=1; found=1 ;;
        esac
    fi
    [ -d "$OPT_DIR" ] && found=1
    [ -f "$STATE_DIR/state" ] && grep -q '^path_' "$STATE_DIR/state" 2>/dev/null && found=1

    if [ "$found" = 0 ]; then
        warn "no script-managed standalone install found in $OPT_DIR"
        warn "ggshield installed another way (brew, apt/rpm, pipx, uv, pip) is left untouched"
        return 0
    fi

    confirm "Remove the standalone ggshield ($OPT_DIR and its symlink $bin_link)?" || return 0
    if [ "$owns_symlink" = 1 ]; then
        say "Removing $bin_link"
        rm -f "$bin_link"
    fi
    remove_path_lines
    if [ "$PATH_STRIP_VERIFIED" = 1 ]; then
        say "Removing $OPT_DIR"
        rm -rf "$OPT_DIR"
        rm -rf "$STATE_DIR"
    else
        warn "could not verify every shell-profile edit was removed; keeping $OPT_DIR/env* as no-op stubs so shell startup keeps working (re-run uninstall once fixed)"
        neutralize_env_files
        find "$OPT_DIR" -mindepth 1 -maxdepth 1 \
            ! -name env ! -name env.nu ! -name env.ps1 -exec rm -rf {} + 2>/dev/null || true
        rmdir "$OPT_DIR" 2>/dev/null || true
    fi
}

purge_user_data() {
    # platformdirs(appname="ggshield") config/cache/data, the global config
    # file, and the scan databases (~/.ggshield)
    local paths=("$HOME/.gitguardian.yaml" "$HOME/.ggshield")
    if [ "$(uname -s)" = Darwin ]; then
        paths+=("$HOME/Library/Application Support/ggshield" "$HOME/Library/Caches/ggshield")
    else
        paths+=(
            "${XDG_CONFIG_HOME:-$HOME/.config}/ggshield"
            "${XDG_CACHE_HOME:-$HOME/.cache}/ggshield"
            "${XDG_DATA_HOME:-$HOME/.local/share}/ggshield"
        )
    fi
    local p found=0
    for p in "${paths[@]}"; do [ -e "$p" ] && found=1; done
    if [ "$found" = 0 ]; then
        say "No ggshield config/cache/data found"
        return 0
    fi
    confirm "Remove ggshield configuration, cache and data (including plugins)?" || return 0
    for p in "${paths[@]}"; do
        [ -e "$p" ] && { say "Removing $p"; rm -rf "$p"; }
    done
    # Explicit return 0: the loop's last [ -e ] test can leave $?=1 under set -e.
    return 0
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -y | --yes) ASSUME_YES=1 ;;
        --purge) PURGE=1 ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
        esac
        shift
    done

    remove_standalone
    [ "$PURGE" = 1 ] && purge_user_data

    hash -r 2>/dev/null || true
    say "Done."
}

# Lets tests `source` this file without running main. BASH_SOURCE is empty (not unset)
# when piped (curl|bash); a naive `:-` default would then wrongly skip main entirely.
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
