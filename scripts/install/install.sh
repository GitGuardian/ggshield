#!/usr/bin/env bash
#
# ggshield installer (Linux / macOS).
#
# Installs the standalone ggshield build into ~/.local/bin (no sudo), then
# best-effort authenticates and installs any requested plugins.
#
#   curl -sSfL \
#     https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh | bash
#
# See scripts/install/README.md for options and other install methods.
# Cleanup: uninstall.sh.

set -euo pipefail

# All paths derive from $HOME; fail early with a clear message (die() isn't defined yet).
[ -n "${HOME:-}" ] || { printf '\033[1;31merror:\033[0m HOME is not set\n' >&2; exit 1; }

GITHUB_REPO="GitGuardian/ggshield"
DEFAULT_INSTANCE="https://dashboard.gitguardian.com"
EU_INSTANCE="https://dashboard.eu1.gitguardian.com"

# Trailing slash stripped so the PATH-membership test and the fish canonical
# form (builtin realpath -s) match what a user-supplied dir with a slash yields.
BIN_DIR="${GGSHIELD_BIN_DIR:-$HOME/.local/bin}"
BIN_DIR="${BIN_DIR%/}"
# NOT ~/.local/share/ggshield: that is ggshield's own data dir (plugins…)
OPT_DIR="${GGSHIELD_OPT_DIR:-$HOME/.local/share/ggshield-standalone}"
OPT_DIR="${OPT_DIR%/}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ggshield-install"
STATE_FILE="$STATE_DIR/state"

# Trailing marker on each rc source line so uninstall strips exactly the lines
# we added, regardless of the OPT_DIR they point at. Kept identical in uninstall.sh.
PATH_SENTINEL="# ggshield-install PATH"

ASSUME_YES=0
INSTALL_ONLY=0
NO_MODIFY_PATH=0
# Set when BIN_DIR is not on PATH; drives the final emit_path_hint summary.
PATH_NEEDS_SETUP=0
# Path of an older ggshield shadowing the fresh one when BIN_DIR is already on PATH.
SHADOWED_BY=""
PLUGINS=()
# honor GITGUARDIAN_INSTANCE like ggshield does; --instance overrides it
INSTANCE="${GITGUARDIAN_INSTANCE:-}"
VERSION="${GGSHIELD_VERSION:-}"

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install the standalone ggshield build, then authenticate and (optionally)
install plugins. Other install methods (Homebrew, apt/rpm, pipx) are listed
in scripts/install/README.md.

Options:
  -y, --yes           never prompt, accept defaults (for CI)
      --instance URL  GitGuardian instance to authenticate against
                      (default: $DEFAULT_INSTANCE)
      --version X.Y.Z ggshield version to install (default: latest;
                      also via GGSHIELD_VERSION env var)
      --install-only  install ggshield only, skip auth and plugins
      --plugin NAME   install this ggshield plugin (repeatable)
      --no-modify-path
                      don't offer to add the install dir to PATH; only print
                      instructions
  -h, --help          show this help

Environment:
  GITGUARDIAN_API_KEY  authenticate with this API key instead of the browser
                       flow (token login; combine with --instance)
  GGSHIELD_BIN_DIR     symlink dir (default ~/.local/bin)
  GGSHIELD_OPT_DIR     extraction dir (default ~/.local/share/ggshield-standalone)
  GGSHIELD_REQUIRE_ATTESTATION
                       set to 1 (or true/yes/on) to require gh build-provenance
                       verification on top of the sha256 check; fails the install
                       if gh is missing, older than 2.56.0, unauthenticated, or
                       cannot verify the artifact (default: off)
EOF
}

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

fetch() {
    curl --proto '=https' --tlsv1.2 -sSfL --retry 3 "$@"
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# BIN_DIR/OPT_DIR are interpolated into generated shell/nu/ps1/fish snippets and
# sourced from an arbitrary cwd, so they must be absolute and free of chars that
# could break out of those string contexts. Both arms die, so `case` (which is 0
# on no match) never trips set -e as a trailing `&& die` would.
assert_safe_path_value() {
    case "$2" in
    '' | [!/]*)
        die "$1='$2' must be an absolute path (start with /)"
        ;;
    *[\"\'\`\$\;\\]* | *$'\n'*)
        die "$1='$2' contains a quote, backtick, \$, ;, backslash, or newline, which cannot safely appear in a generated PATH snippet; use a plain path"
        ;;
    esac
}

# No browser for OAuth in a remote/headless session; ggshield's --method oob is the way out.
is_headless() {
    [ -n "${SSH_CONNECTION:-}${SSH_TTY:-}" ] && return 0
    [ "$OS" = linux ] && [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && return 0
    return 1
}

detect_platform() {
    case "$(uname -s)" in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    MINGW* | MSYS* | CYGWIN*)
        die "Windows is not supported by this script. Use install.ps1 instead: \
irm https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/install/install.ps1 | iex"
        ;;
    *) die "unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
    x86_64 | amd64) ARCH=x86_64 ;;
    arm64 | aarch64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
    esac

    if [ "$OS" = darwin ]; then
        LIBC=""
        # uname -m lies under Rosetta 2; sysctl does not (rustup pattern)
        if [ "$ARCH" = x86_64 ] &&
            [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
            ARCH=arm64
        fi
        TARGET="$ARCH-apple-darwin"
    else
        LIBC=gnu
        # base Alpine has no ldd (musl-utils), so check the loader file too
        if [ -e "/lib/ld-musl-$(uname -m).so.1" ] ||
            ldd --version 2>&1 | grep -qi musl; then
            LIBC=musl
        fi
        # ggshield's Linux target triple uses the kernel arch name (aarch64);
        # macOS keeps arm64.
        local linux_arch="$ARCH"
        [ "$ARCH" = arm64 ] && linux_arch=aarch64
        TARGET="$linux_arch-unknown-linux-gnu"
    fi

    # The standalone build is glibc-only; there is no musl tarball.
    if [ "$LIBC" = musl ]; then
        die "the standalone build is glibc-only; Alpine/musl is not supported here.
Use the Docker image (gitguardian/ggshield) or 'pipx install ggshield'.
See https://docs.gitguardian.com/ggshield-docs/getting-started"
    fi
}

resolve_version() {
    if [ -n "$VERSION" ]; then
        VERSION="${VERSION#v}"
        return 0
    fi
    say "Resolving latest ggshield version"
    VERSION=$(fetch "https://api.github.com/repos/$GITHUB_REPO/releases/latest" |
        grep -o '"tag_name": *"v[^"]*"' | head -1 | grep -o '[0-9][^"]*') || true
    [ -n "$VERSION" ] || die "could not resolve the latest version from the GitHub API"
}

# Pair each asset "name" with the "digest" that follows it in the release JSON.
asset_digest() {
    local asset="$1"
    fetch "https://api.github.com/repos/$GITHUB_REPO/releases/tags/v$VERSION" |
        grep -o '"name": *"[^"]*"\|"digest": *"sha256:[0-9a-f]*"' |
        grep -A1 -F "\"$asset\"" | grep -o 'sha256:[0-9a-f]*' | head -1 || true
}

# HEAD the asset URL to tell "absent" (404) from "unreachable" (504/000).
# Not the `fetch` wrapper: no -f, so 4xx still yields a status code.
asset_http_status() {
    curl --proto '=https' --tlsv1.2 -sIL -o /dev/null -w '%{http_code}' \
        --max-time 20 --retry 2 \
        "https://github.com/$GITHUB_REPO/releases/download/v$VERSION/$1" \
        2>/dev/null || echo 000
}

# sha256 is mandatory and fails closed; gh provenance is opt-in (verify_attestation).
verify_download() {
    local file="$1" asset="$2" digest sum_tool
    digest=$(asset_digest "$asset")
    [ -n "$digest" ] ||
        die "could not retrieve the expected sha256 digest for $asset from the GitHub API; refusing to install unverified"

    if command -v sha256sum >/dev/null 2>&1; then
        sum_tool="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sum_tool="shasum -a 256"
    else
        die "cannot verify $asset: no sha256 tool found (need sha256sum or shasum)"
    fi
    say "Verifying sha256 checksum"
    echo "${digest#sha256:}  $file" | $sum_tool -c - >/dev/null ||
        die "checksum mismatch for $asset"

    verify_attestation "$file" "$asset"
}

# 1/true/yes/on enable it, unset/0/false/no/off disable; warn (not silently ignore) anything else.
require_attestation() {
    local v="${GGSHIELD_REQUIRE_ATTESTATION:-}"
    v="${v#"${v%%[![:space:]]*}"}" # strip leading whitespace
    v="${v%"${v##*[![:space:]]}"}" # strip trailing whitespace
    case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | on) return 0 ;;
    '' | 0 | false | no | off) return 1 ;;
    *)
        warn "unrecognized GGSHIELD_REQUIRE_ATTESTATION value '$GGSHIELD_REQUIRE_ATTESTATION'; treating as off (use 1 to require)"
        return 1
        ;;
    esac
}

# Opt-in, off by default: gh isn't a ggshield dependency and running it automatically
# is fragile; the mandatory sha256 already covers integrity. Fails closed when opted in.
verify_attestation() {
    local file="$1" asset="$2"

    if ! require_attestation; then
        say "Skipping build provenance check (set GGSHIELD_REQUIRE_ATTESTATION=1 to require it). To verify a downloaded asset yourself:"
        printf '    gh attestation verify <asset> --repo %s\n' "$GITHUB_REPO"
        return 0
    fi

    command -v gh >/dev/null 2>&1 ||
        die "GGSHIELD_REQUIRE_ATTESTATION is set but gh is not installed (need gh >= 2.56.0)"
    gh attestation --help >/dev/null 2>&1 ||
        die "GGSHIELD_REQUIRE_ATTESTATION is set but this gh is too old for 'gh attestation' (need >= 2.56.0; e.g. 'brew upgrade gh')"
    gh auth status >/dev/null 2>&1 ||
        die "GGSHIELD_REQUIRE_ATTESTATION is set but gh is not authenticated; run 'gh auth login'"
    say "Verifying build provenance attestation"
    gh attestation verify "$file" --repo "$GITHUB_REPO" >/dev/null ||
        die "build provenance verification failed for $asset: it does not match $GITHUB_REPO"
}

install_tarball() {
    need tar
    resolve_version

    local asset dir tmp bin
    asset="ggshield-$VERSION-$TARGET.tar.gz"
    case "$(asset_http_status "$asset")" in
    200) ;;
    404) die "release v$VERSION has no standalone asset $asset.
arm64 Linux builds ship from v1.52.0 on; pick a newer --version, or see the
other install methods in scripts/install/README.md" ;;
    *) warn "could not confirm $asset availability; attempting the download anyway" ;;
    esac

    dir="$OPT_DIR/ggshield-$VERSION-$TARGET"
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064 # expand now: $tmp is local, gone at exit time
    trap "rm -rf '$tmp'" EXIT

    say "Downloading $asset"
    # Download to a file first: never pipe the network into tar
    fetch -o "$tmp/$asset" \
        "https://github.com/$GITHUB_REPO/releases/download/v$VERSION/$asset"
    verify_download "$tmp/$asset" "$asset"

    say "Installing to $dir"
    rm -rf "$dir"
    mkdir -p "$OPT_DIR"
    tar -xzf "$tmp/$asset" -C "$OPT_DIR"
    [ -d "$dir" ] || die "unexpected archive layout: $dir not found after extraction"

    bin=$(find "$dir" -type f -name ggshield | head -1)
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        die "no ggshield executable found in $dir"
    fi
    mkdir -p "$BIN_DIR"
    if [ -e "$BIN_DIR/ggshield" ] && [ ! -L "$BIN_DIR/ggshield" ]; then
        die "$BIN_DIR/ggshield exists and is not a symlink (manually installed?); remove it first"
    fi
    if [ -L "$BIN_DIR/ggshield" ]; then
        case "$(readlink "$BIN_DIR/ggshield")" in
        "$OPT_DIR"/*) ;;
        *) warn "replacing existing ggshield symlink at $BIN_DIR/ggshield (was: $(readlink "$BIN_DIR/ggshield"))" ;;
        esac
    fi
    ln -sf "$bin" "$BIN_DIR/ggshield"

    # Defer "not on PATH" guidance to the end (emit_path_hint), not buried before auth/plugin output.
    case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) PATH_NEEDS_SETUP=1 ;;
    esac
    GGSHIELD="$BIN_DIR/ggshield"
}

write_state() {
    mkdir -p "$STATE_DIR"
    # Preserve any path_* lines from a prior run: a reinstall only re-records them
    # when PATH still needs setup, so otherwise an upgrade would orphan uninstall's target.
    local existing_path_lines=""
    if [ -f "$STATE_FILE" ]; then
        existing_path_lines=$(grep '^path_' "$STATE_FILE" 2>/dev/null || true)
    fi
    {
        cat <<EOF
method=tarball
version=${VERSION:-latest}
opt_dir=$OPT_DIR
bin_link=$BIN_DIR/ggshield
EOF
        # `if`, not `&&`: as the group's last statement, a false `&&` test would trip set -e.
        if [ -n "$existing_path_lines" ]; then
            printf '%s\n' "$existing_path_lines"
        fi
    } >"$STATE_FILE"
}

run_gg() {
    # Children may prompt; reconnect stdin to the terminal when we are piped.
    # /dev/tty can exist yet be unopenable (no controlling terminal, e.g. CI or
    # a container), so test that it actually opens — not just that it exists.
    if [ ! -t 0 ] && { : </dev/tty; } 2>/dev/null; then
        "$GGSHIELD" "$@" </dev/tty
    else
        "$GGSHIELD" "$@"
    fi
}

# Hints for steps that did NOT complete (auth failed/skipped, plugin failed, --install-only).
emit_auth_hint() {
    local inst="${INSTANCE:-$DEFAULT_INSTANCE}"
    printf '    ggshield auth login --instance %s\n' "$inst"
    [ -z "$INSTANCE" ] &&
        printf '    # EU workspace: ggshield auth login --instance %s\n' "$EU_INSTANCE"
    is_headless && printf '    # headless / no browser: add --method oob\n'
    return 0
}

emit_plugin_hint() {
    [ ${#PLUGINS[@]} -gt 0 ] &&
        printf '    ggshield plugin install %s\n' "${PLUGINS[*]}"
    return 0
}

# ~/.local/bin isn't guaranteed to be on PATH (macOS never adds it; Debian/Ubuntu
# only from login). Uses $SHELL, the login shell, not $0 (always bash under curl|bash).
# SHADOWED_BY stays advisory-only: reordering PATH could fight a deliberate setup.
emit_path_hint() {
    local login_shell
    login_shell="$(basename "${SHELL:-sh}")"
    if [ "$login_shell" = fish ]; then
        emit_path_hint_fish
    else
        emit_path_hint_rc "$login_shell"
    fi
}

# fish persists PATH via universal variables (no file edit, no restart needed);
# --move pulls BIN_DIR to the front for the shadow case.
print_fish_hint() {
    if [ -n "$SHADOWED_BY" ]; then
        warn "an older ggshield at $SHADOWED_BY shadows the new one; move $BIN_DIR to the front with:"
        printf '    fish_add_path --move -- "%s"\n' "$BIN_DIR"
    else
        warn "$BIN_DIR is not on your PATH. Add it permanently with:"
        printf '    fish_add_path -- "%s"\n' "$BIN_DIR"
    fi
}

emit_path_hint_fish() {
    if [ -n "$SHADOWED_BY" ] || [ "$NO_MODIFY_PATH" = 1 ]; then
        print_fish_hint
        return 0
    fi
    warn "$BIN_DIR is not on your PATH."
    if ! confirm_path_update; then
        print_fish_hint
        return 0
    fi
    if ! configure_fish; then
        print_fish_hint
        return 0
    fi
    configure_extra_shells
    export PATH="$BIN_DIR:$PATH"
    say "Restart your terminal to use ggshield directly."
}

# Headline via warn() (stderr, bold) so it isn't missed among the copy-pasteable
# stdout commands below. Paths are double-quoted for a BIN_DIR/rc with spaces.
print_rc_hint() {
    local rc="$1" reload="$2" headline
    if [ -n "$SHADOWED_BY" ]; then
        headline="an older ggshield at $SHADOWED_BY shadows the new one; put $BIN_DIR first on your PATH, then restart your terminal:"
    else
        headline="$BIN_DIR is not on your PATH. Add it, then restart your terminal:"
    fi
    warn "$headline"
    # shellcheck disable=SC2016 # intentional: printing a literal command, not expanding it
    printf '    echo '\''export PATH="%s:$PATH"'\'' >> "%s"\n' "$BIN_DIR" "$rc"
    printf '    # (or apply it to the current shell now: %s "%s")\n' "$reload" "$rc"
}

emit_path_hint_rc() {
    local login_shell="$1" rc reload="source"
    case "$login_shell" in
    zsh) rc="$HOME/.zshrc" ;;
    bash) rc="$(bash_rc_path)" ;;
    *)
        rc="$HOME/.profile"
        reload="."
        ;;
    esac

    if [ -n "$SHADOWED_BY" ] || [ "$NO_MODIFY_PATH" = 1 ]; then
        print_rc_hint "$rc" "$reload"
        return 0
    fi
    warn "$BIN_DIR is not on your PATH."
    if ! confirm_path_update; then
        print_rc_hint "$rc" "$reload"
        return 0
    fi
    if ! configure_rc "$rc"; then
        print_rc_hint "$rc" "$reload"
        return 0
    fi
    configure_extra_shells
    export PATH="$BIN_DIR:$PATH"
    say "Restart your terminal (or run: $reload \"$rc\") to use ggshield directly."
}

# Enter defaults to yes; a non-interactive run with no /dev/tty declines rather
# than silently editing dotfiles without consent.
confirm_path_update() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply=""
    if [ -t 0 ]; then
        read -r -p "Add $BIN_DIR to your PATH now? [Y/n] " reply
    elif { : </dev/tty; } 2>/dev/null; then
        read -r -p "Add $BIN_DIR to your PATH now? [Y/n] " reply </dev/tty
    else
        return 1
    fi
    case "$reply" in
    '' | y* | Y*) return 0 ;;
    *) return 1 ;;
    esac
}

# nu/pwsh are rarely the login shell, so $SHELL can't detect them; configure them
# whenever present instead. `|| true` keeps a write failure from tripping set -e.
configure_extra_shells() {
    command -v nu >/dev/null 2>&1 && { configure_nu || true; }
    [ "$OS" = linux ] && command -v pwsh >/dev/null 2>&1 && { configure_pwsh || true; }
    return 0
}

# Records what this run touched so uninstall.sh can reverse it without re-detecting
# the shell. Deduped: emit_path_hint can fire on repeated same-session reruns (PATH
# still off), and write_state preserves prior path_* lines — a blind append would grow the file.
record_path_state() {
    mkdir -p "$STATE_DIR"
    grep -qxF "$1" "$STATE_FILE" 2>/dev/null || printf '%s\n' "$1" >>"$STATE_FILE"
}

configure_fish() {
    command -v fish >/dev/null 2>&1 || return 1
    local canonical
    # Record the form fish actually stores (builtin realpath -s: absolute, trailing
    # slash and .. collapsed, symlinks NOT resolved) so uninstall can match it exactly.
    # BIN_DIR travels through an env var, not string interpolation, so it can't become fish script.
    # shellcheck disable=SC2016 # intentional: fish expands this, not bash
    canonical=$(GGSHIELD_FISH_BIN_DIR="$BIN_DIR" fish -c 'builtin realpath -s -- "$GGSHIELD_FISH_BIN_DIR"' 2>/dev/null) || return 1
    [ -n "$canonical" ] || return 1
    # shellcheck disable=SC2016 # intentional: fish expands this, not bash
    GGSHIELD_FISH_BIN_DIR="$BIN_DIR" fish -c 'fish_add_path -- "$GGSHIELD_FISH_BIN_DIR"' 2>/dev/null || return 1
    # fish_add_path defaults to universal only when fish_user_paths doesn't already
    # exist; a config.fish that manages it as a global makes the call above a no-op
    # in this throwaway process. Confirm it persisted before claiming success.
    # shellcheck disable=SC2016 # intentional: fish expands this, not bash
    GGSHIELD_FISH_CANON="$canonical" fish -c 'contains -- "$GGSHIELD_FISH_CANON" $fish_user_paths' 2>/dev/null || return 1
    record_path_state "path_fish_bin_dir=$canonical"
    say "Added $BIN_DIR to PATH (fish universal variable)"
}

# Mirrors nushell's own config-dir resolution: $XDG_CONFIG_HOME wins when set,
# else macOS defaults to ~/Library/Application Support, not ~/.config.
nu_config_path() {
    if [ -n "${XDG_CONFIG_HOME:-}" ]; then
        printf '%s/nushell/config.nu' "$XDG_CONFIG_HOME"
    elif [ "$OS" = darwin ]; then
        printf '%s/Library/Application Support/nushell/config.nu' "$HOME"
    else
        printf '%s/.config/nushell/config.nu' "$HOME"
    fi
}

# The three configure_* below record the rc file BEFORE editing it: if the record
# step failed after the edit, uninstall would never learn to strip the line and would
# then delete OPT_DIR out from under a live `source`. Recorded-but-never-edited is
# harmless (uninstall's strip finds no sentinel and no-ops).
configure_nu() {
    local cfg
    cfg="$(nu_config_path)"
    record_path_state "path_rc_file_nu=$cfg"
    write_env_nu || return 1
    append_line_once "$cfg" "source \"$OPT_DIR/env.nu\" $PATH_SENTINEL" || return 1
    say "Added $BIN_DIR to PATH via $cfg"
}

configure_pwsh() {
    local cfg="${XDG_CONFIG_HOME:-$HOME/.config}/powershell/profile.ps1"
    record_path_state "path_rc_file_pwsh=$cfg"
    write_env_ps1 || return 1
    append_line_once "$cfg" ". \"$OPT_DIR/env.ps1\" $PATH_SENTINEL" || return 1
    say "Added $BIN_DIR to PATH via $cfg"
}

configure_rc() {
    local rc="$1"
    record_path_state "path_rc_file=$rc"
    write_env_sh || return 1
    append_line_once "$rc" ". \"$OPT_DIR/env\" $PATH_SENTINEL" || return 1
    say "Added $BIN_DIR to PATH via $rc"
}

# macOS bash login shells read the FIRST of these that exists; reuse whichever
# does so we don't shadow it. Linux interactive shells read ~/.bashrc.
bash_rc_path() {
    if [ "$OS" = darwin ]; then
        local f rc="$HOME/.bash_profile"
        for f in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
            if [ -e "$f" ]; then
                rc="$f"
                break
            fi
        done
        printf '%s' "$rc"
    else
        printf '%s' "$HOME/.bashrc"
    fi
}

# Idempotent: skip if $line is already in $file.
append_line_once() {
    local file="$1" line="$2"
    mkdir -p "$(dirname "$file")" 2>/dev/null || return 1
    touch "$file" 2>/dev/null || return 1
    grep -qxF "$line" "$file" 2>/dev/null || printf '\n%s\n' "$line" 2>/dev/null >>"$file" || return 1
}

# A small sourced file, not a baked-in rc line: uninstall deletes it + one rc line,
# and fixing the PATH logic later only means regenerating it.
write_env_sh() {
    mkdir -p "$OPT_DIR" 2>/dev/null || return 1
    cat 2>/dev/null >"$OPT_DIR/env" <<EOF || return 1
# ggshield shell setup
case ":\${PATH}:" in
*:"$BIN_DIR":*) ;;
*) export PATH="$BIN_DIR:\$PATH" ;;
esac
EOF
}

write_env_nu() {
    mkdir -p "$OPT_DIR" 2>/dev/null || return 1
    cat 2>/dev/null >"$OPT_DIR/env.nu" <<EOF || return 1
# ggshield shell setup
\$env.PATH = (\$env.PATH | prepend "$BIN_DIR" | uniq)
EOF
}

write_env_ps1() {
    mkdir -p "$OPT_DIR" 2>/dev/null || return 1
    # -cnotcontains: PowerShell's -notcontains is case-insensitive, which on a
    # case-sensitive Linux filesystem would treat /x/.Local/bin as already present
    # and skip adding the real /x/.local/bin.
    cat 2>/dev/null >"$OPT_DIR/env.ps1" <<EOF || return 1
# ggshield shell setup
if ((\$env:PATH -split [IO.Path]::PathSeparator) -cnotcontains "$BIN_DIR") {
    \$env:PATH = "$BIN_DIR" + [IO.Path]::PathSeparator + \$env:PATH
}
EOF
}

try_auth() {
    local inst="${INSTANCE:-$DEFAULT_INSTANCE}"
    if [ -n "${GITGUARDIAN_API_KEY:-}" ]; then
        say "Authenticating with GITGUARDIAN_API_KEY against $inst"
        # token login reads the key from stdin; do not use run_gg (it would
        # rebind stdin to /dev/tty)
        printf '%s\n' "$GITGUARDIAN_API_KEY" |
            "$GGSHIELD" auth login --method token ${INSTANCE:+--instance "$INSTANCE"} &&
            return 0
        warn "authentication with GITGUARDIAN_API_KEY failed (instance: $inst)"
        return 1
    fi
    if [ "$ASSUME_YES" = 1 ]; then
        warn "non-interactive run (-y) without GITGUARDIAN_API_KEY: skipping auth"
        return 1
    fi
    say "Authenticating against $inst"
    is_headless &&
        warn "headless/remote session detected; if the browser flow fails, retry with --method oob"
    run_gg auth login ${INSTANCE:+--instance "$INSTANCE"} && return 0
    warn "authentication failed (instance: $inst)"
    return 1
}

post_install() {
    hash -r 2>/dev/null || true
    # actually run it: an executable can still fail (e.g. wrong libc)
    local version_out
    if ! version_out=$("$GGSHIELD" --version 2>&1); then
        die "ggshield was installed but cannot run: $version_out"
    fi
    say "Installed: $version_out"

    # An older ggshield earlier on PATH shadows the one we just linked; route through
    # emit_path_hint (same fix as "not on PATH") only when BIN_DIR is already on PATH.
    local resolved
    resolved=$(command -v ggshield 2>/dev/null || true)
    if [ "$PATH_NEEDS_SETUP" = 0 ] && [ -n "$resolved" ] && [ "$resolved" != "$GGSHIELD" ]; then
        SHADOWED_BY="$resolved"
        PATH_NEEDS_SETUP=1
    fi

    if [ "$INSTALL_ONLY" = 1 ]; then
        # --install-only skips auth, so any --plugin is deferred rather than silently dropped.
        [ ${#PLUGINS[@]} -gt 0 ] &&
            warn "--plugin not installed: --install-only skips authentication; run the steps below once authenticated"
        say "ggshield is installed. To finish setup:"
        [ "$PATH_NEEDS_SETUP" = 1 ] && emit_path_hint
        emit_auth_hint
        emit_plugin_hint
        return 0
    fi

    # Plugins need a working auth, so only attempt them once auth succeeds.
    local auth_ok=0 plugins_pending=0
    if try_auth; then
        auth_ok=1
        local plugin
        # macOS ships bash 3.2: "${arr[@]}" on an empty array trips set -u without this guard.
        for plugin in ${PLUGINS[@]+"${PLUGINS[@]}"}; do
            say "Installing the $plugin plugin"
            run_gg plugin install "$plugin" ||
                { warn "could not install the $plugin plugin (continuing)"; plugins_pending=1; }
        done
    elif [ ${#PLUGINS[@]} -gt 0 ]; then
        warn "skipping plugin install until ggshield is authenticated"
        plugins_pending=1
    fi

    # Only nag about next steps when something remains; PATH setup counts as unfinished too.
    if [ "$auth_ok" = 1 ] && [ "$plugins_pending" = 0 ] && [ "$PATH_NEEDS_SETUP" = 0 ]; then
        say "ggshield is ready."
        return 0
    fi
    say "To finish setup:"
    # PATH first: the other hints below assume ggshield is callable by name.
    [ "$PATH_NEEDS_SETUP" = 1 ] && emit_path_hint
    [ "$auth_ok" = 0 ] && emit_auth_hint
    [ "$plugins_pending" = 1 ] && emit_plugin_hint
    return 0
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -y | --yes) ASSUME_YES=1 ;;
        --instance)
            shift
            INSTANCE="${1:?--instance requires a URL}"
            ;;
        --version)
            shift
            VERSION="${1:?--version requires a value}"
            ;;
        --install-only) INSTALL_ONLY=1 ;;
        --no-modify-path) NO_MODIFY_PATH=1 ;;
        --plugin)
            shift
            PLUGINS+=("${1:?--plugin requires a name}")
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1 (see --help)" ;;
        esac
        shift
    done

    assert_safe_path_value GGSHIELD_BIN_DIR "$BIN_DIR"
    assert_safe_path_value GGSHIELD_OPT_DIR "$OPT_DIR"

    need curl
    need uname
    detect_platform
    say "Platform: $OS/$ARCH${LIBC:+ ($LIBC)} — installing the standalone build"

    install_tarball
    write_state
    post_install
}

# Lets tests `source` this file without running main. BASH_SOURCE is empty (not unset)
# when piped (curl|bash); a naive `:-` default would then wrongly skip main entirely.
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
