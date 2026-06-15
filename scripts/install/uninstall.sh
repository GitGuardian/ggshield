#!/usr/bin/env bash
#
# Uninstall ggshield and its data: uninstall the plugins, log out, remove
# caches/config, then remove ggshield itself using the method recorded by
# install.sh (or detected).
#
#   curl --proto '=https' --tlsv1.2 -sSfL \
#     https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.sh | bash

set -euo pipefail

BIN_DIR="${GGSHIELD_BIN_DIR:-$HOME/.local/bin}"
OPT_DIR="${GGSHIELD_OPT_DIR:-$HOME/.local/share/ggshield-standalone}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ggshield-install"
STATE_FILE="$STATE_DIR/state"

ASSUME_YES=0

usage() {
    cat <<EOF
Usage: uninstall.sh [OPTIONS]

Remove ggshield and every trace it can find: plugins, authentication,
caches, configuration, and the package itself.

Options:
  -y, --yes   never prompt (for CI)
  -h, --help  show this help
EOF
}

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply
    if [ -t 0 ]; then
        read -r -p "$1 [Y/n] " reply
    elif [ -e /dev/tty ]; then
        read -r -p "$1 [Y/n] " reply </dev/tty
    else
        die "cannot prompt for '$1' (no TTY). Re-run with -y"
    fi
    case "$reply" in
    n* | N*) return 1 ;;
    *) return 0 ;;
    esac
}

have_root() {
    [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1
}

run_as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# A machine may carry several installs (e.g. a tarball leftover plus a
# system package): detect and remove them all, not just the recorded one.
detect_methods() {
    if [ -f "$STATE_FILE" ]; then
        sed -n 's/^method=//p' "$STATE_FILE"
    fi
    if command -v brew >/dev/null 2>&1 && brew list ggshield >/dev/null 2>&1; then
        echo brew
    fi
    if command -v dpkg >/dev/null 2>&1 && dpkg -s ggshield >/dev/null 2>&1; then
        echo repo
    elif command -v rpm >/dev/null 2>&1 && rpm -q ggshield >/dev/null 2>&1; then
        echo repo
    fi
    if command -v pacman >/dev/null 2>&1 && pacman -Qi ggshield >/dev/null 2>&1; then
        echo pacman
    fi
    if command -v python3 >/dev/null 2>&1 && python3 -m pip show ggshield >/dev/null 2>&1; then
        echo pip
    fi
    if command -v pkgutil >/dev/null 2>&1 &&
        pkgutil --pkg-info com.gitguardian.ggshield >/dev/null 2>&1; then
        echo pkg
    fi
    if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -q ggshield; then
        echo pipx
    fi
    if command -v uv >/dev/null 2>&1 && uv tool list 2>/dev/null | grep -q '^ggshield '; then
        echo uv
    fi
    # only claim the bin symlink when it points into our own install dir:
    # uv/pipx also place a ggshield shim in ~/.local/bin
    if [ -d "$OPT_DIR" ]; then
        echo tarball
    elif [ -L "$BIN_DIR/ggshield" ]; then
        case "$(readlink "$BIN_DIR/ggshield")" in
        "$OPT_DIR"/*) echo tarball ;;
        esac
    fi
}

# human label: "repo" covers both package formats, say which one it is
method_label() {
    if [ "$1" = repo ]; then
        if command -v dpkg >/dev/null 2>&1 && dpkg -s ggshield >/dev/null 2>&1; then
            echo "repo, deb"
        else
            echo "repo, rpm"
        fi
    else
        echo "$1"
    fi
}

# best-effort version lookup, only used to enrich the prompts
method_version() {
    case "$1" in
    repo)
        dpkg-query -W -f '${Version}' ggshield 2>/dev/null ||
            rpm -q --qf '%{VERSION}' ggshield 2>/dev/null || true
        ;;
    pacman) pacman -Q ggshield 2>/dev/null | awk '{print $2}' ;;
    brew) brew list --versions ggshield 2>/dev/null | awk '{print $2}' ;;
    pipx) pipx list 2>/dev/null | sed -n 's/.*package ggshield \([0-9][0-9.]*\).*/\1/p' ;;
    uv) uv tool list 2>/dev/null | sed -n 's/^ggshield v\{0,1\}\([0-9][0-9.]*\).*/\1/p' ;;
    pip) python3 -m pip show ggshield 2>/dev/null | sed -n 's/^Version: //p' ;;
    pkg) pkgutil --pkg-info com.gitguardian.ggshield 2>/dev/null | sed -n 's/^version: //p' ;;
    tarball)
        # version is embedded in the install dir name: ggshield-<ver>-<target>
        find "$OPT_DIR" -maxdepth 1 -name 'ggshield-*' 2>/dev/null | head -1 |
            sed -n 's/.*ggshield-\([0-9][0-9.]*\)-.*/\1/p'
        ;;
    esac
}

ggshield_cleanup() {
    command -v ggshield >/dev/null 2>&1 || return 0
    # there is no `plugin uninstall --all`: enumerate and remove one by one
    local plugins plugin
    plugins=$(ggshield plugin list 2>/dev/null | sed -n 's/^  \([^:]*\):.*/\1/p') || true
    for plugin in $plugins; do
        confirm "Uninstall the $plugin plugin?" || continue
        ggshield plugin uninstall --yes "$plugin" >/dev/null 2>&1 ||
            warn "could not uninstall the $plugin plugin"
    done
    if confirm "Log out from GitGuardian?"; then
        ggshield auth logout >/dev/null 2>&1 ||
            warn "could not log out (maybe not logged in)"
    fi
}

remove_package() {
    local method="$1"
    case "$method" in
    brew)
        say "Removing ggshield with Homebrew"
        brew uninstall ggshield
        ;;
    repo)
        have_root || die "removing the system package requires root or sudo"
        say "Removing the ggshield system package"
        if command -v dpkg >/dev/null 2>&1 && dpkg -s ggshield >/dev/null 2>&1; then
            run_as_root apt-get remove -y ggshield
        elif command -v zypper >/dev/null 2>&1 && rpm -q ggshield >/dev/null 2>&1; then
            run_as_root zypper remove -y ggshield
        elif command -v dnf >/dev/null 2>&1 && rpm -q ggshield >/dev/null 2>&1; then
            run_as_root dnf remove -y ggshield
        elif command -v yum >/dev/null 2>&1 && rpm -q ggshield >/dev/null 2>&1; then
            run_as_root yum remove -y ggshield
        else
            warn "ggshield system package not found, skipping"
        fi
        ;;
    pipx)
        say "Removing ggshield with pipx"
        pipx uninstall ggshield
        ;;
    uv)
        say "Removing ggshield with uv"
        uv tool uninstall ggshield
        ;;
    pacman)
        have_root || die "removing the pacman package requires root or sudo"
        say "Removing the ggshield pacman package (AUR)"
        run_as_root pacman -R --noconfirm ggshield
        ;;
    pip)
        say "Removing ggshield with pip"
        python3 -m pip uninstall -y ggshield ||
            warn "pip uninstall failed (externally-managed environment?)"
        ;;
    pkg)
        have_root || die "removing the macOS package requires root or sudo"
        say "Removing the macOS package"
        run_as_root rm -rf /opt/gitguardian/ggshield-* /usr/local/bin/ggshield
        run_as_root pkgutil --forget com.gitguardian.ggshield
        ;;
    tarball)
        say "Removing standalone install"
        rm -f "$BIN_DIR/ggshield"
        rm -rf "$OPT_DIR"
        ;;
    none)
        warn "no ggshield installation detected, removing leftovers only"
        ;;
    esac
}

remove_user_data() {
    # platformdirs(appname="ggshield") config/cache/data, the global config
    # file, and the scan databases (~/.ggshield)
    local paths=("$HOME/.gitguardian.yaml" "$HOME/.ggshield")
    if [ "$(uname -s)" = Darwin ]; then
        paths+=(
            "$HOME/Library/Application Support/ggshield"
            "$HOME/Library/Caches/ggshield"
        )
    else
        paths+=(
            "${XDG_CONFIG_HOME:-$HOME/.config}/ggshield"
            "${XDG_CACHE_HOME:-$HOME/.cache}/ggshield"
            "${XDG_DATA_HOME:-$HOME/.local/share}/ggshield"
        )
    fi

    local p found=0
    for p in "${paths[@]}"; do
        [ -e "$p" ] && found=1
    done
    if [ "$found" = 0 ]; then
        say "No ggshield config/cache/data found"
        return 0
    fi

    confirm "Remove ggshield configuration, cache and data (including plugins)?" || return 0
    for p in "${paths[@]}"; do
        if [ -e "$p" ]; then
            say "Removing $p"
            rm -rf "$p"
        fi
    done
}

# system-wide scheduled scans: systemd units, /etc/ggshield, wrapper scripts
remove_system_scheduling() {
    local unit units=""
    for unit in /etc/systemd/system/ggshield-*.timer /etc/systemd/system/ggshield-*.service; do
        [ -e "$unit" ] && units="$units $unit"
    done
    if [ -z "$units" ] && [ ! -d /etc/ggshield ]; then
        return 0
    fi
    confirm "Remove system-wide ggshield scheduling (systemd units, /etc/ggshield)?" || return 0
    if ! have_root; then
        warn "removing system-wide scheduling requires root or sudo, skipping:$units"
        return 0
    fi
    local script
    for unit in $units; do
        case "$unit" in
        *.timer)
            run_as_root systemctl disable --now "$(basename "$unit")" >/dev/null 2>&1 || true
            ;;
        *.service)
            # remove the wrapper script the unit points at, when it is ours
            script=$(sed -n 's/^ExecStart=//p' "$unit" | head -1)
            case "$script" in
            *ggshield*) run_as_root rm -f "$script" ;;
            esac
            ;;
        esac
        say "Removing $unit"
        run_as_root rm -f "$unit"
    done
    run_as_root rm -f /etc/systemd/system/timers.target.wants/ggshield-*.timer
    if [ -d /etc/ggshield ]; then
        say "Removing /etc/ggshield"
        run_as_root rm -rf /etc/ggshield
    fi
    run_as_root systemctl daemon-reload >/dev/null 2>&1 || true
}

# leftovers from ephemeral usages: uvx cache, pre-commit hook environments
remove_ephemeral_leftovers() {
    # uv's download cache only speeds up future installs; pruning it scans
    # the whole cache (slow on large caches), so make it opt-in like pre-commit
    if command -v uv >/dev/null 2>&1 &&
        confirm "Prune ggshield from the uv download cache (scans the whole cache, may be slow)?"; then
        say "Pruning the uv cache (this can take a while)…"
        uv cache clean ggshield >/dev/null 2>&1 || true
    fi
    # Scan the install dir, not `mise ls`: ls only reports tools active in the
    # current dir's config, so it misses ggshield from most cwds. The dir name
    # sanitizes the backend colon to a dash (pipx:ggshield -> pipx-ggshield),
    # so derive the spec back for `mise uninstall` (which is cwd-independent).
    local mise_installs="$HOME/.local/share/mise/installs"
    if [ -d "$mise_installs" ]; then
        local tool name spec
        for tool in "$mise_installs"/*ggshield*; do
            [ -d "$tool" ] || continue
            name=$(basename "$tool")
            spec="${name/-/:}"
            confirm "Remove the mise tool '$spec' (all versions)?" || continue
            if command -v mise >/dev/null 2>&1 &&
                mise uninstall --all "$spec" >/dev/null 2>&1; then
                say "Removed mise tool $spec"
            else
                warn "could not remove mise tool '$spec'; try: mise uninstall --all $spec"
            fi
        done
    fi

    local pc_cache="$HOME/.cache/pre-commit"
    if [ -d "$pc_cache" ] &&
        find "$pc_cache" -name ggshield -type f 2>/dev/null | grep -q .; then
        if confirm "ggshield found in the pre-commit cache. Clean it (removes ALL cached hook envs)?"; then
            if command -v pre-commit >/dev/null 2>&1; then
                pre-commit clean >/dev/null
            else
                rm -rf "$pc_cache"
            fi
        fi
    fi
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -y | --yes) ASSUME_YES=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1 (see --help)" ;;
        esac
        shift
    done

    local methods method
    methods=$(detect_methods | sort -u)
    if [ -z "$methods" ]; then
        methods=none
    fi
    say "Detected install method(s): $(echo "$methods" | tr '\n' ' ')"

    ggshield_cleanup
    local version label
    for method in $methods; do
        if [ "$method" != none ]; then
            version=$(method_version "$method" | head -1)
            label=$(method_label "$method")
            confirm "Remove the ggshield installation ($label${version:+ $version})?" || continue
        fi
        remove_package "$method"
    done
    remove_user_data
    remove_system_scheduling
    remove_ephemeral_leftovers

    hash -r 2>/dev/null || true
    # PATH alone is not enough: ~/.local/bin may not be on PATH in this shell
    local remaining=""
    if command -v ggshield >/dev/null 2>&1; then
        remaining=$(command -v ggshield)
    elif [ -e "$BIN_DIR/ggshield" ] || [ -L "$BIN_DIR/ggshield" ]; then
        remaining="$BIN_DIR/ggshield"
    elif [ -d "$OPT_DIR" ]; then
        remaining="$OPT_DIR"
    fi
    if [ -n "$remaining" ]; then
        # keep the state file: a later run still needs the recorded method
        warn "ggshield is still present: $remaining"
    else
        rm -rf "$STATE_DIR"
        say "ggshield is fully removed"
    fi
}

main "$@"
