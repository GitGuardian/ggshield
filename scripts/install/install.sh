#!/usr/bin/env bash
#
# ggshield installer.
#
# Installs ggshield using the best method available on this machine,
# authenticates, and optionally installs plugins (--plugin NAME).
#
#   curl --proto '=https' --tlsv1.2 -sSfL \
#     https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh | bash
#
# See scripts/install/README.md for options. Cleanup: uninstall.sh.

set -euo pipefail

GITHUB_REPO="GitGuardian/ggshield"
CLOUDSMITH_BASE="https://dl.cloudsmith.io/public/gitguardian/ggshield"

BIN_DIR="${GGSHIELD_BIN_DIR:-$HOME/.local/bin}"
# NOT ~/.local/share/ggshield: that is ggshield's own data dir (plugins…)
OPT_DIR="${GGSHIELD_OPT_DIR:-$HOME/.local/share/ggshield-standalone}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ggshield-install"
STATE_FILE="$STATE_DIR/state"

ASSUME_YES=0
INSTALL_ONLY=0
METHOD_AUTO=0
PLUGINS=()
INSTANCE=""
VERSION="${GGSHIELD_VERSION:-}"
METHOD="auto"

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install ggshield and authenticate. With --plugin, also install the named
plugin(s).

Options:
  -y, --yes           never prompt, accept defaults (for CI)
      --instance URL  GitGuardian instance to authenticate against
      --version X.Y.Z ggshield version to install (default: latest;
                      also via GGSHIELD_VERSION env var)
      --method M      auto|brew|repo|tarball|pipx (default: auto)
      --install-only  install ggshield, skip auth and plugins
      --plugin NAME   install this ggshield plugin (repeatable)
  -h, --help          show this help

Environment:
  GITGUARDIAN_API_KEY  authenticate with this API key instead of the browser
                       flow (token login, combine with --instance)
  GGSHIELD_BIN_DIR     symlink dir for tarball installs (default ~/.local/bin)
EOF
}

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# The script is usually piped into bash, so stdin is not a TTY: reconnect
# prompts to /dev/tty (rustup pattern).
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

fetch() {
    curl --proto '=https' --tlsv1.2 -sSfL --retry 3 "$@"
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
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

    LIBC=gnu
    if [ "$OS" = darwin ]; then
        # uname -m lies under Rosetta 2; sysctl does not (rustup pattern)
        if [ "$ARCH" = x86_64 ] &&
            [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
            ARCH=arm64
        fi
        TARGET="$ARCH-apple-darwin"
    else
        # base Alpine has no ldd (musl-utils), so check the loader file too
        if [ -e "/lib/ld-musl-$(uname -m).so.1" ] ||
            ldd --version 2>&1 | grep -qi musl; then
            LIBC=musl
        fi
        # ggshield's Linux target triple uses the kernel arch name (aarch64);
        # macOS keeps arm64. Normalize only for the Linux triple.
        local linux_arch="$ARCH"
        [ "$ARCH" = arm64 ] && linux_arch=aarch64
        TARGET="$linux_arch-unknown-linux-gnu"
    fi
}

have_root() {
    [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1
}

run_as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    else
        sudo -E "$@"
    fi
}

linux_pkg_manager() {
    local mgr
    for mgr in apt-get dnf yum microdnf zypper; do
        if command -v "$mgr" >/dev/null 2>&1; then
            echo "$mgr"
            return 0
        fi
    done
    return 1
}

# Standalone tarballs exist for both macOS archs and x86_64/arm64 glibc Linux.
# No musl build. arm64 Linux builds are recent, so older releases lack them —
# install_tarball checks the asset actually exists before downloading.
tarball_available() {
    [ "$OS" = darwin ] && return 0
    [ "$LIBC" = gnu ] && { [ "$ARCH" = x86_64 ] || [ "$ARCH" = arm64 ]; }
}

select_method() {
    if [ "$METHOD" != auto ]; then
        return 0
    fi
    METHOD_AUTO=1
    if [ "$OS" = darwin ]; then
        if command -v brew >/dev/null 2>&1; then
            METHOD=brew
        else
            METHOD=tarball
        fi
        return 0
    fi
    if linux_pkg_manager >/dev/null && have_root; then
        METHOD=repo
    elif tarball_available; then
        METHOD=tarball
    elif command -v pipx >/dev/null 2>&1; then
        METHOD=pipx
    else
        die "no standalone build for $ARCH/$LIBC Linux and neither a \
supported package manager with sudo nor pipx is available. \
Install pipx, then re-run, or see https://docs.gitguardian.com/ggshield-docs/getting-started"
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

# GitHub computes a sha256 digest for every release asset; pair each "name"
# with the "digest" that follows it in the release JSON.
asset_digest() {
    local asset="$1"
    fetch "https://api.github.com/repos/$GITHUB_REPO/releases/tags/v$VERSION" |
        grep -o '"name": *"[^"]*"\|"digest": *"sha256:[0-9a-f]*"' |
        grep -A1 -F "\"$asset\"" | grep -o 'sha256:[0-9a-f]*' | head -1 || true
}

# HTTP status of an asset's download URL (HEAD, following redirects). Used to
# tell "asset absent" (404) from "couldn't reach GitHub" (504/000/…) so we
# only fall back when the build is genuinely missing, not on a transient error.
# Deliberately not the `fetch` wrapper: no -f, so 4xx still yields the code.
asset_http_status() {
    curl --proto '=https' --tlsv1.2 -sIL -o /dev/null -w '%{http_code}' \
        --max-time 20 --retry 2 \
        "https://github.com/$GITHUB_REPO/releases/download/v$VERSION/$1" \
        2>/dev/null || echo 000
}

verify_download() {
    local file="$1" asset="$2" digest sum_tool
    digest=$(asset_digest "$asset")
    if [ -z "$digest" ]; then
        warn "could not retrieve the expected sha256 digest from the GitHub API"
        confirm "Continue without checksum verification?" || die "aborted"
    else
        if command -v sha256sum >/dev/null 2>&1; then
            sum_tool="sha256sum"
        else
            sum_tool="shasum -a 256"
        fi
        say "Verifying sha256 checksum"
        echo "${digest#sha256:}  $file" | $sum_tool -c - >/dev/null ||
            die "checksum mismatch for $asset"
    fi

    # older gh releases have no `attestation` subcommand
    if command -v gh >/dev/null 2>&1 &&
        gh attestation --help >/dev/null 2>&1 &&
        gh auth status >/dev/null 2>&1; then
        say "Verifying build provenance attestation"
        gh attestation verify "$file" --repo "$GITHUB_REPO" >/dev/null ||
            die "artifact attestation verification failed for $asset"
    fi
}

install_tarball() {
    tarball_available || die "no standalone build for $ARCH/$LIBC $OS. \
Try --method pipx or --method repo"
    need tar
    resolve_version

    local asset dir tmp bin
    asset="ggshield-$VERSION-$TARGET.tar.gz"
    case "$(asset_http_status "$asset")" in
    200) ;;
    404)
        if [ "$METHOD_AUTO" = 1 ] && command -v pipx >/dev/null 2>&1; then
            warn "release v$VERSION has no $asset (arm64 Linux ships from a later release); using pipx"
            METHOD=pipx
            install_pipx
            return 0
        fi
        die "release v$VERSION has no standalone asset $asset; try --method pipx or --method repo"
        ;;
    *)
        # network/API hiccup: don't spuriously fall back; let the download try
        warn "could not confirm $asset availability; attempting the download anyway"
        ;;
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
    if [ -L "$BIN_DIR/ggshield" ]; then
        case "$(readlink "$BIN_DIR/ggshield")" in
        "$OPT_DIR"/*) ;;
        *) warn "replacing existing ggshield at $BIN_DIR/ggshield (was: $(readlink "$BIN_DIR/ggshield"))" ;;
        esac
    fi
    ln -sf "$bin" "$BIN_DIR/ggshield"

    case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "$BIN_DIR is not in your PATH. Add this to your shell profile:"
        warn "  export PATH=\"$BIN_DIR:\$PATH\""
        ;;
    esac
    GGSHIELD="$BIN_DIR/ggshield"
}

install_repo() {
    local mgr setup pkg
    mgr=$(linux_pkg_manager) || die "no supported package manager found"
    have_root || die "--method repo requires root or sudo"
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064 # expand now: $tmp is local, gone at exit time
    trap "rm -rf '$tmp'" EXIT

    if [ "$mgr" = apt-get ]; then
        setup="setup.deb.sh"
        pkg="ggshield${VERSION:+=$VERSION*}"
    else
        setup="setup.rpm.sh"
        pkg="ggshield${VERSION:+-$VERSION}"
    fi

    say "Configuring the GitGuardian Cloudsmith repository ($setup)"
    fetch -o "$tmp/$setup" "$CLOUDSMITH_BASE/$setup"
    run_as_root bash "$tmp/$setup"

    say "Installing ggshield with $mgr"
    if [ "$mgr" = zypper ]; then
        run_as_root zypper install -y "$pkg"
    else
        run_as_root "$mgr" install -y "$pkg"
    fi
    GGSHIELD="/usr/bin/ggshield"
}

install_brew() {
    [ -z "$VERSION" ] || warn "--version is ignored with brew (installs latest)"
    if brew list ggshield >/dev/null 2>&1; then
        say "Upgrading ggshield with Homebrew"
        brew upgrade ggshield || true
    else
        say "Installing ggshield with Homebrew"
        brew install ggshield
    fi
    GGSHIELD="ggshield"
}

install_pipx() {
    need pipx
    say "Installing ggshield with pipx"
    pipx install ${VERSION:+--force} "ggshield${VERSION:+==$VERSION}"
    GGSHIELD="ggshield"
}

write_state() {
    mkdir -p "$STATE_DIR"
    cat >"$STATE_FILE" <<EOF
method=$METHOD
version=${VERSION:-latest}
opt_dir=$OPT_DIR
bin_link=$BIN_DIR/ggshield
EOF
}

run_gg() {
    # Children may prompt; give them the TTY back when we are piped
    if [ ! -t 0 ] && [ -e /dev/tty ]; then
        "$GGSHIELD" "$@" </dev/tty
    else
        "$GGSHIELD" "$@"
    fi
}

post_install() {
    hash -r 2>/dev/null || true
    # actually run it: an executable can still fail (e.g. wrong libc)
    local version_out
    if ! version_out=$("$GGSHIELD" --version 2>&1); then
        die "ggshield was installed but cannot run: $version_out"
    fi
    say "Installed: $version_out"

    # a leftover from a previous install may shadow the fresh one on PATH
    local resolved
    resolved=$(command -v ggshield 2>/dev/null || true)
    case "$GGSHIELD" in
    */*)
        if [ -n "$resolved" ] && [ "$resolved" != "$GGSHIELD" ]; then
            warn "another ggshield at $resolved shadows the one just installed ($GGSHIELD)"
            warn "remove it or fix your PATH order"
        fi
        ;;
    esac

    if [ "$INSTALL_ONLY" = 1 ]; then
        say "Done (--install-only). Next: ggshield auth login"
        return 0
    fi

    if [ -n "${GITGUARDIAN_API_KEY:-}" ]; then
        # token login persists the key for later shells and validates it
        # against the selected instance. Reads the token from stdin: do not
        # use run_gg here, it would rebind stdin to /dev/tty.
        say "Authenticating with the API key from GITGUARDIAN_API_KEY"
        printf '%s\n' "$GITGUARDIAN_API_KEY" |
            "$GGSHIELD" auth login --method token ${INSTANCE:+--instance "$INSTANCE"}
    elif [ "$ASSUME_YES" = 1 ] && [ ! -e /dev/tty ]; then
        warn "non-interactive run without GITGUARDIAN_API_KEY: skipping auth and setup"
        return 0
    else
        say "Authenticating"
        run_gg auth login ${INSTANCE:+--instance "$INSTANCE"}
    fi

    if [ ${#PLUGINS[@]} -eq 0 ]; then
        say "Done. To list available plugins: ggshield plugin status"
        return 0
    fi

    local plugin
    for plugin in "${PLUGINS[@]}"; do
        say "Installing the $plugin plugin"
        run_gg plugin install "$plugin"
    done
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
        --method)
            shift
            METHOD="${1:?--method requires a value}"
            ;;
        --install-only) INSTALL_ONLY=1 ;;
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

    case "$METHOD" in
    auto | brew | repo | tarball | pipx) ;;
    *) die "invalid --method: $METHOD" ;;
    esac

    need curl
    need uname
    detect_platform
    select_method
    say "Platform: $OS/$ARCH${LIBC:+ ($LIBC)} — install method: $METHOD"

    case "$METHOD" in
    brew) install_brew ;;
    repo) install_repo ;;
    tarball) install_tarball ;;
    pipx) install_pipx ;;
    esac

    write_state
    post_install
}

main "$@"
