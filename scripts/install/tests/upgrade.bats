#!/usr/bin/env bats
#
# Functional tests for the supported install.sh replacement paths. The real
# installer functions consume local fixture archives so these tests exercise
# extraction, launcher activation, and state persistence without a network.
#
#   bats scripts/install/tests/upgrade.bats

# shellcheck disable=SC2030,SC2031,SC2329 # Bats shares state; doubles are indirect callbacks

bats_require_minimum_version 1.5.0

INSTALL_SH="$BATS_TEST_DIRNAME/../install.sh"

setup() {
    SANDBOX="$(mktemp -d)"
    export HOME="$SANDBOX/home"
    export GGSHIELD_BIN_DIR="$SANDBOX/bin"
    export GGSHIELD_OPT_DIR="$SANDBOX/opt"
    export XDG_STATE_HOME="$SANDBOX/state"
    export TMPDIR="$SANDBOX/tmp"
    ASSET_DIR="$SANDBOX/assets"
    mkdir -p "$HOME" "$ASSET_DIR" "$TMPDIR"

    # shellcheck disable=SC1090
    source "$INSTALL_SH"
    install_test_doubles
    TARGET=x86_64-unknown-linux-gnu
    export PATH="$BIN_DIR:$PATH"
}

teardown() {
    rm -rf "$SANDBOX"
}

# install_tarball() calls these network and integrity boundaries after deriving
# the release asset name. Define the doubles after sourcing install.sh so its
# production definitions do not replace them; keep the rest of its path intact.
install_test_doubles() {
    asset_http_status() {
        printf '200'
    }

    fetch() {
        [ "$1" = -o ]
        cp "$ASSET_DIR/ggshield-$VERSION-$TARGET.tar.gz" "$2"
    }

    verify_download() {
        return 0
    }
}

make_asset() {
    local version="$1" marker="${2:-release}"
    local dirname="ggshield-$version-$TARGET"
    local stage="$SANDBOX/stage-$version"

    rm -rf "$stage"
    mkdir -p "$stage/$dirname"
    cat >"$stage/$dirname/ggshield" <<EOF
#!/bin/sh
printf '%s\n' 'ggshield, version $version ($marker)'
EOF
    chmod +x "$stage/$dirname/ggshield"
    tar -czf "$ASSET_DIR/$dirname.tar.gz" -C "$stage" "$dirname"
}

install_version() {
    VERSION="$1"
    make_asset "$@"
    install_tarball
    write_state
}

assert_active_version() {
    local version="$1" marker="${2:-release}"
    [ "$("$BIN_DIR/ggshield")" = "ggshield, version $version ($marker)" ]
    [ "$(readlink "$BIN_DIR/ggshield")" = "$OPT_DIR/ggshield-$version-$TARGET/ggshield" ]
}

@test "fresh install activates the requested version and records it" {
    install_version 1.0.0

    assert_active_version 1.0.0
    grep -qxF "method=tarball" "$STATE_FILE"
    grep -qxF "version=1.0.0" "$STATE_FILE"
    grep -qxF "opt_dir=$OPT_DIR" "$STATE_FILE"
    grep -qxF "bin_link=$BIN_DIR/ggshield" "$STATE_FILE"
}

@test "upgrade activates the newer version and preserves PATH state" {
    install_version 1.0.0
    printf 'path_rc_file=%s/.bashrc\n' "$HOME" >>"$STATE_FILE"

    install_version 2.0.0

    assert_active_version 2.0.0
    grep -qxF "version=2.0.0" "$STATE_FILE"
    grep -qxF "path_rc_file=$HOME/.bashrc" "$STATE_FILE"
    [ "$(grep -c "^path_rc_file=$HOME/.bashrc$" "$STATE_FILE")" -eq 1 ]
}

@test "same-version reinstall replaces the payload and remains active" {
    install_version 2.0.0 original
    local install_dir="$OPT_DIR/ggshield-2.0.0-$TARGET"
    touch "$install_dir/stale-from-first-install"
    printf 'path_rc_file=%s/.zshrc\n' "$HOME" >>"$STATE_FILE"

    install_version 2.0.0 replacement

    assert_active_version 2.0.0 replacement
    [ ! -e "$install_dir/stale-from-first-install" ]
    grep -qxF "path_rc_file=$HOME/.zshrc" "$STATE_FILE"
}

@test "explicit downgrade activates the requested older version" {
    install_version 2.0.0
    install_version 1.0.0

    assert_active_version 1.0.0
    grep -qxF "version=1.0.0" "$STATE_FILE"
}
