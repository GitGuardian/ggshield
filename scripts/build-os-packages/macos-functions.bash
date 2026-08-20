MACOS_P12_FILE=${MACOS_P12_FILE:-}
MACOS_P12_PASSWORD_FILE=${MACOS_P12_PASSWORD_FILE:-}
# macos-sign-file is a separate process: without this it sees neither.
export MACOS_P12_FILE MACOS_P12_PASSWORD_FILE

# Path to a file used by rcodesign for notarizing.
# Follow the instructions from
# https://gregoryszorc.com/docs/apple-codesign/0.27.0/apple_codesign_getting_started.html#apple-codesign-app-store-connect-api-key
# to generate one.
MACOS_API_KEY_FILE=${MACOS_API_KEY_FILE:-}

macos_add_sign_dependencies() {
    REQUIREMENTS="$REQUIREMENTS rcodesign"
    DEFAULT_STEPS="$DEFAULT_STEPS notarize"
}

# The one file in the bundle that gets the JIT entitlement.
#
# The hardened runtime denies JIT (executable MAP_JIT memory) unless the
# process's MAIN executable carries allow-jit, so it goes on the executable that
# JITs — `ggshield-py`, the PyInstaller launcher — and the bundled .so/.dylib
# libraries inherit the process permission. `exec` replaces the process image, so
# ggshield-py's own entitlements are the ones in force. Getting this wrong does
# not fail the build: satori's PCRE2 falls back to its interpreter and
# `ggshield machine scan` runs 6-7x slower.
macos_jit_entitled_binary() {
    echo "$BUILD_DIR/$ARCHIVE_DIR_NAME/$INSTALL_PREFIX/ggshield-py"
}

macos_sign() {
    local jit_entitled
    jit_entitled=$(macos_jit_entitled_binary)
    macos_list_files_to_sign | while read path ; do
        if [ "$path" = "$jit_entitled" ] ; then
            macos_sign_file "$path" "$SCRIPT_DIR/macos-entitlements.plist"
        else
            macos_sign_file "$path"
        fi
    done
}

# $1 is the file to sign, $2 an optional entitlements plist. The invocation lives
# in macos-sign-file, shared with the macOS wheel build.
macos_sign_file() {
    check_var MACOS_P12_FILE
    "$SCRIPT_DIR/macos-sign-file" "$@"
}

# Every Mach-O in the bundle, because notarization rejects the .pkg if a single
# executable inside it is unsigned. Both binaries are named explicitly: the find
# below only matches libraries.
macos_list_files_to_sign() {
    local archive_dir="$BUILD_DIR/$ARCHIVE_DIR_NAME"
    echo "$archive_dir/$INSTALL_PREFIX/ggshield"
    echo "$archive_dir/$INSTALL_PREFIX/ggshield-py"
    find "$archive_dir" -name '*.so' -o -name '*.dylib'
}

step_notarize() {
    if [ "$DO_SIGN" -eq 0 ] ; then
        info "Skipping notarize step"
    fi
    info "Notarizing"
    rcodesign notary-submit \
        --api-key-file "$MACOS_API_KEY_FILE" \
        --staple \
        "$DIST_DIR/$ARCHIVE_DIR_NAME.pkg"
}
