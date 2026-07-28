MACOS_P12_FILE=${MACOS_P12_FILE:-}
MACOS_P12_PASSWORD_FILE=${MACOS_P12_PASSWORD_FILE:-}

# Path to a file used by rcodesign for notarizing.
# Follow the instructions from
# https://gregoryszorc.com/docs/apple-codesign/0.27.0/apple_codesign_getting_started.html#apple-codesign-app-store-connect-api-key
# to generate one.
MACOS_API_KEY_FILE=${MACOS_API_KEY_FILE:-}

macos_add_sign_dependencies() {
    REQUIREMENTS="$REQUIREMENTS rcodesign"
    DEFAULT_STEPS="$DEFAULT_STEPS notarize"
}

macos_sign() {
    macos_list_files_to_sign | while read path ; do
        macos_sign_file "$path"
    done
}

macos_sign_file() {
    check_var MACOS_P12_FILE

    local file
    file="$1"
    info "- Signing $file"

    # The hardened runtime ("runtime" code-signature flag) denies JIT
    # (executable MAP_JIT memory) unless the process's MAIN executable carries
    # the allow-jit entitlement. The machine-scan plugin (satori) matches with
    # PCRE2, whose JIT is ~6-7x faster than its interpreter on regex-heavy
    # files; without the entitlement PCRE2 silently falls back to the
    # interpreter and `ggshield machine scan` is dramatically slower. JIT
    # permission is a process-level attribute taken from the main executable, so
    # the entitlement goes on the `ggshield` launcher only — the bundled
    # .so/.dylib libraries inherit the process permission and don't need it.
    if [ "$(basename "$file")" = "ggshield" ] ; then
        rcodesign sign \
            --p12-file "$MACOS_P12_FILE" \
            --p12-password-file "$MACOS_P12_PASSWORD_FILE" \
            --code-signature-flags runtime \
            --entitlements-xml-path "$SCRIPT_DIR/macos-entitlements.plist" \
            --for-notarization \
            "$file"
    else
        rcodesign sign \
            --p12-file "$MACOS_P12_FILE" \
            --p12-password-file "$MACOS_P12_PASSWORD_FILE" \
            --code-signature-flags runtime \
            --for-notarization \
            "$file"
    fi
}

macos_list_files_to_sign() {
    local archive_dir="$BUILD_DIR/$ARCHIVE_DIR_NAME"
    echo "$archive_dir/$INSTALL_PREFIX/ggshield"
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
