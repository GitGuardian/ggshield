WINDOWS_CERT_FINGERPRINT=${WINDOWS_CERT_FINGERPRINT:-}

windows_add_sign_dependencies() {
    REQUIREMENTS="$REQUIREMENTS smctl signtool"
}

windows_sign() {
    check_var WINDOWS_CERT_FINGERPRINT

    # All the SM_* vars are required by smctl
    check_var SM_API_KEY
    check_var SM_HOST
    check_var SM_CLIENT_CERT_FILE
    check_var SM_CLIENT_CERT_PASSWORD

    if [ ! -f "$SM_CLIENT_CERT_FILE" ] ; then
        die "$SM_CLIENT_CERT_FILE does not exist"
    fi

    local archive_dir="$PACKAGES_DIR/$ARCHIVE_DIR_NAME"
    smctl sign \
        --verbose \
        --exit-non-zero-on-fail \
        --fingerprint "$WINDOWS_CERT_FINGERPRINT" \
        --tool signtool \
        --input "$archive_dir/$INSTALL_PREFIX/ggshield.exe"
}

