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

windows_create_archive() {
    local archive_path="$PACKAGES_DIR/$ARCHIVE_DIR_NAME.zip"
    pushd "$PACKAGES_DIR"
    7z a "$archive_path" "$ARCHIVE_DIR_NAME"
    popd
    info "Archive created in $archive_path"
}

windows_build_chocolatey_package() {
    # choco-package will contain everything needed to build the nupkg
    # we delete it a the end.
    mkdir choco-package
    mkdir choco-package/tools

    cp -r "$PACKAGES_DIR/$ARCHIVE_DIR_NAME/_internal" choco-package/tools
    cp "$PACKAGES_DIR/$ARCHIVE_DIR_NAME/ggshield.exe" choco-package/tools
    cp "$ROOT_DIR/scripts/chocolatey/ggshield.nuspec" choco-package
    cp "$ROOT_DIR/scripts/chocolatey/VERIFICATION.txt" choco-package/tools
    cp "$ROOT_DIR/LICENSE" choco-package/tools/LICENSE.txt
    sed -i "s/__VERSION__/$VERSION/" choco-package/ggshield.nuspec

    choco pack choco-package/* --version $VERSION --outdir $PACKAGES_DIR

    info "Chocolatey package created in $PACKAGES_DIR/ggshield.$VERSION.nupkg"

    rm -rf choco-package

}

# cf https://docs.chocolatey.org/en-us/create/create-packages/#testing-your-package
test_chocolatey_package() {
    pushd "$PACKAGES_DIR"
    choco install ggshield --debug --verbose --source . --noop
    popd
}

windows_build_msi_package() {
    # MSI only supports X.Y.Z version format, strip any suffix (e.g. +sha)
    local msi_version="${VERSION%%[+]*}"

    local wxs_path
    wxs_path=$(cygpath -w "$SCRIPT_DIR/ggshield.wxs")

    local source_dir
    source_dir=$(cygpath -w "$PACKAGES_DIR/$ARCHIVE_DIR_NAME")

    local msi_path="$PACKAGES_DIR/$ARCHIVE_DIR_NAME.msi"
    local msi_path_win
    msi_path_win=$(cygpath -w "$msi_path")

    info "Building MSI package"
    wix build "$wxs_path" \
        -arch x64 \
        -d Version="$msi_version" \
        -bindpath "SourceDir=$source_dir" \
        -o "$msi_path_win"

    if [ "$DO_SIGN" -eq 1 ] ; then
        info "Signing MSI package"
        smctl sign \
            --verbose \
            --exit-non-zero-on-fail \
            --fingerprint "$WINDOWS_CERT_FINGERPRINT" \
            --tool signtool \
            --input "$msi_path"
    fi

    info "MSI package created in $msi_path"
}

test_msi_package() {
    local msi_path="$PACKAGES_DIR/$ARCHIVE_DIR_NAME.msi"
    if [ ! -f "$msi_path" ] ; then
        die "MSI package not found: $msi_path"
    fi
    if [ ! -s "$msi_path" ] ; then
        die "MSI package is empty: $msi_path"
    fi
    info "MSI package OK: $msi_path"
}

create_windows_packages() {
    windows_create_archive
    windows_build_chocolatey_package
    windows_build_msi_package
}
