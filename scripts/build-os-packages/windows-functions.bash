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

create_windows_packages() {
    windows_create_archive
    windows_build_chocolatey_package
}
