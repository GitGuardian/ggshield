# Building OS packages

## Introduction

`ggshield` is written in Python, and this sometimes makes deployment complicated.

To solve those deployment issues, we provide standalone `ggshield` executables, that do not require a Python interpreter. This documentation explains how these executables are produced.

The process of generating the packages is handled by the `scripts/build-os-packages/build-os-packages` script. This script runs a series of "steps". It has a default list of steps, but you can tell it to run only specific steps using `scripts/build-os-packages/build-os-packages step1 step2...`.

All functions in the script starting with `step_` can be used as a step. This means you can get a list of all available steps with: `grep -o '^step_[a-z_]*' scripts/build-os-packages/build-os-packages`.

## Generating the standalone executable

We use [PyInstaller](https://pyinstaller.org) to generate `ggshield` standalone executable.

## macOS-specific information

For macOS, we produce a .pkg archive. The advantage of this file is that it can be installed by double-clicking on it or by using `sudo installer -pkg path/to/ggshield.pkg -target /`, and `ggshield` is immediately usable after install, without the need to alter `$PATH`.

### Inside the pkg

The .pkg itself installs `ggshield` files in `/opt/gitguardian/ggshield-$version` and a `ggshield` symbolic link in `/usr/local/bin/ggshield`.

### Signing & notarizing

The .pkg archive used for releases is signed. Signing the archive is required to ensure macOS Gatekeeper security system does not block `ggshield` when users try to run it.

#### Setting up signing

`build-standalone-exe` won't sign binaries unless it's called with `--sign`. This is because:

- signing requires access to secrets not available for PR from forks.
- signing (and especially notarizing) can take a long time.

When called with `--sign`, `build-standalone-exe` expects the following environment variables to be set:

- `$MACOS_P12_FILE`: Path to a signing certificate. You can export one from Xcode by following [Apple documentation][apple-signing-certificate].
- `$MACOS_P12_PASSWORD_FILE`: Path containing the password protecting the signing certificate. Xcode will ask for it when exporting it.
- `$MACOS_API_KEY_FILE`: Path to a JSON file holding the "App Store Connect API Key". This file is used by `rcodesign` for the notarization step. Follow [`rcodesign` documentation][rcodesign-api-key] to generate one.

Attention: these 3 files should be treated as secrets (even if `$MACOS_P12_FILE` is protected by a password).

[apple-signing-certificate]: https://help.apple.com/xcode/mac/current/#/dev154b28f09
[rcodesign-api-key]: https://gregoryszorc.com/docs/apple-codesign/0.27.0/apple_codesign_getting_started.html#obtaining-an-app-store-connect-api-key

#### Signing implementation details

Although PyInstaller supports signing, it did not work at the time we tried it, so we use [rcodesign][] to do so.

`rcodesign` is a cross-platform CLI tool to sign, notarize and staple macOS binaries.

For Gatekeeper to accept the app, the executable and all the dynamic libraries must be signed, as well as the .pkg archive itself. Signing the executable and the libraries is done by the `sign` step, whereas signing the .pkg archive is done by the `create_archive` step.

[rcodesign]: https://gregoryszorc.com/docs/apple-codesign/
