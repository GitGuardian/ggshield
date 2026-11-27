### Changed

- Installing ggshield from the git repository, as the pre-commit framework does, now downloads the native `ggshield` executable of the same version from PyPI. When the download is not possible, the build compiles the executable instead, which needs Rust and a C compiler. The build installs Rust if it is missing.
