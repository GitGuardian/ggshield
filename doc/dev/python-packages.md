# Python packages

Each release publishes two kinds of files on PyPI.

| File                | What `ggshield` is after the install                                                       | Built by                                                       |
| ------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| Platform wheels     | The Rust executable. The Python entry point is `ggshield-py`.                              | `.github/workflows/wheels.yml` and `.github/workflows/tag.yml` |
| Source distribution | The Rust executable, compiled during the install. The Python entry point is `ggshield-py`. | `.github/workflows/build_release_assets.yml`                   |

No generic `py3-none-any` wheel is published. On a machine that no platform wheel fits, pip and uv install from the source distribution.

## Installing from the source distribution

A build from the source distribution compiles the Rust sources in `rust/` for the machine it runs on, with `cargo build --release --locked`. The versions in `rust/Cargo.lock` are used.

If `cargo` is not on the `PATH`, the build installs a Rust toolchain with [puccinialin](https://pypi.org/project/puccinialin/) into the cache directory of the user. The build also needs a C compiler. Without one, the install fails.

The executable is not signed by GitGuardian. Signed executables come with the macOS and Windows platform wheels and with the OS packages. On macOS, access to a Keychain item is granted to a signed program, so an executable without the GitGuardian signature does not keep that access across upgrades.

## Building from a git checkout

A wheel built from a git checkout does not contain the Rust executable, and `ggshield` is the Python entry point. This covers `uv build --wheel`, `pip install .` and installs through the pre-commit framework. An editable install, such as the one `uv sync` creates, behaves the same.

`uv build` and `python -m build` without `--wheel` build the source distribution first and then the wheel from it, so they compile.

## Release builds

Set `GGSHIELD_BUILD_RUST=1` to build a platform wheel as the release does: from the sources, signed when the signing secrets are present, and on macOS for both architectures, which requires `rustup`.

`hatch_build.py` implements these rules.
