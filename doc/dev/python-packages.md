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

## Installing from a git checkout

A wheel built from a git checkout downloads the platform wheel of the same version from PyPI and takes the Rust executable from it. This is the signed executable of the release. The pre-commit framework installs ggshield this way, and so do `pip install .` and `pip install git+https://github.com/GitGuardian/ggshield`.

The version is the one in `ggshield/__init__.py`. Between two releases, the checkout therefore gets the executable of the last release together with the Python code of the commit.

When the download is not possible, the build compiles the executable from the sources of the checkout, as a build from the source distribution does. This happens when:

- PyPI does not have that version, for example between the version bump and the publication of a release,
- PyPI has no platform wheel for the machine,
- PyPI cannot be reached, or the download does not match its checksum.

`uv build` and `python -m build` without `--wheel` build the source distribution first and then the wheel from it, so they compile.

## Editable installs

An editable install, such as the one `uv sync` creates, does not contain the Rust executable. `ggshield` is then the Python entry point.

## Release builds

Set `GGSHIELD_BUILD_RUST=1` to build a platform wheel as the release does: from the sources, signed when the signing secrets are present, and on macOS for both architectures, which requires `rustup`. The Docker image, the wheel check in `ci.yml` and `scripts/run-functional-tests` use it, so that they ship and test the Rust code of the commit.

`hatch_build.py` implements these rules.
