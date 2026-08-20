"""Embed the Rust ``ggshield`` dispatcher into a platform-specific wheel.

Active only when ``GGSHIELD_BUILD_RUST=1`` (set by the wheel CI matrix);
otherwise the build is the pure-Python ``py3-none-any`` fallback wheel. When
active the wheel installs both ``ggshield`` (the dispatcher) and ``ggshield-py``
(the Python entry point, renamed by hatch_meta.py), the layout the dispatcher
expects to exec its sibling from.
"""

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


# macOS wheels are universal2: the arm64 runner builds an Intel slice too and
# lipo-fuses them, so no Intel runner is needed.
MACOS_TARGETS = ["aarch64-apple-darwin", "x86_64-apple-darwin"]

# The same two slices as MACOS_TARGETS, spelled the way `lipo -archs` spells them
# (`arm64`, not `aarch64`).
MACOS_ARCHS = {"arm64", "x86_64"}

# ELF `e_machine` values, as they are spelled in a wheel platform tag.
ELF_MACHINES = {62: "x86_64", 183: "aarch64"}


class WrongBinaryError(Exception):
    """The built binary does not match the platform tag we are about to write."""


class SigningError(Exception):
    """A signing script failed, with whatever it printed about why."""


class RustDispatcherBuildHook(BuildHookInterface):
    PLUGIN_NAME = "ggshield-rust"

    def initialize(self, version, build_data):
        if os.environ.get("GGSHIELD_BUILD_RUST") != "1":
            return

        crate = Path(self.root) / "rust"
        name = "ggshield" + (".exe" if sys.platform == "win32" else "")
        binary = crate / "target" / "release" / name

        # Unconditionally, never `if not binary.exists()`: a leftover
        # target/release/ggshield from another arch -- or another OS -- is
        # indistinguishable from a fresh one by existence alone, and cargo is
        # nearly free when the artifact is already current.
        self._build(crate, binary)

        # A native binary but no Python extension module: platform-specific yet
        # valid for any Python 3 -> py3-none-<platform>. (Linux relabels the raw
        # linux_* tag to manylinux/musllinux in CI.)
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{self._platform_tag(binary)}"
        build_data["shared_scripts"][str(binary)] = name

    def _platform_tag(self, binary: Path) -> str:
        """The wheel's platform tag, checked against what ``binary`` really is.

        Cargo decides freshness from its fingerprint database and dependency
        mtimes, not from the content of the output file, so an artifact that was
        replaced behind its back is reported as "Finished" and shipped as-is.
        Reading the binary is the only way the tag and the payload cannot
        disagree; a mismatch is a build failure, not a wheel.
        """
        if sys.platform == "darwin":
            # Not sysconfig: it reports the building interpreter's own arch
            # (`_arm64` under an arm64 Python), not the universal2 we lipo.
            archs = subprocess.run(
                ["lipo", "-archs", str(binary)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()
            if set(archs) != MACOS_ARCHS:
                raise WrongBinaryError(
                    f"{binary} holds {archs or ['nothing']}, not the "
                    f"{sorted(MACOS_ARCHS)} macosx_11_0_universal2 promises"
                )
            return "macosx_11_0_universal2"

        plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        if sys.platform.startswith("linux"):
            self._verify_elf(binary, plat)
        # No equivalent check on Windows: reading the PE machine field means
        # following e_lfanew, and the unconditional build above already rules
        # out the stale-artifact case the ELF/lipo checks exist for.
        return plat

    @staticmethod
    def _verify_elf(binary: Path, plat: str) -> None:
        with binary.open("rb") as fp:
            header = fp.read(20)
        if header[:4] != b"\x7fELF":
            raise WrongBinaryError(
                f"{binary} is not an ELF binary (magic {header[:4]!r}), "
                f"so it cannot go in a {plat} wheel"
            )
        # Little-endian read: both machines we ship are, and a big-endian header
        # reads as an unknown value here, which fails below -- correctly.
        machine = ELF_MACHINES.get(int.from_bytes(header[18:20], "little"))
        if machine is None or not plat.endswith(machine):
            raise WrongBinaryError(
                f"{binary} is an ELF for {machine or 'an unsupported machine'}, "
                f"which does not match the {plat} wheel tag"
            )

    def _sign(self, binary: Path) -> None:
        """Code-sign the binary, when the build was given a certificate.

        On macOS this is the fused file rather than the slices: one signature
        covers both, and cargo leaves the x86_64 slice unsigned altogether.

        Unsigned -- local builds and PRs from forks, neither of which can read the
        secrets -- the wheel still installs and runs. On macOS what it loses is a
        stable designated requirement: an ad-hoc signature carries no signing
        identity, so the requirement degenerates to the binary's cdhash, which
        changes on every build. That requirement is what a Keychain item's ACL
        records, so the grant the user gives `ggshield` for the API token stops
        matching on the next upgrade. On Windows nothing binds a stored credential
        to a signature, so an unsigned build costs only the trust an AV or EDR
        heuristic extends to a native executable sitting in a venv.
        """
        scripts = Path(self.root) / "scripts/build-os-packages"
        if sys.platform == "darwin":
            if not os.environ.get("MACOS_P12_FILE"):
                return
            self._run_signer([str(scripts / "macos-sign-file"), str(binary)])
        elif sys.platform == "win32":
            if not os.environ.get("SM_API_KEY"):
                return
            # Through bash, since Windows honours no shebang, and with a
            # forward-slash path: bash reads the backslashes of a native path as
            # escapes, so `dirname` sees no directory and `cp` no such file.
            self._run_signer(
                [
                    self._git_bash(),
                    str(scripts / "windows-sign-file"),
                    binary.as_posix(),
                ]
            )

    @staticmethod
    def _git_bash() -> str:
        """The bash that Git for Windows ships.

        Never a bare ``bash``: on PATH that is System32's WSL launcher, which
        answers every invocation with "no installed distributions". Git for
        Windows keeps its bash in ``bin``, but ships ``git`` in ``cmd``, ``bin``
        and ``mingw64/bin`` alike, so which one PATH offers says nothing about
        how far up the install root is. Try each depth, then the default
        locations.
        """
        roots = []
        git = shutil.which("git")
        if git:
            found = Path(git).resolve().parent
            roots += [found, found.parent, found.parent.parent]
        roots += [Path(r"C:\Program Files\Git"), Path(r"C:\Program Files (x86)\Git")]

        tried = []
        for root in roots:
            bash = root / "bin" / "bash.exe"
            tried.append(str(bash))
            if bash.is_file():
                return str(bash)
        raise SigningError(
            "no Git for Windows bash to sign with, tried:\n  " + "\n  ".join(tried)
        )

    def _run_signer(self, argv: list[str]) -> None:
        """Run a signing script, and say what it said when it fails.

        The output goes in the exception rather than to stderr: the build backend
        forwards neither of a child's streams, and the traceback is the only text
        that reaches the log.
        """
        signer = subprocess.run(argv, capture_output=True, text=True)
        if signer.returncode:
            raise SigningError(
                f"{argv[0]} exited {signer.returncode}\n{signer.stdout}{signer.stderr}"
            )

    def _build(self, crate: Path, binary: Path) -> None:
        # --locked: build the dependency versions committed in rust/Cargo.lock,
        # not whatever resolves today.
        if sys.platform == "darwin":
            for target in MACOS_TARGETS:
                # cwd=crate: add the target to the toolchain pinned by
                # rust-toolchain.toml, which is the one cargo below uses.
                subprocess.run(
                    ["rustup", "target", "add", target], cwd=crate, check=True
                )
                subprocess.run(
                    [
                        "cargo",
                        "build",
                        "--release",
                        "--locked",
                        "--target",
                        target,
                        "--bin",
                        "ggshield",
                    ],
                    cwd=crate,
                    check=True,
                )
            binary.parent.mkdir(parents=True, exist_ok=True)
            slices = [
                str(crate / "target" / t / "release" / "ggshield")
                for t in MACOS_TARGETS
            ]
            subprocess.run(
                ["lipo", "-create", "-output", str(binary), *slices], check=True
            )
            self._sign(binary)
        else:
            subprocess.run(
                ["cargo", "build", "--release", "--locked", "--bin", "ggshield"],
                cwd=crate,
                check=True,
            )
            self._sign(binary)
