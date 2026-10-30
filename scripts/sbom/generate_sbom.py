#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM for a standalone ggshield bundle (the PyInstaller
onedir output, with the Rust dispatcher next to `ggshield-py`).

The bundle is the source of truth: a PyInstaller bundle keeps the metadata of
only a handful of the packages it contains, so a scanner run on it misses most
of them, while a list built from uv.lock misses what PyInstaller pulls in
from other dependency groups (setuptools, for instance). Instead, this lists
the modules in the bundle's PYZ archive and the files under `_internal/`, and
attributes each of them to a distribution through the RECORD files of the
environment the bundle was built from.

On top of the Python packages, the SBOM lists:
- the Python runtime, and the native libraries it embeds when this script runs
  on the interpreter that was bundled (--describe-interpreter),
- every OpenSSL build found in the bundle's binaries,
- the PyInstaller bootloader,
- the Rust crates linked into the dispatcher, read from `cargo metadata`,
- native libraries no package claims, as files with their SHA-256.

Needs Python 3.10 or later, PyInstaller to read the PYZ archive, and cargo when
--cargo-manifest is set. Everything else is the standard library.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import Distribution, distributions
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote


SPEC_VERSION = "1.5"

# ggshield's own code is the root component, not one of its components
ROOT_PACKAGE = "ggshield"

# Top-level modules PyInstaller adds to the PYZ archive itself
PYINSTALLER_MODULE_PREFIXES = ("pyimod", "pyi_rth_", "_pyi_rth_utils")

SHARED_LIBRARY_RE = re.compile(r"\.(so|dylib|dll|pyd)$|\.so\.")

# "OpenSSL 3.5.9 29 Sep 2026", as OpenSSL_version(OPENSSL_VERSION) prints it.
# Requiring the date keeps unrelated strings mentioning OpenSSL out.
OPENSSL_VERSION_RE = re.compile(
    rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2}) +\d{1,2} [A-Z][a-z]{2} \d{4}"
)

PYINSTALLER_LICENSE = "GPL-2.0-or-later WITH Bootloader-exception"


def make_purl(type_: str, name: str, version: str) -> str:
    # Versions such as `1.57.0+abc1234` need their `+` percent-encoded
    return f"pkg:{type_}/{name}@{quote(version, safe='')}"


def normalize_name(name: str) -> str:
    """PEP 503 normalization, as used by pkg:pypi purls"""
    return re.sub(r"[-_.]+", "-", name).lower()


def module_name_from_path(path: PurePosixPath) -> Optional[str]:
    """Return the module a RECORD entry defines, if it is a Python source file"""
    if path.suffix != ".py" or ".." in path.parts:
        return None
    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def is_stdlib_module(name: str) -> bool:
    top = name.split(".")[0]
    return top in sys.stdlib_module_names or top.startswith("_sysconfigdata")


def is_shared_library(path: PurePosixPath) -> bool:
    return bool(SHARED_LIBRARY_RE.search(path.name))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_openssl_versions(path: Path) -> Set[str]:
    return {m.decode() for m in OPENSSL_VERSION_RE.findall(path.read_bytes())}


@dataclass
class Component:
    bom_ref: str
    name: str
    version: str
    type: str = "library"
    purl: Optional[str] = None
    cpe: Optional[str] = None
    licenses: List[Dict[str, Any]] = field(default_factory=list)
    description: Optional[str] = None
    hashes: List[Dict[str, str]] = field(default_factory=list)
    depends_on: Set[str] = field(default_factory=set)

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"type": self.type, "bom-ref": self.bom_ref}
        out["name"] = self.name
        if self.version:
            out["version"] = self.version
        if self.description:
            out["description"] = self.description
        if self.hashes:
            out["hashes"] = self.hashes
        if self.licenses:
            out["licenses"] = self.licenses
        if self.cpe:
            out["cpe"] = self.cpe
        if self.purl:
            out["purl"] = self.purl
        return out


def pypi_component(dist: Distribution) -> Component:
    name = dist.metadata["Name"]
    version = dist.version
    purl = make_purl("pypi", normalize_name(name), version)
    return Component(
        bom_ref=purl,
        name=name,
        version=version,
        purl=purl,
        licenses=python_licenses(dist),
    )


def python_licenses(dist: Distribution) -> List[Dict[str, Any]]:
    """Read the license from the core metadata, most precise field first"""
    metadata = dist.metadata
    expression = metadata.get("License-Expression")
    if expression:
        return [{"expression": expression}]
    # The License field often holds the whole license text: only keep a name
    text = (metadata.get("License") or "").strip()
    if text and "\n" not in text and len(text) <= 64 and text != "UNKNOWN":
        return [{"license": {"name": text}}]
    prefix = "License :: OSI Approved :: "
    return [
        {"license": {"name": c[len(prefix) :]}}
        for c in metadata.get_all("Classifier") or []
        if c.startswith(prefix)
    ]


def requirement_names(dist: Distribution) -> Set[str]:
    """Normalized names of the distributions `dist` requires, extras excluded.

    Other markers are ignored: callers only keep the edges whose both ends are
    in the bundle, which is what platform and version markers would have
    decided anyway. Extras would not: `idna[all]` requiring pytest does not
    make pytest a dependency of idna.
    """
    names = set()
    for req in dist.requires or []:
        requirement, _, marker = req.partition(";")
        if re.search(r"\bextra\s*==", marker):
            continue
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
        if match:
            names.add(normalize_name(match.group(1)))
    return names


class DistributionIndex:
    """Maps modules and files to the distributions installed in site-packages"""

    def __init__(self, site_packages: List[Path]):
        self.dists: Dict[str, Distribution] = {}
        self.modules: Dict[str, str] = {}
        self.files: Dict[str, str] = {}
        self.library_names: Dict[str, str] = {}
        # Packages with no file of their own (implicit namespace packages, such
        # as `jaraco`): their submodules are attributed instead
        self.namespaces: Set[str] = set()
        for dist in distributions(path=[str(p) for p in site_packages]):
            key = normalize_name(dist.metadata["Name"])
            if key in self.dists:
                # Same package seen twice on the path: the first one wins, as
                # it does for imports
                continue
            self.dists[key] = dist
            for file in dist.files or []:
                path = PurePosixPath(file.as_posix())
                module = module_name_from_path(path)
                if module:
                    self.modules.setdefault(module, key)
                    parts = module.split(".")
                    for i in range(1, len(parts)):
                        self.namespaces.add(".".join(parts[:i]))
                self.files.setdefault(str(path), key)
                if is_shared_library(path):
                    # PyInstaller moves the libraries an extension links to
                    # next to the executable, so match them by name too
                    self.library_names.setdefault(path.name, key)

    def owner_of_module(self, name: str) -> Optional[str]:
        return self.modules.get(name)

    def owner_of_file(self, path: PurePosixPath) -> Optional[str]:
        owner = self.files.get(str(path))
        if owner is None and is_shared_library(path):
            owner = self.library_names.get(path.name)
        return owner


def list_pyz_modules(executable: Path) -> List[str]:
    # Only in the `standalone` dependency group, hence the late import
    from PyInstaller.archive.readers import CArchiveReader  # type: ignore

    archive = CArchiveReader(str(executable))
    modules: List[str] = []
    for name in archive.toc:
        if name.endswith(".pyz"):
            modules.extend(archive.open_embedded_archive(name).toc)
    if not modules:
        raise ValueError(f"{executable} contains no PYZ archive")
    return modules


@dataclass
class BundleContent:
    # Normalized distribution name -> why it is included, for --verbose
    dists: Dict[str, str] = field(default_factory=dict)
    runtime_files: List[PurePosixPath] = field(default_factory=list)
    # Native libraries of the packages, with their owner
    package_libraries: List[Tuple[PurePosixPath, str]] = field(default_factory=list)
    unclaimed_libraries: List[PurePosixPath] = field(default_factory=list)
    unclaimed_modules: List[str] = field(default_factory=list)


def is_runtime_file(path: PurePosixPath) -> bool:
    """Files of the Python runtime itself, rather than of a package"""
    name = path.name
    if len(path.parts) == 1 and name == "base_library.zip":
        return True
    if re.match(r"(lib)?python3[\d.]*(\.dll|\.dylib|\.so)", name):
        return True
    # Extension modules of the standard library, which Windows ships as .pyd
    return is_shared_library(path) and is_stdlib_module(name.split(".")[0])


def scan_bundle(bundle_dir: Path, index: DistributionIndex) -> BundleContent:
    content = BundleContent()
    executables = [
        bundle_dir / name
        for name in ("ggshield-py", "ggshield-py.exe")
        if (bundle_dir / name).exists()
    ]
    if not executables:
        raise SystemExit(f"error: {bundle_dir} contains no ggshield-py executable")
    executable = executables[0]

    for module in list_pyz_modules(executable):
        if is_stdlib_module(module) or module.split(".")[0] == ROOT_PACKAGE:
            continue
        if module.startswith(PYINSTALLER_MODULE_PREFIXES):
            continue
        owner = index.owner_of_module(module)
        if owner:
            content.dists.setdefault(owner, f"module {module}")
        elif module not in index.namespaces:
            content.unclaimed_modules.append(module)

    internal_dir = bundle_dir / "_internal"
    for path in sorted(internal_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = PurePosixPath(path.relative_to(internal_dir).as_posix())
        if any(part.endswith(".dist-info") for part in rel.parts):
            continue
        owner = index.owner_of_file(rel)
        if owner == ROOT_PACKAGE:
            continue
        if owner:
            content.dists.setdefault(owner, f"file {rel}")
            if is_shared_library(rel):
                content.package_libraries.append((rel, owner))
        elif is_runtime_file(rel):
            content.runtime_files.append(rel)
        elif is_shared_library(rel):
            content.unclaimed_libraries.append(rel)
    return content


class SbomBuilder:
    def __init__(self, root: Component):
        self.root = root
        self.components: Dict[str, Component] = {}

    def add(self, component: Component, parent: Optional[Component] = None) -> None:
        self.components.setdefault(component.bom_ref, component)
        (parent or self.root).depends_on.add(component.bom_ref)

    def to_json(self, target: str) -> Dict[str, Any]:
        components = sorted(self.components.values(), key=lambda c: c.bom_ref)
        all_components = [self.root] + components
        timestamp = datetime.fromtimestamp(
            int(os.environ.get("SOURCE_DATE_EPOCH", datetime.now().timestamp())),
            tz=timezone.utc,
        )
        return {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "ggshield scripts/sbom/generate_sbom.py",
                        }
                    ]
                },
                "component": self.root.to_json(),
                "supplier": {
                    "name": "GitGuardian",
                    "url": ["https://www.gitguardian.com"],
                },
                "properties": [{"name": "ggshield:target", "value": target}],
            },
            "components": [c.to_json() for c in components],
            "dependencies": [
                {"ref": c.bom_ref, "dependsOn": sorted(c.depends_on)}
                for c in all_components
            ],
        }


def add_python_packages(
    builder: SbomBuilder, content: BundleContent, index: DistributionIndex
) -> Dict[str, Component]:
    included = {key: pypi_component(index.dists[key]) for key in content.dists}
    required: Set[str] = set()
    for key, component in included.items():
        for dep in requirement_names(index.dists[key]) & included.keys() - {key}:
            component.depends_on.add(included[dep].bom_ref)
            required.add(dep)

    # ggshield's direct dependencies, plus what nothing in the bundle requires:
    # PyInstaller pulled those in (its hooks, or another dependency group)
    root_dist = index.dists.get(ROOT_PACKAGE)
    direct = requirement_names(root_dist) if root_dist else set()
    for key, component in included.items():
        if key in direct or key not in required:
            builder.add(component)
        else:
            builder.components[component.bom_ref] = component
    return included


def interpreter_libraries() -> List[Component]:
    """Native libraries the running interpreter embeds or links to"""
    libraries = []

    def add(name: str, version: str, cpe_vendor_product: str) -> None:
        purl = make_purl("generic", name, version)
        libraries.append(
            Component(
                bom_ref=purl,
                name=name,
                version=version,
                purl=purl,
                cpe=f"cpe:2.3:a:{cpe_vendor_product}:{version}:*:*:*:*:*:*:*",
            )
        )

    import sqlite3
    import zlib
    from xml.parsers import expat

    add("sqlite", sqlite3.sqlite_version, "sqlite:sqlite")
    add("zlib", zlib.ZLIB_RUNTIME_VERSION, "zlib:zlib")
    add("expat", expat.EXPAT_VERSION.split("_")[-1], "libexpat_project:libexpat")
    return libraries


def bundled_python_version(internal_dir: Path, content: BundleContent) -> str:
    """Read the version of the bundled Python from its shared library.

    libpython3.14.so.1.0, libpython3.14.dylib and python314.dll all hold the
    full version (PY_VERSION) as a NUL-terminated string.
    """
    versions = set()
    for rel in content.runtime_files:
        match = re.match(r"(?:lib)?python3\.?(\d+)", rel.name)
        if match and is_shared_library(rel):
            minor = match.group(1)
            pattern = rb"\x00(3\." + minor.encode() + rb"\.\d+(?:(?:a|b|rc)\d+)?)\x00"
            found = re.findall(pattern, (internal_dir / rel).read_bytes())
            versions.update(v.decode() for v in found)
    if len(versions) != 1:
        raise SystemExit(
            f"error: cannot tell the bundled Python version (found: {sorted(versions)})"
        )
    return versions.pop()


def python_component(version: str) -> Component:
    purl = make_purl("generic", "python", version)
    return Component(
        bom_ref=purl,
        name="python",
        version=version,
        purl=purl,
        cpe=f"cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
        licenses=[{"expression": "PSF-2.0"}],
        description="CPython runtime",
    )


def add_runtime(
    builder: SbomBuilder,
    bundle_dir: Path,
    content: BundleContent,
    index: DistributionIndex,
    packages: Dict[str, Component],
    describe_interpreter: bool,
) -> None:
    internal_dir = bundle_dir / "_internal"
    python = python_component(bundled_python_version(internal_dir, content))
    builder.add(python)
    if describe_interpreter:
        if platform.python_version() != python.version:
            raise SystemExit(
                f"error: --describe-interpreter, but this is Python"
                f" {platform.python_version()} and the bundle has {python.version}"
            )
        for library in interpreter_libraries():
            builder.add(library, parent=python)

    # Only PyInstaller's bootloader ships, not the package nor its dependencies
    pyinstaller = index.dists.get("pyinstaller")
    if pyinstaller is None:
        raise SystemExit("error: PyInstaller is not installed in the build environment")
    purl = make_purl("pypi", "pyinstaller", pyinstaller.version)
    builder.add(
        Component(
            bom_ref=purl,
            name="pyinstaller",
            version=pyinstaller.version,
            purl=purl,
            licenses=[{"expression": PYINSTALLER_LICENSE}],
            description="PyInstaller bootloader",
        )
    )

    for rel in content.unclaimed_libraries:
        builder.add(
            Component(
                bom_ref=f"file:{rel}",
                type="file",
                name=str(rel),
                version="",
                hashes=[{"alg": "SHA-256", "content": sha256_file(internal_dir / rel)}],
            )
        )

    # OpenSSL is linked statically into libpython and into some extensions:
    # look for its version string in every native file of the bundle
    native_files: List[Tuple[PurePosixPath, Component]] = [
        (rel, python) for rel in content.runtime_files if is_shared_library(rel)
    ]
    native_files += [(rel, packages[key]) for rel, key in content.package_libraries]
    native_files += [
        (rel, builder.components[f"file:{rel}"]) for rel in content.unclaimed_libraries
    ]
    for rel, owner in native_files:
        path = internal_dir / rel
        for version in sorted(find_openssl_versions(path)):
            purl = make_purl("generic", "openssl", version)
            builder.add(
                Component(
                    bom_ref=purl,
                    name="openssl",
                    version=version,
                    purl=purl,
                    cpe=f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
                    licenses=[{"expression": "Apache-2.0"}],
                ),
                parent=owner,
            )


def rust_triple(target: str) -> str:
    # ggshield names Apple Silicon archives "arm64", Rust says "aarch64"
    return re.sub(r"^arm64-", "aarch64-", target)


def add_rust_crates(builder: SbomBuilder, manifest: Path, target: str) -> None:
    manifest = manifest.resolve()
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version=1",
            "--locked",
            f"--manifest-path={manifest}",
            f"--filter-platform={rust_triple(target)}",
        ],
        # rustup reads rust-toolchain.toml from the working directory, not
        # from the manifest's
        cwd=manifest.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}

    def is_proc_macro(pkg_id: str) -> bool:
        return any(
            "proc-macro" in target["kind"] for target in packages[pkg_id]["targets"]
        )

    def normal_deps(pkg_id: str) -> List[str]:
        # Build and dev dependencies, and proc-macros, run at build time only:
        # they do not end up in the binary
        return [
            dep["pkg"]
            for dep in nodes[pkg_id]["deps"]
            if any(kind["kind"] is None for kind in dep["dep_kinds"])
            and not is_proc_macro(dep["pkg"])
        ]

    def component(pkg_id: str) -> Component:
        pkg = packages[pkg_id]
        purl = make_purl("cargo", pkg["name"], pkg["version"])
        if purl not in builder.components:
            licenses = [{"expression": pkg["license"]}] if pkg.get("license") else []
            builder.components[purl] = Component(
                bom_ref=purl,
                name=pkg["name"],
                version=pkg["version"],
                purl=purl,
                licenses=licenses,
            )
        return builder.components[purl]

    dispatcher = next(
        p["id"] for p in metadata["packages"] if p["name"] == "ggshield-dispatcher"
    )
    # Workspace crates (no `source`) are ggshield itself: walk through them,
    # attaching their external dependencies to the root
    seen: Set[str] = set()
    stack: List[Tuple[str, Optional[Component]]] = [(dispatcher, None)]
    while stack:
        pkg_id, parent = stack.pop()
        is_external = packages[pkg_id]["source"] is not None
        current = parent
        if is_external:
            current = component(pkg_id)
            (parent or builder.root).depends_on.add(current.bom_ref)
        if pkg_id in seen:
            continue
        seen.add(pkg_id)
        for dep in normal_deps(pkg_id):
            stack.append((dep, current))


def default_site_packages() -> List[Path]:
    paths = sysconfig.get_paths()
    return sorted({Path(paths["purelib"]), Path(paths["platlib"])})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a CycloneDX SBOM for a standalone ggshield bundle"
    )
    parser.add_argument("bundle_dir", type=Path, help="PyInstaller onedir output")
    parser.add_argument("--version", required=True, help="ggshield version")
    parser.add_argument("--target", required=True, help="e.g. x86_64-apple-darwin")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--site-packages",
        type=Path,
        action="append",
        help="Environment the bundle was built from (default: this interpreter's)",
    )
    parser.add_argument("--cargo-manifest", type=Path, help="rust/Cargo.toml")
    parser.add_argument(
        "--describe-interpreter",
        action="store_true",
        help="Also list the native libraries of this interpreter. Only correct"
        " when this interpreter is the one PyInstaller bundled",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    index = DistributionIndex(args.site_packages or default_site_packages())
    content = scan_bundle(args.bundle_dir, index)

    purl = make_purl("pypi", ROOT_PACKAGE, args.version)
    root = Component(
        bom_ref=purl,
        type="application",
        name="ggshield",
        version=args.version,
        purl=purl,
        licenses=[{"expression": "MIT"}],
        description="ggshield standalone executable",
    )
    builder = SbomBuilder(root)
    packages = add_python_packages(builder, content, index)
    add_runtime(
        builder, args.bundle_dir, content, index, packages, args.describe_interpreter
    )
    if args.cargo_manifest:
        add_rust_crates(builder, args.cargo_manifest, args.target)

    if args.verbose:
        for key, reason in sorted(content.dists.items()):
            print(f"{key}: {reason}", file=sys.stderr)
    for module in content.unclaimed_modules:
        print(f"warning: no package provides module {module}", file=sys.stderr)

    sbom = builder.to_json(args.target)
    args.output.write_text(json.dumps(sbom, indent=2) + "\n")
    print(f"{args.output}: {len(sbom['components'])} components", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
