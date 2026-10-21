import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence

import generate_sbom
import pytest


def make_dist(
    site_packages: Path,
    name: str,
    version: str,
    files: List[str],
    requires: Sequence[str] = (),
    license_expression: str = "MIT",
) -> None:
    """Install a fake distribution: its files, plus METADATA and RECORD"""
    dist_info = site_packages / f"{name.replace('-', '_')}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    metadata = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if license_expression:
        metadata.append(f"License-Expression: {license_expression}")
    metadata += [f"Requires-Dist: {r}" for r in requires]
    (dist_info / "METADATA").write_text("\n".join(metadata) + "\n")
    record = files + [f"{dist_info.name}/METADATA", f"{dist_info.name}/RECORD"]
    (dist_info / "RECORD").write_text("".join(f"{f},,\n" for f in record))
    for file in files:
        path = site_packages / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")


@pytest.fixture
def site_packages(tmp_path: Path) -> Path:
    sp = tmp_path / "site-packages"
    make_dist(
        sp, "ggshield", "1.2.3", ["ggshield/__init__.py"], ["requests>=2", "rich"]
    )
    make_dist(sp, "requests", "2.32.0", ["requests/__init__.py"], ["urllib3<3"])
    make_dist(sp, "urllib3", "2.2.0", ["urllib3/__init__.py"])
    make_dist(
        sp,
        "rich",
        "13.0.0",
        ["rich/__init__.py"],
        ["urllib3 ; extra == 'test' and python_version >= '3.9'"],
    )
    make_dist(
        sp,
        "cryptography",
        "50.0.0",
        ["cryptography/__init__.py", "cryptography/hazmat/bindings/_rust.abi3.so"],
        license_expression="Apache-2.0 OR BSD-3-Clause",
    )
    make_dist(sp, "jaraco-classes", "3.4.0", ["jaraco/classes/__init__.py"])
    make_dist(sp, "setuptools", "82.0.0", ["_distutils_hack/__init__.py"])
    make_dist(sp, "pyinstaller", "6.21.0", ["PyInstaller/__init__.py"])
    # Installed but not bundled: must not show up
    make_dist(sp, "pytest-mock", "3.0.0", ["pytest_mock/__init__.py"])
    return sp


OPENSSL_PYTHON = b"OpenSSL 3.5.9 29 Sep 2026"
OPENSSL_CRYPTOGRAPHY = b"OpenSSL 4.0.1 7 Jul 2026"


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    internal = bundle / "_internal"
    files: Dict[str, bytes] = {
        "base_library.zip": b"",
        "libpython3.14.so.1.0": b"junk\x003.14.8\x00" + OPENSSL_PYTHON + b"\x00",
        "cryptography/hazmat/bindings/_rust.abi3.so": OPENSSL_CRYPTOGRAPHY,
        "cryptography-50.0.0.dist-info/METADATA": b"",
        "libgcc_s.so.1": b"gcc runtime",
        "certifi/cacert.pem": b"unclaimed data files are ignored",
    }
    for name, data in files.items():
        path = internal / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (bundle / "ggshield-py").write_bytes(b"")
    return bundle


PYZ_MODULES = [
    "pyimod02_importers",
    "json",
    "json.decoder",
    "_sysconfigdata__linux_x86_64-linux-gnu",
    "ggshield",
    "ggshield.cmd",
    "requests",
    "urllib3",
    "rich",
    "jaraco",
    "jaraco.classes",
    "_distutils_hack",
    "mystery",
]


@pytest.fixture(autouse=True)
def fake_pyz(monkeypatch):
    monkeypatch.setattr(generate_sbom, "list_pyz_modules", lambda _: PYZ_MODULES)


def cargo_metadata() -> Dict:
    def pkg(name: str, version: str, source=None, license=None, kind="lib") -> Dict:
        return {
            "id": f"{name} {version}",
            "name": name,
            "version": version,
            "source": source,
            "license": license,
            "targets": [{"kind": [kind]}],
        }

    registry = "registry+https://github.com/rust-lang/crates.io-index"
    packages = [
        pkg("ggshield-dispatcher", "0.1.0"),
        pkg("ggshield-hook", "0.1.0"),
        pkg("ureq", "3.4.2", registry, "MIT OR Apache-2.0"),
        pkg("rustls", "0.23.0", registry, "Apache-2.0 OR ISC OR MIT"),
        pkg("serde_derive", "1.0.0", registry, "MIT OR Apache-2.0", "proc-macro"),
        pkg("syn", "2.0.0", registry, "MIT OR Apache-2.0"),
        pkg("cc", "1.0.0", registry, "MIT OR Apache-2.0"),
        pkg("tempfile", "3.0.0", registry, "MIT OR Apache-2.0"),
    ]

    def dep(pkg_id: str, kind=None) -> Dict:
        return {"pkg": pkg_id, "dep_kinds": [{"kind": kind, "target": None}]}

    nodes = [
        {
            "id": "ggshield-dispatcher 0.1.0",
            "deps": [dep("ggshield-hook 0.1.0"), dep("tempfile 3.0.0", "dev")],
        },
        {
            "id": "ggshield-hook 0.1.0",
            "deps": [dep("ureq 3.4.2"), dep("cc 1.0.0", "build")],
        },
        {
            "id": "ureq 3.4.2",
            "deps": [dep("rustls 0.23.0"), dep("serde_derive 1.0.0")],
        },
        {"id": "serde_derive 1.0.0", "deps": [dep("syn 2.0.0")]},
        {"id": "syn 2.0.0", "deps": []},
        {"id": "rustls 0.23.0", "deps": []},
        {"id": "cc 1.0.0", "deps": []},
        {"id": "tempfile 3.0.0", "deps": []},
    ]
    return {"packages": packages, "resolve": {"nodes": nodes}}


def run_main(monkeypatch, args: List[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["generate_sbom.py"] + args)
    return generate_sbom.main()


def generate(tmp_path: Path, monkeypatch, bundle: Path, site_packages: Path) -> Dict:
    def fake_run(cmd, **kwargs):
        assert "--filter-platform=aarch64-apple-darwin" in cmd
        # So that rustup finds rust/rust-toolchain.toml
        assert kwargs["cwd"] == tmp_path.resolve()
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(cargo_metadata()))

    monkeypatch.setattr(subprocess, "run", fake_run)
    output = tmp_path / "sbom.cdx.json"
    exit_code = run_main(
        monkeypatch,
        [
            str(bundle),
            "--version=1.2.3",
            "--target=arm64-apple-darwin",
            f"--site-packages={site_packages}",
            f"--cargo-manifest={tmp_path / 'Cargo.toml'}",
            f"--output={output}",
        ],
    )
    assert exit_code == 0
    return json.loads(output.read_text())


@pytest.fixture
def sbom(tmp_path, monkeypatch, bundle, site_packages) -> Dict:
    return generate(tmp_path, monkeypatch, bundle, site_packages)


def components_by_ref(sbom: Dict) -> Dict[str, Dict]:
    return {c["bom-ref"]: c for c in sbom["components"]}


def dependencies(sbom: Dict) -> Dict[str, List[str]]:
    return {d["ref"]: d["dependsOn"] for d in sbom["dependencies"]}


def test_lists_only_bundled_python_packages(sbom):
    """
    GIVEN a bundle and the environment it was built from
    WHEN generating its SBOM
    THEN it lists the packages providing a bundled module or file, and no
    other installed package
    """
    pypi = {r for r in components_by_ref(sbom) if r.startswith("pkg:pypi/")}
    assert pypi == {
        "pkg:pypi/requests@2.32.0",
        "pkg:pypi/urllib3@2.2.0",
        "pkg:pypi/rich@13.0.0",
        "pkg:pypi/cryptography@50.0.0",
        "pkg:pypi/jaraco-classes@3.4.0",
        "pkg:pypi/setuptools@82.0.0",
        "pkg:pypi/pyinstaller@6.21.0",
    }
    assert components_by_ref(sbom)["pkg:pypi/cryptography@50.0.0"]["licenses"] == [
        {"expression": "Apache-2.0 OR BSD-3-Clause"}
    ]


def test_warns_about_unclaimed_modules(
    tmp_path, monkeypatch, bundle, site_packages, capsys
):
    """
    GIVEN a bundled module no installed package provides
    WHEN generating the SBOM
    THEN a warning names it, and namespace packages do not get one
    """
    generate(tmp_path, monkeypatch, bundle, site_packages)
    err = capsys.readouterr().err
    assert "no package provides module mystery" in err
    assert "module jaraco\n" not in err


def test_python_dependency_graph(sbom):
    """
    GIVEN bundled packages requiring each other
    WHEN generating the SBOM
    THEN the root depends on ggshield's direct requirements and on what nothing
    else requires, and transitive requirements hang off their parent
    """
    deps = dependencies(sbom)
    root = deps["pkg:pypi/ggshield@1.2.3"]
    assert "pkg:pypi/requests@2.32.0" in root
    assert "pkg:pypi/setuptools@82.0.0" in root
    assert "pkg:pypi/urllib3@2.2.0" not in root
    assert deps["pkg:pypi/requests@2.32.0"] == ["pkg:pypi/urllib3@2.2.0"]
    # Only an extra requires it
    assert deps["pkg:pypi/rich@13.0.0"] == []


def test_python_runtime_and_openssl(sbom):
    """
    GIVEN a bundle whose libpython and an extension embed OpenSSL
    WHEN generating the SBOM
    THEN the Python version comes from the bundle, and each OpenSSL build is
    listed under the component that embeds it
    """
    components = components_by_ref(sbom)
    deps = dependencies(sbom)
    assert components["pkg:generic/python@3.14.8"]["cpe"].startswith(
        "cpe:2.3:a:python:python:3.14.8:"
    )
    assert deps["pkg:generic/python@3.14.8"] == ["pkg:generic/openssl@3.5.9"]
    assert "pkg:generic/openssl@4.0.1" in deps["pkg:pypi/cryptography@50.0.0"]


def test_unclaimed_libraries_are_listed_as_files(sbom, bundle):
    """
    GIVEN a native library no package provides
    WHEN generating the SBOM
    THEN it is listed as a file, with its SHA-256
    """
    component = components_by_ref(sbom)["file:libgcc_s.so.1"]
    assert component["type"] == "file"
    assert component["hashes"] == [
        {"alg": "SHA-256", "content": hashlib.sha256(b"gcc runtime").hexdigest()}
    ]
    assert not any("cacert" in ref for ref in components_by_ref(sbom))


def test_rust_crates(sbom):
    """
    GIVEN the dispatcher's cargo metadata
    WHEN generating the SBOM
    THEN external crates linked into it are listed, workspace crates are
    walked through, and build and dev dependencies and proc-macros are left out
    """
    components = components_by_ref(sbom)
    cargo = {r for r in components if r.startswith("pkg:cargo/")}
    assert cargo == {"pkg:cargo/ureq@3.4.2", "pkg:cargo/rustls@0.23.0"}
    deps = dependencies(sbom)
    assert "pkg:cargo/ureq@3.4.2" in deps["pkg:pypi/ggshield@1.2.3"]
    assert deps["pkg:cargo/ureq@3.4.2"] == ["pkg:cargo/rustls@0.23.0"]
    assert components["pkg:cargo/ureq@3.4.2"]["licenses"] == [
        {"expression": "MIT OR Apache-2.0"}
    ]


def test_document(sbom):
    """
    GIVEN a generated SBOM
    THEN it is a CycloneDX 1.5 document describing ggshield for the target,
    and every dependency points at a declared component
    """
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["purl"] == "pkg:pypi/ggshield@1.2.3"
    assert sbom["metadata"]["properties"] == [
        {"name": "ggshield:target", "value": "arm64-apple-darwin"}
    ]
    refs = set(components_by_ref(sbom)) | {"pkg:pypi/ggshield@1.2.3"}
    for dep in sbom["dependencies"]:
        assert dep["ref"] in refs
        assert set(dep["dependsOn"]) <= refs


def test_describe_interpreter_refuses_another_python(
    tmp_path, monkeypatch, bundle, site_packages
):
    """
    GIVEN --describe-interpreter
    WHEN the running Python is not the bundled one
    THEN the script fails rather than describe the wrong libraries
    """
    monkeypatch.setattr(generate_sbom.platform, "python_version", lambda: "3.14.4")
    with pytest.raises(SystemExit, match="Python 3.14.4 and the bundle has 3.14.8"):
        run_main(
            monkeypatch,
            [
                str(bundle),
                "--version=1.2.3",
                "--target=x86_64-unknown-linux-gnu",
                f"--site-packages={site_packages}",
                "--describe-interpreter",
                f"--output={tmp_path / 'sbom.json'}",
            ],
        )


def test_purl_encodes_local_versions():
    """
    GIVEN a version with a `+` local part, as internal builds have
    THEN the purl percent-encodes it
    """
    assert (
        generate_sbom.make_purl("pypi", "ggshield", "1.57.0+abc1234")
        == "pkg:pypi/ggshield@1.57.0%2Babc1234"
    )


def test_rejects_a_directory_without_bundle(tmp_path, monkeypatch, site_packages):
    """
    GIVEN a directory that is not a ggshield bundle
    THEN the script fails with an explicit error
    """
    with pytest.raises(SystemExit, match="contains no ggshield-py executable"):
        run_main(
            monkeypatch,
            [
                str(tmp_path),
                "--version=1.2.3",
                "--target=x86_64-unknown-linux-gnu",
                f"--site-packages={site_packages}",
                f"--output={tmp_path / 'sbom.json'}",
            ],
        )
