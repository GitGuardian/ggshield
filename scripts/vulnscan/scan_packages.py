#!/usr/bin/env python3
"""
Scan the ggshield packages built by build_release_assets.yml for known
vulnerabilities using Grype (https://github.com/anchore/grype), and print a
Markdown report to stdout (meant to be piped into $GITHUB_STEP_SUMMARY).

Only stdlib imports on purpose: this runs in CI straight off a checkout,
without installing ggshield's own dependencies. Grype itself must already be
installed and on PATH.
"""
import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple


SEVERITY_ORDER = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def find_packages(packages_dir: Path) -> List[Path]:
    """Find the plain tar.gz/zip bundles under packages_dir.

    Skips .rpm/.deb/.msi/.nupkg: those need OS-specific tooling to unpack,
    while the tar.gz/zip bundles can just be extracted directly.
    """
    return sorted(
        p
        for p in packages_dir.rglob("*")
        if p.name.endswith(".tar.gz") or p.name.endswith(".zip")
    )


def extract(package: Path, dest: Path) -> None:
    if package.name.endswith(".zip"):
        with zipfile.ZipFile(package) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(package) as tf:
            tf.extractall(dest)


def scan(extracted_dir: Path) -> List[Dict[str, Any]]:
    result = subprocess.run(
        ["grype", f"dir:{extracted_dir}", "-o", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout).get("matches", [])


def format_vulnerability(vulnerability: Dict[str, Any]) -> str:
    vuln_id = vulnerability.get("id", "?")
    data_source = vulnerability.get("dataSource")
    return f"[{vuln_id}]({data_source})" if data_source else vuln_id


def format_fix(vulnerability: Dict[str, Any]) -> str:
    versions = vulnerability.get("fix", {}).get("versions") or []
    return ", ".join(versions) if versions else "-"


def sort_key(row: Tuple[str, Dict[str, Any]]) -> Tuple[str, int, str]:
    package_name, match = row
    severity = match.get("vulnerability", {}).get("severity", "Unknown")
    vuln_id = match.get("vulnerability", {}).get("id", "")
    return (package_name, -severity_rank(severity), vuln_id)


def render_markdown(results: Dict[str, List[Dict[str, Any]]]) -> str:
    lines = ["# Release package vulnerability scan", ""]
    if not results:
        lines.append("No packages found to scan.")
        return "\n".join(lines)

    # A single vulnerable component (e.g. Python) is often detected via more
    # than one file in the bundle (Windows ships both python3.dll and
    # python310.dll) - dedupe those down to one row per (package, component,
    # CVE), since the file path isn't meaningful to a reader of this report.
    deduped: Dict[Tuple[str, str, str], Tuple[str, Dict[str, Any]]] = {}
    for package_name, matches in results.items():
        for match in matches:
            key = (
                package_name,
                match.get("artifact", {}).get("name", "?"),
                match.get("vulnerability", {}).get("id", "?"),
            )
            deduped.setdefault(key, (package_name, match))

    rows = list(deduped.values())
    if not rows:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines)

    lines.append(
        "| Package | Component | Installed | Fixed in | Vulnerability | Severity |"
    )
    lines.append("|---|---|---|---|---|---|")
    for package_name, match in sorted(rows, key=sort_key):
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        lines.append(
            f"| {package_name} | {artifact.get('name', '?')} "
            f"| {artifact.get('version', '?')} | {format_fix(vulnerability)} "
            f"| {format_vulnerability(vulnerability)} "
            f"| {vulnerability.get('severity', 'Unknown')} |"
        )
    lines.append("")
    lines.append(
        "To silence a false positive or an accepted risk, see "
        "[doc/dev/vulnerability-scanning.md]"
        "(https://github.com/GitGuardian/ggshield/blob/main/doc/dev/vulnerability-scanning.md)."
    )
    return "\n".join(lines)


def has_critical(results: Dict[str, List[Dict[str, Any]]]) -> bool:
    return any(
        match.get("vulnerability", {}).get("severity") == "Critical"
        for matches in results.values()
        for match in matches
    )


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "packages_dir",
        type=Path,
        help="Directory containing the downloaded build_os_packages artifacts",
    )
    args = parser.parse_args(argv)

    results: Dict[str, List[Dict[str, Any]]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for package in find_packages(args.packages_dir):
            extracted_dir = Path(tmp) / package.name
            extract(package, extracted_dir)
            results[package.name] = scan(extracted_dir)

    print(render_markdown(results))

    if has_critical(results):
        print(
            "\n:x: Critical severity vulnerabilities found - see the table "
            "above. Fix them, or add an ignore rule (with a reason comment) "
            "to .grype.yaml if this is a false positive or an accepted risk.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
