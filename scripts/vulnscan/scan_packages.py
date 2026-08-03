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
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


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


def summarize(matches: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for match in matches:
        severity = match.get("vulnerability", {}).get("severity", "Unknown")
        counts[severity] += 1
    return dict(counts)


def format_counts(counts: Dict[str, int]) -> str:
    if not counts:
        return "none"
    ordered = sorted(counts.items(), key=lambda kv: severity_rank(kv[0]), reverse=True)
    return ", ".join(f"{severity}: {count}" for severity, count in ordered)


def render_markdown(results: Dict[str, List[Dict[str, Any]]]) -> str:
    lines = ["# Release package vulnerability scan", ""]
    if not results:
        lines.append("No packages found to scan.")
        return "\n".join(lines)

    lines.append("| Package | Vulnerabilities |")
    lines.append("|---|---|")
    for name in sorted(results):
        lines.append(f"| {name} | {format_counts(summarize(results[name]))} |")
    lines.append("")
    lines.append(
        "To silence a false positive or an accepted risk, see "
        "[doc/dev/vulnerability-scanning.md]"
        "(https://github.com/GitGuardian/ggshield/blob/main/doc/dev/vulnerability-scanning.md)."
    )
    return "\n".join(lines)


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
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
