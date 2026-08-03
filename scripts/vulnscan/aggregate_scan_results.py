#!/usr/bin/env python3
"""
Aggregate Grype scan results for a batch of ggshield release assets into a
single Markdown summary, and decide whether the scan should fail based on
vulnerabilities found in the most recent release.

Only stdlib imports on purpose: this runs in CI straight off a checkout,
without installing ggshield's own dependencies.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


SEVERITY_ORDER = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def load_reports(results_dir: Path) -> List[Dict[str, Any]]:
    """Load every (meta.json, report.json) pair found under results_dir.

    Each scan job uploads its own artifact under a unique name; downloading
    all of them lands one subdirectory per artifact under results_dir, in no
    particular order, so we just look for the pair anywhere underneath
    instead of assuming a fixed layout.
    """
    reports = []
    for meta_path in sorted(results_dir.rglob("meta.json")):
        report_path = meta_path.with_name("report.json")
        if not report_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        report = json.loads(report_path.read_text())
        reports.append(
            {
                "tag": meta["tag"],
                "asset": meta["asset"],
                "matches": report.get("matches", []),
            }
        )
    return reports


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


def render_markdown(reports: List[Dict[str, Any]]) -> str:
    lines = ["# Release vulnerability scan", ""]
    if not reports:
        lines.append("No release assets were scanned.")
        return "\n".join(lines)

    by_tag: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for report in reports:
        by_tag[report["tag"]].append(report)

    lines.append("| Release | Asset | Vulnerabilities |")
    lines.append("|---|---|---|")
    for tag in sorted(by_tag, reverse=True):
        for report in sorted(by_tag[tag], key=lambda r: r["asset"]):
            counts = summarize(report["matches"])
            lines.append(f"| {tag} | {report['asset']} | {format_counts(counts)} |")
    return "\n".join(lines)


def worst_severity(matches: List[Dict[str, Any]]) -> str:
    worst = "Unknown"
    for match in matches:
        severity = match.get("vulnerability", {}).get("severity", "Unknown")
        if severity_rank(severity) > severity_rank(worst):
            worst = severity
    return worst


def find_failing_assets(
    reports: List[Dict[str, Any]], latest_tag: str, fail_on: str
) -> List[Tuple[str, str]]:
    threshold = severity_rank(fail_on.capitalize())
    latest_reports = [r for r in reports if r["tag"] == latest_tag]
    return [
        (r["asset"], worst_severity(r["matches"]))
        for r in latest_reports
        if severity_rank(worst_severity(r["matches"])) >= threshold
    ]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_dir", type=Path, help="Directory containing downloaded scan artifacts"
    )
    parser.add_argument(
        "--latest-tag",
        required=True,
        help="Release tag whose vulnerabilities gate the exit code",
    )
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["none", "low", "medium", "high", "critical"],
        help=(
            "Minimum severity in the latest release that fails the run. "
            "Defaults to 'critical': the bundled Python interpreter almost "
            "always has some outstanding medium/high CVE at any given time "
            "(tracked separately via interpreter version bumps), so gating "
            "on those by default would make this check permanently red."
        ),
    )
    args = parser.parse_args(argv)

    reports = load_reports(args.results_dir)
    print(render_markdown(reports))

    if args.fail_on == "none":
        return 0

    if not any(r["tag"] == args.latest_tag for r in reports):
        print(
            f"\n:warning: no scan results found for the latest release ({args.latest_tag})",
            file=sys.stderr,
        )
        return 0

    failing = find_failing_assets(reports, args.latest_tag, args.fail_on)
    if failing:
        print(
            f"\n:x: latest release ({args.latest_tag}) has vulnerabilities at or "
            f"above '{args.fail_on}':",
            file=sys.stderr,
        )
        for asset, severity in failing:
            print(f"  - {asset}: {severity}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
