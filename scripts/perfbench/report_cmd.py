import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median, stdev
from typing import Dict, Iterable, List, Optional, TextIO, Tuple

import click
from perfbench_utils import (
    RawReportEntry,
    find_latest_prod_version,
    get_raw_report_path,
    work_dir_option,
)


# Do not report changes if the delta is less than this duration
DEFAULT_MIN_DELTA_SECS = 1

# Report a failure if delta is more than this duration
DEFAULT_MAX_DELTA_SECS = 3


@dataclass
class ReportRow:
    command: str
    dataset: str
    # Mapping of version => [durations]
    durations_for_versions: Dict[str, List[float]] = field(default_factory=dict)


def key_for_version(version: str) -> Tuple[int, ...]:
    if version == "current":
        # Make sure "current" is always last
        return 999999, 0, 0
    if version == "prod":
        version = find_latest_prod_version()
    return tuple(int(x) for x in version.split("."))


def print_markdown_table(
    out: TextIO, rows: List[List[str]], headers: List[str], alignments: str
) -> None:
    """
    Prints a Markdown table.

    `alignments` is a string of one character per column. The character must be L or R,
    defining left or right alignment.
    """
    assert len(headers) == len(alignments)

    widths = [0] * len(headers)
    for row in [headers, *rows]:
        for idx, cell in enumerate(row):
            width = len(cell)
            widths[idx] = max(widths[idx], width)

    def print_row(row: Iterable[str]) -> None:
        for cell, alignment, width in zip(row, alignments, widths):
            if alignment == "R":
                cell = cell.rjust(width)
            else:
                cell = cell.ljust(width)
            out.write(f"| {cell} ")
        out.write("|\n")

    # print rows
    print_row(headers)
    separator_row = [
        "-" * (w - 1) + (":" if a == "R" else "-") for a, w in zip(alignments, widths)
    ]
    print_row(separator_row)

    for row in rows:
        print_row(row)


def create_duration_cells(
    sorted_versions: List[str],
    durations_for_versions: Dict[str, List[float]],
    min_delta: float,
    max_delta: float,
) -> Tuple[List[str], bool]:
    """Returns a list of cells, and a bool indicating whether we noticed a delta
    higher than MAX_DELTA_SECS"""
    cells: List[str] = []
    reference: Optional[float] = None
    fail = False
    for version in sorted_versions:
        durations_for_version = durations_for_versions[version]
        duration = median(durations_for_version)
        cell = f"{duration:.2f}s"

        if len(durations_for_version) > 1:
            deviation = stdev(durations_for_version)
            cell += f" ±{deviation:.2f}"
        cells.append(cell)

        if reference is None:
            reference = duration
        else:
            delta = duration - reference
            if abs(delta) > min_delta:
                if delta > max_delta:
                    symbol = "▲" * 3
                    fail = True
                elif delta > 0:
                    symbol = "▲"
                else:
                    symbol = "▼"
            else:
                symbol = "≈"

            cells.append(f"{delta:+.2f} {symbol}")
    return cells, fail


@click.command()
@click.option(
    "--min-delta",
    type=float,
    help="If the duration difference with the reference run is less than this number of seconds,"
    " do not report a change.",
    default=DEFAULT_MIN_DELTA_SECS,
)
@click.option(
    "--max-delta",
    type=float,
    help="If the duration difference with the reference run is *more* than this number of seconds,"
    " exit with error.",
    default=DEFAULT_MAX_DELTA_SECS,
)
@work_dir_option
def report_cmd(min_delta: float, max_delta: float, work_dir: Path) -> None:
    """
    Generate a report from a benchmark run
    """
    report_path = get_raw_report_path(work_dir)
    if not report_path.exists():
        logging.error(
            "Raw report not found (%s does not exist). Use the `run` command first",
            report_path,
        )

    # Load raw report file, group report rows by command and dataset
    version_set = set()
    row_dict: Dict[Tuple[str, str], ReportRow] = {}
    with report_path.open() as fp:
        for line in fp:
            dct = json.loads(line)
            entry = RawReportEntry(**dct)

            version_set.add(entry.version)

            row = row_dict.setdefault(
                (entry.command, entry.dataset),
                ReportRow(entry.command, entry.dataset),
            )
            durations = row.durations_for_versions.setdefault(entry.version, [])
            durations.append(entry.duration)

    sorted_versions = sorted(version_set, key=key_for_version)

    # Create table rows
    table_rows = []
    has_failed = False
    for row in sorted(row_dict.values(), key=lambda x: (x.command, x.dataset)):
        duration_cells, fail = create_duration_cells(
            sorted_versions,
            row.durations_for_versions,
            min_delta,
            max_delta,
        )
        has_failed |= fail
        table_rows.append([row.command, row.dataset, *duration_cells])

    # Create headers (no delta column for reference)
    version_headers = [sorted_versions[0]]
    for version in sorted_versions[1:]:
        version_headers.extend([version, "delta"])

    print_markdown_table(
        sys.stdout,
        table_rows,
        headers=["command", "dataset", *version_headers],
        alignments="LL" + "R" * len(version_headers),
    )

    sys.exit(1 if has_failed else 0)
