import csv
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median, stdev
from typing import Dict, Iterable, List, Optional, TextIO, Tuple

import click
from perfbench_utils import RawReport, get_raw_report_path, work_dir_option


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


@dataclass
class Duration:
    value: float
    deviation: Optional[float]


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


def create_duration_row(
    sorted_versions: List[str], durations_for_versions: Dict[str, List[float]]
) -> List[Duration]:
    row: List[Duration] = []
    for version in sorted_versions:
        durations_for_version = durations_for_versions[version]
        value = median(durations_for_version)

        if len(durations_for_version) > 1:
            deviation = stdev(durations_for_version)
        else:
            deviation = None
        row.append(Duration(value, deviation))

    return row


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

    durations = create_duration_row(sorted_versions, durations_for_versions)

    for duration in durations:
        cell = f"{duration.value:.2f}s"

        if duration.deviation:
            cell += f" ±{duration.deviation:.2f}"
        cells.append(cell)

        if reference is None:
            reference = duration.value
        else:
            delta = duration.value - reference
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


def create_header_row(sorted_versions: List[str]) -> List[str]:
    """Create headers (no delta column for reference)"""
    headers = ["command", "dataset", sorted_versions[0]]
    for version in sorted_versions[1:]:
        headers.extend([version, "delta"])
    return headers


def print_csv_output(
    sorted_versions: List[str],
    rows: Iterable[ReportRow],
):
    writer = csv.writer(sys.stdout)

    # Header row
    headers = ["command", "dataset"]
    for version in sorted_versions:
        headers.extend([version, f"{version} (deviation)"])
    writer.writerow(headers)

    # Data
    for row in sorted(rows, key=lambda x: (x.command, x.dataset)):
        durations = create_duration_row(
            sorted_versions,
            row.durations_for_versions,
        )
        table_row = [row.command, row.dataset]
        for duration in durations:
            table_row.append(str(duration.value))
            table_row.append(str(duration.deviation))
        writer.writerow(table_row)


def print_markdown_output(
    sorted_versions: List[str],
    rows: Iterable[ReportRow],
    min_delta: float,
    max_delta: float,
):
    # Create table rows
    table_rows = []
    has_failed = False
    for row in sorted(rows, key=lambda x: (x.command, x.dataset)):
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

    headers = ["command", "dataset", *version_headers]
    print_markdown_table(
        sys.stdout,
        table_rows,
        headers=headers,
        alignments="LL" + "R" * len(version_headers),
    )

    sys.exit(1 if has_failed else 0)


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
@click.option(
    "--csv",
    "use_csv",
    is_flag=True,
)
@work_dir_option
def report_cmd(
    min_delta: float, max_delta: float, use_csv: bool, work_dir: Path
) -> None:
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
    row_dict: Dict[Tuple[str, str], ReportRow] = {}

    with report_path.open() as fp:
        raw_report = RawReport.load(fp)

    for entry in raw_report.entries:
        row = row_dict.setdefault(
            (entry.command, entry.dataset),
            ReportRow(entry.command, entry.dataset),
        )
        durations = row.durations_for_versions.setdefault(entry.version, [])
        durations.append(entry.duration)

    sorted_versions = raw_report.versions

    if use_csv:
        print_csv_output(sorted_versions, row_dict.values())
    else:
        print_markdown_output(sorted_versions, row_dict.values(), min_delta, max_delta)
