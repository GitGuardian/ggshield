import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import click


DEFAULT_WORK_DIR = (Path(__file__).parent / ".perfbench").absolute()


@dataclass
class RawReportEntry:
    """Represent the fields stored in the benchmark.jsonl file"""

    version: str
    dataset: str
    command: str
    duration: float


def check_run(args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, **kwargs)


work_dir_option = click.option(
    "-w",
    "--work-dir",
    help="Where to store benchmark script work files.",
    default=DEFAULT_WORK_DIR,
    type=click.Path(),
)


def get_raw_report_path(work_dir: Path) -> Path:
    return work_dir / "benchmark.jsonl"


def find_latest_prod_version() -> str:
    """Assumes we are in a ggshield checkout: returns the version for the latest tag"""
    # List latest v* tag first
    out = check_run(
        ["git", "tag", "--list", "v*", "--sort=-v:refname"],
        capture_output=True,
        text=True,
    )
    lines: Sequence[str] = out.stdout.splitlines()
    assert lines
    return lines[0][1:]
