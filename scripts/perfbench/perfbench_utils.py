import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Sequence, TextIO

import click


DEFAULT_WORK_DIR = (Path(__file__).parent / ".perfbench").absolute()


@dataclass
class RawReportEntry:
    """Represent an entry in the benchmark.json file"""

    version: str
    dataset: str
    command: str
    duration: float


@dataclass
class RawReport:
    """Represent the fields stored in the benchmark.json file"""

    versions: List[str]
    entries: List[RawReportEntry] = field(default_factory=list)

    def add_entry(self, entry: RawReportEntry) -> None:
        self.entries.append(entry)

    def save(self, fp: TextIO) -> None:
        json.dump(
            asdict(self),
            fp,
            sort_keys=True,
            indent=True,
        )

    @staticmethod
    def load(fp: TextIO) -> "RawReport":
        dct = json.load(fp)
        entries = [RawReportEntry(**x) for x in dct["entries"]]
        return RawReport(dct["versions"], entries)


def check_run(args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, **kwargs)


work_dir_option = click.option(
    "-w",
    "--work-dir",
    help="Where to store benchmark script work files.",
    default=DEFAULT_WORK_DIR,
    type=click.Path(path_type=Path),
)


def get_raw_report_path(work_dir: Path) -> Path:
    return work_dir / "benchmark.json"


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
