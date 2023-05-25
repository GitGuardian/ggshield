import json
import logging
import os
import subprocess
import sys
import time
import typing
from dataclasses import asdict
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import click
from perfbench_utils import (
    RawReportEntry,
    check_run,
    find_latest_prod_version,
    get_raw_report_path,
    work_dir_option,
)


DEFAULT_GGSHIELD_VERSIONS = ["prod", "current"]

REPO_BENCHMARK_COMMANDS = [
    ("secret", "scan", "--exit-zero", "path", "-ry", "."),
    ("secret", "scan", "--exit-zero", "commit-range", "HEAD~6.."),
    ("iac", "scan", "--exit-zero", "."),
]

DOCKER_IMAGES = ["ubuntu:22.04", "busybox:1.36.0-musl"]


class JSONLWriter:
    def __init__(self, fp: typing.TextIO) -> None:
        self.fp = fp

    def add_entry(self, entry: Dict[str, Any]) -> None:
        json.dump(entry, self.fp, sort_keys=True)
        self.fp.write("\n")
        self.fp.flush()


def setup_ggshield(work_dir: Path, version: str) -> Path:
    """
    Install a version of ggshield in the work dir, return the path to the ggshield
    command
    """
    if version == "current":
        current_path = which("ggshield")
        if current_path is None:
            logging.error("Can't find ggshield in $PATH")
            sys.exit(1)
        return Path(current_path)

    if version == "prod":
        version = find_latest_prod_version()
        logging.info("Latest prod version is %s", version)

    ggshield_base_dir = work_dir / "ggshields" / version
    if ggshield_base_dir.exists():
        logging.info("ggshield %s is already installed", version)
    else:
        ggshield_base_dir.mkdir(parents=True)
        logging.info("Installing ggshield %s in %s", version, ggshield_base_dir)
        out = subprocess.run(
            ["pipenv", "run", "pip", "install", f"ggshield=={version}"],
            cwd=str(ggshield_base_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if out.returncode > 0:
            logging.error("Failed to install ggshield %s", version)
            # Use print() here, otherwise the output is unreadable because logging ignores \n characters
            print(out.stdout, file=sys.stderr)
            sys.exit(128)

    proc = check_run(
        ["pipenv", "run", "which", "ggshield"],
        cwd=str(ggshield_base_dir),
        capture_output=True,
        text=True,
    )
    path = Path(proc.stdout.strip())
    assert path.exists(), path
    return path


def run_benchmark_command(
    writer: JSONLWriter,
    version: str,
    dataset: str,
    ggshield_path: Path,
    command: Tuple[str, ...],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> None:
    command_str = " ".join(command)

    logging.info(
        "Benchmarking version='%s', command='%s', dataset='%s'",
        version,
        command_str,
        dataset,
    )

    cmd = [str(ggshield_path)] + list(command)
    start = time.time()
    out = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    duration = time.time() - start
    logging.info("Command took %f seconds", duration)
    if out.returncode > 0:
        logging.error("Command failed with exit code %d", out.returncode)
        # Use print() here, otherwise the output is unreadable because logging ignores \n characters
        print(out.stdout, file=sys.stderr)
        sys.exit(1)

    writer.add_entry(
        asdict(
            RawReportEntry(
                version=version,
                dataset=dataset,
                command=command_str,
                duration=duration,
            )
        )
    )


def run_repo_command(
    writer: JSONLWriter,
    version: str,
    ggshield_path: Path,
    repo_dir: Path,
    command: Tuple[str, ...],
) -> None:
    run_benchmark_command(
        writer, version, repo_dir.name, ggshield_path, command, repo_dir
    )


def run_docker_command(
    writer: JSONLWriter,
    version: str,
    ggshield_path: Path,
    docker_image: str,
) -> None:
    command = ("secret", "scan", "docker", docker_image)
    with TemporaryDirectory() as cache_dir:
        # Set $GG_CACHE_DIR to a temporary directory so that caching does not affect
        # benchmark results
        env = dict(**os.environ, GG_CACHE_DIR=cache_dir)
        run_benchmark_command(
            writer, version, docker_image, ggshield_path, command, env=env
        )


def pull_docker_image(docker_image: str):
    """Pull the docker image so that the first run of `secret scan docker` does not
    include the time to download the image"""
    logging.info("Pulling Docker image %s", docker_image)
    subprocess.run(["docker", "pull", docker_image], check=True)


@click.command(
    epilog='VERSION can be "prod" for the latest released version and "current" for'
    " the version from the current branch.",
)
@work_dir_option
@click.option(
    "-V",
    "--version",
    "versions",
    multiple=True,
    default=DEFAULT_GGSHIELD_VERSIONS,
    metavar="VERSION",
    help="Versions of ggshield to benchmark. Use prod and current if not set.",
)
@click.option(
    "-r",
    "--repository",
    "repositories",
    multiple=True,
    default=[],
    help="Repositories to bench against. Must be a directory name from the work directory.",
)
@click.option(
    "--only-docker",
    is_flag=True,
    default=False,
    help="Only run docker benchmarks",
)
@click.option(
    "--repeats",
    default=1,
    help="Number of times to repeat each command (no repeat by default).",
)
def run_cmd(
    work_dir: Path,
    versions: List[str],
    repositories: List[str],
    only_docker: bool,
    repeats: int,
) -> None:
    """Run the benchmark"""
    ggshield_paths = [(v, setup_ggshield(work_dir, v)) for v in versions]

    # Prepare repository list
    base_repo_dir = work_dir / "repositories"
    if not base_repo_dir.exists():
        logging.error("No repositories directory in %s, run `setup` first", work_dir)
        sys.exit(1)

    if only_docker:
        repository_paths = []
    else:
        if repositories:
            repository_paths = [base_repo_dir / r for r in repositories]
            for path in repository_paths:
                if not path.exists():
                    logging.error("No such repository '%s'", path)
                    sys.exit(1)
        else:
            repository_paths = [
                r for r in base_repo_dir.glob("*") if (r / ".git").exists()
            ]

    # Run the benchmark
    report_path = get_raw_report_path(work_dir)

    with report_path.open("w") as fp:
        writer = JSONLWriter(fp)

        for repository_path in repository_paths:
            for command in REPO_BENCHMARK_COMMANDS:
                # Loop on `repeats` and then on `version` to ensure runs for the different
                # versions are interleaved. This should avoid getting different results
                # between versions if the performance of the API changes during the
                # benchmark.
                for _ in range(repeats):
                    for version, ggshield_path in ggshield_paths:
                        run_repo_command(
                            writer, version, ggshield_path, repository_path, command
                        )

        for docker_image in DOCKER_IMAGES:
            pull_docker_image(docker_image)
            for _ in range(repeats):
                for version, ggshield_path in ggshield_paths:
                    run_docker_command(writer, version, ggshield_path, docker_image)

    logging.info("Raw report has been generated in %s", report_path)
