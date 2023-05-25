import logging
from pathlib import Path

import click
from perfbench_utils import check_run, work_dir_option


BENCHMARK_REPOSITORIES = [
    ("https://github.com/vuejs/vue", "v2.7.14"),
    ("https://github.com/python-pillow/Pillow", "9.3.0"),
    ("https://github.com/docker/compose", "v2.12.2"),
    ("https://github.com/sqlite/sqlite", "version-3.39.4"),
    ("https://github.com/GitGuardian/sample_secrets", "ggshield-perfbench"),
]


def git_clone(base_repo_dir: Path, url: str, revision: str) -> None:
    logging.info("Cloning %s (%s)", url, revision)
    cmd = ["git", "clone", url, "--branch", revision]
    check_run(cmd, cwd=str(base_repo_dir))


@click.command()
@work_dir_option
def setup_cmd(work_dir: Path) -> None:
    """Clone all the required repositories to run the benchmarks"""
    base_repo_dir = work_dir / "repositories"
    base_repo_dir.mkdir(parents=True, exist_ok=True)
    for url, revision in BENCHMARK_REPOSITORIES:
        _, name = url.rsplit("/", 1)
        if (base_repo_dir / name).exists():
            logging.info("%s has already been cloned", url)
        else:
            git_clone(base_repo_dir, url, revision)
    logging.info("All set, you can now use the `run` command")
