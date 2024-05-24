from typing import Iterable, Tuple

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail
from pygitguardian.remediation_models import Source

from ggshield.core.errors import RepositoryNotTrackedError, UnexpectedError
from ggshield.utils.git_shell import git


def extract_git_remotes() -> Iterable[Tuple[str, str]]:
    seen = set()
    for line in git(["remote", "--verbose"]).splitlines():
        remote_name, remote_url, _ = line.split(
            None,
        )
        repository_name = "/".join(
            remote_url.split(":")[-1].removesuffix(".git").split("/")[-2:]
        )
        if remote_name in seen:
            continue
        seen.add(remote_name)
        yield remote_name, repository_name


def get_current_source(client: GGClient) -> Tuple[str, Source]:
    for remote, repository_name in extract_git_remotes():
        sources_found = client.list_sources(
            params=dict(search=repository_name, per_page=1, ordering="-last_scan_date")
        )
        if not sources_found.success:
            raise UnexpectedError("Failed to list sources")

        if isinstance(sources_found, Detail):
            raise UnexpectedError(sources_found.detail)

        click.echo(
            "Select the tracked repository corresponding to the local repository:"
        )
        for source in sources_found.sources:
            source_type = source.type.replace("_", " ").title()
            if click.confirm(
                f"- [{source_type}] {source.full_name}?",
                default=True,
            ):
                return remote, source
    raise RepositoryNotTrackedError()


def get_source_locations(client: GGClient, source_id: int) -> Iterable[dict]:
    for response in client.get_all_pages(f"sources/{source_id}/locations"):
        yield from response.json()
