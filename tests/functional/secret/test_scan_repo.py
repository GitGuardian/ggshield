import json
import os
from unittest.mock import patch

import pytest
from pytest_voluptuous import S
from voluptuous import Optional as SOptional
from voluptuous import Url

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content, run_ggshield_scan
from tests.repository import Repository


LEAK_CONTENT = f"password = {GG_VALID_TOKEN}"


SECRET_JSON_SCHEMA = S(
    {
        "id": str,
        "type": "commit-range",
        "scans": [
            {
                "id": str,
                "type": "commit",
                SOptional("entities_with_incidents"): [
                    {
                        "mode": str,
                        "filename": str,
                        "incidents": [
                            {
                                "policy": "Secrets detection",
                                "occurrences": [
                                    {
                                        "match": str,
                                        "type": str,
                                        "line_start": int,
                                        "line_end": int,
                                        "index_start": int,
                                        "index_end": int,
                                        "post_line_start": int,
                                        "post_line_end": int,
                                    },
                                ],
                                "type": str,
                                "validity": str,
                                "ignore_sha": str,
                                "total_occurrences": int,
                                SOptional("incident_url"): Url(),
                                "known_secret": bool,
                            },
                        ],
                        "total_incidents": int,
                        "total_occurrences": int,
                    },
                ],
                "extra_info": {
                    "author": str,
                    "email": str,
                    "date": str,
                },
                "total_incidents": int,
                "total_occurrences": int,
            },
        ],
        "total_incidents": int,
        "total_occurrences": int,
    }
)


@pytest.fixture(scope="module")
def leaky_repo(tmp_path_factory: pytest.TempPathFactory) -> Repository:
    """
    Create a repository, add a commit with a secret in it, then add 2 clean commits on
    top of it
    """
    repo = Repository.create(tmp_path_factory.mktemp("test_scan_repo"))

    secret_file = repo.path / "secret.conf"
    secret_file.write_text(LEAK_CONTENT)
    repo.add("secret.conf")
    repo.create_commit()

    for _ in range(2):
        repo.create_commit()

    return repo


def test_scan_repo(leaky_repo: Repository) -> None:
    # GIVEN a repository with a past commit containing a leak
    # WHEN scanning the repo
    # THEN the leak is found
    proc = run_ggshield_scan(
        "repo", str(leaky_repo.path), expected_code=1, cwd=leaky_repo.path
    )

    # AND the output contains the line of the leak
    assert recreate_censored_content(LEAK_CONTENT, GG_VALID_TOKEN) in proc.stdout


def test_scan_repo_json(leaky_repo: Repository) -> None:
    # GIVEN a repository with a past commit containing a leak
    # WHEN scanning the repo
    # THEN the leak is found
    proc = run_ggshield_scan(
        "repo", "--json", str(leaky_repo.path), expected_code=1, cwd=leaky_repo.path
    )
    # AND the JSON output matches the expected format
    dct = json.loads(proc.stdout)
    assert SECRET_JSON_SCHEMA == dct


def test_scan_repo_quota_limit_reached(
    leaky_repo: Repository, no_quota_gitguardian_api: str, caplog
) -> None:
    # GIVEN a repository with a past commit containing a leak

    # WHEN scanning the repo
    # THEN error code is 128
    with patch.dict(
        os.environ, {**os.environ, "GITGUARDIAN_API_URL": no_quota_gitguardian_api}
    ):
        proc = run_ggshield_scan(
            "repo",
            str(leaky_repo.path),
            "--json",
            expected_code=128,
            cwd=leaky_repo.path,
        )

    # AND stderr contains an error message
    assert (
        "Error: Could not perform the requested action: no more API calls available."
        in proc.stderr
    )
    # AND stdout is empty
    assert proc.stdout.strip() == ""
