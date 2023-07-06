import io
import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from tests.repository import Repository


PIPFILE_WITH_VULN = """
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
sqlparse = "==0.4.3"

[dev-packages]

[requires]
python_version = "3.10"
"""

PIPFILE_LOCK_WITH_VULN = """
{
    "_meta": {
        "hash": {
            "sha256": "2bf167f6a72aaa0f48f5876945f2a37874f3f114dad5e952cd7df9dfe8d9d281"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.10"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "sqlparse": {
            "hashes": [
                "sha256:0323c0ec29cd52bceabc1b4d9d579e311f3e4961b98d174201d5622a23b85e34",
                "sha256:69ca804846bb114d2ec380e4360a8a340db83f0ccf3afceeb1404df028f57268"
            ],
            "index": "pypi",
            "version": "==0.4.3"
        }
    },
    "develop": {}
}
"""

PIPFILE_NO_VULN = """
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
sqlparse = "==0.4.4"

[dev-packages]

[requires]
python_version = "3.10"
"""

PIPFILE_LOCK_NO_VULN = """
{
    "_meta": {
        "hash": {
            "sha256": "9e0257467cb126854e4a922f143941c3ffd38bca1c5805c778f96af3832f9fd3"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.10"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "sqlparse": {
            "hashes": [
                "sha256:5430a4fe2ac7d0f93e66f1efc6e1338a41884b7ddf2a350cedd20ccc4d9d28f3",
                "sha256:d446183e84b8349fa3061f0fe7f06ca94ba65b426946ffebe6e3e8295332420c"
            ],
            "index": "pypi",
            "version": "==0.4.4"
        }
    },
    "develop": {}
}
"""


def clean_directory(path: Path):
    for filepath in path.iterdir():
        if filepath.is_file():
            os.remove(filepath)


def make_dummy_sca_repo():
    """Function to create a dummy SCA repo as a tarfile"""
    result_buffer = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmp_path_str:
        tmp_path = Path(tmp_path_str)
        repo = Repository.create(tmp_path)

        repo.create_branch("branch_with_vuln", orphan=True)
        clean_directory(tmp_path)
        (tmp_path / "Pipfile").write_text(PIPFILE_WITH_VULN)
        (tmp_path / "Pipfile.lock").write_text(PIPFILE_LOCK_WITH_VULN)
        (tmp_path / "dummy_file.py").touch()
        repo.add(".")
        repo.create_commit("pipfile_with_vuln")

        repo.create_branch("branch_without_vuln", orphan=True)
        clean_directory(tmp_path)
        (tmp_path / "Pipfile").write_text(PIPFILE_NO_VULN)
        (tmp_path / "Pipfile.lock").write_text(PIPFILE_LOCK_NO_VULN)
        (tmp_path / "dummy_file.py").touch()
        repo.add(".")
        repo.create_commit("pipfile_without_vuln")

        repo.create_branch("branch_without_lock", orphan=True)
        clean_directory(tmp_path)
        (tmp_path / "Pipfile").write_text(PIPFILE_NO_VULN)
        (tmp_path / "dummy_file.py").touch()
        repo.add(".")
        repo.create_commit("pipfile_without_lock")

        repo.create_branch("branch_without_sca", orphan=True)
        clean_directory(tmp_path)
        (tmp_path / "dummy_file.py").touch()
        repo.add(".")
        repo.create_commit("dummy file")

        result_tar = tarfile.TarFile(fileobj=result_buffer, mode="w")
        result_tar.add(tmp_path_str, arcname="sca_repo")
    result_buffer.seek(0)
    return tarfile.TarFile(fileobj=result_buffer, mode="r")


DUMMY_SCA_REPO = make_dummy_sca_repo()


@pytest.fixture
def dummy_sca_repo(tmp_path):
    """Return a fresh copy of a dummy sca repo"""
    DUMMY_SCA_REPO.extractall(path=tmp_path)
    return Repository(tmp_path / "sca_repo")
