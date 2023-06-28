import tarfile
from io import BytesIO
from pathlib import Path

from ggshield.cmd.iac.scan.iac_scan_utils import get_iac_tar
from ggshield.core.filter import init_exclusion_regexes
from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.repository import Repository


def test_get_iac_tar(tmp_path: Path) -> None:
    # GIVEN a repository with vulnerabilities in 3 files
    repo = Repository.create(tmp_path)
    repo.create_commit()

    file1 = tmp_path / "file1.tf"
    file1.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file1)

    file2 = tmp_path / "file2.tf"
    file2.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file2)

    file3 = tmp_path / "file3.tf"
    file3.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file3)

    repo.create_commit()

    # WHEN creating a tar, excluding files 1 & 2
    exclusion_regexes = init_exclusion_regexes(["file1.tf", "file2.tf"])
    bytes = get_iac_tar(tmp_path, "HEAD", exclusion_regexes)

    # THEN only file3 is in tar
    stream = BytesIO(bytes)
    with tarfile.open(fileobj=stream, mode="r:gz") as tar:
        names = tar.getnames()
        assert "file1.tf" not in names
        assert "file2.tf" not in names
        assert "file3.tf" in names
