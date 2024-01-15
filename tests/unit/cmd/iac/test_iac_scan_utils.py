import tarfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pytest
from pygitguardian.iac_models import IaCFileResult

from ggshield.cmd.iac.scan.iac_scan_utils import augment_unignored_issues, get_iac_tar
from ggshield.core.config.user_config import UserConfig
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan.scan_mode import ScanMode
from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import write_yaml
from tests.unit.verticals.iac.utils import (
    generate_diff_scan_collection,
    generate_path_scan_collection,
    generate_vulnerability,
)


def test_get_iac_tar(tmp_path: Path) -> None:
    # GIVEN a repository with vulnerabilities in 3 files
    repo = Repository.create(tmp_path)
    repo.create_commit()

    file1 = tmp_path / "file1.tf"
    file1.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(file1)

    file2 = tmp_path / "file2.tf"
    file2.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(file2)

    file3 = tmp_path / "file3.tf"
    file3.write_text(IAC_SINGLE_VULNERABILITY)
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


@pytest.mark.parametrize("scan_type", [ScanMode.DIRECTORY_ALL, ScanMode.DIRECTORY_DIFF])
def test_augment_unignored_issues(scan_type: ScanMode, tmp_path: Path) -> None:
    # GIVEN a config file with outdated ignore rules
    config_path = tmp_path / "config.yaml"
    date_format = "%Y-%m-%d %H:%M:%S"
    date_2000 = "2000-01-01 00:00:00"
    date_2000_utc = datetime.strptime(date_2000, date_format).astimezone(timezone.utc)
    date_2005 = "2005-01-01 00:00:00"
    date_2005_utc = datetime.strptime(date_2005, date_format).astimezone(timezone.utc)
    date_2010 = "2010-01-01 00:00:00"
    date_2010_utc = datetime.strptime(date_2010, date_format).astimezone(timezone.utc)
    date_2015 = "2015-01-01 00:00:00"
    date_2015_utc = datetime.strptime(date_2015, date_format).astimezone(timezone.utc)
    config_data = {
        "ignored_paths": [
            {
                "path": "ignored_path/*",
                "until": date_2000,
            },
            {
                "path": "**/ignored_iac_file.tf",
                "until": date_2010,
            },
        ],
        "ignored_policies": [
            {
                "policy": "GG_IAC_0001",
                "until": date_2005,
            },
            {
                "policy": "GG_IAC_0002",
                "until": date_2015,
            },
        ],
    }
    write_yaml(
        config_path,
        {
            "version": 2,
            "iac": config_data,
        },
    )
    config, _ = UserConfig.load(config_path)

    # GIVEN files whose some vulnerabilities are affected by the outdated config rules
    collection_factory_fn = (
        generate_path_scan_collection
        if scan_type == ScanMode.DIRECTORY_ALL
        else generate_diff_scan_collection
    )
    scan_result = collection_factory_fn(
        [
            IaCFileResult(
                filename=filename,
                incidents=[
                    generate_vulnerability(policy_id="GG_IAC_0001"),
                    generate_vulnerability(policy_id="GG_IAC_0002"),
                    generate_vulnerability(policy_id="GG_IAC_0003"),
                ],
            )
            for filename in [
                "ignored_path/ignored_iac_file.tf",
                "ignored_path/iac_file.tf",
                "path/iac_file.tf",
            ]
        ]
    ).result

    # WHEN augmenting issues with the outdated ignore rules
    augment_unignored_issues(config, scan_result)

    if scan_type == ScanMode.DIRECTORY_ALL:
        files = scan_result.entities_with_incidents
    else:
        files = scan_result.entities_with_incidents.new

    # THEN vulnerabilites are associated to the last date they were ignored
    # # File ignored_path/ignored_iac_file.tf
    assert files[0].incidents[0].ignored_until == date_2010_utc
    assert files[0].incidents[1].ignored_until == date_2015_utc
    assert files[0].incidents[2].ignored_until == date_2010_utc
    # # File ignored_path/iac_file.tf
    assert files[1].incidents[0].ignored_until == date_2005_utc
    assert files[1].incidents[1].ignored_until == date_2015_utc
    assert files[1].incidents[2].ignored_until == date_2000_utc
    # # File path/iac_file.tf
    assert files[2].incidents[0].ignored_until == date_2005_utc
    assert files[2].incidents[1].ignored_until == date_2015_utc
    assert files[2].incidents[2].ignored_until is None
