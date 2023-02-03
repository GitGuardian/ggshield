from pathlib import Path

import pytest

from tests.functional.utils import run_ggshield_scan


@pytest.mark.parametrize(
    "package, expected_code",
    (
        ("ggshield==1.14.2", 1),  # ggshield 1.14.2 contains some test secrets
        ("marshmallow", 0),
    ),
)
def test_scan_pypi(tmp_path: Path, package: str, expected_code: int) -> None:
    # Run the command from a temporary path to ensure we don't load the
    # .gitguardian.yaml stored at the root of ggshield repo.
    # If we did then we would not find secrets in ggshield package because the
    # test secrets would be ignored.
    run_ggshield_scan("pypi", package, expected_code=expected_code, cwd=tmp_path)
