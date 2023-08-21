import tarfile
from io import BytesIO
from pathlib import Path
from typing import List, Tuple

from pygitguardian import GGClient
from pygitguardian.client import _create_tar
from pygitguardian.models import Detail

from ggshield.verticals.sca.client import SCAClient
from ggshield.verticals.sca.sca_scan_models import (
    ComputeSCAFilesResult,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)
from tests.unit.conftest import my_vcr


current_dir = Path(__file__).parent


PIPFILE_LOCK1 = """
{
    "default": {
        "foo": {
            "version": "==1.2.3"
        },
        "bar": {
            "version": "==3.4.5"
        }
    }
}
"""


PIPFILE_LOCK2 = """
{
    "default": {
        "foo": {
            "version": "==1.2.4"
        },
        "baz": {
            "version": "==7.3.4"
        }
    }
}
"""


def make_tar_bytes(files: List[Tuple[str, str]]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar_file:
        for name, content in files:
            raw_content = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(raw_content)
            tar_file.addfile(info, BytesIO(raw_content))
    buffer.seek(0)
    return buffer.getvalue()


reference_files = [
    (
        "Pipfile.lock",
        PIPFILE_LOCK1,
    ),
]
current_files = [
    (
        "Pipfile",
        "# This Pipfile is empty",
    ),
    (
        "Pipfile.lock",
        PIPFILE_LOCK2,
    ),
]


class TestSCAClient:
    @my_vcr.use_cassette
    def test_compute_sca_files(self, client: GGClient):
        sca_client = SCAClient(client)
        result = sca_client.compute_sca_files(files=["Pipfile", "something_else"])
        assert isinstance(result, ComputeSCAFilesResult)
        assert result.sca_files == ["Pipfile"]
        assert result.potential_siblings == ["Pipfile.lock"]

    @my_vcr.use_cassette("test_sca_scan_directory_valid.yaml", ignore_localhost=False)
    def test_sca_scan_directory(self, client: GGClient):
        """
        GIVEN a directory with a Pipfile.lock containing vulnerabilities
        WHEN calling sca_scan_directory on this directory
        THEN we get the expected vulnerabilities
        """
        sca_client = SCAClient(client)

        piplock_filepath = Path(current_dir / "../../data/Pipfile.lock").resolve()

        tar = _create_tar(".", [piplock_filepath])
        scan_params = SCAScanParameters()

        response = sca_client.sca_scan_directory(tar, scan_params)
        assert isinstance(response, SCAScanAllOutput)
        assert response.status_code == 200
        assert len(response.scanned_files) == 1
        vuln_pkg = next(
            (
                package_vuln
                for package_vuln in response.found_package_vulns[0].package_vulns
                if package_vuln.package_full_name == "vyper"
            ),
            None,
        )
        assert vuln_pkg is not None
        assert len(vuln_pkg.vulns) == 13

    @my_vcr.use_cassette(
        "test_sca_scan_directory_invalid_tar.yaml", ignore_localhost=False
    )
    def test_sca_scan_directory_tar_not_valid(self, client: GGClient):
        """
        GIVEN an invalid tar argument
        WHEN calling sca_scan_directory
        THEN we get a 400 status code
        """
        sca_client = SCAClient(client)
        tar = ""
        scan_params = SCAScanParameters()

        response = sca_client.sca_scan_directory(tar, scan_params)
        assert isinstance(response, Detail)
        assert response.status_code == 400

    @my_vcr.use_cassette("test_sca_client_scan_diff.yaml", ignore_localhost=False)
    def test_sca_client_scan_diff(self, client: GGClient):
        """
        GIVEN a directory in two different states
        WHEN calling scan_diff on it
        THEN the scan succeeds
        """
        sca_client = SCAClient(client)
        scan_params = SCAScanParameters()

        result = sca_client.scan_diff(
            reference=make_tar_bytes(reference_files),
            current=make_tar_bytes(current_files),
            scan_parameters=scan_params,
        )
        assert isinstance(result, SCAScanDiffOutput), result.content
        assert result.scanned_files == ["Pipfile", "Pipfile.lock"]
