import tarfile
from io import BytesIO
from typing import List, Tuple

from pygitguardian import GGClient

from ggshield.sca.client import ComputeSCAFilesResult, SCAClient, SCAScanDiffResult
from tests.unit.conftest import my_vcr


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
        result = sca_client.compute_sca_files(
            touched_files=["Pipfile", "something_else"]
        )
        assert isinstance(result, ComputeSCAFilesResult)
        assert result.sca_files == ["Pipfile"]
        assert result.potential_siblings == ["Pipfile.lock"]

    @my_vcr.use_cassette
    def test_scan_diff(self, client: GGClient):
        sca_client = SCAClient(client)
        result = sca_client.scan_diff(
            reference=make_tar_bytes(reference_files),
            current=make_tar_bytes(current_files),
        )
        assert isinstance(result, SCAScanDiffResult), result.content
        assert result.scanned_files == ["Pipfile", "Pipfile.lock"]
