from pygitguardian import GGClient

from ggshield.sca.client import ComputeSCAFilesResult, SCAClient
from tests.unit.conftest import my_vcr


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
