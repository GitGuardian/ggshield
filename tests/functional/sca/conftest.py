import pytest

from tests.repository import Repository
from tests.unit.sca.conftest import DUMMY_SCA_REPO


@pytest.fixture
def dummy_sca_repo(tmp_path):
    """Return a fresh copy of a dummy sca repo"""
    DUMMY_SCA_REPO.extractall(path=tmp_path)
    return Repository(tmp_path / "sca_repo")
