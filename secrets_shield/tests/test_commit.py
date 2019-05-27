import os
import pytest

from secrets_shield.commit import Commit
from secrets_shield.client import PublicScanningApiClient


@pytest.fixture(scope="session")
def client():
    return PublicScanningApiClient(os.getenv("GITGUARDIAN_TOKEN", "1234567890"))


def test_get_filename(client):
    line = "a/test.txt b/test.txt"
    c = Commit(client)
    assert c.get_filename(line) == "test.txt"


def test_get_filemode_new(client):
    line = "new file mode 100644\n"
    c = Commit(client)
    assert c.get_filemode(line) == "new file"


def test_get_filemode_delete(client):
    line = "deleted file mode 100644\n"
    c = Commit(client)
    assert c.get_filemode(line) == "deleted file"


def test_get_filemode_modify(client):
    line = "index 3d47bfe..ee93988 100644\n"
    c = Commit(client)
    assert c.get_filemode(line) == "modified file"
