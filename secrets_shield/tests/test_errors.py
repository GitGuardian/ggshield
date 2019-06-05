import pytest

from .conftest import my_vcr
from secrets_shield.scannable import Files, File
from secrets_shield.client import PublicScanningApiClient, PublicScanningUnauthorized


@my_vcr.use_cassette()
def test_not_authorized():
    f = Files([File("This is a test file", "test.txt")])

    with pytest.raises(PublicScanningUnauthorized):
        assert f.scan(PublicScanningApiClient("1234567890"))
