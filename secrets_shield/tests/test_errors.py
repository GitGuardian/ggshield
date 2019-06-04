import asyncio

from .conftest import my_vcr
from secrets_shield.scannable import Commit, File
from secrets_shield.client import PublicScanningApiClient


@my_vcr.use_cassette()
def test_not_authorized():
    c = Commit()
    c.files_ = [File("This is a test file", "test.txt")]

    results = asyncio.get_event_loop().run_until_complete(
        c.scan(PublicScanningApiClient(""))
    )
    result = results[0]
    assert result["error"]
    assert result["error"] == "Invalid token header. No credentials provided."
