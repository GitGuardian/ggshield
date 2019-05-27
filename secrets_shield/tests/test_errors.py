import asyncio

from .conftest import my_vcr

from secrets_shield.commit import Commit
from secrets_shield.client import PublicScanningApiClient


@my_vcr.use_cassette()
def test_not_authorized():
    c = Commit(PublicScanningApiClient(""))
    c.diffs_ = [
        {
            "filename": "test.txt",
            "filemode": "new file",
            "content": "This is a test file",
        }
    ]

    results = asyncio.get_event_loop().run_until_complete(c.scan())
    result = results[0]
    assert result["error"]
    assert result["scan"]["error"] == "Invalid token header. No credentials provided."
