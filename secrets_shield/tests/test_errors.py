import asyncio
from vcr import use_cassette
from secrets_shield.commit import Commit


def test_not_authorized():
    c = Commit()
    c.diffs_ = [{"filename": "test.txt", "filemode": "new file", "content": ""}]
    c.client.apikey = ""

    with use_cassette("secrets_shield/tests/cassettes/test_not_authorized.yaml"):
        results = asyncio.get_event_loop().run_until_complete(c.scan())

    result = results[0]
    assert result["error"]
    assert result["scan"]["error"] == "not_authorized"
