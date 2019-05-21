import unittest
import asyncio
from vcr import use_cassette
from secrets_shield.commit import Commit


class TestErrors(unittest.TestCase):
    def test_not_authorized(self):
        c = Commit()
        c.diffs_ = [{"filename": "test.txt", "filemode": "new file", "content": ""}]
        c.client.apikey = ""

        with use_cassette("secrets_shield/tests/cassettes/test_not_authorized.yaml"):
            results = asyncio.get_event_loop().run_until_complete(c.scan())

        result = results[0]
        self.assertEqual(result["error"], True)
        self.assertEqual(result["scan"]["error"], "not_authorized")

    def test_no_content_provided(self):
        c = Commit()
        c.diffs_ = [{"filename": "test.txt", "filemode": "new file", "content": ""}]

        with use_cassette(
            "secrets_shield/tests/cassettes/test_no_content_provided.yaml"
        ):
            results = asyncio.get_event_loop().run_until_complete(c.scan())

        result = results[0]
        self.assertEqual(result["error"], True)
        self.assertEqual(result["scan"]["error"], "no content provided")
