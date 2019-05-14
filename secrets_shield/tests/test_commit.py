import unittest

from secrets_shield.commit import Commit

import asyncio


class TestCommitClass(unittest.TestCase):
    def test_get_filename(self):
        line = "a/test.txt b/test.txt"
        c = Commit()
        self.assertEqual(c.get_filename(line), "test.txt")

    def test_get_filemode_new(self):
        line = "new file mode 100644\n"
        c = Commit()
        self.assertEqual(c.get_filemode(line), "new file")

    def test_get_filemode_delete(self):
        line = "deleted file mode 100644\n"
        c = Commit()
        self.assertEqual(c.get_filemode(line), "deleted file")

    def test_get_filemode_modify(self):
        line = "index 3d47bfe..ee93988 100644\n"
        c = Commit()
        self.assertEqual(c.get_filemode(line), "modified file")

    def test_scan_without_leak(self):
        patch = (
            "diff --git a/test.txt b/test.txt\n"
            "new file mode 100644\n"
            "index 0000000..b80e3df\n"
            "--- /dev/null\n"
            "+++ b/test\n"
            "@@ -0,0 +1,28 @@\n"
            "+this is a test patch\n"
        )

        expect = [
            {
                "content": "+this is a test patch\n",
                "filename": "test.txt",
                "filemode": "new file",
                "scan": {
                    "metadata": {"leak_count": 0, "version": "1.0.14"},
                    "secrets": [],
                },
                "error": False,
                "has_leak": False,
            }
        ]

        c = Commit()
        c.patch_ = patch
        results = asyncio.get_event_loop().run_until_complete(c.scan())

        self.assertEqual(results, expect)

    def test_scan_with_leak(self):
        patch = (
            "diff --git a/test.txt b/test.txt\n"
            "new file mode 100644\n"
            "index 0000000..b80e3df\n"
            "--- /dev/null\n"
            "+++ b/test\n"
            "@@ -0,0 +1,28 @@\n"
            '+Datadog:\n+- text: dogapi token = "dd52c29224affe29d163c6bf99e5c3f4";\n'
        )

        c = Commit()
        c.patch_ = patch

        result = asyncio.get_event_loop().run_until_complete(c.scan())[0]
        self.assertEqual(result["has_leak"], True)
        self.assertEqual(result["error"], False)
        self.assertEqual(
            result["scan"]["secrets"][0]["matches"][0]["string_matched"],
            "dd52c29224affe29d163c6bf99e5c3f4",
        )
