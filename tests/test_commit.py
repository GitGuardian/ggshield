import unittest
from secrets_shield.secrets_shield import get_branch
from secrets_shield.secrets_shield import Commit


class TestCommitClass(unittest.TestCase):
    def test_get_branch(self):
        branches = "  dev\n" "* master\n" "  staging\n" "  test\n"
        self.assertEqual(get_branch(branches), "master")

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

    def test_get_diffs_one_file(self):
        patch = (
            "diff --git a/test.txt b/test.txt\n"
            "new file mode 100644\n"
            "index 0000000..b80e3df\n"
            "--- /dev/null\n"
            "+++ b/test\n"
            "@@ -0,0 +1,28 @@\n"
            "+this is a test patch\n"
        )

        c = Commit()
        self.assertEqual(
            c.get_diffs(patch),
            [
                {
                    "filename": "test.txt",
                    "filemode": "new file",
                    "content": "+this is a test patch\n",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
