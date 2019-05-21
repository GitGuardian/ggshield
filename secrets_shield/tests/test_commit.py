import unittest
from secrets_shield.commit import Commit


class TestCommit(unittest.TestCase):
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
