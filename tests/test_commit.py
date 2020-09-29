from ggshield.scan import Commit
from ggshield.utils import Filemode


def test_get_filename():
    line = "a/test.txt b/test.txt"
    assert Commit().get_filename(line) == "test.txt"


def test_get_filemode_new():
    line = "new file mode 100644\n"
    assert Commit().get_filemode(line) == Filemode.NEW


def test_get_filemode_delete():
    line = "deleted file mode 100644\n"
    assert Commit().get_filemode(line) == Filemode.DELETE


def test_get_filemode_modify():
    line = "index 3d47bfe..ee93988 100644\n"
    assert Commit().get_filemode(line) == Filemode.MODIFY


def test_get_filemode_rename():
    line = "similarity index 99%\n"
    assert Commit().get_filemode(line) == Filemode.RENAME
