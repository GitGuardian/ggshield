from secrets_shield.commit import Commit


def test_get_filename():
    line = "a/test.txt b/test.txt"
    c = Commit()
    assert c.get_filename(line) == "test.txt"


def test_get_filemode_new():
    line = "new file mode 100644\n"
    c = Commit()
    assert c.get_filemode(line) == "new file"


def test_get_filemode_delete():
    line = "deleted file mode 100644\n"
    c = Commit()
    assert c.get_filemode(line) == "deleted file"


def test_get_filemode_modify():
    line = "index 3d47bfe..ee93988 100644\n"
    c = Commit()
    assert c.get_filemode(line) == "modified file"
