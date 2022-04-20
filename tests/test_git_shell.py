from ggshield.core.git_shell import GIT_PATH, is_git_dir, shell


def test_git_shell():
    assert "usage: git" in shell([GIT_PATH, "help"])


def test_is_git_dir():
    assert is_git_dir()
