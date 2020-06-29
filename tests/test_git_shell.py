from ggshield.git_shell import is_git_dir, shell


def test_git_shell():
    assert "See 'git help git' for an overview of the system." in shell(
        ["git", "--help"]
    )


def test_is_git_dir():
    assert is_git_dir()
