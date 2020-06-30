from os import getcwd

from ggshield.dev_scan import cd


def test_cd_context_manager():
    prev = getcwd()
    with cd("/tmp"):
        assert getcwd() == "/tmp"
    assert getcwd() == prev
