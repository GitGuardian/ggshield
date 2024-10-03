from ggshield.cmd.secret.scan.docset import generate_files_from_docsets
from tests.unit.conftest import DATA_PATH


DOCSET_EXAMPLE_PATH = DATA_PATH / "docset-example.jsonl"


class TestDocsetScan:
    def test_generate_files_from_docsets(self):
        input_file = open(DOCSET_EXAMPLE_PATH)
        files = list(generate_files_from_docsets(input_file))
        assert {f.filename for f in files} == {
            "https://github.com/owner/repo/issues/1",
            "https://github.com/owner/repo/issues/3",
            "https://github.com/owner/repo/issues/4",
            "https://github.com/owner/repo/issues/4#issuecomment-10069",
            "https://github.com/owner/repo/issues/4#issuecomment-10070",
            "https://github.com/owner/repo/issues/5",
            "https://github.com/owner/repo/issues/6",
            "https://github.com/owner/repo/issues/7",
            "https://github.com/owner/repo/issues/8",
            "https://github.com/owner/repo/issues/8#issuecomment-10071",
        }
