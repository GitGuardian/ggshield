from ggshield.cmd.secret.scan.docset import generate_files_from_docsets
from ggshield.core.ui.plain_text import PlainTextGGShieldUI
from tests.unit.conftest import DATA_PATH


DOCSET_EXAMPLE_PATH = DATA_PATH / "docset-example.jsonl"


class TestDocsetScan:
    def test_generate_files_from_docsets(self):
        input_file = open(DOCSET_EXAMPLE_PATH)
        ui = PlainTextGGShieldUI()
        files = list(generate_files_from_docsets(input_file, ui.create_progress(1)))
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
