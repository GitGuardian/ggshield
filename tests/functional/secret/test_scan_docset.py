from pathlib import Path

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import run_ggshield_scan


def test_scan_docset_positive(tmp_path: Path) -> None:
    test_file = tmp_path / "docset.jsonl"
    test_file.write_text(
        '{"type": "github_issue", "id": "https://github.com/foo/bar/issues/2", "documents": ['
        + '{"id": "https://github.com/foo/bar/issues/2", "content": "issue", "authors": [{"id": "ghost"}]}]}\n'
        + '{"type": "github_issue", "id": "https://github.com/foo/bar/issues/1", "documents": ['
        + '{"id": "https://github.com/foo/bar/issues/1", "content": "Token in comment", "authors": [{"id": "ghost"}]},'
        + '{"id": "https://github.com/foo/bar/issues/1#issuecomment-42",'
        + f'"content": "apikey = {GG_VALID_TOKEN}",'
        + ' "authors": [{"id": "ghost2"}]}'
        + "]}"
    )

    result = run_ggshield_scan("docset", str(test_file), cwd=tmp_path, expected_code=1)
    assert "apikey =" in result.stdout
    assert (
        "https://github.com/foo/bar/issues/1#issuecomment-42: 1 secret detected"
        in result.stdout
    )


def test_scan_docset_negative(tmp_path: Path) -> None:
    test_file = tmp_path / "docset.jsonl"
    test_file.write_text(
        '{"type": "github_issue", "id": "https://github.com/foo/bar/issues/2", "documents": ['
        + '{"id": "https://github.com/foo/bar/issues/2", "content": "issue", "authors": [{"id": "ghost"}]}]}\n'
        + '{"type": "github_issue", "id": "https://github.com/foo/bar/issues/1", "documents": ['
        + '{"id": "https://github.com/foo/bar/issues/1", "content": "No token", "authors": [{"id": "ghost"}]},'
        + '{"id": "https://github.com/foo/bar/issues/1#issuecomment-42",'
        + '"content": "Nothing to see, move along",'
        + ' "authors": [{"id": "ghost2"}]}'
        + "]}"
    )

    run_ggshield_scan("docset", str(test_file), cwd=tmp_path, expected_code=0)
