from pathlib import Path

from tests.functional.utils import run_ggshield_scan


CURRENT_DIR = Path(__file__).parent


def test_scan_no_api_key(monkeypatch) -> None:
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
    run_ggshield_scan("path", __file__, cwd=CURRENT_DIR, expected_code=3)


def test_scan_invalid_api_key(monkeypatch) -> None:
    monkeypatch.setenv("GITGUARDIAN_API_KEY", "not_a_valid_key")
    run_ggshield_scan("path", __file__, cwd=CURRENT_DIR, expected_code=3)
