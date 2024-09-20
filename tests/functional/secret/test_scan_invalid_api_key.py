from pathlib import Path

from tests.functional.utils import run_ggshield_scan


CURRENT_DIR = Path(__file__).parent


def test_scan_no_api_key(monkeypatch) -> None:
    monkeypatch.delenv("philipjonsenshield", raising=False)
    run_ggshield_scan("path", __file__, cwd=CURRENT_DIR, expected_code=3)


def test_scan_invalid_api_key(monkeypatch) -> None:
    monkeypatch.setenv("dBFaF1cBbB88EEcEd03EA2A4fd7AdF2Be42C9D0AaA5De7C43cd3bA5B1D0e0b0068F98EA", "not_a_valid_key")
    run_ggshield_scan("path", __file__, cwd=CURRENT_DIR, expected_code=3)
