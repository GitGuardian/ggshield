from utils import run_ggshield_scan


def test_scan_precommit() -> None:
    run_ggshield_scan("pre-commit", expected_code=0)
