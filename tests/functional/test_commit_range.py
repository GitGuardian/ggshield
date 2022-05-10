from utils import run_ggshield_scan


def test_scan_commit_range() -> None:
    run_ggshield_scan("commit-range", "HEAD~4...", expected_code=0)
