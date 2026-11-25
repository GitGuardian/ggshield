"""Collect contract tests: each folder holding a test.yaml is one test.

Options (--impl, --record, --record-api, --rust-bin) are declared in
tests/conftest.py. See tests/contract/README.md.
"""

from pathlib import Path
from typing import List, Optional

import pytest

from tests.contract.harness.case import ContractCase, ContractFile


def pytest_collect_file(
    parent: pytest.Collector, file_path: Path
) -> Optional[pytest.Collector]:
    if file_path.name == "test.yaml":
        return ContractFile.from_parent(parent, path=file_path)
    return None


def pytest_collection_modifyitems(
    config: pytest.Config, items: List[pytest.Item]
) -> None:
    """When recording (--record, or --record-api which turns --record on in
    tests/conftest.py), run contract tests only: the harness's own tests
    (harness/tests/), or any other test collected alongside, have nothing to
    record. They still run when validating, and in CI."""
    if not config.getoption("--record"):
        return
    kept = [item for item in items if isinstance(item, ContractCase)]
    deselected = [item for item in items if not isinstance(item, ContractCase)]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept
