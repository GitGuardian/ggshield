from pathlib import Path
from typing import Any, Type

import pytest

from ggshield.core.errors import ExitCode
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.verticals.iac.output.iac_json_output_handler import IaCJSONOutputHandler
from ggshield.verticals.iac.output.iac_output_handler import IaCOutputHandler
from ggshield.verticals.iac.output.iac_text_output_handler import IaCTextOutputHandler
from tests.unit.verticals.iac.utils import (
    generate_diff_scan_collection,
    generate_file_result_with_vulnerability,
    generate_path_scan_collection,
)


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("source_found", [True, False])
@pytest.mark.parametrize("handler_cls", [IaCTextOutputHandler, IaCJSONOutputHandler])
@pytest.mark.parametrize("scan_type", [ScanMode.DIRECTORY_ALL, ScanMode.DIRECTORY_DIFF])
def test_iac_output_no_source_warning(
    verbose: bool,
    source_found: bool,
    handler_cls: Type[IaCOutputHandler],
    scan_type: ScanMode,
    tmp_path: Path,
    capsys: Any,
):
    """
    GIVEN   a scan result
    WHEN    showing scan output
    THEN    a warning is shown in verbose mode if the source was not linked
    """
    output_path = tmp_path / "output"

    collection_factory_fn = (
        generate_path_scan_collection
        if scan_type == ScanMode.DIRECTORY_ALL
        else generate_diff_scan_collection
    )
    collection = collection_factory_fn(
        [generate_file_result_with_vulnerability()],
        source_found=source_found,
    )

    output_handler = handler_cls(verbose=verbose, output=str(output_path))
    process_fn = (
        output_handler.process_scan
        if scan_type == ScanMode.DIRECTORY_ALL
        else output_handler.process_diff_scan
    )
    exit_code = process_fn(collection)

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS

    captured = capsys.readouterr().err
    is_warning_expected = verbose and not source_found
    warning_text = (
        "ggshield cannot fetch incidents monitored by the platform on this repository"
    )
    assert (warning_text in captured) == is_warning_expected
