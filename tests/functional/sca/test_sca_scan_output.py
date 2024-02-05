import re
from pathlib import Path
from typing import List, Type

import pytest
from pygitguardian.sca_models import (
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)

from ggshield.core.errors import ExitCode
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
)
from ggshield.verticals.sca.output.handler import SCAOutputHandler
from ggshield.verticals.sca.output.json_handler import SCAJsonOutputHandler
from ggshield.verticals.sca.output.text_handler import SCATextOutputHandler


def generate_vulnerability(id: str, is_ignored: bool = False) -> SCAVulnerability:
    return SCAVulnerability(
        identifier=id,
        severity="HIGH",
        summary="summary",
        cve_ids=[],
        status="IGNORED" if is_ignored else None,
    )


def generate_package_vuln(
    id: str, *vulns: List[SCAVulnerability]
) -> SCAVulnerablePackageVersion:
    return SCAVulnerablePackageVersion(
        package_full_name=id,
        dependency_type="type",
        ecosystem="ecosystem",
        version="1.0.0",
        vulns=vulns,
    )


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("handler_cls", [SCATextOutputHandler, SCAJsonOutputHandler])
def test_text_all_output_no_ignored(
    verbose: bool, handler_cls: Type[SCAOutputHandler], tmp_path: Path
):
    """
    GIVEN   - a location 1 with:
              - a package with only unignored vulns
              - a package with one ignored, one unignored vulns
              - a package with all ignored vulns
            - a location 2 with all vulns ignored in all packages
    WHEN    showing scan output
    THEN    - All ignored vulns are hidden
            - Packages and locations with no remaining vulns are hidden
    """
    output_path = tmp_path / "output"

    collection = SCAScanAllVulnerabilityCollection(
        ".",
        SCAScanAllOutput(
            scanned_files=["Pipfile.lock"],
            source_found=True,
            found_package_vulns=[
                SCALocationVulnerability(
                    location="1/Pipfile.lock",
                    package_vulns=[
                        # one package full
                        generate_package_vuln(
                            "package1",
                            generate_vulnerability("vuln1"),
                            generate_vulnerability("vuln2"),
                        ),
                        # one package with one ignored vuln
                        generate_package_vuln(
                            "package2",
                            generate_vulnerability("vuln3"),
                            generate_vulnerability("vuln4", is_ignored=True),
                        ),
                        # one package with all ignored vulns
                        generate_package_vuln(
                            "package3",
                            generate_vulnerability("vuln5", is_ignored=True),
                            generate_vulnerability("vuln6", is_ignored=True),
                        ),
                    ],
                ),
                # one location with only ignored vulns in packages
                SCALocationVulnerability(
                    location="2/Pipfile.lock",
                    package_vulns=[
                        generate_package_vuln(
                            "package4", generate_vulnerability("vuln7", is_ignored=True)
                        ),
                        generate_package_vuln(
                            "package5", generate_vulnerability("vuln8", is_ignored=True)
                        ),
                    ],
                ),
            ],
        ),
    )

    output_handler = handler_cls(verbose=verbose, output=str(output_path))
    exit_code = output_handler.process_scan_all_result(collection)

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS

    output = output_path.read_text()
    assert set(re.findall(r"\d/Pipfile.lock", output)) == {"1/Pipfile.lock"}
    assert set(re.findall(r"package\d", output)) == {"package1", "package2"}
    assert set(re.findall(r"vuln\d", output)) == {"vuln1", "vuln2", "vuln3"}
