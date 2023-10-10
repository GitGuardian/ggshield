from abc import ABC, abstractproperty
from enum import Enum
from typing import Optional, Union

from pygitguardian.sca_models import SCAScanAllOutput, SCAScanDiffOutput


SCAScanResult = Union[SCAScanAllOutput, SCAScanDiffOutput]


class SCAVulnerabilityCollectionType(Enum):
    UNKNOWN = "unknown"
    DIRECTORY = "sca_directory"
    DIFF = "sca_diff"


class SCAScanVulnerabilityCollection(ABC):
    """
    A Collection of SCA vulnerabilities
    """

    type = SCAVulnerabilityCollectionType.UNKNOWN

    def __init__(
        self,
        id: str,
        # Can be None if the scan failed
        result: Optional[SCAScanResult],
    ):
        self.id = id
        self.result = result

    @abstractproperty
    def has_results(self) -> bool:
        """
        Whether the scan found problems
        """
        return self.result is not None


class SCAScanAllVulnerabilityCollection(SCAScanVulnerabilityCollection):
    type = SCAVulnerabilityCollectionType.DIRECTORY
    result: Optional[SCAScanAllOutput]

    @property
    def has_results(self) -> bool:
        """
        Checks if at least one package in a location has one vulnerability
        """
        return self.result is not None and any(
            len(package.vulns) > 0
            for location in self.result.found_package_vulns
            for package in location.package_vulns
        )


class SCAScanDiffVulnerabilityCollection(SCAScanVulnerabilityCollection):
    type = SCAVulnerabilityCollectionType.DIFF
    result: Optional[SCAScanDiffOutput]

    @property
    def has_results(self) -> bool:
        """
        Checks if at least one package in a location defined in added_vuls
        has one vulnerability
        """
        return self.result is not None and any(
            len(package.vulns) > 0
            for location in self.result.added_vulns
            for package in location.package_vulns
        )
