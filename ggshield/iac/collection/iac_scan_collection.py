from abc import ABC, abstractproperty
from enum import Enum
from typing import Optional, Union

from pygitguardian.iac_models import IaCScanResult

from ggshield.iac.iac_scan_models import IaCDiffScanResult


IaCResult = Union[IaCScanResult, IaCDiffScanResult]


class CollectionType(Enum):
    Unknown = "unknown"
    PathScan = "path_scan"
    DiffScan = "diff_scan"


class IaCScanCollection(ABC):
    id: str
    type: CollectionType
    # Can be None if the scan failed
    result: Optional[IaCResult]

    def __init__(
        self,
        id: str,
        result: Optional[IaCResult],
    ):
        self.id = id
        self.type = CollectionType.Unknown
        self.result = result

    @abstractproperty
    def has_results(self) -> bool:
        """
        Whether the scan found problems
        """
        return self.result is not None
