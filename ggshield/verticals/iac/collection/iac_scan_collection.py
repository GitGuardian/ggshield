from abc import ABC, abstractproperty
from enum import Enum
from typing import Optional, Union

from pygitguardian.iac_models import IaCDiffScanResult, IaCScanResult


IaCResult = Union[IaCScanResult, IaCDiffScanResult]


class CollectionType(Enum):
    Unknown = "unknown"
    PathScan = "path_scan"
    DiffScan = "diff_scan"


class IaCScanCollection(ABC):
    type = CollectionType.Unknown
    id: str
    # Can be None if the scan failed
    result: Optional[IaCResult]

    def __init__(
        self,
        id: str,
        result: Optional[IaCResult],
    ):
        self.id = id
        self.result = result

    @abstractproperty
    def has_results(self) -> bool:
        """
        Whether the scan found problems
        """
        return self.result is not None
