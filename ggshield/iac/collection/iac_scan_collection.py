from abc import ABC, abstractproperty
from typing import Literal, Optional, Union

from pygitguardian.iac_models import IaCScanResult

from ggshield.iac.iac_scan_models import IaCDiffScanResult


IaCResult = Union[IaCScanResult, IaCDiffScanResult]
CollectionType = Literal["unknown", "path_scan", "diff_scan"]


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
        self.type = "unknown"
        self.result = result

    @abstractproperty
    def has_results(self) -> bool:
        """
        Whether the scan found problems
        """
        return self.result is not None
