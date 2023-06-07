from abc import ABC
from typing import Literal, Optional, Union

from pygitguardian.iac_models import IaCScanResult

from ggshield.iac.iac_scan_models import IaCDiffScanResult


IaCResult = Union[IaCScanResult, IaCDiffScanResult]
CollectionType = Literal["unknown", "path_scan", "diff_scan"]


class IaCScanCollection(ABC):
    # TODO: It may be possible to get rid of this class and just use IaCScanResult
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


class IaCPathScanCollection(IaCScanCollection):
    def __init__(
        self,
        id: str,
        result: Optional[IaCScanResult],
    ):
        super().__init__(id, result)
        self.type = "path_scan"


class IaCDiffScanCollection(IaCScanCollection):
    def __init__(
        self,
        id: str,
        result: Optional[IaCDiffScanResult],
    ):
        super().__init__(id, result)
        self.type = "diff_scan"
