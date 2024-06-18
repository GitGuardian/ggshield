from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, List, Optional, TypeVar, Union

from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCDiffScanResult,
    IaCFileResult,
    IaCScanResult,
)


IaCResult = Union[IaCScanResult, IaCDiffScanResult]


IaCResultT = TypeVar("IaCResultT", IaCDiffScanResult, IaCScanResult)


class CollectionType(Enum):
    Unknown = "unknown"
    PathScan = "path_scan"
    DiffScan = "diff_scan"


class IaCScanCollection(ABC, Generic[IaCResultT]):
    type: CollectionType = CollectionType.Unknown
    # Can be None if the scan failed
    result: Optional[IaCResultT]

    def __init__(
        self,
        id: str,
        result: Optional[IaCResultT],
    ):
        self.id = id
        self.result = result

    @property
    @abstractmethod
    def has_results(self) -> bool:
        """
        Whether the scan found problems
        """
        raise NotImplementedError()

    @abstractmethod
    def get_entities_without_ignored(
        self,
    ) -> Optional[Union[List[IaCFileResult], IaCDiffScanEntities]]:
        """
        Removes vulnerabilities marked as ignored.
        Removes files that only have ignored vulnerabilities.
        Returns file list.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_result_without_ignored(self) -> Optional[IaCResultT]:
        """
        Removes vulnerabilities marked as ignored.
        Removes files that only have ignored vulnerabilities.
        Returns result object
        """
        raise NotImplementedError()
