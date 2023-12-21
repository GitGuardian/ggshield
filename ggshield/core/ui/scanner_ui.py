from abc import ABC, abstractmethod
from typing import Any, Sequence

from typing_extensions import Self

from ggshield.core.scan import Scannable


class ScannerUI(ABC):
    """
    An abstract class used by scanning code to notify user about progress or events
    during a scan
    """

    @abstractmethod
    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        """
        Called when a scannable was skipped, `reason` explains why. If `reason` is empty
        then the user should not be notified of the skipped scannable (this happens for
        example when skipping empty files)
        """
        raise NotImplementedError

    @abstractmethod
    def __enter__(self) -> Self:
        raise NotImplementedError

    @abstractmethod
    def __exit__(self, *args: Any) -> None:
        raise NotImplementedError
