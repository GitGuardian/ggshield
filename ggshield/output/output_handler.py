from typing import Any, Tuple

from ggshield.scan import Result, ScanCollection


class OutputHandler:
    show_secrets: bool = False
    verbose: bool = False

    def __init__(self, show_secrets: bool, verbose: bool, *args: Any, **kwargs: Any):
        self.show_secrets = show_secrets
        self.verbose = verbose

    def process_scan(self, scan: ScanCollection, top: bool = True) -> Tuple[Any, int]:
        pass

    def process_result(self, result: Result) -> Any:
        pass
