from typing import Any, Optional, Tuple

from ggshield.scan import ScanCollection


class OutputHandler:
    show_secrets: bool = False
    verbose: bool = False
    output: Optional[str] = None

    def __init__(
        self,
        show_secrets: bool,
        verbose: bool,
        output: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ):
        self.show_secrets = show_secrets
        self.verbose = verbose
        self.output = output

    def process_scan(self, scan: ScanCollection, top: bool = True) -> Tuple[Any, int]:
        pass
