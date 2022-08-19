from abc import ABC, abstractmethod
from typing import Optional

import click

from ggshield.scan import ScanCollection


class OutputHandler(ABC):
    show_secrets: bool = False
    verbose: bool = False
    output: Optional[str] = None

    def __init__(
        self,
        show_secrets: bool,
        verbose: bool,
        output: Optional[str] = None,
    ):
        self.show_secrets = show_secrets
        self.verbose = verbose
        self.output = output

    def process_scan(self, scan: ScanCollection) -> int:
        """Process a scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        text = self._process_scan_impl(scan)
        if self.output:
            with open(self.output, "w+") as f:
                f.write(text)
        else:
            click.echo(text)
        return OutputHandler._get_exit_code(scan)

    @abstractmethod
    def _process_scan_impl(self, scan: ScanCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    @staticmethod
    def _get_exit_code(scan: ScanCollection) -> int:
        if scan.has_results or scan.has_iac_result:
            return 1
        if scan.scans and any(x.has_results for x in scan.scans):
            return 1
        return 0
