from abc import ABC, abstractmethod
from typing import Optional

import click

from ggshield.core.errors import ExitCode
from ggshield.iac.iac_scan_collection import IaCScanCollection


class IaCOutputHandler(ABC):
    verbose: bool = False
    output: Optional[str] = None

    def __init__(
        self,
        verbose: bool,
        output: Optional[str] = None,
    ):
        self.verbose = verbose
        self.output = output

    def process_scan(self, scan: IaCScanCollection) -> ExitCode:
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
        return self._get_exit_code(scan)

    @abstractmethod
    def _process_scan_impl(self, scan: IaCScanCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    def _get_exit_code(self, scan: IaCScanCollection) -> ExitCode:
        if scan.result is None:
            return ExitCode.UNEXPECTED_ERROR
        if scan.result.entities_with_incidents:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS
