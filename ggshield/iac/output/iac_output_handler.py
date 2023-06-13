from abc import ABC, abstractmethod
from typing import Optional

import click

from ggshield.core.errors import ExitCode
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


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

    def process_scan(self, scan: IaCPathScanCollection) -> ExitCode:
        """Process a scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        text = self._process_scan_impl(scan)
        return self._handle_process_scan_result(scan, text)

    def process_diff_scan(self, scan: IaCDiffScanCollection) -> ExitCode:
        """Process a diff scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        text = self._process_diff_scan_impl(scan)
        return self._handle_process_scan_result(scan, text)

    @abstractmethod
    def _process_scan_impl(self, scan: IaCPathScanCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    @abstractmethod
    def _process_diff_scan_impl(self, scan: IaCDiffScanCollection) -> str:
        """Implementation of diff scan processing,
        called by :meth:`OutputHandler.process_diff_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    def _get_exit_code(self, scan: IaCScanCollection) -> ExitCode:
        if scan.result is None or scan.type == CollectionType.Unknown:
            return ExitCode.UNEXPECTED_ERROR
        if scan.has_results:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS

    def _handle_process_scan_result(
        self, scan: IaCScanCollection, text: str
    ) -> ExitCode:
        if self.output:
            with open(self.output, "w+") as f:
                f.write(text)
        else:
            click.echo(text)
        return self._get_exit_code(scan)
