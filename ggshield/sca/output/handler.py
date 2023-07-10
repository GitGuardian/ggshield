from abc import ABC, abstractmethod
from typing import Optional

import click

from ggshield.core.errors import ExitCode
from ggshield.sca.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanVulnerabilityCollection,
    SCAVulnerabilityCollectionType,
)


class SCAOutputHandler(ABC):
    verbose: bool
    output: Optional[str]

    def __init__(
        self,
        verbose: bool = False,
        output: Optional[str] = None,
    ):
        self.verbose = verbose
        self.output = output

    def process_scan_all_result(
        self, scan: SCAScanAllVulnerabilityCollection
    ) -> ExitCode:
        """Process a scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        text = self._process_scan_all_impl(scan)
        return self._handle_process_scan_result(scan, text)

    @abstractmethod
    def _process_scan_all_impl(self, scan: SCAScanAllVulnerabilityCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    def _get_exit_code(self, scan: SCAScanVulnerabilityCollection) -> ExitCode:
        if scan.result is None or scan.type == SCAVulnerabilityCollectionType.UNKNOWN:
            return ExitCode.UNEXPECTED_ERROR
        if scan.has_results:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS

    def _handle_process_scan_result(
        self, scan: SCAScanVulnerabilityCollection, text: str
    ) -> ExitCode:
        if self.output:
            with open(self.output, "w+") as f:
                f.write(text)
        else:
            click.echo(text)
        return self._get_exit_code(scan)
