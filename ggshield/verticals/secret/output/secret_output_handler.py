from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import click

from ggshield.core.errors import ExitCode
from ggshield.verticals.secret import SecretScanCollection


class SecretOutputHandler(ABC):
    show_secrets: bool = False
    verbose: bool = False
    output: Optional[Path] = None
    use_stderr: bool = False

    def __init__(
        self,
        show_secrets: bool,
        verbose: bool,
        output: Optional[Path] = None,
        ignore_known_secrets: bool = False,
    ):
        self.show_secrets = show_secrets
        self.verbose = verbose
        self.output = output
        self.ignore_known_secrets = ignore_known_secrets

    def process_scan(self, scan: SecretScanCollection) -> ExitCode:
        """Process a scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        text = self._process_scan_impl(scan)
        if self.output:
            self.output.write_text(text)
        else:
            click.echo(text, err=self.use_stderr)
        return self._get_exit_code(scan)

    @abstractmethod
    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    def _get_exit_code(self, scan: SecretScanCollection) -> ExitCode:
        if self.ignore_known_secrets:
            if scan.has_new_secrets:
                return ExitCode.SCAN_FOUND_PROBLEMS
        elif scan.has_secrets:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS
