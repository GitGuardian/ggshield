from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import click
from pygitguardian import GGClient

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import ExitCode
from ggshield.verticals.secret import SecretScanCollection


class SecretOutputHandler(ABC):
    verbose: bool = False
    client: Optional[GGClient] = None
    output: Optional[Path] = None
    use_stderr: bool = False

    def __init__(
        self,
        verbose: bool,
        secret_config: SecretConfig,
        client: Optional[GGClient] = None,
        output: Optional[Path] = None,
    ):
        self.show_secrets = secret_config.show_secrets
        self.verbose = verbose
        self.client = client
        self.output = output
        self.ignore_known_secrets = secret_config.ignore_known_secrets
        self.with_incident_details = secret_config.with_incident_details

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
        if scan.total_secrets_count > 0:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS
