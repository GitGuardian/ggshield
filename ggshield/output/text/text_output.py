from typing import Tuple

import click

from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result, ScanCollection

from .message import leak_message, no_leak_message


class TextHandler(OutputHandler):
    def process_scan(self, scan: ScanCollection, top: bool = True) -> Tuple[str, int]:
        if scan.optional_info and (scan.results or self.verbose):
            click.echo(scan.optional_info)
        if not scan.results:
            if self.verbose:
                no_leak_message()
            return "", 0

        for result in scan.results:
            if isinstance(result, ScanCollection):
                self.process_scan(result, top=False)
            else:
                self.process_result(result)

        return "", 1

    def process_result(self, result: Result) -> Tuple[str, int]:
        leak_message(result, self.show_secrets)
        return "", 0
